#include "sandbox.h"

#include <linux/capability.h>
#include <linux/sockios.h>
#include <seccomp.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <wchar.h>

static int set_caps(__u32 inheritable) {
	struct __user_cap_header_struct hdr = {_LINUX_CAPABILITY_VERSION_3, 0};
	struct __user_cap_data_struct data[_LINUX_CAPABILITY_U32S_3];

	if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) < 0) {
		perror("PR_CAP_AMBIENT error");
		return -1;
	}
	if (syscall(SYS_capget, &hdr, data) < 0) {
		perror("capget error");
		return -1;
	}
	for (int i = 0; i < _LINUX_CAPABILITY_U32S_3; i++) {
		data[i].effective = 0;
		data[i].permitted = 0;
		data[i].inheritable &= i == 0 ? inheritable : 0;
	}
	if (syscall(SYS_capset, &hdr, data) < 0) {
		perror("capset error");
		return -1;
	}
	return 0;
}

/* What the tools it runs need as inheritable: tundra-ip and the probe of
 * tundra-blueice-arp. Root keeps everything: its children regain it on exec
 * anyway, and it needs CAP_DAC_OVERRIDE for a lease directory of another
 * user. */
int sandbox_monitor(void) {
	if (geteuid() == 0)
		return 0;
	return set_caps(1u << CAP_NET_ADMIN | 1u << CAP_NET_RAW);
}

static int allow(scmp_filter_ctx ctx) {
	static const int calls[] = {
	    SCMP_SYS(read),          SCMP_SYS(write),
	    SCMP_SYS(close),         SCMP_SYS(poll),
	    SCMP_SYS(ppoll),         SCMP_SYS(recvmsg),
	    SCMP_SYS(recvfrom),      SCMP_SYS(sendto),
	    SCMP_SYS(clock_gettime), SCMP_SYS(getrandom),
	    SCMP_SYS(brk),           SCMP_SYS(munmap),
	    SCMP_SYS(rt_sigreturn),  SCMP_SYS(restart_syscall),
	    SCMP_SYS(exit),          SCMP_SYS(exit_group),
	};

	for (size_t i = 0; i < sizeof(calls) / sizeof(calls[0]); i++)
		if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, calls[i], 0) < 0)
			return -1;
	if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ioctl), 1,
	                     SCMP_A1(SCMP_CMP_EQ, SIOCGIFHWADDR)) < 0)
		return -1;
	return seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mmap), 1,
	                        SCMP_A2(SCMP_CMP_MASKED_EQ, PROT_EXEC, 0));
}

int sandbox_worker(void) {
	/* perror() on a stream without orientation dups and reopens its fd */
	fwide(stderr, -1);

	if (set_caps(0) < 0)
		return -1;
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
		perror("PR_SET_NO_NEW_PRIVS error");
		return -1;
	}

	scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL_PROCESS);
	if (!ctx ||
	    seccomp_attr_set(ctx, SCMP_FLTATR_ACT_BADARCH, SCMP_ACT_KILL_PROCESS) <
	        0 ||
	    allow(ctx) < 0 || seccomp_load(ctx) < 0) {
		fprintf(stderr, "could not load the seccomp filter\n");
		if (ctx)
			seccomp_release(ctx);
		return -1;
	}
	seccomp_release(ctx);
	return 0;
}
