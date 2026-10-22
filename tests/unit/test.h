#ifndef TUNDRA_TEST_H
#define TUNDRA_TEST_H

#include <stdio.h>

static int test_pass;
static int test_fail;

#define CHECK(cond, desc)                                                      \
	do {                                                                       \
		if (cond) {                                                            \
			test_pass++;                                                       \
			printf("ok - %s\n", desc);                                         \
		} else {                                                               \
			test_fail++;                                                       \
			printf("not ok - %s (%s:%d)\n", desc, __FILE__, __LINE__);         \
		}                                                                      \
	} while (0)

static int test_summary(void) {
	printf("# %d passed, %d failed\n", test_pass, test_fail);
	return test_fail ? 1 : 0;
}

#endif
