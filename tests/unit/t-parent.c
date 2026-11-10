#include "parent.c"
#include "test.h"

int main(void) {
	pid_t pid = -7;

	CHECK(parent_parse("1234", &pid) == 0 && pid == 1234, "a valid pid");
	CHECK(parent_parse("2", &pid) == 0 && pid == 2, "the smallest pid");
	CHECK(parent_parse("2147483647", &pid) == 0 && pid == 2147483647,
	      "the largest pid");

	pid = -7;
	CHECK(parent_parse(NULL, &pid) < 0, "an absent variable");
	CHECK(parent_parse("", &pid) < 0, "an empty value");
	CHECK(parent_parse("0", &pid) < 0, "zero");
	CHECK(parent_parse("1", &pid) < 0, "pid 1");
	CHECK(parent_parse("-5", &pid) < 0, "a negative number");
	CHECK(parent_parse("+5", &pid) < 0, "a sign");
	CHECK(parent_parse(" 5", &pid) < 0, "leading space");
	CHECK(parent_parse("12x", &pid) < 0, "trailing text");
	CHECK(parent_parse("abc", &pid) < 0, "text");
	CHECK(parent_parse("2147483648", &pid) < 0, "out of range");
	CHECK(parent_parse("99999999999999999999999", &pid) < 0, "overflow");
	CHECK(pid == -7, "a refused value leaves the pid untouched");
	return test_summary();
}
