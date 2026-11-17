#pragma once

// The whole test framework: CHECK counts a failure and carries on, so that
// one run shows every broken expectation; the test's exit status is the count.

#include <stdio.h>
#include <string.h>

static int check_failures;

#define CHECK(cond) do { \
        if (!(cond)) { \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            check_failures++; \
        } \
    } while (0)

#define CHECK_EQ(a, b) do { \
        const long long check_a = (long long)(a), check_b = (long long)(b); \
        if (check_a != check_b) { \
            fprintf(stderr, "FAIL %s:%d: %s == %s (%lld != %lld)\n", __FILE__, __LINE__, #a, #b, check_a, check_b); \
            check_failures++; \
        } \
    } while (0)

#define CHECK_STR(a, b) do { \
        const char* check_a = (a); const char* check_b = (b); \
        if (!check_a || !check_b || strcmp(check_a, check_b) != 0) { \
            fprintf(stderr, "FAIL %s:%d: %s == %s (\"%s\" != \"%s\")\n", __FILE__, __LINE__, #a, #b, \
                check_a ? check_a : "(null)", check_b ? check_b : "(null)"); \
            check_failures++; \
        } \
    } while (0)

#define CHECK_DONE() do { \
        if (check_failures) fprintf(stderr, "%d check(s) failed\n", check_failures); \
        else printf("ok\n"); \
        return check_failures ? 1 : 0; \
    } while (0)
