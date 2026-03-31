/*
 * Allocation failure injection: make the nth malloc()/calloc()/realloc() of a
 * test case return NULL, so the library's out-of-memory paths get fuzzed too.
 * The seeded index is flags_t.alloc_fail_nth (fuzz_flags.h).
 *
 * Every harness links with -Wl,--wrap=malloc,--wrap=calloc,--wrap=realloc
 * (fuzz_add_harness() in CMakeLists.txt). The linker points each undefined
 * reference to those three in a *statically linked* object - the harness and
 * the libfyaml archive - at the __wrap_* functions below, and __real_* at the
 * real one, which under a sanitizer is its interceptor. So:
 *
 *   - ASAN/MSAN/LSAN still see every allocation. Nothing overrides their
 *     malloc interceptors, which is what defining malloc() here would do.
 *   - Allocations made inside a shared object are never counted or failed:
 *     libc's own (strdup(), fopen(), open_memstream(), ...) and libclang's,
 *     whose operator new would throw on a NULL.
 *   - The library has to be linked statically, which is why fuzz2 links
 *     fyaml_static rather than the shared fyaml.
 *
 * The count is armed per test case - T_RUN() in fuzz_utils.h and RF() in
 * main.c - restarts from zero each time, and fires exactly once: with nth = 5
 * the fifth allocation fails and every one after it succeeds. nth = 0 is off,
 * and costs a TLS load and a never-taken branch per allocation.
 *
 * Thread-local on purpose: counting a library worker thread's allocations
 * would make "the nth" depend on scheduling. Worker threads are never armed,
 * so their allocations never fail.
 */

#ifndef FUZZ_ALLOC_FAIL_H
#define FUZZ_ALLOC_FAIL_H

#include <stdbool.h>
#include <stddef.h>

void *__real_malloc(size_t size);
void *__real_calloc(size_t nmemb, size_t size);
void *__real_realloc(void *ptr, size_t size);

static _Thread_local unsigned int alloc_fail_nth;     /* 0 = off */
static _Thread_local unsigned int alloc_fail_count;
/*
 * volatile, and written through barriers in ALLOC_FAIL_EXEMPT() below: the
 * only reader is __wrap_malloc(), which the compiler cannot see is the callee
 * of a plain malloc() call - --wrap is a link-time rewrite. Without this the
 * increment/decrement pair is a dead store pair around an opaque call and is
 * deleted outright at -O2, silently making every exemption a no-op.
 */
static _Thread_local volatile unsigned int alloc_fail_exempt;  /* ALLOC_FAIL_EXEMPT() depth */

static inline void alloc_fail_arm(unsigned int nth)
{
  alloc_fail_nth = nth;
  alloc_fail_count = 0;
}

/* Returns true when the armed allocation was reached, and so failed. */
static inline bool alloc_fail_disarm(void)
{
  bool fired = alloc_fail_nth && alloc_fail_count >= alloc_fail_nth;

  alloc_fail_nth = 0;
  return fired;
}

static inline bool alloc_fail_now(void)
{
  if (__builtin_expect(alloc_fail_nth == 0, 1) || alloc_fail_exempt ||
      alloc_fail_count >= alloc_fail_nth)
    return false;
  return ++alloc_fail_count == alloc_fail_nth;
}

/*
 * Run @stmt with injection suspended and its allocations uncounted. For
 * harness-owned buffers, which have no failure path worth testing, and for
 * one-time process state: counting the corpus fixture's allocations in the
 * first exec only would shift "the nth" between that exec and every later one.
 */
#define ALLOC_FAIL_EXEMPT(stmt) do { \
  alloc_fail_exempt++; \
  __asm__ __volatile__("" ::: "memory"); \
  stmt; \
  __asm__ __volatile__("" ::: "memory"); \
  alloc_fail_exempt--; \
} while (0)

void *__wrap_malloc(size_t size)
{
  if (alloc_fail_now())
    return NULL;
  return __real_malloc(size);
}

void *__wrap_calloc(size_t nmemb, size_t size)
{
  if (alloc_fail_now())
    return NULL;
  return __real_calloc(nmemb, size);
}

/*
 * realloc(p, 0) frees p. A NULL from it is indistinguishable from success, so
 * failing it would only leak p - it is passed through and not counted.
 */
void *__wrap_realloc(void *ptr, size_t size)
{
  if ((!ptr || size) && alloc_fail_now())
    return NULL;
  return __real_realloc(ptr, size);
}

#endif /* FUZZ_ALLOC_FAIL_H */
