/*
 * Allocation failure injection: make the nth malloc()/calloc()/realloc() of a
 * test case return NULL, so the library's out-of-memory paths get fuzzed too.
 * The seeded index is flags_t.alloc_fail_nth (fuzz_flags.h).
 *
 * Every harness links with -Wl,--wrap=<fn> for malloc, calloc, realloc and
 * for the libc functions that allocate internally (FUZZ_ALLOC_WRAP_LINK_OPTIONS
 * in CMakeLists.txt). The linker points each undefined reference to one of
 * them in a *statically linked* object - the harness and the libfyaml archive
 * - at the __wrap_* functions below, and __real_* at the real one, which under
 * a sanitizer is its interceptor. So:
 *
 *   - ASAN/MSAN/LSAN still see every allocation. Nothing overrides their
 *     malloc interceptors, which is what defining malloc() here would do.
 *   - An allocation made inside a shared object is never counted or failed:
 *     libc's own malloc() calls made on behalf of strdup(), fopen() and the
 *     like never reach __wrap_malloc(), and neither do libclang's, whose
 *     operator new would throw on a NULL. That is why the libc functions the
 *     library calls and that allocate internally get a wrapper of their own,
 *     each counted as one allocation and failing the way libc reports it:
 *     strdup, asprintf, vasprintf, posix_memalign (fy_align_alloc()),
 *     open_memstream, fopen, fdopen, opendir, fdopendir, realpath(path, NULL),
 *     setenv, regcomp, regexec and pthread_create. Left alone on purpose:
 *     qsort() (falls back to heapsort), stdio's lazy buffer (falls back to a
 *     1-byte one), the printf/scanf family (allocates only for exotic
 *     formats) and mmap()/mremap(), which are not heap allocations.
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

#include <dirent.h>
#include <errno.h>
#include <pthread.h>
#include <regex.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

void *__real_malloc(size_t size);
void *__real_calloc(size_t nmemb, size_t size);
void *__real_realloc(void *ptr, size_t size);
char *__real_strdup(const char *s);
int __real_vasprintf(char **strp, const char *fmt, va_list ap);
int __real_posix_memalign(void **memptr, size_t alignment, size_t size);
FILE *__real_open_memstream(char **ptr, size_t *sizeloc);
FILE *__real_fopen(const char *path, const char *mode);
FILE *__real_fdopen(int fd, const char *mode);
DIR *__real_opendir(const char *name);
DIR *__real_fdopendir(int fd);
char *__real_realpath(const char *path, char *resolved);
int __real_setenv(const char *name, const char *value, int overwrite);
int __real_regcomp(regex_t *preg, const char *regex, int cflags);
int __real_regexec(const regex_t *preg, const char *string, size_t nmatch,
                   regmatch_t pmatch[], int eflags);
int __real_pthread_create(pthread_t *thread, const pthread_attr_t *attr,
                          void *(*start)(void *), void *arg);

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

/*
 * libc functions that allocate inside libc. Each counts as one allocation and,
 * when it is the armed one, fails the way libc reports out of memory.
 */
char *__wrap_strdup(const char *s)
{
  if (alloc_fail_now()) {
    errno = ENOMEM;
    return NULL;
  }
  return __real_strdup(s);
}

int __wrap_vasprintf(char **strp, const char *fmt, va_list ap)
{
  if (alloc_fail_now()) {
    errno = ENOMEM;
    return -1;
  }
  return __real_vasprintf(strp, fmt, ap);
}

/* Calls __real_vasprintf(), so it is counted once, here. */
int __wrap_asprintf(char **strp, const char *fmt, ...)
{
  va_list ap;
  int ret;

  if (alloc_fail_now()) {
    errno = ENOMEM;
    return -1;
  }
  va_start(ap, fmt);
  ret = __real_vasprintf(strp, fmt, ap);
  va_end(ap);
  return ret;
}

int __wrap_posix_memalign(void **memptr, size_t alignment, size_t size)
{
  if (alloc_fail_now())
    return ENOMEM;
  return __real_posix_memalign(memptr, alignment, size);
}

FILE *__wrap_open_memstream(char **ptr, size_t *sizeloc)
{
  if (alloc_fail_now()) {
    errno = ENOMEM;
    return NULL;
  }
  return __real_open_memstream(ptr, sizeloc);
}

FILE *__wrap_fopen(const char *path, const char *mode)
{
  if (alloc_fail_now()) {
    errno = ENOMEM;
    return NULL;
  }
  return __real_fopen(path, mode);
}

FILE *__wrap_fdopen(int fd, const char *mode)
{
  if (alloc_fail_now()) {
    errno = ENOMEM;
    return NULL;
  }
  return __real_fdopen(fd, mode);
}

DIR *__wrap_opendir(const char *name)
{
  if (alloc_fail_now()) {
    errno = ENOMEM;
    return NULL;
  }
  return __real_opendir(name);
}

DIR *__wrap_fdopendir(int fd)
{
  if (alloc_fail_now()) {
    errno = ENOMEM;
    return NULL;
  }
  return __real_fdopendir(fd);
}

/* Only realpath(path, NULL) allocates; with a caller's buffer it does not. */
char *__wrap_realpath(const char *path, char *resolved)
{
  if (!resolved && alloc_fail_now()) {
    errno = ENOMEM;
    return NULL;
  }
  return __real_realpath(path, resolved);
}

int __wrap_setenv(const char *name, const char *value, int overwrite)
{
  if (alloc_fail_now()) {
    errno = ENOMEM;
    return -1;
  }
  return __real_setenv(name, value, overwrite);
}

int __wrap_regcomp(regex_t *preg, const char *regex, int cflags)
{
  if (alloc_fail_now())
    return REG_ESPACE;
  return __real_regcomp(preg, regex, cflags);
}

int __wrap_regexec(const regex_t *preg, const char *string, size_t nmatch,
                   regmatch_t pmatch[], int eflags)
{
  if (alloc_fail_now())
    return REG_ESPACE;
  return __real_regexec(preg, string, nmatch, pmatch, eflags);
}

/* glibc maps the stack and TLS allocation failing to EAGAIN. */
int __wrap_pthread_create(pthread_t *thread, const pthread_attr_t *attr,
                          void *(*start)(void *), void *arg)
{
  if (alloc_fail_now())
    return EAGAIN;
  return __real_pthread_create(thread, attr, start, arg);
}

#endif /* FUZZ_ALLOC_FAIL_H */
