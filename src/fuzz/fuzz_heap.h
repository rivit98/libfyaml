/*
 * A deterministic heap for the coverage-guided builds - every allocation a test
 * case makes lands at the same address on every exec of the same input.
 *
 * Why: libfyaml hashes raw pointers. fy_malloc_ptr_set (the "malloc"
 * allocator), fy_generic_idset and the node -> anchor accelerator in fy-doc.c
 * all bucket by XXH(pointer), so which bucket chain gets walked, how long it
 * is, whether fy_accel_resize() runs - and how many buckets get malloc()ed,
 * which moves the allocation alloc_fail_nth fails - depend on where glibc put
 * the object. In a persistent loop that is a function of every exec before
 * this one. Measured on the yaml seeds with fuzz_cov: every input diverged
 * between two processes in fy-accel.c and the list walks under it, and inputs
 * with alloc_fail_nth set diverged in 150-1700 lines. That is the 66-77 %
 * stability of the test_yaml campaign.
 *
 * How: while a test case runs (fuzz_heap_begin()/fuzz_heap_end(), driven by
 * alloc_fail_arm()/alloc_fail_disarm()), the __wrap_* allocators in
 * fuzz_alloc_fail.h serve from one region mapped once, before the fork server
 * starts, at a fixed address. Power-of-two size classes with LIFO free lists:
 * the address returned is a function of the test case's own alloc/free
 * sequence and nothing else. When the test case ends with nothing live, the
 * region is rewound, so the next one starts from the same empty state.
 *
 * Not for the sanitizer builds. ASAN/MSAN/LSAN have to see every allocation
 * through their interceptors, which serving from a private region would hide -
 * so under any of them this compiles to nothing and the wrappers fall through
 * to __real_*, exactly as before. Those lanes keep the old instability; the
 * fast, laf, cmplog and cov builds, where coverage is decided, lose it.
 *
 * Anonymous private mmap()s are made deterministic the same way, from a
 * second fixed region (fuzz_map_*): the "mremap" allocator and the "auto"
 * scenarios built on it take their arenas from mmap() and grow them with
 * mremap() or a hinted mmap() next to the old arena, so arena addresses - and
 * every generic value in them, which the emitter hashes for auto-anchoring -
 * moved with whatever earlier execs had left mapped. Measured: generic
 * parse+emit alone took test_generic_document_builder from 99.99 % to 75 %
 * stability. Mappings are bumped from the region top; growing in place works
 * only for the topmost one, as it would next to unmapped address space.
 *
 * Pointers that did not come from the region - allocated before the test case,
 * or by libc on the library's behalf (open_memstream()'s buffer, realpath()) -
 * are recognised by address and handed to the real free()/realloc().
 */

#ifndef FUZZ_HEAP_H
#define FUZZ_HEAP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>

#if defined(__has_feature)
# if __has_feature(address_sanitizer) || __has_feature(memory_sanitizer) || \
     __has_feature(thread_sanitizer) || __has_feature(leak_sanitizer)
#  define FUZZ_HEAP_DISABLED 1
# endif
#endif
#if defined(__SANITIZE_ADDRESS__) || defined(__AFL_LEAK_CHECK)
# define FUZZ_HEAP_DISABLED 1
#endif

/* block header size, and so the minimum alignment of every payload */
#define FUZZ_HEAP_HDR 16u

#ifndef FUZZ_HEAP_DISABLED

void __real_free(void *ptr);

/* 16 GiB of address space, MAP_NORESERVE: only what is touched is backed */
#define FUZZ_HEAP_SIZE      (16ull << 30)
#define FUZZ_HEAP_BASE      ((void *)0x600000000000ull)
#define FUZZ_HEAP_MIN_SHIFT 4                    /* smallest class: 16 bytes */
#define FUZZ_HEAP_CLASSES   36
/* what stays resident between test cases; above it is given back on rewind */
#define FUZZ_HEAP_KEEP      (64u << 20)

#include <errno.h>
#include <stdarg.h>

void *__real_mmap(void *addr, size_t len, int prot, int flags, int fd, off_t off);
int __real_munmap(void *addr, size_t len);
void *__real_mremap(void *old, size_t old_size, size_t new_size, int flags, ...);

#define FUZZ_MAP_SIZE (64ull << 30)
#define FUZZ_MAP_BASE ((void *)0x680000000000ull)
#define FUZZ_MAP_PAGE 4096ul

static char *fuzz_map_base;           /* NULL: never mapped, always pass through */
static char *fuzz_map_top;            /* everything at and above it is zero */
static size_t fuzz_map_live;          /* bytes mapped and not yet unmapped */

struct fuzz_heap_hdr {
  uint32_t cls;        /* size class: capacity is 1 << cls */
  uint32_t magic;
  void *next_free;     /* free-list link, valid only while on a free list */
};
_Static_assert(sizeof(struct fuzz_heap_hdr) == FUZZ_HEAP_HDR, "header size");

#define FUZZ_HEAP_MAGIC_LIVE 0xa110ca7e
#define FUZZ_HEAP_MAGIC_FREE 0xf4eeb10c

static char *fuzz_heap_base;          /* NULL: never mapped, always pass through */
static char *fuzz_heap_top;           /* bump pointer */
static size_t fuzz_heap_live;         /* blocks handed out and not yet freed */
static bool fuzz_heap_active;
static void *fuzz_heap_free_list[FUZZ_HEAP_CLASSES];
static volatile char fuzz_heap_lock_flag;
/* rewinds skipped because a test case left blocks live - VERBOSE reports it */
static unsigned long fuzz_heap_skipped_rewinds;

/* library worker threads allocate too (fy-thread.c) */
static inline void fuzz_heap_lock(void)
{
  while (__atomic_test_and_set(&fuzz_heap_lock_flag, __ATOMIC_ACQUIRE))
    ;
}

static inline void fuzz_heap_unlock(void)
{
  __atomic_clear(&fuzz_heap_lock_flag, __ATOMIC_RELEASE);
}

/* Mapped from a constructor, so the fork server's children all inherit it. */
__attribute__((constructor)) static void fuzz_heap_init(void)
{
  void *p = mmap(FUZZ_HEAP_BASE, FUZZ_HEAP_SIZE, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE | MAP_FIXED_NOREPLACE,
                 -1, 0);
  /* Taken (or an old kernel ignoring the flag): anywhere will do - the region
   * is mapped once per process, so every exec in it still sees one base. */
  if (p == MAP_FAILED || p != FUZZ_HEAP_BASE) {
    if (p != MAP_FAILED)
      munmap(p, FUZZ_HEAP_SIZE);
    p = mmap(NULL, FUZZ_HEAP_SIZE, PROT_READ | PROT_WRITE,
             MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    if (p == MAP_FAILED)
      return;
  }
  fuzz_heap_base = p;
  fuzz_heap_top = p;

  p = mmap(FUZZ_MAP_BASE, FUZZ_MAP_SIZE, PROT_READ | PROT_WRITE,
           MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE | MAP_FIXED_NOREPLACE, -1, 0);
  if (p == MAP_FAILED || p != FUZZ_MAP_BASE) {
    if (p != MAP_FAILED)
      munmap(p, FUZZ_MAP_SIZE);
    p = mmap(NULL, FUZZ_MAP_SIZE, PROT_READ | PROT_WRITE,
             MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    if (p == MAP_FAILED)
      return;
  }
  fuzz_map_base = p;
  fuzz_map_top = p;
}

static inline bool fuzz_map_owns(const void *p)
{
  return fuzz_map_base && (const char *)p >= fuzz_map_base &&
         (const char *)p < fuzz_map_base + FUZZ_MAP_SIZE;
}

static inline size_t fuzz_map_align(size_t len)
{
  return (len + FUZZ_MAP_PAGE - 1) & ~(FUZZ_MAP_PAGE - 1);
}

/* give pages back, so they read as zero when they are handed out again */
static inline void fuzz_map_zap(char *p, size_t len)
{
  if (len)
    madvise(p, len, MADV_DONTNEED);
}

static inline bool fuzz_heap_owns(const void *ptr)
{
  return fuzz_heap_base && (const char *)ptr >= fuzz_heap_base &&
         (const char *)ptr < fuzz_heap_base + FUZZ_HEAP_SIZE;
}

static inline bool fuzz_heap_on(void)
{
  return __builtin_expect(fuzz_heap_active, 0);
}

static inline struct fuzz_heap_hdr *fuzz_heap_hdr_of(void *ptr)
{
  return (struct fuzz_heap_hdr *)((char *)ptr - FUZZ_HEAP_HDR);
}

static inline unsigned int fuzz_heap_class(size_t size)
{
  unsigned int cls = FUZZ_HEAP_MIN_SHIFT;

  while (cls < FUZZ_HEAP_CLASSES && ((size_t)1 << cls) < size)
    cls++;
  return cls;
}

/* @align is a power of two >= 16. NULL when the region is exhausted. */
static void *fuzz_heap_alloc(size_t size, size_t align)
{
  struct fuzz_heap_hdr *h;
  unsigned int cls;
  uintptr_t payload;
  char *start;
  void *p;

  if (size == 0)
    size = 1;
  cls = fuzz_heap_class(size);
  if (cls >= FUZZ_HEAP_CLASSES)
    return NULL;

  fuzz_heap_lock();

  /* reuse only a block that already satisfies the alignment */
  p = fuzz_heap_free_list[cls];
  if (p && ((uintptr_t)p & (align - 1)) == 0) {
    h = fuzz_heap_hdr_of(p);
    fuzz_heap_free_list[cls] = h->next_free;
  } else {
    start = fuzz_heap_top;
    payload = ((uintptr_t)start + FUZZ_HEAP_HDR + align - 1) & ~(uintptr_t)(align - 1);
    if (payload + ((size_t)1 << cls) > (uintptr_t)(fuzz_heap_base + FUZZ_HEAP_SIZE)) {
      fuzz_heap_unlock();
      return NULL;
    }
    p = (void *)payload;
    fuzz_heap_top = (char *)payload + ((size_t)1 << cls);
    h = fuzz_heap_hdr_of(p);
  }
  h->cls = cls;
  h->magic = FUZZ_HEAP_MAGIC_LIVE;
  h->next_free = NULL;
  fuzz_heap_live++;

  fuzz_heap_unlock();
  return p;
}

static void fuzz_heap_free(void *ptr)
{
  struct fuzz_heap_hdr *h = fuzz_heap_hdr_of(ptr);

  /* a double free here would silently corrupt the free list - crash instead,
   * so the fast lanes still report what ASAN would */
  if (h->magic != FUZZ_HEAP_MAGIC_LIVE)
    __builtin_trap();

  fuzz_heap_lock();
  h->magic = FUZZ_HEAP_MAGIC_FREE;
  h->next_free = fuzz_heap_free_list[h->cls];
  fuzz_heap_free_list[h->cls] = ptr;
  fuzz_heap_live--;
  fuzz_heap_unlock();
}

/* NULL when the region is exhausted */
static char *fuzz_map_bump(size_t len)
{
  char *p = fuzz_map_top;

  if ((size_t)(fuzz_map_base + FUZZ_MAP_SIZE - p) < len)
    return NULL;
  fuzz_map_top = p + len;
  fuzz_map_live += len;
  return p;
}

static inline bool fuzz_map_serves(void *addr, int flags, int fd)
{
  return fuzz_heap_active && fuzz_map_base && fd == -1 &&
         (flags & MAP_ANONYMOUS) && (flags & MAP_PRIVATE) &&
         !(flags & (MAP_FIXED | MAP_FIXED_NOREPLACE | MAP_SHARED)) &&
         (!addr || fuzz_map_owns(addr) || addr == fuzz_map_base + FUZZ_MAP_SIZE);
}

/*
 * A hint is honoured only where the kernel would honour it too: at the
 * region top, which is the only place with free address space next to it.
 */
void *__wrap_mmap(void *addr, size_t len, int prot, int flags, int fd, off_t off)
{
  char *p;

  if (!fuzz_map_serves(addr, flags, fd))
    return __real_mmap(addr, len, prot, flags, fd, off);
  fuzz_heap_lock();
  p = fuzz_map_bump(fuzz_map_align(len));
  fuzz_heap_unlock();
  if (!p) {
    errno = ENOMEM;
    return MAP_FAILED;
  }
  return p;
}

int __wrap_munmap(void *addr, size_t len)
{
  char *p = addr;

  if (!fuzz_map_owns(addr))
    return __real_munmap(addr, len);
  len = fuzz_map_align(len);
  fuzz_heap_lock();
  fuzz_map_zap(p, len);
  if (p + len == fuzz_map_top)
    fuzz_map_top = p;
  fuzz_map_live -= len < fuzz_map_live ? len : fuzz_map_live;
  fuzz_heap_unlock();
  return 0;
}

void *__wrap_mremap(void *old, size_t old_size, size_t new_size, int flags, ...)
{
  char *p = old, *n;
  void *new_address = NULL;
  va_list ap;

  if (!fuzz_map_owns(old)) {
    va_start(ap, flags);
    if (flags & MREMAP_FIXED)
      new_address = va_arg(ap, void *);
    va_end(ap);
    return __real_mremap(old, old_size, new_size, flags, new_address);
  }

  old_size = fuzz_map_align(old_size);
  new_size = fuzz_map_align(new_size);
  fuzz_heap_lock();
  if (new_size <= old_size) {
    fuzz_map_zap(p + new_size, old_size - new_size);
    if (p + old_size == fuzz_map_top)
      fuzz_map_top = p + new_size;
    fuzz_map_live -= old_size - new_size;
    fuzz_heap_unlock();
    return p;
  }
  if (p + old_size == fuzz_map_top && fuzz_map_bump(new_size - old_size)) {
    fuzz_heap_unlock();
    return p;
  }
  if (!(flags & MREMAP_MAYMOVE) || !(n = fuzz_map_bump(new_size))) {
    fuzz_heap_unlock();
    errno = ENOMEM;
    return MAP_FAILED;
  }
  memcpy(n, p, old_size);
  fuzz_map_zap(p, old_size);
  fuzz_map_live -= old_size;
  fuzz_heap_unlock();
  return n;
}

static inline size_t fuzz_heap_usable(void *ptr)
{
  return (size_t)1 << fuzz_heap_hdr_of(ptr)->cls;
}

static inline void fuzz_heap_begin(void)
{
  if (fuzz_heap_base)
    fuzz_heap_active = true;
}

/*
 * Rewind after every test case, live blocks or not. A block that outlives its
 * test case is a leak - libfyaml keeps no state across calls that a test case
 * allocates - so nothing can reach it, and handing its memory out again is
 * safe. Not rewinding was not: report9.md's leak happens on any generic emit
 * of a document without document state, and one such input left the heap
 * unrewound for the rest of the process, every later exec at new addresses
 * (measured: test_generic_document_builder at 70-76 % stability). VERBOSE
 * still says when a test case leaked (fuzz_heap_skipped_rewinds).
 */
static inline void fuzz_heap_end(void)
{
  fuzz_heap_active = false;
  if (!fuzz_heap_base)
    return;

  fuzz_heap_lock();
  if (fuzz_heap_live) {
    fuzz_heap_skipped_rewinds++;
    fuzz_heap_live = 0;
  }
  memset(fuzz_heap_free_list, 0, sizeof(fuzz_heap_free_list));
  /*
   * The top only grows inside a test case, and every earlier one gave its
   * excess back, so this test case's own top is all there is to trim. No
   * process-wide high-water mark: a branch on one is taken by whichever exec
   * first grows past it and by no later one - instability of its own.
   */
  if ((size_t)(fuzz_heap_top - fuzz_heap_base) > FUZZ_HEAP_KEEP)
    madvise(fuzz_heap_base + FUZZ_HEAP_KEEP,
            (size_t)(fuzz_heap_top - fuzz_heap_base) - FUZZ_HEAP_KEEP,
            MADV_DONTNEED);
  fuzz_heap_top = fuzz_heap_base;

  /* the mmap region the same way */
  if (fuzz_map_base) {
    fuzz_map_zap(fuzz_map_base, (size_t)(fuzz_map_top - fuzz_map_base));
    fuzz_map_top = fuzz_map_base;
    fuzz_map_live = 0;
  }
  fuzz_heap_unlock();
}

#else /* FUZZ_HEAP_DISABLED */

static unsigned long fuzz_heap_skipped_rewinds;

static inline bool fuzz_heap_on(void) { return false; }
static inline bool fuzz_heap_owns(const void *ptr) { (void)ptr; return false; }
static inline void *fuzz_heap_alloc(size_t size, size_t align) { (void)size; (void)align; return NULL; }
static inline void fuzz_heap_free(void *ptr) { (void)ptr; }
static inline size_t fuzz_heap_usable(void *ptr) { (void)ptr; return 0; }
static inline void fuzz_heap_begin(void) { }
static inline void fuzz_heap_end(void) { }

/* --wrap is on the link line of every build; these pass straight through */
#include <stdarg.h>

void *__real_mmap(void *addr, size_t len, int prot, int flags, int fd, off_t off);
int __real_munmap(void *addr, size_t len);
void *__real_mremap(void *old, size_t old_size, size_t new_size, int flags, ...);

void *__wrap_mmap(void *addr, size_t len, int prot, int flags, int fd, off_t off)
{
  return __real_mmap(addr, len, prot, flags, fd, off);
}

int __wrap_munmap(void *addr, size_t len)
{
  return __real_munmap(addr, len);
}

void *__wrap_mremap(void *old, size_t old_size, size_t new_size, int flags, ...)
{
  void *new_address = NULL;
  va_list ap;

  va_start(ap, flags);
  if (flags & MREMAP_FIXED)
    new_address = va_arg(ap, void *);
  va_end(ap);
  return __real_mremap(old, old_size, new_size, flags, new_address);
}

#endif /* FUZZ_HEAP_DISABLED */

#endif /* FUZZ_HEAP_H */
