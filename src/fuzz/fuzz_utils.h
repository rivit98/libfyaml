#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include <libfyaml.h>
#include <libfyaml/libfyaml-reflection.h>
#include <libfyaml/libfyaml-generic.h>

#include "fuzz_flags.h"
#include "fuzz_alloc_fail.h"


/* fy-walk.h, internal; linked statically - see corpus_ypath_document() */
int fy_document_setup_path_expr_data(struct fy_document *fyd);
void fy_document_cleanup_path_expr_data(struct fy_document *fyd);
/* fy-token.h, internal - see corpus_prime_tokens() */
struct fy_text_analysis;
const struct fy_text_analysis *fy_token_text_analyze(struct fy_token *fyt);

static const char corpus_yaml[] = {
#embed "corpus.yaml" suffix(,)
  '\0'
};

#define CORPUS_YAML     corpus_yaml
#define CORPUS_YAML_LEN (sizeof(corpus_yaml) - 1)

static struct fy_document *corpus_fyd = NULL;
static bool corpus_fyd_built = false;

/*
 * A token's text is materialized on first use and cached on the token
 * (fy_token_get_text()/_text0(): fyt->text0). For a fixture token that first
 * use is some exec's path comparison, so the cache would be allocated in the
 * deterministic heap and left dangling by its rewind - destroying the fixture
 * at exit then freed region memory and spun in fuzz_heap_free(). Its text
 * analysis is cached the same way (no allocation, but fy-atom.c's analyzer
 * ran on the first exec to need it and never again). Every token of a fixture
 * gets both before the fork server starts instead.
 */
static void corpus_prime_tokens(struct fy_node *fyn)
{
  struct fy_node_pair *fynp;
  struct fy_node *fyni;
  void *iter = NULL;

  if (!fyn)
    return;

  /* exported, not inline: a discarded result does not drop the call */
  (void)fy_token_get_text0(fy_node_get_tag_token(fyn));
  (void)fy_token_text_analyze(fy_node_get_tag_token(fyn));

  switch (fy_node_get_type(fyn)) {
  case FYNT_SCALAR:   /* aliases too */
    (void)fy_token_get_text0(fy_node_get_scalar_token(fyn));
    (void)fy_token_text_analyze(fy_node_get_scalar_token(fyn));
    break;
  case FYNT_SEQUENCE:
    while ((fyni = fy_node_sequence_iterate(fyn, &iter)) != NULL)
      corpus_prime_tokens(fyni);
    break;
  case FYNT_MAPPING:
    while ((fynp = fy_node_mapping_iterate(fyn, &iter)) != NULL) {
      corpus_prime_tokens(fy_node_pair_key(fynp));
      corpus_prime_tokens(fy_node_pair_value(fynp));
    }
    break;
  }
}

/*
 * The shared fixture. READ ONLY - never mutate what this returns.
 */
static struct fy_document *corpus_document(void)
{
  if (corpus_fyd_built)
    return corpus_fyd;

  struct fy_parse_cfg cfg = {
    .flags = FYPCF_QUIET | FYPCF_RESOLVE_DOCUMENT | FYPCF_KEEP_COMMENTS,
  };
  /* built inside whichever test case gets here first - see ALLOC_FAIL_EXEMPT() */
  ALLOC_FAIL_EXEMPT({
    corpus_fyd = fy_document_build_from_string(&cfg, CORPUS_YAML, CORPUS_YAML_LEN);
    corpus_prime_tokens(fy_document_root(corpus_fyd));
  });
  corpus_fyd_built = true;

  return corpus_fyd;
}

/* corpus.yaml with corpus_ypath.yaml appended: one document, one more key */
static const char corpus_ypath_yaml[] = {
#embed "corpus.yaml"
  ,
#embed "corpus_ypath.yaml" suffix(,)
  '\0'
};

static struct fy_document *corpus_ypath_fyd = NULL;
static bool corpus_ypath_fyd_built = false;

/*
 * The second fixture: the same corpus, parsed with FYPCF_YPATH_ALIASES and
 * left unresolved. corpus_document() resolves every alias away, so no ypath
 * walk over it ever meets an alias node, and none of fy-walk.c's alias
 * handling runs (fy_node_alias_resolve_by_ypath*(), the per-node expression
 * cache, the recursion check).
 *
 * READ ONLY too, and ypath makes that harder. Resolving an alias by ypath
 * caches two things:
 *
 *   - the alias text parsed as an expression, on the alias node (fyn->pxnd).
 *     Left lazy, the first exec of each forked child to walk through an alias
 *     would parse it and later ones would not, so every alias is resolved once
 *     here, before the fork server starts. Aliases whose text does not parse
 *     cache nothing and fail the same way on every exec.
 *
 *   - a path parser and a walk-result recycle list on the document
 *     (fyd->pxdd), which any ypath lookup creates - fy_node_by_path() with
 *     FYNWF_PTR_YPATH too, so on corpus_document() as well. Both grow: the
 *     parser recycles tokens and expressions, the list every result an alias
 *     resolution freed. Made inside a test case they sit in the deterministic
 *     heap, which is rewound when the test case ends, and the next exec finds
 *     the fixture pointing into reused memory (the cov build hung, then
 *     trapped, on a plain "/" seed). So it lives exactly one test case:
 *     created when the test case asks for this fixture, dropped by
 *     corpus_documents_release_path_data() before it returns. It is created
 *     up front because a node with pxnd never creates it on its own - it is
 *     assumed to exist, and without it every cached alias fails to resolve.
 */
static struct fy_document *corpus_ypath_document(void)
{
  if (corpus_ypath_fyd_built) {
    fy_document_setup_path_expr_data(corpus_ypath_fyd);   /* NULL-safe */
    return corpus_ypath_fyd;
  }

  struct fy_parse_cfg cfg = {
    .flags = FYPCF_QUIET | FYPCF_KEEP_COMMENTS | FYPCF_YPATH_ALIASES,
  };
  ALLOC_FAIL_EXEMPT({
    corpus_ypath_fyd = fy_document_build_from_string(&cfg, corpus_ypath_yaml,
                                                     sizeof(corpus_ypath_yaml) - 1);
    struct fy_document_iterator *fydi = fy_document_iterator_create();
    if (corpus_ypath_fyd && fydi) {
      struct fy_node *fyn;

      fy_document_iterator_node_start(fydi, fy_document_root(corpus_ypath_fyd));
      while ((fyn = fy_document_iterator_node_next(fydi)) != NULL)
        if (fy_node_is_alias(fyn))
          fy_node_resolve_alias(fyn);
    }
    fy_document_iterator_destroy(fydi);
    fy_document_cleanup_path_expr_data(corpus_ypath_fyd);
    corpus_prime_tokens(fy_document_root(corpus_ypath_fyd));
  });
  corpus_ypath_fyd_built = true;

  return corpus_ypath_fyd;
}

/* Every test case that looks paths up in a fixture ends with this. */
static void corpus_documents_release_path_data(void)
{
  fy_document_cleanup_path_expr_data(corpus_fyd);
  fy_document_cleanup_path_expr_data(corpus_ypath_fyd);
}

__attribute__((destructor)) static void corpus_document_free(void)
{
  fy_document_destroy(corpus_fyd);
  corpus_fyd = NULL;
  corpus_fyd_built = false;
  fy_document_destroy(corpus_ypath_fyd);
  corpus_ypath_fyd = NULL;
  corpus_ypath_fyd_built = false;
}

#define CHECK(cond) do { if (!(cond)) goto out; } while(0)

/*
 * Consume a value the harness does not inspect - and keep the call that
 * produced it.
 *
 * Much of libfyaml's API is `static inline` in the public headers
 * (libfyaml-core.h, -reflection.h, and nearly all of -generic.h). A call whose
 * result is discarded can be deleted outright at -O2, taking its coverage and
 * its sanitizer checks with it - the accessor sweeps below exist precisely to
 * run those functions, so losing them loses the test.
 *
 * A `(void)` cast does NOT prevent that; measured on clang -O2, both a bare
 * call and a cast one compile to a lone `ret`. An asm operand does: the value
 * has to be materialised in memory for the (empty) asm statement, so the call
 * cannot be folded away. "+m" keeps it local - no memory clobber, so the code
 * around it still optimises normally.
 *
 * Only for value-returning calls; a void function has nothing to sink (and
 * nothing to delete either, unless it is side-effect free, in which case there
 * is nothing to test).
 */
#define USE(expr) \
  do { __typeof__(expr) _use_tmp = (expr); __asm__ volatile("" : "+m"(_use_tmp)); } while (0)


/*
 * Build the allocator named by a recipe (see fy_alloc_recipes[] in
 * fuzz_flags.h).
 *
 * Ownership is entirely the caller's: nothing here sets
 * FYGBCF_OWNS_ALLOCATOR, so fy_generic_builder_cleanup() never destroys what
 * this returns. Destroy the builder first, then call
 * make_recipe_allocator_free() with the same two pointers - the "dedup" recipe
 * layers over a parent allocator that fy_dedup_cleanup() does not free either,
 * so both have to come back out, youngest first.
 *
 * Returns NULL for FY_ALLOC_RECIPE_DEFAULT (and on failure) - which is the
 * correct thing to hand fy_generic_builder_cfg.allocator to make the builder
 * create its own "auto".
 */
static struct fy_allocator *make_recipe_allocator(const struct fy_alloc_recipe *r,
                                                  struct fy_allocator **parent_out)
{
  *parent_out = NULL;

  switch (r->kind) {
  case FY_ALLOC_RECIPE_DEFAULT:
    return NULL;

  case FY_ALLOC_RECIPE_MALLOC:
    return fy_allocator_create("malloc", NULL);

  case FY_ALLOC_RECIPE_LINEAR: {
    struct fy_linear_allocator_cfg cfg = { .buf = NULL, .size = r->size };
    return fy_allocator_create("linear", &cfg);
  }

  case FY_ALLOC_RECIPE_MREMAP: {
    struct fy_mremap_allocator_cfg cfg = {
      .minimum_arena_size = r->size,
      .grow_ratio = r->grow_ratio,
      .balloon_ratio = r->balloon_ratio,
      .arena_type = (enum fy_mremap_arena_type)r->choice,
    };
    return fy_allocator_create("mremap", &cfg);
  }

  case FY_ALLOC_RECIPE_AUTO: {
    struct fy_auto_allocator_cfg cfg = {
      .scenario = (enum fy_auto_allocator_scenario_type)r->choice,
      .estimated_max_size = r->size,
    };
    return fy_allocator_create("auto", &cfg);
  }

  case FY_ALLOC_RECIPE_DEDUP: {
    struct fy_allocator *parent, *dedup;
    struct fy_dedup_allocator_cfg cfg;

    /* the parent is required, and stays ours to destroy */
    parent = fy_allocator_create("malloc", NULL);
    if (!parent)
      return NULL;

    memset(&cfg, 0, sizeof(cfg));
    cfg.parent_allocator = parent;
    cfg.bucket_count_bits = r->bits;
    cfg.estimated_content_size = r->size;

    dedup = fy_allocator_create("dedup", &cfg);
    if (!dedup) {
      fy_allocator_destroy(parent);
      return NULL;
    }

    *parent_out = parent;
    return dedup;
  }
  }

  return NULL;
}

static void make_recipe_allocator_free(struct fy_allocator *a, struct fy_allocator *parent)
{
  if (a)
    fy_allocator_destroy(a);
  if (parent)
    fy_allocator_destroy(parent);
}

/////////////////////////

void dump_testsuite_event(struct fy_parser *fyp,
			  struct fy_event *fye)
{
	/* The token texts below are fetched, not printed: the point is to make
	 * the library produce them, so every accessor runs under the
	 * sanitizers. Nothing here reads them back. */
	const char *anchor __attribute__((unused)) = NULL;
	const char *tag __attribute__((unused)) = NULL;
	const char *text __attribute__((unused)) = NULL;
	const char *alias __attribute__((unused)) = NULL;
	size_t anchor_len = 0, tag_len = 0, text_len = 0, alias_len = 0;

	(void)fyp;

	USE(fy_event_start_mark(fye));
	USE(fy_event_end_mark(fye));

	switch (fye->type) {
	case FYET_NONE:
	case FYET_STREAM_START:
	case FYET_STREAM_END:
	case FYET_DOCUMENT_START:
	case FYET_DOCUMENT_END:
	case FYET_MAPPING_END:
	case FYET_SEQUENCE_END:
	case FYET_ALIAS:
		break;
	case FYET_MAPPING_START:
		if (fye->mapping_start.anchor)
			anchor = fy_token_get_text(fye->mapping_start.anchor, &anchor_len);
		if (fye->mapping_start.tag)
			tag = fy_token_get_text(fye->mapping_start.tag, &tag_len);
		break;
	case FYET_SEQUENCE_START:
		if (fye->sequence_start.anchor)
			anchor = fy_token_get_text(fye->sequence_start.anchor, &anchor_len);
		if (fye->sequence_start.tag)
			tag = fy_token_get_text(fye->sequence_start.tag, &tag_len);
		break;
	case FYET_SCALAR:
		if (fye->scalar.anchor)
			anchor = fy_token_get_text(fye->scalar.anchor, &anchor_len);
		if (fye->scalar.tag)
			tag = fy_token_get_text(fye->scalar.tag, &tag_len);
		break;
	default:
		assert(0);
	}

	switch (fye->type) {
	default:
		break;
	case FYET_SCALAR:
		text = fy_token_get_text(fye->scalar.value, &text_len);
		break;
	case FYET_ALIAS:
		alias = fy_token_get_text(fye->alias.anchor, &alias_len);
		break;
	}

	fy_event_type_get_text(fye->type);
	fy_event_is_implicit(fye);
	fy_event_get_node_style(fye);
	fy_event_style_start_mark(fye);
	fy_event_style_end_mark(fye);
	fy_document_event_is_implicit(fye);

	struct fy_token *evtok = fy_event_get_token(fye);
	if (evtok) {
		fy_token_get_type(evtok);
		fy_token_start_mark(evtok);
		fy_token_end_mark(evtok);
		fy_token_style_start_mark(evtok);
		fy_token_style_end_mark(evtok);
		fy_token_scalar_style(evtok);
		fy_token_scalar_is_null(evtok);
		fy_token_collection_style(evtok);
	}

	struct fy_token *evanchor = fy_event_get_anchor_token(fye);
	(void)evanchor;

	struct fy_token *evtag = fy_event_get_tag_token(fye);
	if (evtag) {
		size_t l;
		fy_tag_token_handle(evtag, &l);
		fy_tag_token_handle0(evtag);
		fy_tag_token_short(evtag, &l);
		fy_tag_token_short0(evtag);
		fy_tag_token_suffix(evtag, &l);
		fy_tag_token_suffix0(evtag);
		fy_tag_token_tag(evtag);
	}

	if (fye->type == FYET_DOCUMENT_START)
		fy_document_start_event_version(fye);
}

/////////////////////////////

char *nullterminated(const char *data, size_t size) {
  char *newdata;

  ALLOC_FAIL_EXEMPT(newdata = malloc(size + 1));
  memcpy(newdata, data, size);
  newdata[size] = '\0';
  return newdata;
}

bool split_two_parts(const char *data, size_t size,
                      char **out1, size_t *out1_len,
                      char **out2, size_t *out2_len) {
  const char *nl = memchr(data, '\n', size);
  if (!nl)
    return false;

  size_t len1 = (size_t)(nl - data);
  size_t len2 = size - len1 - 1;

  *out1 = nullterminated(data, len1);
  *out1_len = len1;
  *out2 = nullterminated(nl + 1, len2);
  *out2_len = len2;
  return true;
}

void sprintf_artifact_as_hexstr(char *out, size_t out_size,
                              const char *buf, size_t buf_size)
{
    size_t pos = 0;

    for (size_t i = 0; i < buf_size; i++) {
        int written = snprintf(out + pos,
                               (pos < out_size) ? out_size - pos : 0,
                               "\\x%02x",
                               (unsigned char)buf[i]);

        if (written < 0 || (size_t)written >= out_size - pos)
            break; // truncated or full

        pos += (size_t)written;
    }

    if (pos < out_size)
        out[pos] = '\0';
    else
        out[out_size - 1] = '\0';
}

/*
 * mmap the artifact in full, seed prefix included, so the caller sees
 * exactly the bytes the fuzzer wrote - no fixed-size read buffer to
 * silently truncate oversized inputs, and no separate seed-stripping
 * here that would double up with LLVMFuzzerTestOneInput()'s own.
 * Caller must munmap(*out_buf, return value) instead of free()ing it.
 */
int read_artifact_raw(const char *filename, char **out_buf) {
  int fd = open(filename, O_RDONLY);
  if (fd < 0) {
    perror("open");
    exit(1);
  }

  struct stat st;
  if (fstat(fd, &st) < 0) {
    perror("fstat");
    exit(1);
  }
  size_t size = (size_t)st.st_size;

  if (size == 0) {
    close(fd);
    *out_buf = NULL;
    return 0;
  }

  void *map = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
  close(fd);
  if (map == MAP_FAILED) {
    perror("mmap");
    exit(1);
  }

  *out_buf = map;
  return (int)size;
}

/*
 * The T() trampoline. Every T() test case gets @data as a private copy of the
 * input, NUL terminated at data[size] and freed once the test returns - so a
 * test needs no nullterminated() of its own, and one that writes through the
 * buffer (after casting the const away) corrupts neither libFuzzer's input nor
 * the next test case, which is handed a fresh copy.
 *
 * T2() test cases get libFuzzer's buffer unchanged and must not write to it:
 * every later T2() in the same run would see the mutation, and the crash would
 * not reproduce from the artifact.
 */
int tc(struct flags_t *flags, const uint8_t *data, size_t size, void (*f)(struct flags_t *, const char *, size_t)) {
  char *d = nullterminated((const char *)data, size);
  f(flags, d, size);
  free(d);
  return 0;
}

/*
 * Per-call-site selection cache: the strcmp() against TC runs once per site,
 * afterwards the decision is a byte load. When TC is unset the whole thing
 * collapses to a single (never taken) branch on a hot global.
 */
/*
 * Set by G() while a group runs: true when TC= named this group (or named
 * nothing), which means every member of it runs. False when TC= named
 * something else - then each member checks its own name, so TC= can still
 * select one test case inside a group.
 */
bool tc_group_all = true;

#define TC_SKIP(func) ({ \
  static signed char _tc_sel = -1; \
  bool _tc_skip = false; \
  if (__builtin_expect(tc_filter != NULL, 0)) { \
    if (__builtin_expect(_tc_sel < 0, 0)) { \
      _tc_sel = strcmp(tc_filter, #func) == 0; \
      tc_filter_matched |= (bool)_tc_sel; \
    } \
    _tc_skip = !_tc_sel && !tc_group_all; \
  } \
  _tc_skip; \
})

/*
 * Monotonic wall clock: what a test case actually costs the fuzzer per exec,
 * blocking included. Only ever reached on the verbose path.
 */
static double now_ms(void)
{
  struct timespec ts;

  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1000000.0;
}

/*
 * Run one test case, and under VERBOSE=1 time it.
 *
 * The banner goes out before the call, so a test case that crashes or hangs is
 * still named; the timing line follows when it returns - a banner with no
 * timing line after it is the test case that died.
 *
 * Both go to stderr, unbuffered and on a stream the library never writes to.
 * On stdout they were unparseable: test cases emit YAML and diagnostics that
 * do not end in a newline, so the next line printed lands mid-line (measured:
 * 27 of 195 execs lost their test_parse_with_flags timing that way). It also
 * keeps them clear of the RF() reproducer text the RR() macros harvest.
 *
 * The timing lives entirely behind the verbose branch: a normal fuzzing run
 * pays the same single load of a hot global it always did, and no clock call.
 *
 * Allocation failure injection is armed around the call, so every test case
 * counts its allocations from zero (fuzz_alloc_fail.h). Under VERBOSE a line
 * after the timing says when the failure actually fired - a test case that
 * makes fewer allocations than the index never sees one - and another when the
 * test case leaked, which leaves the deterministic heap (fuzz_heap.h) unrewound.
 */
#define T_RUN(func, call) do { \
  if (TC_SKIP(func)) \
    break; \
  if (__builtin_expect(!verbose, 1)) { \
    alloc_fail_arm(FLAGS_ALLOC_FAIL_NTH(flags)); \
    call; \
    alloc_fail_disarm(); \
    break; \
  } \
  fprintf(stderr, "=== Running %s ===\n", #func); \
  double _t0 = now_ms(); \
  unsigned long _skipped = fuzz_heap_skipped_rewinds; \
  alloc_fail_arm(FLAGS_ALLOC_FAIL_NTH(flags)); \
  call; \
  bool _alloc_failed = alloc_fail_disarm(); \
  fprintf(stderr, "=== %s: %.3f ms ===\n", #func, now_ms() - _t0); \
  if (_alloc_failed) \
    fprintf(stderr, "=== %s: allocation %u failed (injected) ===\n", #func, \
            FLAGS_ALLOC_FAIL_NTH(flags)); \
  if (fuzz_heap_skipped_rewinds != _skipped) \
    fprintf(stderr, "=== %s: left heap blocks live, heap not rewound ===\n", #func); \
} while(0)

#define T(func)  T_RUN(func, tc(flags, (const uint8_t *)(data), size, func))
#define T2(func) T_RUN(func, func(flags, (const char *)(data), size))

/*
 * A test group: the unit TC= selects, and the unit fuzzer/seeds/<group>/ is
 * built for. Members inside it are dispatched with BRANCH()/BRANCH2(), which
 * are T()/T2() - a private NUL-terminated copy, or the raw buffer.
 *
 * The group is entered even when TC= names something else, because what it
 * names may be one of the members; tc_group_all tells the members whether to
 * run unconditionally or to check their own name. A group whose members all
 * skip costs a call and nothing else.
 */
#define G(func) do { \
  static signed char _g_sel = -1; \
  if (__builtin_expect(tc_filter != NULL, 0)) { \
    if (__builtin_expect(_g_sel < 0, 0)) { \
      _g_sel = strcmp(tc_filter, #func) == 0; \
      tc_filter_matched |= (bool)_g_sel; \
    } \
    tc_group_all = (bool)_g_sel; \
  } \
  /* Under VERBOSE, a group that is only being entered so its members can
     check their own names has nothing to announce - the member that matches
     announces itself. */ \
  if (__builtin_expect(!verbose, 1) || !tc_group_all) { \
    func(flags, (const char *)(data), size); \
  } else { \
    fprintf(stderr, "=== Running %s ===\n", #func); \
    double _t0 = now_ms(); \
    func(flags, (const char *)(data), size); \
    fprintf(stderr, "=== %s: %.3f ms ===\n", #func, now_ms() - _t0); \
  } \
} while (0)

/*
 * The sink for everything the harness emits and never reads back:
 * fy_emit_document_to_fp(), the testsuite event dumper and
 * fy_generic_dump_primitive() all write here.
 *
 * It is a fopencookie() stream rather than /dev/null, so the bytes are dropped
 * in-process by the write callback below - no file descriptor, and nothing
 * reaches write(2) on the flush path. glibc still buffers ahead of the
 * callback, so the callback sees whole buffers rather than every fwrite.
 *
 * _GNU_SOURCE comes from COMMON_C_DEFINITIONS (see the top-level CMakeLists),
 * which is what puts fopencookie() and cookie_io_functions_t in scope.
 */
static ssize_t null_write(void *cookie, const char *buf, size_t size)
{
  (void)cookie;
  (void)buf;

  return (ssize_t)size;   /* consumed everything, stored none of it */
}

static const cookie_io_functions_t null_io = {
  .read  = NULL,
  .write = null_write,
  .seek  = NULL,
  .close = NULL,
};

FILE *null_fp;

__attribute__((constructor)) void init_common() {
  verbose = getenv("VERBOSE") != NULL;
  tc_filter = getenv("TC");
  if (tc_filter && !*tc_filter)
    tc_filter = NULL;
  null_fp = fopencookie(NULL, "w", null_io);
  if (!null_fp) {
    perror("fopencookie");
    exit(1);
  }
}


#if defined REPRODUCER

#include <dlfcn.h>

/*
 * The non-engine entry point, shared by both binaries built without a fuzzing
 * engine: fuzz2 (the RR()/RF() reproducer, asan+ubsan) and fuzz_cov
 * (coverage). Both need a main() of their own - there is no driver to supply
 * one - and both want the same two behaviours, so the logic lives here once.
 *
 *   ./fuzz2 <artifact>          run one input through the harness
 *   ./fuzz2 tc3 / vc3           run a harvested test case
 *   ./fuzz_cov <file> [...]     the same replay, for llvm-cov
 *
 * An argument that can be opened is an input; anything else is looked up as a
 * test case name. Test cases are identifiers (vc<n>, tc<n>), so the two can
 * never be confused for one another.
 */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
int LLVMFuzzerInitialize(int *argc, char ***argv);

/*
 * Run one input file through the harness. The buffer is a private copy, freed
 * here, so the harness sees exactly what the fuzzer would have handed it - and
 * the sanitizers see the same allocation lifetime.
 *
 * Returns -1 when @path cannot be opened or is not a regular file; that is the
 * caller's signal to try the argument as a test case name. A directory would
 * otherwise fopen() happily and then hand ftell() a nonsense size.
 */
int run_input_file(const char *path) {
  unsigned char *buf;
  struct stat st;
  long size;
  FILE *f;

  f = fopen(path, "rb");
  if (!f)
    return -1;

  if (fstat(fileno(f), &st) != 0 || !S_ISREG(st.st_mode)) {
    fclose(f);
    return -1;
  }

  if (fseek(f, 0, SEEK_END) != 0 || (size = ftell(f)) < 0) {
    fclose(f);
    return -1;
  }
  rewind(f);

  buf = malloc((size_t)size + 1);
  if (!buf) {
    fclose(f);
    return -1;
  }

  if (size > 0 && fread(buf, 1, (size_t)size, f) != (size_t)size) {
    free(buf);
    fclose(f);
    return -1;
  }
  fclose(f);

  LLVMFuzzerTestOneInput(buf, (size_t)size);
  free(buf);
  return 0;
}

/*
 * Call a test case by name - the vc<n>/tc<n> functions the RR()/RF() macros
 * define. dlsym against the executable itself, which is what -rdynamic in
 * fuzz_add_harness() is for.
 */
int run_test_case(const char *name) {
  void *handle, *sym;

  handle = dlopen(NULL, RTLD_NOW);
  if (!handle) {
    printf("dlopen failed: %s\n", dlerror());
    return 1;
  }

  sym = dlsym(handle, name);
  if (!sym) {
    printf("dlsym failed: %s\n", dlerror());
    dlclose(handle);
    return 1;
  }
  dlclose(handle);

  return ((int (*)())sym)();
}

/*
 * Walk argv: inputs are replayed in order, a name that is not a file runs as a
 * test case and its return value ends the run (vc<n> prints the RF() text,
 * tc<n> is expected to crash).
 */
int fuzz_replay_main(int argc, char **argv) {
  int i, n = 0;

  if (argc < 2) {
    printf("Usage: %s <input-file>... | <testcase>\n", argv[0]);
    return 1;
  }

  /* What the driver does for the campaign binaries: LLVMFuzzerInitialize()
   * builds the fixture and runs the warm-up exec before the first input, so a
   * replay here matches what the fuzzer executed. */
  LLVMFuzzerInitialize(&argc, &argv);

  for (i = 1; i < argc; i++) {
    if (run_input_file(argv[i]) == 0) {
      n++;
      continue;
    }
    return run_test_case(argv[i]);
  }

  fprintf(stderr, "%s: ran %d input(s)\n", argv[0], n);
  return 0;
}

#endif /* REPRODUCER */
