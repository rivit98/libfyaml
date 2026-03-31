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


#if !defined(__has_embed)
#error "the fuzz harness needs a compiler with C23 #embed (clang 19+, gcc 15+)"
#endif

static const char corpus_yaml[] = {
#embed "corpus.yaml" suffix(,)
  '\0'
};

#define CORPUS_YAML     corpus_yaml
#define CORPUS_YAML_LEN (sizeof(corpus_yaml) - 1)

/*
 * The corpus fixture.
 *
 * corpus.yaml is a fixture, not a parser test input - the tests below care
 * about what they can do to a big well-formed document, not about how it got
 * parsed. Rebuilding it per run cost 12-24 ms under ASAN, and with four tests
 * each wanting their own copy that was ~74 ms of a ~109 ms exec. So it is
 * parsed exactly once per process, with a fixed flag set:
 *
 *   FYPCF_QUIET            - no diagnostics for a document we know parses
 *   FYPCF_RESOLVE_DOCUMENT - aliases resolved, so paths reach through them
 *   FYPCF_KEEP_COMMENTS    - comments attached, so token accessors find some
 *
 * Dropping the fuzzed parse flags here costs nothing. The parser still gets
 * them every run from test_parse_with_flags(), test_fy_parser_parse(),
 * test_document_builder() and the rest, which parse fuzzer-controlled input;
 * and running one constant document through the flag space saturates after a
 * few thousand execs, after which it is pure overhead. It also stops throwing
 * runs away: the flag seed picks FYPCF_JSON_FORCE one time in three, the
 * corpus cannot be JSON, and every reader used to bail - measured at 29% of
 * seeds.
 *
 * The one thing this gives up: a bug that only fires against a cold document
 * is now hit once per process instead of once per run.
 */
static struct fy_document *corpus_fyd = NULL;
static bool corpus_fyd_built = false;

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
  corpus_fyd = fy_document_build_from_string(&cfg, CORPUS_YAML, CORPUS_YAML_LEN);
  corpus_fyd_built = true;

  return corpus_fyd;
}

/*
 * A private copy for tests that restructure the document. fy_node_copy() deep
 * copies nodes, so appends, prepends, removals, sorts and inserts stay local
 * to the clone - verified: a removal on a clone is not visible in the source.
 *
 * It does NOT copy tokens, it fy_token_ref()s them, so anything that writes to
 * a token - fy_token_set_comment() above all - would write straight through
 * into the fixture and must build its own document instead.
 *
 * Caller destroys. Falls back to a parse because fy_node_copy() refuses to
 * descend past FY_NODE_PATH_WALK_DEPTH_DEFAULT (16) levels.
 */
static struct fy_document *corpus_document_private(struct flags_t *flags)
{
  struct fy_document *fyd;

  fyd = fy_document_clone(corpus_document());
  if (fyd)
    return fyd;

  struct fy_parse_cfg cfg = { .flags = flags->parse_flags };
  return fy_document_build_from_string(&cfg, CORPUS_YAML, CORPUS_YAML_LEN);
}

__attribute__((destructor)) static void corpus_document_free(void)
{
  fy_document_destroy(corpus_fyd);
  corpus_fyd = NULL;
  corpus_fyd_built = false;
}

/*
 * A small feature-dense document for test_token_comments(). It rewrites token
 * comments, which a clone would push through into the fixture (see above), so
 * it needs a document of its own - and a small one keeps that parse off the
 * hot path at ~0.5 ms instead of the corpus' 12-24 ms. Parsed with the run's
 * flags, so a valid document still goes through the fuzzed flag space on every
 * single exec.
 */
static const char corpus_tokens_yaml[] =
  "# leading comment\n"
  "plain: a plain scalar   # trailing comment\n"
  "single: 'single quoted'\n"
  "double: \"double \\t quoted\"\n"
  "literal: |\n"
  "  block\n"
  "  scalar\n"
  "folded: >-\n"
  "  folded\n"
  "  scalar\n"
  "tagged: !!str 42\n"
  "anchored: &a anchored value\n"
  "alias: *a\n"
  "ints: [0, -1, 0x1F, 1_000]\n"
  "floats: [1.5, .inf, .NaN]\n"
  "consts: [true, false, null, ~]\n"
  "empty:\n"
  "nested:\n"
  "  # inner comment\n"
  "  key: value\n"
  "  seq:\n"
  "    - one\n"
  "    - two\n"
  "? complex key\n"
  ": complex value\n";

#define CORPUS_TOKENS_YAML     corpus_tokens_yaml
#define CORPUS_TOKENS_YAML_LEN (sizeof(corpus_tokens_yaml) - 1)

#define CHECK(cond) do { if (!(cond)) goto out; } while(0)

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
	const char *anchor = NULL;
	const char *tag = NULL;
	const char *text = NULL;
	const char *alias = NULL;
	size_t anchor_len = 0, tag_len = 0, text_len = 0, alias_len = 0;
	const struct fy_mark *sm, *em = NULL;

	sm = fy_event_start_mark(fye);
	em = fy_event_end_mark(fye);

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
  char *newdata = malloc(size + 1);
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

void print_artifact_as_hexstr(char *buf, size_t buf_size) {
  for (size_t i = 0; i < buf_size; i++)
    printf("\\x%02x", (unsigned char)buf[i]);
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

char *read_file(const char *filename, size_t *out_size) {
  FILE *fp = fopen(filename, "r");
  if (!fp) {
    perror("fopen");
    exit(1);
  }
  char *buf = malloc(0x10000);
  int n = fread(buf, 1, 0x10000, fp);
  fclose(fp);
  *out_size = n;
  return buf;
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

int read_artifact(const char *filename, char **out_buf) {
  return read_artifact_raw(filename, out_buf);
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
#define TC_SKIP(func) ({ \
  static signed char _tc_sel = -1; \
  bool _tc_skip = false; \
  if (__builtin_expect(tc_filter != NULL, 0)) { \
    if (__builtin_expect(_tc_sel < 0, 0)) { \
      _tc_sel = strcmp(tc_filter, #func) == 0; \
      tc_filter_matched |= (bool)_tc_sel; \
    } \
    _tc_skip = !_tc_sel; \
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
 */
#define T_RUN(func, call) do { \
  if (TC_SKIP(func)) \
    break; \
  if (__builtin_expect(!verbose, 1)) { \
    call; \
    break; \
  } \
  fprintf(stderr, "=== Running %s ===\n", #func); \
  double _t0 = now_ms(); \
  call; \
  fprintf(stderr, "=== %s: %.3f ms ===\n", #func, now_ms() - _t0); \
} while(0)

#define T(func)  T_RUN(func, tc(flags, data, size, func))
#define T2(func) T_RUN(func, func(flags, data, size))

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
