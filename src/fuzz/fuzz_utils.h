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

#define CHECK(cond) do { if (!(cond)) goto out; } while(0)

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

#define T(func) do { \
  if (TC_SKIP(func)) \
    break; \
  if(verbose) { \
	printf("=== Running %s ===\n", #func); \
  } \
  tc(flags, data, size, func); \
} while(0)

#define T2(func) do { \
  if (TC_SKIP(func)) \
    break; \
  if(verbose) { \
	printf("=== Running %s ===\n", #func); \
  } \
  func(flags, data, size); \
} while(0)

FILE *null_fp;

__attribute__((constructor)) void init_common() {
  verbose = getenv("VERBOSE") != NULL;
  tc_filter = getenv("TC");
  if (tc_filter && !*tc_filter)
    tc_filter = NULL;
  null_fp = fopen("/dev/null", "w");
  if (!null_fp) {
    perror("fopen");
    exit(1);
  }
}
