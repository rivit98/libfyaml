#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>
#include <time.h>
#include <unistd.h>

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
}

/////////////////////////////

char *nullterminated(const char *data, size_t size) {
  char *newdata = malloc(size + 1);
  memcpy(newdata, data, size);
  newdata[size] = '\0';
  return newdata;
}

/*
 * strtok() requires NUL-terminated C strings, so it can't correctly find a
 * '\n' delimiter (or preserve embedded NULs on either side of it) when the
 * fuzz input itself contains an embedded NUL byte. This splits the real
 * [data, data+size) byte range on the first '\n' instead, returning
 * newly-allocated, explicitly-sized (and still NUL-terminated, for callers
 * that need a plain C string) copies of both halves.
 *
 * Returns false if no '\n' was found in the buffer (mirrors strtok()==NULL).
 */
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

int read_artifact(const char *filename, char **out_buf) {
  FILE *fp = fopen(filename, "r");
  if (!fp) {
    perror("fopen");
    exit(1);
  }
  char buf[0x10000] = {0};
  int n = fread(buf, 1, sizeof(buf), fp);
  fclose(fp);

  n -= sizeof(uint32_t);
  *out_buf = nullterminated(buf+sizeof(uint32_t), n);
  print_artifact_as_hexstr(*out_buf, n);
  return n;
}

int read_artifact_raw(const char *filename, char **out_buf) {
  FILE *fp = fopen(filename, "r");
  if (!fp) {
    perror("fopen");
    exit(1);
  }
  char buf[0x10000] = {0};
  int n = fread(buf, 1, sizeof(buf), fp);
  fclose(fp);

  n -= sizeof(uint32_t);
  *out_buf = malloc(n);
  memcpy(*out_buf, buf+sizeof(uint32_t), n);

  print_artifact_as_hexstr(*out_buf, n);
  return n;
}

int tc(struct flags_t *flags, const uint8_t *data, size_t size, void (*f)(struct flags_t *, const char *, size_t)) {
  char *d = nullterminated((const char *)data, size);
  f(flags, d, size);
  free(d);
  return 0;
}

#define T(func) do { \
  if(verbose) { \
	printf("=== Running %s ===\n", #func); \
  } \
  tc(flags, data, size, func); \
} while(0)

#define T2(func) do { \
  if(verbose) { \
	printf("=== Running %s ===\n", #func); \
  } \
  func(flags, data, size); \
} while(0)


__attribute__((constructor)) void init_common() {
  verbose = getenv("VERBOSE") != NULL;
}
