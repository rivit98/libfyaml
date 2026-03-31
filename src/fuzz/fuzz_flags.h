/*
 * struct flags_t and everything needed to derive one from a fuzzer-supplied
 * seed (setup_flags()), and to print one back out as a C initializer for
 * crash reproducers (flags_to_struct_string()).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <assert.h>

#include <libfyaml.h>
#include <libfyaml/libfyaml-reflection.h>

// https://stackoverflow.com/questions/33010010/how-to-generate-random-64-bit-unsigned-integer-in-c
#define IMAX_BITS(m) ((m)/((m)%255+1) / 255%255*8 + 7-86/((m)%255+12))
#define RAND_MAX_WIDTH IMAX_BITS(RAND_MAX)
_Static_assert((RAND_MAX & (RAND_MAX + 1u)) == 0, "RAND_MAX not a Mersenne number");

uint64_t rand64(void) {
  uint64_t r = 0;
  for (int i = 0; i < 64; i += RAND_MAX_WIDTH) {
    r <<= RAND_MAX_WIDTH;
    r ^= (unsigned) rand();
  }
  return r;
}

bool verbose = false;

const char *tc_filter = NULL;
bool tc_filter_matched = false;

struct flags_t {
  enum fy_parse_cfg_flags parse_flags;
  enum fy_emitter_cfg_flags emitter_flags;
  enum fy_emitter_xcfg_flags extended_emitter_flags;
  enum fy_node_walk_flags node_walk_flags;
  enum fy_path_parse_cfg_flags path_parse_flags;
  enum fy_node_style node_style;
  char *primitive_type;
  enum fy_type_info_flags type_info_flags;
  uint64_t cgen_flag;
};

#define array_elements(x) (sizeof(x) / sizeof(x[0]))

void __print__flags(uint64_t flags, uint64_t *flags_vals, const char** flags_desc, size_t len, const char *prefix) {
  static char buffer[0x4000];
  buffer[0] = '\0';

  for (size_t i = 0; i < len; i++)
  {
    if(flags & flags_vals[i]) {
      if(buffer[0] != '\0') {
        strcat(buffer, " | ");
      }
      strcat(buffer, flags_desc[i]);
    }
  }

  if(buffer[0] == '\0') {
    strcat(buffer, "None");
  }

  printf("%s: 0x%x %s\n", prefix, flags, buffer);
}

/*
 * NOTE: FYPCF_DEFAULT_VERSION_* and FYPCF_JSON_* are NOT independent bits -
 * they are enum values packed into their own masked sub-fields of the flags
 * word (see FYPCF_DEFAULT_VERSION_SHIFT/MASK and FYPCF_JSON_SHIFT/MASK in
 * libfyaml-core.h). OR-ing more than one value from the same group together
 * produces a value outside the defined enum range. They are therefore kept
 * out of this "independent bits" array and resolved separately below, by
 * picking exactly one value per group.
 */
const char *fy_parse_cfg_flags__desc[] = {
	"FYPCF_QUIET",
	"FYPCF_COLLECT_DIAG",
	"FYPCF_RESOLVE_DOCUMENT",
	"FYPCF_DISABLE_MMAP_OPT",
	"FYPCF_DISABLE_RECYCLING",
	"FYPCF_KEEP_COMMENTS",
	"FYPCF_DISABLE_DEPTH_LIMIT",
	"FYPCF_DISABLE_ACCELERATORS",
	"FYPCF_DISABLE_BUFFERING",
	"FYPCF_SLOPPY_FLOW_INDENTATION",
	"FYPCF_PREFER_RECURSIVE",
	"FYPCF_YPATH_ALIASES",
	"FYPCF_ALLOW_DUPLICATE_KEYS",
  "FYPCF_CREATE_MARKERS",
	"FYPCF_KEEP_STYLE",
	"FYPCF_RELAXED_FLOW_DOC",
	"FYPCF_KEEP_ANCHORS",
	"FYPCF_ENABLE_CACHE",
};

uint64_t fy_parse_cfg_flags__vals[] = {
	FYPCF_QUIET,
	FYPCF_COLLECT_DIAG,
	FYPCF_RESOLVE_DOCUMENT,
	FYPCF_DISABLE_MMAP_OPT,
	FYPCF_DISABLE_RECYCLING,
	FYPCF_KEEP_COMMENTS,
	FYPCF_DISABLE_DEPTH_LIMIT,
	FYPCF_DISABLE_ACCELERATORS,
	FYPCF_DISABLE_BUFFERING,
	FYPCF_SLOPPY_FLOW_INDENTATION,
	FYPCF_PREFER_RECURSIVE,
	FYPCF_YPATH_ALIASES,
	FYPCF_ALLOW_DUPLICATE_KEYS,
  FYPCF_CREATE_MARKERS,
	FYPCF_KEEP_STYLE,
	FYPCF_RELAXED_FLOW_DOC,
	FYPCF_KEEP_ANCHORS,
	FYPCF_ENABLE_CACHE,
};

static_assert(array_elements(fy_parse_cfg_flags__desc) == array_elements(fy_parse_cfg_flags__vals));

/* FYPCF_DEFAULT_VERSION_* - masked sub-field, pick exactly one value */
const char *fy_parse_cfg_default_version_group__desc[] = {
	"FYPCF_DEFAULT_VERSION_AUTO",
	"FYPCF_DEFAULT_VERSION_1_1",
	"FYPCF_DEFAULT_VERSION_1_2",
	"FYPCF_DEFAULT_VERSION_1_3",
};

uint64_t fy_parse_cfg_default_version_group__vals[] = {
	FYPCF_DEFAULT_VERSION_AUTO,
	FYPCF_DEFAULT_VERSION_1_1,
	FYPCF_DEFAULT_VERSION_1_2,
	FYPCF_DEFAULT_VERSION_1_3,
};

static_assert(array_elements(fy_parse_cfg_default_version_group__desc) == array_elements(fy_parse_cfg_default_version_group__vals));

/* FYPCF_JSON_* - masked sub-field, pick exactly one value */
const char *fy_parse_cfg_json_group__desc[] = {
	"FYPCF_JSON_AUTO",
	"FYPCF_JSON_NONE",
	"FYPCF_JSON_FORCE",
};

uint64_t fy_parse_cfg_json_group__vals[] = {
	FYPCF_JSON_AUTO,
	FYPCF_JSON_NONE,
	FYPCF_JSON_FORCE,
};

static_assert(array_elements(fy_parse_cfg_json_group__desc) == array_elements(fy_parse_cfg_json_group__vals));

const char *fy_node_walk_flags__desc[] = {
    "FYNWF_DONT_FOLLOW",
    "FYNWF_FOLLOW",
    "FYNWF_PTR_YAML",
    "FYNWF_PTR_JSON",
    "FYNWF_PTR_RELJSON",
    "FYNWF_PTR_YPATH",
    "FYNWF_URI_ENCODED",
    "FYNWF_MAXDEPTH_DEFAULT",
    "FYNWF_MARKER_DEFAULT",
    "FYNWF_PTR_DEFAULT"
};

uint64_t fy_node_walk_flags__vals[] = {
    FYNWF_DONT_FOLLOW,
    FYNWF_FOLLOW,
    FYNWF_PTR_YAML,
    FYNWF_PTR_JSON,
    FYNWF_PTR_RELJSON,
    FYNWF_PTR_YPATH,
    FYNWF_URI_ENCODED,
    FYNWF_MAXDEPTH_DEFAULT,
    FYNWF_MARKER_DEFAULT,
    FYNWF_PTR_DEFAULT
};

static_assert(array_elements(fy_node_walk_flags__desc) == array_elements(fy_node_walk_flags__vals));


/*
 * NOTE: FYECF_INDENT_*, FYECF_WIDTH_*, FYECF_MODE_*, FYECF_DOC_START_MARK_*,
 * FYECF_DOC_END_MARK_*, FYECF_VERSION_DIR_* and FYECF_TAG_DIR_* are NOT
 * independent bits - each group is an enum packed into its own masked
 * sub-field of the flags word (FYECF_*_SHIFT/MASK in libfyaml-core.h).
 * OR-ing more than one value from the same group together produces a value
 * outside the defined enum range, so they are resolved separately below by
 * picking exactly one value per group, instead of living in this
 * independent-bits array.
 */
const char *fy_emitter_cfg_flags__desc[] = {
    "FYECF_SORT_KEYS",
    "FYECF_OUTPUT_COMMENTS",
    "FYECF_STRIP_LABELS",
    "FYECF_STRIP_TAGS",
    "FYECF_STRIP_DOC",
    "FYECF_NO_ENDING_NEWLINE",
    "FYECF_STRIP_EMPTY_KV",
    "FYECF_EXTENDED_CFG",
};

uint64_t fy_emitter_cfg_flags__vals[] = {
    FYECF_SORT_KEYS,
    FYECF_OUTPUT_COMMENTS,
    FYECF_STRIP_LABELS,
    FYECF_STRIP_TAGS,
    FYECF_STRIP_DOC,
    FYECF_NO_ENDING_NEWLINE,
    FYECF_STRIP_EMPTY_KV,
    FYECF_EXTENDED_CFG,
};

static_assert(array_elements(fy_emitter_cfg_flags__desc) == array_elements(fy_emitter_cfg_flags__vals));

const char *fy_emitter_cfg_indent_group__desc[] = { "FYECF_INDENT_DEFAULT" };
uint64_t fy_emitter_cfg_indent_group__vals[] = { FYECF_INDENT_DEFAULT };
static_assert(array_elements(fy_emitter_cfg_indent_group__desc) == array_elements(fy_emitter_cfg_indent_group__vals));

const char *fy_emitter_cfg_width_group__desc[] = {
    "FYECF_WIDTH_DEFAULT", "FYECF_WIDTH_80", "FYECF_WIDTH_132", "FYECF_WIDTH_INF",
};
uint64_t fy_emitter_cfg_width_group__vals[] = {
    FYECF_WIDTH_DEFAULT, FYECF_WIDTH_80, FYECF_WIDTH_132, FYECF_WIDTH_INF,
};
static_assert(array_elements(fy_emitter_cfg_width_group__desc) == array_elements(fy_emitter_cfg_width_group__vals));

const char *fy_emitter_cfg_mode_group__desc[] = {
    "FYECF_MODE_ORIGINAL", "FYECF_MODE_BLOCK", "FYECF_MODE_FLOW", "FYECF_MODE_FLOW_ONELINE",
    "FYECF_MODE_JSON", "FYECF_MODE_JSON_TP", "FYECF_MODE_JSON_ONELINE", "FYECF_MODE_DEJSON",
    "FYECF_MODE_PRETTY", "FYECF_MODE_MANUAL", "FYECF_MODE_FLOW_COMPACT", "FYECF_MODE_JSON_COMPACT",
};
uint64_t fy_emitter_cfg_mode_group__vals[] = {
    FYECF_MODE_ORIGINAL, FYECF_MODE_BLOCK, FYECF_MODE_FLOW, FYECF_MODE_FLOW_ONELINE,
    FYECF_MODE_JSON, FYECF_MODE_JSON_TP, FYECF_MODE_JSON_ONELINE, FYECF_MODE_DEJSON,
    FYECF_MODE_PRETTY, FYECF_MODE_MANUAL, FYECF_MODE_FLOW_COMPACT, FYECF_MODE_JSON_COMPACT,
};
static_assert(array_elements(fy_emitter_cfg_mode_group__desc) == array_elements(fy_emitter_cfg_mode_group__vals));

const char *fy_emitter_cfg_doc_start_mark_group__desc[] = {
    "FYECF_DOC_START_MARK_AUTO", "FYECF_DOC_START_MARK_OFF", "FYECF_DOC_START_MARK_ON",
};
uint64_t fy_emitter_cfg_doc_start_mark_group__vals[] = {
    FYECF_DOC_START_MARK_AUTO, FYECF_DOC_START_MARK_OFF, FYECF_DOC_START_MARK_ON,
};
static_assert(array_elements(fy_emitter_cfg_doc_start_mark_group__desc) == array_elements(fy_emitter_cfg_doc_start_mark_group__vals));

const char *fy_emitter_cfg_doc_end_mark_group__desc[] = {
    "FYECF_DOC_END_MARK_AUTO", "FYECF_DOC_END_MARK_OFF", "FYECF_DOC_END_MARK_ON",
};
uint64_t fy_emitter_cfg_doc_end_mark_group__vals[] = {
    FYECF_DOC_END_MARK_AUTO, FYECF_DOC_END_MARK_OFF, FYECF_DOC_END_MARK_ON,
};
static_assert(array_elements(fy_emitter_cfg_doc_end_mark_group__desc) == array_elements(fy_emitter_cfg_doc_end_mark_group__vals));

const char *fy_emitter_cfg_version_dir_group__desc[] = {
    "FYECF_VERSION_DIR_AUTO", "FYECF_VERSION_DIR_OFF", "FYECF_VERSION_DIR_ON",
};
uint64_t fy_emitter_cfg_version_dir_group__vals[] = {
    FYECF_VERSION_DIR_AUTO, FYECF_VERSION_DIR_OFF, FYECF_VERSION_DIR_ON,
};
static_assert(array_elements(fy_emitter_cfg_version_dir_group__desc) == array_elements(fy_emitter_cfg_version_dir_group__vals));

const char *fy_emitter_cfg_tag_dir_group__desc[] = {
    "FYECF_TAG_DIR_AUTO", "FYECF_TAG_DIR_OFF", "FYECF_TAG_DIR_ON",
};
uint64_t fy_emitter_cfg_tag_dir_group__vals[] = {
    FYECF_TAG_DIR_AUTO, FYECF_TAG_DIR_OFF, FYECF_TAG_DIR_ON,
};
static_assert(array_elements(fy_emitter_cfg_tag_dir_group__desc) == array_elements(fy_emitter_cfg_tag_dir_group__vals));


const char* fy_emitter_xcfg_flags__desc[] = {
    "FYEXCF_COLOR_AUTO",
    "FYEXCF_COLOR_NONE",
    "FYEXCF_COLOR_FORCE",
    "FYEXCF_OUTPUT_STDOUT",
    "FYEXCF_OUTPUT_STDERR",
    "FYEXCF_OUTPUT_FILE",
    "FYEXCF_OUTPUT_FD",
    "FYEXCF_NULL_OUTPUT",
    "FYEXCF_OUTPUT_FILENAME",
    "FYEXCF_VISIBLE_WS",
    "FYEXCF_EXTENDED_INDICATORS",
    "FYEXCF_INDENTED_SEQ_IN_MAP",
    "FYEXCF_PRESERVE_FLOW_LAYOUT",
};

uint64_t fy_emitter_xcfg_flags__vals[] = {
    FYEXCF_COLOR_AUTO,
    FYEXCF_COLOR_NONE,
    FYEXCF_COLOR_FORCE,
    FYEXCF_OUTPUT_STDOUT,
    FYEXCF_OUTPUT_STDERR,
    FYEXCF_OUTPUT_FILE,
    FYEXCF_OUTPUT_FD,
    FYEXCF_NULL_OUTPUT,
    FYEXCF_OUTPUT_FILENAME,
    FYEXCF_VISIBLE_WS,
    FYEXCF_EXTENDED_INDICATORS,
    FYEXCF_INDENTED_SEQ_IN_MAP,
    FYEXCF_PRESERVE_FLOW_LAYOUT,
};

static_assert(array_elements(fy_emitter_xcfg_flags__desc) == array_elements(fy_emitter_xcfg_flags__vals));

const char* fy_path_parse_cfg_flags__desc[] = {
    "FYPPCF_QUIET",
    "FYPPCF_DISABLE_RECYCLING",
    "FYPPCF_DISABLE_ACCELERATORS"
};

uint64_t fy_path_parse_cfg_flags__vals[] = {
    FYPPCF_QUIET,
    FYPPCF_DISABLE_RECYCLING,
    FYPPCF_DISABLE_ACCELERATORS
};

static_assert(array_elements(fy_path_parse_cfg_flags__desc) == array_elements(fy_path_parse_cfg_flags__vals));


const char* fy_node_style__desc[] = {
	"FYNS_ANY",
	"FYNS_FLOW",
	"FYNS_BLOCK",
	"FYNS_PLAIN",
	"FYNS_SINGLE_QUOTED",
	"FYNS_DOUBLE_QUOTED",
	"FYNS_LITERAL",
	"FYNS_FOLDED",
	"FYNS_ALIAS",
};

uint64_t fy_node_style__vals[] = {
	FYNS_ANY,
	FYNS_FLOW,
	FYNS_BLOCK,
	FYNS_PLAIN,
	FYNS_SINGLE_QUOTED,
	FYNS_DOUBLE_QUOTED,
	FYNS_LITERAL,
	FYNS_FOLDED,
	FYNS_ALIAS,
};

static_assert(array_elements(fy_node_style__desc) == array_elements(fy_node_style__vals));


static const char * const primitive_type_names[] = {
  "bool",
  "char",
  "signed char",
  "unsigned char",
  "short",
  "unsigned short",
  "int",
  "unsigned int",
  "long",
  "unsigned long",
  "long long",
  "unsigned long long",
  "float",
  "double",
  "long double",
};


const char *fy_type_info_flags__desc[] = {
    "FYTIF_CONST",
    "FYTIF_VOLATILE",
    "FYTIF_RESTRICT",
    "FYTIF_ELABORATED",
    "FYTIF_ANONYMOUS",
    "FYTIF_ANONYMOUS_RECORD_DECL",
    "FYTIF_ANONYMOUS_GLOBAL",
    "FYTIF_ANONYMOUS_DEP",
    "FYTIF_INCOMPLETE",
    "FYTIF_UNRESOLVED",
    "FYTIF_MAIN_FILE",
    "FYTIF_SYSTEM_HEADER",
};

uint64_t fy_type_info_flags__vals[] = {
    FYTIF_CONST,
    FYTIF_VOLATILE,
    FYTIF_RESTRICT,
    FYTIF_ELABORATED,
    FYTIF_ANONYMOUS,
    FYTIF_ANONYMOUS_RECORD_DECL,
    FYTIF_ANONYMOUS_GLOBAL,
    FYTIF_ANONYMOUS_DEP,
    FYTIF_INCOMPLETE,
    FYTIF_UNRESOLVED,
    FYTIF_MAIN_FILE,
    FYTIF_SYSTEM_HEADER,
};

static_assert(array_elements(fy_type_info_flags__desc) == array_elements(fy_type_info_flags__vals));


static const enum fy_c_generation_flags cgen_flag_combos[] = {
  FYCGF_INDENT_TAB      | FYCGF_COMMENT_NONE,
  FYCGF_INDENT_TAB      | FYCGF_COMMENT_RAW,
  FYCGF_INDENT_TAB      | FYCGF_COMMENT_YAML,
};


/////////////////////////////

static uint64_t flags_from_seed(uint64_t seed, const uint64_t *vals, size_t len)
{
  uint64_t result = 0;
  if (len > 64) {
    fprintf(stderr, "Warning: flags_from_seed only supports up to 64 flags, but got %zu\n", len);
    len = 64;
  }

  for (size_t i = 0; i < len; i++) {
    if (seed & (1ull << i))
      result |= vals[i];
  }
  return result;
}

/*
 * Pick exactly one value out of a group of values that share a masked
 * sub-field (e.g. FYECF_MODE_*), instead of independently OR-ing each one
 * in like flags_from_seed() does for true independent bits. OR-ing more
 * than one value from the same masked sub-field together produces a value
 * outside the field's defined range.
 */
static uint64_t pick_one(uint64_t seed, const uint64_t *vals, size_t len)
{
  return vals[seed % len];
}

/* forward decls: defined further below, alongside the other append_* string helpers */
static void append_parse_cfg_flags(char **dst, size_t *left, uint64_t flags);
static void append_emitter_cfg_flags(char **dst, size_t *left, uint64_t flags);

void setup_flags(uint32_t seed, struct flags_t *flags) {
  srand(seed);
  flags->parse_flags      = flags_from_seed(rand64(), fy_parse_cfg_flags__vals,   array_elements(fy_parse_cfg_flags__vals))
                           | pick_one(rand64(), fy_parse_cfg_default_version_group__vals, array_elements(fy_parse_cfg_default_version_group__vals))
                           | pick_one(rand64(), fy_parse_cfg_json_group__vals,            array_elements(fy_parse_cfg_json_group__vals));
  flags->emitter_flags    = flags_from_seed(rand64(), fy_emitter_cfg_flags__vals, array_elements(fy_emitter_cfg_flags__vals))
                           | pick_one(rand64(), fy_emitter_cfg_indent_group__vals,          array_elements(fy_emitter_cfg_indent_group__vals))
                           | pick_one(rand64(), fy_emitter_cfg_width_group__vals,           array_elements(fy_emitter_cfg_width_group__vals))
                           | pick_one(rand64(), fy_emitter_cfg_mode_group__vals,            array_elements(fy_emitter_cfg_mode_group__vals))
                           | pick_one(rand64(), fy_emitter_cfg_doc_start_mark_group__vals,  array_elements(fy_emitter_cfg_doc_start_mark_group__vals))
                           | pick_one(rand64(), fy_emitter_cfg_doc_end_mark_group__vals,    array_elements(fy_emitter_cfg_doc_end_mark_group__vals))
                           | pick_one(rand64(), fy_emitter_cfg_version_dir_group__vals,     array_elements(fy_emitter_cfg_version_dir_group__vals))
                           | pick_one(rand64(), fy_emitter_cfg_tag_dir_group__vals,         array_elements(fy_emitter_cfg_tag_dir_group__vals));
  flags->node_walk_flags  = flags_from_seed(rand64(), fy_node_walk_flags__vals,   array_elements(fy_node_walk_flags__vals));
  flags->path_parse_flags = flags_from_seed(rand64(), fy_path_parse_cfg_flags__vals, array_elements(fy_path_parse_cfg_flags__vals));
  flags->node_style       = fy_node_style__vals[rand64() % array_elements(fy_node_style__vals)];
  flags->extended_emitter_flags = flags_from_seed(rand64(), fy_emitter_xcfg_flags__vals, array_elements(fy_emitter_xcfg_flags__vals)) & ~(
        FYEXCF_OUTPUT_STDOUT
      | FYEXCF_OUTPUT_STDERR
      | FYEXCF_OUTPUT_FILE
      | FYEXCF_OUTPUT_FD
      | FYEXCF_NULL_OUTPUT
      | FYEXCF_OUTPUT_FILENAME
    );

  flags->primitive_type = primitive_type_names[rand64() % array_elements(primitive_type_names)];

  flags->type_info_flags = flags_from_seed(rand64(), fy_type_info_flags__vals, array_elements(fy_type_info_flags__vals));
  flags->cgen_flag = cgen_flag_combos[rand64() % array_elements(cgen_flag_combos)];

  if (verbose) {
    {
      char buf[0x1000];
      char *p;
      size_t left;

      p = buf; left = sizeof(buf);
      append_parse_cfg_flags(&p, &left, flags->parse_flags);
      printf("fy_parse_cfg_flags: 0x%x %s\n", flags->parse_flags, buf);

      p = buf; left = sizeof(buf);
      append_emitter_cfg_flags(&p, &left, flags->emitter_flags);
      printf("fy_emitter_cfg_flags: 0x%x %s\n", flags->emitter_flags, buf);
    }
    __print__flags(flags->node_walk_flags,  fy_node_walk_flags__vals,    fy_node_walk_flags__desc,    array_elements(fy_node_walk_flags__vals),    "fy_node_walk_flags");
    __print__flags(flags->path_parse_flags, fy_path_parse_cfg_flags__vals, fy_path_parse_cfg_flags__desc, array_elements(fy_path_parse_cfg_flags__vals), "fy_path_parse_cfg_flags");
    __print__flags(flags->node_style,       fy_node_style__vals,         fy_node_style__desc,         array_elements(fy_node_style__vals),         "fy_node_style");
    __print__flags(flags->extended_emitter_flags, fy_emitter_xcfg_flags__vals, fy_emitter_xcfg_flags__desc, array_elements(fy_emitter_xcfg_flags__vals), "extended_emitter_flags");
    printf("primitive_type: %s\n", flags->primitive_type);
    __print__flags(flags->type_info_flags, fy_type_info_flags__vals, fy_type_info_flags__desc, array_elements(fy_type_info_flags__vals), "fy_type_info_flags");
  }
}


static void append_str(char **dst, size_t *left, const char *s)
{
	size_t n = strlen(s);
	if (*left <= 1)
		return;
	if (n >= *left)
		n = *left - 1;
	memcpy(*dst, s, n);
	*dst += n;
	**dst = '\0';
	*left -= n;
}

static void append_fmt(char **dst, size_t *left, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	int n = vsnprintf(*dst, *left, fmt, ap);
	va_end(ap);

	if (n <= 0)
		return;

	if ((size_t)n >= *left) {
		*dst += *left - 1;
		**dst = '\0';
		*left = 1;
		return;
	}

	*dst += n;
	*left -= (size_t)n;
}

static void append_flag_names(char **dst, size_t *left,
			      uint64_t flags,
			      const uint64_t *vals,
			      const char *const *desc,
			      size_t len)
{
	bool first = true;

	for (size_t i = 0; i < len; i++) {
		if (vals[i] != 0 && (flags & vals[i]) == vals[i]) {
			if (!first)
				append_str(dst, left, " | ");
			append_str(dst, left, desc[i]);
			first = false;
		}
	}

	if (first)
		append_str(dst, left, "0");
}

/* Like append_flag_names(), but shares a caller-owned "first" across multiple calls. */
static void append_flag_names_into(char **dst, size_t *left, bool *first,
				    uint64_t flags,
				    const uint64_t *vals,
				    const char *const *desc,
				    size_t len)
{
	for (size_t i = 0; i < len; i++) {
		if (vals[i] != 0 && (flags & vals[i]) == vals[i]) {
			if (!*first)
				append_str(dst, left, " | ");
			append_str(dst, left, desc[i]);
			*first = false;
		}
	}
}

/*
 * Identify which single value of a masked sub-field group (e.g. FYECF_MODE_*)
 * is set in @flags, by exact match against the group's own mask - NOT a
 * nonzero-intersection test, since these values are sequential integers
 * packed into a shift+mask sub-field, not independent one-hot bits (e.g.
 * FYECF_INDENT_3 has bits in common with FYECF_INDENT_1's bit pattern).
 */
static void append_flag_group_match(char **dst, size_t *left, bool *first,
				     uint64_t flags,
				     const uint64_t *vals,
				     const char *const *desc,
				     size_t len)
{
	uint64_t group_mask = 0;

	for (size_t i = 0; i < len; i++)
		group_mask |= vals[i];

	for (size_t i = 0; i < len; i++) {
		if ((flags & group_mask) == vals[i]) {
			if (!*first)
				append_str(dst, left, " | ");
			append_str(dst, left, desc[i]);
			*first = false;
			return;
		}
	}
}

static void append_parse_cfg_flags(char **dst, size_t *left, uint64_t flags)
{
	bool first = true;

	append_flag_names_into(dst, left, &first, flags,
				fy_parse_cfg_flags__vals, fy_parse_cfg_flags__desc,
				array_elements(fy_parse_cfg_flags__vals));
	append_flag_group_match(dst, left, &first, flags,
				 fy_parse_cfg_default_version_group__vals, fy_parse_cfg_default_version_group__desc,
				 array_elements(fy_parse_cfg_default_version_group__vals));
	append_flag_group_match(dst, left, &first, flags,
				 fy_parse_cfg_json_group__vals, fy_parse_cfg_json_group__desc,
				 array_elements(fy_parse_cfg_json_group__vals));
	if (first)
		append_str(dst, left, "0");
}

static void append_emitter_cfg_flags(char **dst, size_t *left, uint64_t flags)
{
	bool first = true;

	append_flag_names_into(dst, left, &first, flags,
				fy_emitter_cfg_flags__vals, fy_emitter_cfg_flags__desc,
				array_elements(fy_emitter_cfg_flags__vals));
	append_flag_group_match(dst, left, &first, flags,
				 fy_emitter_cfg_indent_group__vals, fy_emitter_cfg_indent_group__desc,
				 array_elements(fy_emitter_cfg_indent_group__vals));
	append_flag_group_match(dst, left, &first, flags,
				 fy_emitter_cfg_width_group__vals, fy_emitter_cfg_width_group__desc,
				 array_elements(fy_emitter_cfg_width_group__vals));
	append_flag_group_match(dst, left, &first, flags,
				 fy_emitter_cfg_mode_group__vals, fy_emitter_cfg_mode_group__desc,
				 array_elements(fy_emitter_cfg_mode_group__vals));
	append_flag_group_match(dst, left, &first, flags,
				 fy_emitter_cfg_doc_start_mark_group__vals, fy_emitter_cfg_doc_start_mark_group__desc,
				 array_elements(fy_emitter_cfg_doc_start_mark_group__vals));
	append_flag_group_match(dst, left, &first, flags,
				 fy_emitter_cfg_doc_end_mark_group__vals, fy_emitter_cfg_doc_end_mark_group__desc,
				 array_elements(fy_emitter_cfg_doc_end_mark_group__vals));
	append_flag_group_match(dst, left, &first, flags,
				 fy_emitter_cfg_version_dir_group__vals, fy_emitter_cfg_version_dir_group__desc,
				 array_elements(fy_emitter_cfg_version_dir_group__vals));
	append_flag_group_match(dst, left, &first, flags,
				 fy_emitter_cfg_tag_dir_group__vals, fy_emitter_cfg_tag_dir_group__desc,
				 array_elements(fy_emitter_cfg_tag_dir_group__vals));
	if (first)
		append_str(dst, left, "0");
}

static const char *const cgen_flag_exprs[] = {
	"FYCGF_INDENT_TAB | FYCGF_COMMENT_NONE",
	"FYCGF_INDENT_TAB | FYCGF_COMMENT_RAW",
	"FYCGF_INDENT_TAB | FYCGF_COMMENT_YAML",
	"FYCGF_INDENT_SPACES_2 | FYCGF_COMMENT_NONE",
	"FYCGF_INDENT_SPACES_4 | FYCGF_COMMENT_RAW",
	"FYCGF_INDENT_SPACES_8 | FYCGF_COMMENT_YAML",
};

static const enum fy_c_generation_flags cgen_flag_vals[] = {
	FYCGF_INDENT_TAB      | FYCGF_COMMENT_NONE,
	FYCGF_INDENT_TAB      | FYCGF_COMMENT_RAW,
	FYCGF_INDENT_TAB      | FYCGF_COMMENT_YAML,
	FYCGF_INDENT_SPACES_2 | FYCGF_COMMENT_NONE,
	FYCGF_INDENT_SPACES_4 | FYCGF_COMMENT_RAW,
	FYCGF_INDENT_SPACES_8 | FYCGF_COMMENT_YAML,
};

static void append_cgen_flag_expr(char **dst, size_t *left, uint64_t flag)
{
	for (size_t i = 0; i < array_elements(cgen_flag_vals); i++) {
		if (flag == cgen_flag_vals[i]) {
			append_str(dst, left, cgen_flag_exprs[i]);
			return;
		}
	}
	append_fmt(dst, left, "0x%x", flag);
}

char *flags_to_struct_string(struct flags_t *flags)
{
	static char buf[0x4000];
	char *p = buf;
	size_t left = sizeof(buf);

	buf[0] = '\0';

	append_str(&p, &left, "{\n");
	append_str(&p, &left, "  .parse_flags = ");
	append_parse_cfg_flags(&p, &left, flags->parse_flags);
	append_str(&p, &left, ",\n");

	append_str(&p, &left, "  .emitter_flags = ");
	append_emitter_cfg_flags(&p, &left, flags->emitter_flags);
	append_str(&p, &left, ",\n");

	append_str(&p, &left, "  .extended_emitter_flags = ");
	append_flag_names(&p, &left,
			  flags->extended_emitter_flags,
			  fy_emitter_xcfg_flags__vals,
			  fy_emitter_xcfg_flags__desc,
			  array_elements(fy_emitter_xcfg_flags__vals));
	append_str(&p, &left, ",\n");

	append_str(&p, &left, "  .node_walk_flags = ");
	append_flag_names(&p, &left,
			  flags->node_walk_flags,
			  fy_node_walk_flags__vals,
			  fy_node_walk_flags__desc,
			  array_elements(fy_node_walk_flags__vals));
	append_str(&p, &left, ",\n");

	append_str(&p, &left, "  .path_parse_flags = ");
	append_flag_names(&p, &left,
			  flags->path_parse_flags,
			  fy_path_parse_cfg_flags__vals,
			  fy_path_parse_cfg_flags__desc,
			  array_elements(fy_path_parse_cfg_flags__vals));
	append_str(&p, &left, ",\n");

	append_str(&p, &left, "  .node_style = ");
	if (flags->node_style < array_elements(fy_node_style__vals))
		append_str(&p, &left, fy_node_style__desc[flags->node_style]);
	else
		append_fmt(&p, &left, "%u", (unsigned)flags->node_style);
	append_str(&p, &left, ",\n");

	append_str(&p, &left, "  .primitive_type = \"");
	append_str(&p, &left, flags->primitive_type ? flags->primitive_type : "");
	append_str(&p, &left, "\",\n");

	append_str(&p, &left, "  .type_info_flags = ");
	append_flag_names(&p, &left,
			  flags->type_info_flags,
			  fy_type_info_flags__vals,
			  fy_type_info_flags__desc,
			  array_elements(fy_type_info_flags__vals));
	append_str(&p, &left, ",\n");

	append_str(&p, &left, "  .cgen_flag = ");
	append_cgen_flag_expr(&p, &left, flags->cgen_flag);
	append_str(&p, &left, "\n}");

	return buf;
}
