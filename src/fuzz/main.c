#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>
#include <dlfcn.h>
#include <unistd.h>
#include <sys/mman.h>

#include <libfyaml.h>
#include "fuzz_utils.h"

static enum fy_composer_return compose_inspect_cb(struct fy_parser *fyp,
    struct fy_event *fye, struct fy_path *path, void *userdata)
{
  fy_path_in_root(path);
  fy_path_in_mapping(path);
  fy_path_in_sequence(path);
  fy_path_in_mapping_key(path);
  fy_path_in_mapping_value(path);
  fy_path_in_collection_root(path);

  char *ptext = fy_path_get_text(path);
  free(ptext);

  struct fy_path *parent = fy_path_parent(path);
  (void)parent;

  struct fy_path_component *last = fy_path_last_component(path);
  struct fy_path_component *lastnc = fy_path_last_not_collection_root_component(path);
  (void)lastnc;
  if (last) {
    char *ctext = fy_path_component_get_text(last);
    free(ctext);
    if (fy_path_component_is_mapping(last)) {
      fy_path_component_mapping_get_scalar_key(last);
      fy_path_component_mapping_get_scalar_key_tag(last);
      fy_document_destroy(fy_path_component_mapping_get_complex_key(last)); /* caller-owned */
    }
    if (fy_path_component_is_sequence(last))
      fy_path_component_sequence_get_index(last);
  }

  if (fy_path_depth(path) > 10)
    return FYCR_OK_START_SKIP;
  return FYCR_OK_CONTINUE;
}

void test_parse_path(struct flags_t *flags, const char *data, size_t size) {
  struct fy_document *fyd = NULL;
  struct fy_parse_cfg cfg = { .flags = flags->parse_flags };
  char *doc = NULL;
  char *path = NULL;
  size_t doc_len, path_len;

  CHECK(split_two_parts(data, size, &doc, &doc_len, &path, &path_len));

  int flags2 = flags->node_walk_flags;

  fyd = fy_document_build_from_string(&cfg, doc, doc_len);
  struct fy_node *root = fy_document_root(fyd);
  struct fy_node *node = fy_node_by_path(root, path, path_len, flags2);
  CHECK(node);

out:
  fy_document_destroy(fyd);
  free(doc);
  free(path);
}

void test_fy_node_build_from_string(struct flags_t *flags, const char *data, size_t size) {
  struct fy_document *fyd = NULL;

  fyd = fy_document_create(NULL);
  CHECK(fyd);

  struct fy_node *fyn = fy_node_build_from_string(fyd, data, size);
  if(fyn) {
    fy_document_set_root(fyd, fyn);
  }
  
  struct fy_node *fyn2 = fy_node_create_scalar(fyd, data, size);
  if (fyn2) {
    fy_document_set_root(fyd, fyn2);
  }
  
out:
  fy_document_destroy(fyd);
}


void test_fy_node_build_from_fp(struct flags_t *flags, const char *data, size_t size) {
  struct fy_document *fyd = NULL;
  FILE *f = NULL;

  fyd = fy_document_create(NULL);
  CHECK(fyd);

  f = fmemopen((void *)data, size, "r");
  CHECK(f);

  struct fy_node *fyn = fy_node_build_from_fp(fyd, f);
  CHECK(fyn);
  
  fy_document_set_root(fyd, fyn);

out:
  if(f) fclose(f);
  fy_document_destroy(fyd);
}

void test_fy_node_set_anchor(struct flags_t *flags, const char *data, size_t size) {
  struct fy_document *fyd = NULL;
  struct fy_node *fyn = NULL;
  int ret;

  fyd = fy_document_create(NULL);
  CHECK(fyd);
  fyn = fy_node_create_sequence(fyd);
  CHECK(fyn);
  fy_document_set_root(fyd, fyn);
  fyn = fy_node_create_scalar(fyd, "foo", FY_NT);
  ret = fy_node_sequence_append(fy_document_root(fyd), fyn);
  CHECK(ret == 0);
  ret = fy_node_set_anchor(fyn, data, size);
  CHECK(ret == 0);

out:
  fy_document_destroy(fyd);
}


void test_token_iteration(struct fy_document *fyd) {
  CHECK(fyd);

  struct fy_node *root = fy_document_root(fyd);
  CHECK(root);
  CHECK(fy_node_is_scalar(root));

  struct fy_token *token = fy_node_get_scalar_token(root);
  CHECK(token);

  size_t len;
  const char *text = fy_token_get_text(token, &len);
  const char *text0 = fy_token_get_text0(token);
  size_t text_len = fy_token_get_text_length(token);
  
  struct fy_token_iter *iter = fy_token_iter_create(token);
  CHECK(iter);

  char buf[256];
  ssize_t read = fy_token_iter_read(iter, buf, sizeof(buf) - 1);
  
  int c = fy_token_iter_getc(iter);
  if (c != -1) {
    fy_token_iter_ungetc(iter, c);
  }
  
  int utf8_char = fy_token_iter_utf8_get(iter);
  if (utf8_char != -1) {
    fy_token_iter_utf8_unget(iter, utf8_char);
  }
  
  int peeked = fy_token_iter_peekc(iter);
  int peeked_utf8 = fy_token_iter_utf8_peek(iter);
  
  /* fy_token_iter_start()/_finish() re-arm the same iterator (fy-token.c) */
  fy_token_iter_start(token, iter);
  const struct fy_iter_chunk *chunk = fy_token_iter_peek_chunk(iter);
  if (chunk && chunk->len) {
    int err = 0;
    chunk = fy_token_iter_chunk_next(iter, chunk, &err);
    if (chunk)
      fy_token_iter_advance(iter, chunk->len < 4 ? chunk->len : 4);
  }
  fy_token_iter_finish(iter);

  fy_token_iter_destroy(iter);

  const char *comment = fy_token_get_comment(token, fycp_top);
  const char *all_comments = fy_token_get_comments(token);

  /* accessor sweep (fy-token.c) */
  fy_token_get_type(token);
  fy_token_start_mark(token);
  fy_token_end_mark(token);
  fy_token_style_start_mark(token);
  fy_token_style_end_mark(token);
  fy_token_scalar_style(token);
  fy_token_scalar_is_null(token);
  fy_token_collection_style(token);
  fy_scalar_token_get_style(token);

out:
}

void test_sequence_operations(struct fy_document *fyd) {
  struct fy_node *new_node = NULL;
  void *iter;
  struct fy_node *fyn;

  CHECK(fyd);

  struct fy_node *root = fy_document_root(fyd);
  CHECK(fy_node_is_sequence(root));

  iter = NULL;
  while ((fyn = fy_node_sequence_reverse_iterate(root, &iter)) != NULL)
    ;

  fy_node_sequence_item_count(root);
  fy_node_sequence_get_by_index(root, 0);
  fy_node_sequence_get_by_index(root, -1);

  struct fy_node *first = fy_node_sequence_get_by_index(root, 0);
  new_node = fy_node_build_from_string(fyd, "fuzz_inserted", FY_NT);
  if (new_node) {
    if (first)
      fy_node_sequence_insert_before(root, first, new_node);
    else
      fy_node_sequence_append(root, new_node);
    fy_node_sequence_remove(root, new_node);
    fy_node_free(new_node);
    new_node = NULL;
  }

  fy_node_sequence_is_empty(root);

  iter = NULL;
  while ((fyn = fy_node_sequence_iterate(root, &iter)) != NULL)
    ;

  fy_node_sequence_sort(root, NULL, NULL);

  struct fy_node *added = fy_node_build_from_string(fyd, "fuzz_added", FY_NT);
  if (added) {
    fy_node_sequence_add_item(root, added);
    fy_node_sequence_remove(root, added);
    fy_node_free(added);
  }

  if (first) {
    struct fy_node *after = fy_node_build_from_string(fyd, "fuzz_after", FY_NT);
    if (after) {
      fy_node_sequence_insert_after(root, first, after);
      fy_node_sequence_remove(root, after);
      fy_node_free(after);
    }
  }

out:
  fy_node_free(new_node);
}


void test_parse_with_flags(struct flags_t *flags, const char *data, size_t size) {
  struct fy_document *fyd = NULL;
  struct fy_document *fyd2 = NULL;
  struct fy_document *fyd3 = NULL;
  struct fy_parse_cfg cfg = { .flags = flags->parse_flags };
  char* buf = NULL;
  int rc;
  struct fy_emitter *emitter = NULL;
  struct fy_emitter* emit = NULL;
  char *collected = NULL;
  struct fy_node* node2 = NULL;
  char *plain = NULL;
  struct fy_document *fyd4 = NULL;
  struct fy_document_iterator *fydi = NULL;
  struct fy_document_iterator *fydi2 = NULL;
  struct fy_document_iterator *fydi3 = NULL;

  struct fy_emitter_xcfg emit_xcfg = {
    .cfg = {
      .flags = flags->emitter_flags
    },
    .xflags = flags->extended_emitter_flags | FYEXCF_OUTPUT_FD,
    .output_fp = null_fp,
  };

  fyd = fy_document_build_from_string(&cfg, data, size);
  CHECK(fyd);


  // test_node_comparisons
  {
    struct fy_node *root2 = fy_document_root(fyd);
    if (root2) {
      bool same = fy_node_compare(root2, root2);
      fyd4 = fy_document_clone(fyd);
      if(fyd4) {
        struct fy_node *root3 = fy_document_root(fyd4);
        bool equal = fy_node_compare(root2, root3);
        bool matches = fy_node_compare_string(root2, data, size);
        bool text_matches = fy_node_compare_text(root2, data, size);
      }
    }
  }

  // test_node_styles
  {
    fy_node_set_style(fy_document_root(fyd), flags->node_style);
  }


  // test_emit
  {
    buf = fy_emit_document_to_string(fyd, flags->emitter_flags);
  }


  // test_emit2
  {
    rc = fy_emit_document_to_fp(fyd, flags->emitter_flags, null_fp);
    // ignore rc
  }


  // test_emit_to_buffer
  {
    char buf2[4096] = {0};
    rc = fy_emit_document_to_buffer(fyd, flags->emitter_flags, buf2, sizeof(buf2));
    // ignore rc

    emitter = fy_emit_to_string(flags->emitter_flags);
    fy_emit_document(emitter, fyd);
    size_t out_size;
    collected = fy_emit_to_string_collect(emitter, &out_size);
  }


  // test_fy_emitter_create
  {
    emit = fy_emitter_create(&emit_xcfg.cfg);
    if(emit) {
      rc = fy_emit_document(emit, fyd);
      fy_emitter_get_cfg(emit);
      fy_diag_unref(fy_emitter_get_diag(emit)); /* returns a ref'd object */
      fy_emitter_get_document_state(emit);
    }
  }


  // test_emit_to_buffer_api (fy-emit.c)
  {
    char ebuf[4096];
    struct fy_emitter *ebuf_emit = fy_emit_to_buffer(flags->emitter_flags, ebuf, sizeof(ebuf));
    if (ebuf_emit) {
      fy_emit_document(ebuf_emit, fyd);
      size_t ebuf_size;
      fy_emit_to_buffer_collect(ebuf_emit, &ebuf_size);
      fy_emitter_destroy(ebuf_emit);
    }

    char nbuf[4096];
    int nrc = fy_emit_node_to_buffer(fy_document_root(fyd), flags->emitter_flags, nbuf, sizeof(nbuf));
    (void)nrc;
  }


  // test_emit_node_to_string
  {
    plain = fy_emit_node_to_string(fy_document_root(fyd), flags->emitter_flags);
  }


  // test_clone
  {
    fyd2 = fy_document_clone(fyd);
    if (fyd2) {
      fy_document_resolve(fyd2);
      struct fy_node* root = fy_document_root(fyd2);
      fyd3 = fy_document_create(NULL);
      node2 = fy_node_copy(fyd3, root);
    }
  }


  // test_document_iterator_node
  {
    struct fy_node *fyn = NULL;
    fydi = fy_document_iterator_create();
    if (fydi) {
      fy_document_iterator_node_start(fydi, fy_document_root(fyd));
      while ((fyn = fy_document_iterator_node_next(fydi)) != NULL) {
        if (fy_node_is_alias(fyn)) {
          fy_node_resolve_alias(fyn);
          fy_node_dereference(fyn);
        }
      }
    }

    fy_document_iterator_get_error(fydi);
  }


  // test_document_iterator_generate
  {
    struct fy_event *fye2 = NULL;

    fydi2 = fy_document_iterator_create_on_document(fyd);
    if (fydi2) {
      while ((fye2 = fy_document_iterator_generate_next(fydi2)) != NULL)
        fy_document_iterator_event_free(fydi2, fye2);
    }

    fy_document_iterator_get_error(fydi2);
  }


  // test_document_iterator
  {
    struct fy_event *fye = NULL;

    fydi3 = fy_document_iterator_create();
    if (fydi3) {
      fye = fy_document_iterator_stream_start(fydi3);
      if (fye) fy_document_iterator_event_free(fydi3, fye);

      fye = fy_document_iterator_document_start(fydi3, fyd);
      if (fye) fy_document_iterator_event_free(fydi3, fye);

      while ((fye = fy_document_iterator_body_next(fydi3)) != NULL)
        fy_document_iterator_event_free(fydi3, fye);

      fy_document_iterator_get_error(fydi3);

      fye = fy_document_iterator_document_end(fydi3);
      if (fye) fy_document_iterator_event_free(fydi3, fye);

      fye = fy_document_iterator_stream_end(fydi3);
      if (fye) fy_document_iterator_event_free(fydi3, fye);
    }

    fy_document_iterator_get_error(fydi3);
  }

  // test_node_accessors (fy-doc.c)
  {
    struct fy_node *root = fy_document_root(fyd);
    if (root) {
      fy_node_get_type(root);
      fy_node_get_style(root);
      size_t taglen;
      fy_node_get_tag(root, &taglen);
      fy_node_get_tag0(root);
      fy_node_get_tag_length(root);
      fy_node_get_tag_token(root);
      fy_node_get_anchor(root);
      fy_node_get_comment(root, fycp_top);
      fy_node_get_comments(root);
      char *path = fy_node_get_path(root);
      free(path);
      char *spath = fy_node_get_short_path(root);
      free(spath);
      fy_node_get_parent(root);
      fy_node_get_document_parent(root);
      char *paddr = fy_node_get_parent_address(root);
      free(paddr);
      fy_node_get_nearest_anchor(root);
      fy_node_is_attached(root);
      fy_node_is_marker_set(root, 0);
      fy_node_set_marker(root, 0);
      fy_node_is_marker_set(root, 0);
      fy_node_clear_marker(root, 0);
      fy_node_set_meta(root, (void *)flags);
      fy_node_get_meta(root);
      fy_node_clear_meta(root);
      fy_node_document(root);
      fy_node_get_scalar0(root);
      fy_node_get_scalar_length(root);
      fy_node_get_scalar_utf8_length(root);
      fy_node_compare_token(root, fy_node_get_scalar_token(root));
      fy_node_compare_user(root, root, NULL, NULL, NULL, NULL);
      fy_node_sort(root, NULL, NULL);
      fy_node_is_null(root);

      struct fy_node *child = fy_node_get_nearest_child_of(root, root);
      (void)child;
      char *relpath = fy_node_get_path_relative_to(root, root);
      free(relpath);
    }
  }

  // test_document_state_accessors (fy-doc.c)
  {
    fy_document_has_directives(fyd);
    fy_document_has_explicit_document_end(fyd);
    fy_document_has_explicit_document_start(fyd);
    fy_document_get_cfg(fyd);
    fy_diag_unref(fy_document_get_diag(fyd)); /* returns a ref'd object */

    struct fy_document_state *fyds = fy_document_get_document_state(fyd);
    if (fyds) {
      fy_document_state_version(fyds);
      fy_document_state_version_explicit(fyds);
      fy_document_state_tags_explicit(fyds);
      fy_document_state_start_implicit(fyds);
      fy_document_state_start_explicit(fyds);
      fy_document_state_end_implicit(fyds);
      fy_document_state_end_explicit(fyds);
      fy_document_state_start_mark(fyds);
      fy_document_state_end_mark(fyds);
      fy_document_state_json_mode(fyds);
      free(fy_document_state_tag_directives(fyds)); /* caller-owned array */

      void *tdprev = NULL;
      const struct fy_tag *tag;
      while ((tag = fy_document_state_tag_directive_iterate(fyds, &tdprev)) != NULL)
        fy_document_state_tag_is_default(fyds, tag);
    }

    void *tprev = NULL;
    while (fy_document_tag_directive_iterate(fyd, &tprev) != NULL)
      ;
    fy_document_tag_directive_lookup(fyd, "!!");
    fy_document_tag_directive_add(fyd, "!x!", "tag:example.com,2000:app/");
    fy_document_tag_directive_remove(fyd, "!x!");

    void *aprev = NULL;
    struct fy_anchor *anch;
    while ((anch = fy_document_anchor_iterate(fyd, &aprev)) != NULL) {
      fy_anchor_node(anch);
      size_t alen;
      fy_anchor_get_text(anch, &alen);
    }
    fy_document_lookup_anchor(fyd, "a", 1);
    struct fy_node *root2 = fy_document_root(fyd);
    if (root2) {
      fy_document_lookup_anchor_by_node(fyd, root2);
      fy_document_lookup_anchor_by_token(fyd, fy_node_get_scalar_token(root2));
    }
  }

  test_token_iteration(fyd);
  test_sequence_operations(fyd);



out:
  free(collected);
  free(buf);
  free(plain);

  fy_node_free(node2);
  fy_document_iterator_destroy(fydi);
  fy_document_iterator_destroy(fydi2);
  fy_document_iterator_destroy(fydi3);

  fy_emitter_destroy(emitter);
  fy_emitter_destroy(emit);
  fy_document_destroy(fyd);
  fy_document_destroy(fyd2);
  fy_document_destroy(fyd3);
  fy_document_destroy(fyd4);
}


void test_parse_with_flags_fp(struct flags_t *flags, const char *data, size_t size) {
  struct fy_document *fyd = NULL;
  struct fy_parse_cfg cfg = { .flags = flags->parse_flags };
  FILE *f = NULL;

  f = fmemopen((void *)data, size, "r");
  fyd = fy_document_build_from_fp(&cfg, f);
  CHECK(f);

out:
  if(f) fclose(f);
  fy_document_destroy(fyd);
}

/*
 * fy_node_vscanf() (fy-doc.c) sizes two alloca()s directly off
 * attacker-controlled lengths - alloca(strlen(fmt)+1) for the format
 * itself, and alloca(value_len+1) for the text of whatever scalar a
 * pathspec resolves to - with no cap on either. That's the interesting
 * surface here, and the original test_scanf() (kept below as
 * test_scanf2) couldn't reach it: banning '%' outright from the
 * fuzzer-controlled text means the format handed to fy_document_scanf()
 * never has more than the one hardcoded "%s" conversion this harness
 * appends itself.
 *
 * Instead, every literal '%' in the fuzzer-controlled text is escaped to
 * "%%" (exactly how fy_node_vscanf's own scanner already treats a
 * doubled '%' as literal), so arbitrary bytes stay fuzzable as pathspec
 * text while every real conversion in the final format is one we chose
 * ourselves, matched to a correctly sized destination - so a crash here
 * is attributable to the library's alloca()s, not to this harness's own
 * buffer handling.
 */
#define TEST_SCANF_MAX_CLAUSES 4

void test_scanf(struct flags_t *flags, const char *data, size_t size) {
  static const char *convspecs[] = { "%d", "%ld", "%f", "%c", "%x", "%1023s" };
  struct fy_document *fyd = NULL;
  struct fy_parse_cfg cfg = { .flags = flags->parse_flags };
  char *raw = NULL;
  char *d = NULL;
  char *escaped = NULL;
  char *fmt = NULL;
  size_t raw_len, d_len;
  union { long long ll; double dv; char buf[1024]; } dst[TEST_SCANF_MAX_CLAUSES] = {0};

  CHECK(split_two_parts(data, size, &raw, &raw_len, &d, &d_len));

  fyd = fy_document_build_from_string(&cfg, d, d_len);
  CHECK(fyd);

  escaped = malloc(raw_len * 2 + 1);
  size_t epos = 0;
  for (size_t i = 0; i < raw_len; i++) {
    if (raw[i] == '%')
      escaped[epos++] = '%';
    escaped[epos++] = raw[i];
  }
  escaped[epos] = '\0';

  int nclauses = raw_len ? 1 + ((unsigned char)raw[0] % TEST_SCANF_MAX_CLAUSES) : 1;
  size_t chunk = epos / nclauses;

  fmt = malloc(epos + nclauses * 16 + 1);
  size_t fpos = 0;
  for (int i = 0; i < nclauses; i++) {
    size_t start = (size_t)i * chunk;
    size_t len = (i == nclauses - 1) ? (epos - start) : chunk;
    memcpy(fmt + fpos, escaped + start, len);
    fpos += len;
    fmt[fpos++] = ' ';

    unsigned char sel = raw_len ? (unsigned char)raw[i % raw_len] : (unsigned char)i;
    const char *conv = convspecs[sel % (sizeof(convspecs) / sizeof(convspecs[0]))];
    size_t convlen = strlen(conv);
    memcpy(fmt + fpos, conv, convlen);
    fpos += convlen;
    fmt[fpos++] = ' ';
  }
  fmt[fpos] = '\0';

  fy_document_scanf(fyd, fmt, &dst[0], &dst[1], &dst[2], &dst[3]);

out:
  fy_document_destroy(fyd);
  free(escaped);
  free(fmt);
  free(raw);
  free(d);
}


void test_fy_path_expr_build_from_string(struct flags_t *flags, const char *data, size_t size) {
  struct fy_path_parse_cfg parse_cfg = {0};
  parse_cfg.flags = flags->path_parse_flags;

  struct fy_path_expr *expr = fy_path_expr_build_from_string(&parse_cfg, data, size);
  if (expr) {
    /*
     * fy_path_expr_dump() (fy-walk.c:1679) dereferences @diag
     * unconditionally - passing NULL (a value every other diag-taking
     * function in this API treats as "use the default") SEGVs. Feeding
     * it a real diag object here to keep exercising this function;
     * the NULL-deref itself is a real finding worth reporting upstream.
     */
    struct fy_diag_cfg dcfg;
    fy_diag_cfg_default(&dcfg);
    struct fy_diag *diag = fy_diag_create(&dcfg);
    if (diag) {
      fy_path_expr_dump(expr, diag, FYET_NOTICE, 0, "fuzz");
      fy_diag_unref(diag);
    }
    struct fy_document *exprdoc = fy_path_expr_to_document(expr);
    fy_document_destroy(exprdoc);
  }
  fy_path_expr_free(expr);

  /* lower-level path-parser API driving the same input (fy-walk.c) */
  struct fy_path_parser *fypp = fy_path_parser_create(&parse_cfg);
  if (fypp) {
    struct fy_path_expr *expr2 = fy_path_parse_expr_from_string(fypp, data, size);
    fy_path_expr_free(expr2);
    fy_path_parser_reset(fypp);
    struct fy_path_expr *expr3 = fy_path_parse_expr_from_string(fypp, data, size);
    fy_path_expr_free(expr3);
    fy_path_parser_destroy(fypp);
  }
}

void test_fy_parser_parse(struct flags_t *flags, const char *data, size_t size) {
  struct fy_parser *fyp = NULL;
  struct fy_parse_cfg cfg = { .flags = flags->parse_flags };
  struct fy_event *fyev = NULL;

  fyp = fy_parser_create(&cfg);
  CHECK(fyp);

  int rc = fy_parser_set_string(fyp, data, size);
  CHECK(rc == 0);

  while ((fyev = fy_parser_parse(fyp)) != NULL) {
    dump_testsuite_event(fyp, fyev);
    fy_event_get_comments(fyev);
    fy_parser_event_free(fyp, fyev);
  }

  fy_parse_compose(fyp, compose_inspect_cb, NULL);

  /* parser accessors (fy-parse.c) */
  fy_parser_get_cfg(fyp);
  fy_diag_unref(fy_parser_get_diag(fyp)); /* fy_parser_get_diag() returns a ref'd object */
  fy_parser_get_mode(fyp);
  fy_parser_get_stream_error(fyp);
  /*
   * fy_parser_count_mapping_items()/fy_parser_count_sequence_items() are
   * deliberately NOT called here: both call fy_parser_checkpoint_create()
   * internally, which has a real heap-buffer-overflow (fy-parse.c:9122,
   * an over-long memcpy) whenever it runs after the parser has gone
   * through merge-key/alias resolution (fy_parser_event_resolve_hook_merge_key
   * -> fy_parse_streaming_alias_collection_state_push, fy-parse.c:8397) -
   * which is most ordinary YAML using merge keys. That hits on a large
   * fraction of real corpus files, so calling it here would make the
   * harness crash on most inputs instead of building broad coverage.
   * Worth its own bug report; tracked separately from this harness.
   */
  fy_parser_reset(fyp);

out:
  fy_parser_destroy(fyp);
}

void test_fy_parser_parse_fp(struct flags_t *flags, const char *data, size_t size) {
  struct fy_parser *fyp = NULL;
  struct fy_parse_cfg cfg = { .flags = flags->parse_flags };
  struct fy_event *fyev = NULL;
  FILE *f = NULL;

  f = fmemopen((void *)data, size, "r");
  CHECK(f);

  fyp = fy_parser_create(&cfg);
  CHECK(fyp);

  int rc = fy_parser_set_input_fp(fyp, NULL, f);
  CHECK(rc == 0);

  while ((fyev = fy_parser_parse(fyp)) != NULL) {
    dump_testsuite_event(fyp, fyev);
    fy_event_get_comments(fyev);
    fy_parser_event_free(fyp, fyev);
  }

out:
  if(f) fclose(f);
  fy_parser_destroy(fyp);
}



void test_mapping_operations(struct flags_t *flags, const char *data, size_t size) {
  struct fy_document *fyd = NULL;
  struct fy_parse_cfg cfg = { .flags = flags->parse_flags };
  char *doc = NULL;
  char *path = NULL;
  size_t doc_len, path_len;

  CHECK(split_two_parts(data, size, &doc, &doc_len, &path, &path_len));

  fyd = fy_document_build_from_string(&cfg, doc, doc_len);
  CHECK(fyd);

  struct fy_node *root = fy_document_root(fyd);
  CHECK(fy_node_is_mapping(root));

  fy_node_mapping_lookup_by_string(root, path, path_len);
  
  void *iter = NULL;
  struct fy_node_pair *pair;
  while ((pair = fy_node_mapping_iterate(root, &iter)) != NULL) {
  }
  
out:
  free(doc);
  free(path);
  fy_document_destroy(fyd);
}


void test_path_exec(struct flags_t *flags, const char *data, size_t size) {
  struct fy_document *fyd = NULL;
  struct fy_path_expr *expr = NULL;
  struct fy_path_exec *fypx = NULL;
  struct fy_path_parse_cfg parse_cfg = {0};
  struct fy_parse_cfg cfg = { .flags = flags->parse_flags };
  struct fy_node *fyn = NULL;
  char *path = NULL;
  char *doc_str = NULL;
  void *iter;
  size_t path_len, doc_str_len;

  CHECK(split_two_parts(data, size, &path, &path_len, &doc_str, &doc_str_len));

  parse_cfg.flags = flags->path_parse_flags;
  expr = fy_path_expr_build_from_string(&parse_cfg, path, path_len);
  CHECK(expr);

  fyd = fy_document_build_from_string(&cfg, doc_str, doc_str_len);
  CHECK(fyd);

  fypx = fy_path_exec_create(NULL);
  CHECK(fypx);

  fy_path_exec_execute(fypx, expr, fy_document_root(fyd));
  iter = NULL;
  while ((fyn = fy_path_exec_results_iterate(fypx, &iter)) != NULL)
    ;

  fy_path_exec_reset(fypx);
  fy_path_exec_execute(fypx, expr, fy_document_root(fyd));
  iter = NULL;
  while ((fyn = fy_path_exec_results_iterate(fypx, &iter)) != NULL)
    ;

out:
  fy_path_exec_destroy(fypx);
  fy_path_expr_free(expr);
  fy_document_destroy(fyd);
  free(path);
  free(doc_str);
}

void test_document_builder(struct flags_t *flags, const char *data, size_t size) {
  struct fy_parser *fyp = NULL;
  struct fy_document_builder *fydb = NULL;
  struct fy_document *fyd = NULL;
  struct fy_parse_cfg cfg = { .flags = flags->parse_flags };

  fyp = fy_parser_create(&cfg);
  CHECK(fyp);

  int rc = fy_parser_set_string(fyp, data, size);
  CHECK(rc == 0);

  fydb = fy_document_builder_create_on_parser(fyp);
  CHECK(fydb);

  while ((fyd = fy_document_builder_load_document(fydb, fyp)) != NULL) {
    fy_document_builder_is_in_stream(fydb);
    fy_document_builder_is_in_document(fydb);
    fy_document_destroy(fyd);
    fyd = NULL;
  }

out:
  fy_document_builder_destroy(fydb);
  fy_document_destroy(fyd);
  fy_parser_destroy(fyp);
}


void test_mapping_operations_extended(struct flags_t *flags, const char *data, size_t size) {
  struct fy_document *fyd = NULL;
  struct fy_node *removed_val = NULL;
  struct fy_parse_cfg cfg = { .flags = flags->parse_flags };
  char *doc_str = NULL;
  char *path = NULL;
  void *iter;
  struct fy_node_pair *pair;
  size_t doc_str_len, path_len;

  CHECK(split_two_parts(data, size, &doc_str, &doc_str_len, &path, &path_len));

  fyd = fy_document_build_from_string(&cfg, doc_str, doc_str_len);
  CHECK(fyd);

  struct fy_node *root = fy_document_root(fyd);
  CHECK(fy_node_is_mapping(root));

  iter = NULL;
  while ((pair = fy_node_mapping_reverse_iterate(root, &iter)) != NULL)
    ;

  struct fy_node *append_key = fy_node_build_from_string(fyd, "fuzz_append_key", FY_NT);
  struct fy_node *append_val = fy_node_build_from_string(fyd, "fuzz_append_val", FY_NT);
  /* a failed append takes no ownership (fy_node_mapping_pair_insert_prepare()
   * bails before it touches either node), so the pair is still ours to free */
  if (!append_key || !append_val ||
      fy_node_mapping_append(root, append_key, append_val)) {
    fy_node_free(append_key);
    fy_node_free(append_val);
  }

  struct fy_node *prepend_key = fy_node_build_from_string(fyd, "fuzz_prepend_key", FY_NT);
  struct fy_node *prepend_val = fy_node_build_from_string(fyd, "fuzz_prepend_val", FY_NT);
  if (!prepend_key || !prepend_val ||
      fy_node_mapping_prepend(root, prepend_key, prepend_val)) {
    fy_node_free(prepend_key);
    fy_node_free(prepend_val);
  }

  fy_node_mapping_item_count(root);
  fy_node_mapping_lookup_by_string(root, path, path_len);
  fy_node_mapping_lookup_key_by_string(root, path, path_len);
  fy_node_mapping_lookup_pair_by_string(root, path, path_len);

  fy_node_mapping_sort(root, NULL, NULL);

  struct fy_node *key_node = fy_node_build_from_string(fyd, path, path_len);
  if (key_node) {
    removed_val = fy_node_mapping_remove_by_key(root, key_node);
    fy_node_free(key_node);
  }

  /* extra mapping/pair accessors (fy-doc.c) */
  fy_node_mapping_is_empty(root);
  fy_node_mapping_get_by_index(root, 0);
  fy_node_mapping_lookup_pair_by_simple_key(root, path, path_len);
  fy_node_mapping_lookup_value_by_simple_key(root, path, path_len);
  size_t slen;
  fy_node_mapping_lookup_scalar_by_simple_key(root, &slen, path, path_len);
  fy_node_mapping_lookup_scalar0_by_simple_key(root, path, path_len);
  fy_node_mapping_lookup_value_by_string(root, path, path_len);
  fy_node_mapping_lookup_pair_by_null_key(root);
  fy_node_mapping_lookup_value_by_null_key(root);

  struct fy_node_pair *fpair = fy_node_mapping_get_by_index(root, 0);
  if (fpair) {
    fy_node_mapping_get_pair_index(root, fpair);
    struct fy_node *pkey = fy_node_pair_key(fpair);
    struct fy_node *pval = fy_node_pair_value(fpair);
    (void)pkey;
    (void)pval;
  }


out:
  fy_node_free(removed_val);
  free(doc_str);
  free(path);
  fy_document_destroy(fyd);
}

void test_document_insert_at(struct flags_t *flags, const char *data, size_t size) {
  struct fy_document *fyd = NULL;
  struct fy_node *new_node = NULL;
  struct fy_parse_cfg cfg = { .flags = flags->parse_flags };
  char *path = NULL;
  char *doc_str = NULL;
  size_t path_len, doc_str_len;

  CHECK(split_two_parts(data, size, &path, &path_len, &doc_str, &doc_str_len));

  fyd = fy_document_build_from_string(&cfg, doc_str, doc_str_len);
  CHECK(fyd);

  new_node = fy_node_build_from_string(fyd, "inserted", FY_NT);
  CHECK(new_node);

  fy_document_insert_at(fyd, path, path_len, new_node);
  new_node = NULL;

out:
  fy_node_free(new_node);
  free(path);
  free(doc_str);
  fy_document_destroy(fyd);
}

void test_parser_checkpoint_rollback(struct flags_t *flags, const char *data, size_t size) {
  struct fy_parser *fyp = NULL;
  struct fy_parser_checkpoint *fypchk = NULL;
  struct fy_event *fyev = NULL;
  struct fy_parse_cfg cfg = { .flags = flags->parse_flags };

  fyp = fy_parser_create(&cfg);
  CHECK(fyp);

  int rc = fy_parser_set_string(fyp, data, size);
  CHECK(rc == 0);

  fyev = fy_parser_parse(fyp);
  if (fyev) fy_parser_event_free(fyp, fyev);

  fypchk = fy_parser_checkpoint_create(fyp);
  CHECK(fypchk);

  fyev = fy_parser_parse(fyp);
  if (fyev) fy_parser_event_free(fyp, fyev);

  fyev = fy_parser_parse(fyp);
  if (fyev) fy_parser_event_free(fyp, fyev);

  fy_parser_rollback(fyp, fypchk);
  fy_parser_checkpoint_destroy(fypchk);
  fypchk = NULL;

  while ((fyev = fy_parser_parse(fyp)) != NULL)
    fy_parser_event_free(fyp, fyev);

out:
  if (fypchk) fy_parser_checkpoint_destroy(fypchk);
  fy_parser_destroy(fyp);
}

void test_token_comments(struct flags_t *flags, const char *data, size_t size) {
  struct fy_document *fyd = NULL;
  struct fy_parse_cfg cfg = { .flags = flags->parse_flags };
  char *doc = NULL;
  char *comment = NULL;
  size_t doc_len, comment_len;

  CHECK(split_two_parts(data, size, &doc, &doc_len, &comment, &comment_len));

  fyd = fy_document_build_from_string(&cfg, doc, doc_len);
  CHECK(fyd);

  struct fy_node *root = fy_document_root(fyd);
  CHECK(root);
  CHECK(fy_node_is_scalar(root));

  struct fy_token *token = fy_node_get_scalar_token(root);
  CHECK(token);

  fy_token_set_comment(token, fycp_top, comment, comment_len);
  fy_token_set_comment(token, fycp_right, comment, comment_len);
  fy_token_set_comment(token, fycp_bottom, comment, comment_len);
  fy_token_get_comment(token, fycp_top);
  fy_token_get_comment(token, fycp_right);
  fy_token_get_comment(token, fycp_bottom);
  fy_token_get_comments(token);

out:
  fy_document_destroy(fyd);
  free(doc);
  free(comment);
}

void test_reflection_packed_blob(struct flags_t *flags, const char *data, size_t size) {
  struct fy_reflection *rfl = NULL;
  struct fy_type_context *ctx = NULL;
  struct fy_parser *fyp = NULL;
  void *parsed_data = NULL;
  struct fy_parse_cfg parse_cfg = { .flags = flags->parse_flags };
  int rc;
  struct fy_emitter *emit = NULL;

  rfl = fy_reflection_from_packed_blob((const void *)data, size, NULL);
  CHECK(rfl);

  const struct fy_type_info *ti;
  void *prev = NULL;
  while ((ti = fy_type_info_iterate(rfl, &prev)) != NULL) {
    fy_type_info_get_id(ti);
    fy_type_info_eponymous_offset(ti);
    fy_type_info_get_comment(ti);
    fy_type_info_get_yaml_comment(ti);
    fy_type_info_get_yaml_annotation(ti);
    fy_type_info_is_marked(ti);
    fy_type_info_mark(ti);
    fy_type_info_clear_marker(ti);
    fy_type_info_unqualified(ti);
    fy_type_info_with_qualifiers(ti, flags->type_info_flags);
    fy_type_info_to_reflection(ti);

    char *gen_name = fy_type_info_generate_name(ti, NULL);
    free(gen_name);

    size_t nfields = fy_type_info_get_count(ti);
    for (size_t i = 0; i < nfields; i++) {
      const struct fy_field_info *fi = fy_type_info_get_field_at(ti, i);
      if (!fi)
        continue;
      fy_field_info_get_comment(fi);
      fy_field_info_get_yaml_comment(fi);
      fy_field_info_get_yaml_annotation(fi);
      fy_field_info_index(fi);

      char *fgen_name = fy_field_info_generate_name(fi);
      free(fgen_name);
    }
  }

  struct fy_type_context_cfg ctx_cfg = {
    .rfl = rfl,
    .entry_type = flags->primitive_type,
  };
  ctx = fy_type_context_create(&ctx_cfg);
  CHECK(ctx);

  fyp = fy_parser_create(&parse_cfg);
  CHECK(fyp);

  rc = fy_parser_set_string(fyp, data, size);
  CHECK(rc == 0);

  rc = fy_type_context_parse(ctx, fyp, &parsed_data);
  if (rc == 0 && parsed_data) {
    emit = fy_emit_to_string(flags->emitter_flags);
    CHECK(emit);

    rc = fy_type_context_emit(ctx, emit, parsed_data,
        FYTCEF_SS | FYTCEF_DS | FYTCEF_DE | FYTCEF_SE);

    if (rc == 0) {
      size_t out_size;
      char *out_str = fy_emit_to_string_collect(emit, &out_size);
      free(out_str);
    }
  }

out:
  fy_type_context_free_data(ctx, parsed_data);
  fy_parser_destroy(fyp);
  fy_type_context_destroy(ctx);
  fy_reflection_destroy(rfl);
  fy_emitter_destroy(emit);
}

void test_reflection_c(struct flags_t *flags, const char *data, size_t size) {
  struct fy_reflection *rfl = NULL;
  char *generated = NULL;

  rfl = fy_reflection_from_packed_blob((const void *)data, size, NULL);
  CHECK(rfl);

  generated = fy_reflection_generate_c_string(rfl, flags->cgen_flag);

out:
  if (generated) free(generated);
  fy_reflection_destroy(rfl);
}

void test_reflection_type_lookup(struct flags_t *flags, const char *data, size_t size) {
  struct fy_reflection *rfl = NULL;
  const struct fy_type_info *ti;
  char *gen_name = NULL;
  char *type_info_lookup = NULL;
  char *type_info_lookup_field = NULL;
  size_t type_info_lookup_len, type_info_lookup_field_len;

  CHECK(split_two_parts(data, size, &type_info_lookup, &type_info_lookup_len,
                         &type_info_lookup_field, &type_info_lookup_field_len));

  rfl = fy_reflection_from_null(NULL);
  CHECK(rfl);

  ti = fy_type_info_lookup(rfl, type_info_lookup);
  if (ti) {
    fy_type_info_get_kind(ti);
    fy_type_info_get_size(ti);
    fy_type_info_get_align(ti);
    fy_type_info_is_marked(ti);
    fy_type_info_mark(ti);
    fy_type_info_is_marked(ti);
    fy_type_info_clear_marker(ti);
    fy_type_info_unqualified(ti);
    fy_type_info_with_qualifiers(ti, flags->type_info_flags);
    gen_name = fy_type_info_generate_name(ti, NULL);
    fy_type_info_lookup_field(ti, type_info_lookup_field);
    fy_type_info_lookup_field_by_enum_value(ti, (intmax_t)flags->type_info_flags); // just random flag
  }

  ti = fy_type_info_lookup(rfl, flags->primitive_type);
  if (ti)
    fy_type_info_get_size(ti);

out:
  free(gen_name);
  fy_reflection_destroy(rfl);
  free(type_info_lookup);
  free(type_info_lookup_field);
}

void test_reflection_type_context_entry_meta(struct flags_t *flags, const char *data, size_t size) {
  struct fy_reflection *rfl = NULL;
  struct fy_type_context *ctx = NULL;
  struct fy_parser *fyp = NULL;
  void *parsed_data = NULL;
  char *meta_str = NULL;
  char *yaml_str = NULL;
  size_t meta_str_len, yaml_str_len;
  struct fy_parse_cfg parse_cfg = { .flags = flags->parse_flags };

  CHECK(split_two_parts(data, size, &meta_str, &meta_str_len, &yaml_str, &yaml_str_len));

  rfl = fy_reflection_from_null(NULL);
  CHECK(rfl);

  struct fy_type_context_cfg ctx_cfg = {
    .rfl = rfl,
    .entry_type = flags->primitive_type,
    .entry_meta = meta_str,
  };
  ctx = fy_type_context_create(&ctx_cfg);
  CHECK(ctx);

  fyp = fy_parser_create(&parse_cfg);
  CHECK(fyp);

  int rc = fy_parser_set_string(fyp, yaml_str, yaml_str_len);
  CHECK(rc == 0);

  fy_type_context_parse(ctx, fyp, &parsed_data);

out:
  fy_type_context_free_data(ctx, parsed_data);
  fy_parser_destroy(fyp);
  fy_type_context_destroy(ctx);
  fy_reflection_destroy(rfl);
  free(meta_str);
  free(yaml_str);
}

/*
 * fy_reflection_from_null() already registers a set of built-in types, so
 * this walks every one of them (and every field of every one) exercising
 * the type/field introspection accessors (fy-reflection.c) without needing
 * fuzzer bytes to satisfy libclang or the packed-blob format first. Fuzzer
 * bytes drive the name-based lookups, the include/exclude filter, and the
 * to_packed_blob()/from_packed_blob() round trip (fy-meta-serdes.c,
 * fy-packed-backend.c) - serializing a well-formed reflection instead of
 * only ever trying to deserialize random garbage.
 */
void test_reflection_walk_types(struct flags_t *flags, const char *data, size_t size) {
  struct fy_reflection *rfl = NULL;
  struct fy_reflection *rfl2 = NULL;
  char *name = NULL;
  char *field_name = NULL;
  size_t name_len, field_name_len;
  void *blob = NULL;
  size_t blob_size = 0;

  rfl = fy_reflection_from_null(NULL);
  CHECK(rfl);

  /* fuzzer-driven name/field lookups against the same reflection */
  if (split_two_parts(data, size, &name, &name_len, &field_name, &field_name_len)) {
    const struct fy_type_info *tin = fy_type_info_lookup(rfl, name);
    if (tin)
      fy_type_info_lookup_field(tin, field_name);

    /* fy_reflection_type_filter() regcomp()s these directly - a handful of
     * fuzzer bytes (repeated quantifiers) can make glibc's regex compiler
     * blow up to gigabytes of memory (see id: TODO, regex DoS via
     * fy-meta-serdes.c:93). Capping the pattern length here keeps that
     * from swallowing every run; the underlying regcomp() issue is a
     * genuine finding on its own, tracked separately. */
    char inc_buf[17], exc_buf[17];
    size_t inc_len = name_len < sizeof(inc_buf) - 1 ? name_len : sizeof(inc_buf) - 1;
    size_t exc_len = field_name_len < sizeof(exc_buf) - 1 ? field_name_len : sizeof(exc_buf) - 1;
    memcpy(inc_buf, name, inc_len); inc_buf[inc_len] = '\0';
    memcpy(exc_buf, field_name, exc_len); exc_buf[exc_len] = '\0';
    fy_reflection_type_filter(rfl, inc_buf, exc_buf);
  }

  /* serialize a well-formed reflection, then round-trip it back */
  blob = fy_reflection_to_packed_blob(rfl, &blob_size, true, true);
  if (blob) {
    rfl2 = fy_reflection_from_packed_blob(blob, blob_size, NULL);
    if (rfl2) {
      fy_reflection_equal(rfl, rfl2);
      fy_reflection_prune_system(rfl2);
    }
  }

  fy_reflection_clear_all_markers(rfl);
  fy_reflection_prune_unmarked(rfl);

out:
  free(blob);
  fy_reflection_destroy(rfl2);
  fy_reflection_destroy(rfl);
  free(name);
  free(field_name);
}

/*
 * The mmap-backed input path (fy-input.c, fyit_file) is only reachable via
 * fy_parser_set_input_file()/fy_document_build_from_file() - every other
 * test function here goes through fy_parser_set_string()/fmemopen(), which
 * bypass it entirely.
 *
 * The entry point needs a real path, not just an fd, so this uses
 * memfd_create() - an anonymous, RAM-backed file with no filesystem entry -
 * and hands it "/proc/self/fd/<fd>" as the path. Re-opening that symlink
 * yields a fresh, independent file description on the *same* memfd inode,
 * so fy_document_build_from_file()'s own open()+mmap() still work exactly
 * as they would on a real file, without this harness ever touching disk.
 *
 * FYPCF_ENABLE_CACHE is deliberately masked off here. This is the only
 * caller of fy_parser_set_input_file() in the harness, and the disk-backed
 * parse cache it gates (fy-cache.c) hashes its cache key by spinning up a
 * fresh pthread pool (via fy_blake3_hasher_create() -> a zeroed
 * fy_blake3_hasher_cfg, which enables multithreading by default -
 * see fy-blake3.c) and tearing it down again on every single call. Doing
 * that on every fuzz iteration reliably triggers a real, pre-existing
 * use-after-free/race in the library's own thread-pool teardown
 * (fy_worker_thread_shutdown, src/thread/fy-thread.c:264) within a few
 * thousand executions - reproducible with -fork=1, content-independent
 * (tiny crash artifacts), and never reproducible by replaying a single
 * saved input in isolation. That's a genuine library bug, not a harness
 * bug, but until it's fixed upstream there's no point burning the whole
 * fuzzing campaign on the same known crash instead of finding new ones -
 * so the cache path is disabled here rather than worked around.
 */
void test_parse_from_file(struct flags_t *flags, const char *data, size_t size) {
  struct fy_document *fyd = NULL;
  struct fy_parse_cfg cfg = { .flags = flags->parse_flags & ~FYPCF_ENABLE_CACHE };
  char path[32];
  int fd = -1;
  ssize_t n;

  fd = memfd_create("fy-fuzz", MFD_CLOEXEC);
  CHECK(fd >= 0);

  n = write(fd, data, size);
  CHECK(n == (ssize_t)size);

  snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
  fyd = fy_document_build_from_file(&cfg, path);

out:
  if (fd >= 0)
    close(fd);
  fy_document_destroy(fyd);
}

/*
 * The fy_generic_* value-model subsystem (src/generic) has no other
 * entry point in this harness - build a generic document straight off the
 * parser's event stream, mirroring test_document_builder() but for the
 * generic API instead of the document-tree API.
 */
void test_generic_document_builder(struct flags_t *flags, const char *data, size_t size) {
  struct fy_parser *fyp = NULL;
  struct fy_generic_builder *gb = NULL;
  struct fy_generic_document_builder *fygdb = NULL;
  struct fy_generic_iterator *fygi = NULL;
  struct fy_parse_cfg cfg = { .flags = flags->parse_flags };
  fy_generic fyg;

  fyp = fy_parser_create(&cfg);
  CHECK(fyp);

  int rc = fy_parser_set_string(fyp, data, size);
  CHECK(rc == 0);

  gb = fy_generic_builder_create(NULL);
  CHECK(gb);

  /*
   * fy_generic_document_builder_create_on_parser() (fy-generic-docbuilder.c)
   * is broken for the ordinary "fresh parser" case: it unconditionally
   * seeds the builder via fy_generic_document_builder_set_in_document()
   * whenever fy_parser_get_document_state(fyp) is non-NULL, which happens
   * even before a single event has been pumped - that pre-seeds a bogus
   * "already inside a document" state that then makes the real
   * load_document() loop below silently process zero documents for every
   * input (confirmed with FYGDBF_TRACE: the seeded run never even emits
   * +STR). Building the same cfg by hand and calling
   * fy_generic_document_builder_create() directly - skipping the buggy
   * pre-seed - works correctly, so that's what's used here.
   */
  struct fy_generic_document_builder_cfg gdb_cfg = {0};
  gdb_cfg.parse_cfg = cfg;
  gdb_cfg.gb = gb;
  gdb_cfg.flags = FYGDBF_DEFAULT;
  if (flags->parse_flags & FYPCF_KEEP_COMMENTS)
    gdb_cfg.flags |= FYGDBF_KEEP_COMMENTS;
  if (flags->parse_flags & FYPCF_CREATE_MARKERS)
    gdb_cfg.flags |= FYGDBF_CREATE_MARKERS;
  if (flags->parse_flags & FYPCF_KEEP_STYLE)
    gdb_cfg.flags |= FYGDBF_KEEP_STYLE;
  fygdb = fy_generic_document_builder_create(&gdb_cfg);
  CHECK(fygdb);

  while (fy_generic_is_valid(fyg = fy_generic_document_builder_load_document(fygdb, fyp))) {

    /* inspection / accessors (fy-generic.c) */
    {
      fy_generic_get_type(fyg);
      fy_generic_get_anchor(fyg);
      fy_generic_get_tag(fyg);
      fy_generic_get_diag(fyg);
      fy_generic_get_marker(fyg);
      fy_generic_get_style(fyg);
      fy_generic_get_node_style(fyg);
      fy_generic_get_scalar_style(fyg);
      fy_generic_get_collection_style(fyg);
      fy_generic_get_comment(fyg, fycp_top);
      fy_generic_get_comment(fyg, fycp_right);
      fy_generic_get_comment(fyg, fycp_bottom);
      fy_generic_has_comments(fyg);
      free(fy_generic_get_comments(fyg)); /* caller-owned */
      fy_generic_compare(fyg, fyg);
      fy_generic_compare_out_of_place(fyg, fyg);

      struct fy_generic_storage_stats stats = {0};
      fy_generic_calc_storage_stats(fyg, size, &stats);

      uint8_t sigbuf[FY_BLAKE3_OUT_LEN];
      fy_generic_signature(fyg, FYGSF_CONTENT_ONLY, sigbuf);
      fy_generic_signature(fyg, FYGSF_WITH_INDIRECTS, sigbuf);

      fy_generic_dump_primitive(null_fp, 0, fyg);
    }

    /* collection accessors (fy-generic.c) */
    {
      size_t count = 0;
      fy_generic_collection_get_items(fyg, &count);
      fy_generic_sequence_resolve(fyg);
      fy_generic_sequence_resolve_outofplace(fyg);
      fy_generic_mapping_resolve(fyg);
      fy_generic_mapping_resolve_outofplace(fyg);
      fy_generic_mapping_get_pairs(fyg, &count);
      fy_generic_mapping_get_items(fyg, &count);
    }

    /* generic event iterator (fy-generic-iter.c) */
    {
      fygi = fy_generic_iterator_create();
      if (fygi) {
        fy_generic_iterator_generic_start(fygi, fyg);
        fy_generic fygv;
        while (fy_generic_is_valid(fygv = fy_generic_iterator_generic_next(fygi)))
          fy_generic_get_type(fygv);
        fy_generic_iterator_get_error(fygi);
        fy_generic_iterator_destroy(fygi);
        fygi = NULL;
      }
    }

    /* builder-backed collection ops (fy-generic-op.c) */
    {
      fy_generic str1 = fy_gb_string_size_create_out_of_place(gb, data, size);
      fy_generic num  = fy_gb_int_type_create_out_of_place(gb, (long long)size);
      fy_generic key  = fy_gb_string_create_out_of_place(gb, "k");

      fy_generic seq = fy_gb_create_sequence(gb, fyg, str1, num);
      seq = fy_gb_append(gb, seq, fyg);
      seq = fy_gb_insert(gb, seq, 0, str1);
      seq = fy_gb_replace(gb, seq, 0, fyg);
      fy_generic rseq = fy_gb_reverse(gb, seq);
      fy_gb_contains(gb, seq, fyg);
      fy_gb_concat(gb, seq, rseq);
      fy_gb_unique(gb, seq);

      fy_generic map = fy_gb_create_mapping(gb, key, fyg);
      map = fy_gb_assoc(gb, map, key, str1);
      fy_gb_keys(gb, map);
      fy_gb_values(gb, map);
      fy_gb_items(gb, map);
      fy_gb_get_at_path(gb, map, key);
      fy_gb_set_at_path(gb, map, key, fyg);
      fy_gb_merge(gb, map, map);
      fy_gb_disassoc(gb, map, key);
      fy_gb_delete_at_path(gb, map, key);
    }
  }

out:
  fy_generic_iterator_destroy(fygi);
  fy_generic_document_builder_destroy(fygdb);
  fy_generic_builder_destroy(gb);
  fy_parser_destroy(fyp);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size <= sizeof(uint32_t)) return 0;

  struct flags_t _flags = {0};
  struct flags_t *flags = &_flags;
  uint32_t seed = *(uint32_t*)data;
  setup_flags(seed, flags);
  data += sizeof(uint32_t);
  size -= sizeof(uint32_t);

  #define BRANCH(func) T(func);
  #define BRANCH2(func) T2(func);

  BRANCH(test_parse_with_flags);
  BRANCH(test_parse_path);
  BRANCH(test_scanf);
  BRANCH(test_fy_path_expr_build_from_string);
  BRANCH(test_fy_parser_parse);
  BRANCH(test_mapping_operations);
  BRANCH(test_fy_node_build_from_string);
  BRANCH(test_fy_node_set_anchor);
  BRANCH(test_token_comments);
  BRANCH(test_path_exec);
  BRANCH(test_document_builder);
  BRANCH(test_mapping_operations_extended);
  BRANCH(test_document_insert_at);
  BRANCH(test_parser_checkpoint_rollback);
  BRANCH(test_reflection_type_lookup);
  BRANCH(test_reflection_type_context_entry_meta);
  BRANCH(test_reflection_walk_types);

  BRANCH(test_reflection_c);

  BRANCH2(test_fy_node_build_from_fp);
  BRANCH2(test_fy_parser_parse_fp);
  BRANCH2(test_parse_with_flags_fp);
  BRANCH2(test_reflection_packed_blob);
  BRANCH2(test_parse_from_file);
  BRANCH2(test_generic_document_builder);

  if (__builtin_expect(tc_filter != NULL, 0) && !tc_filter_matched) {
    fprintf(stderr, "TC=%s does not name any test case\n", tc_filter);
    exit(1);
  }

  return 0;
}

#if defined REPRODUCER

#define CONCAT2(a, b) a##b
#define CONCAT(a, b) CONCAT2(a, b)

#define RR(nr,artifact_path) R(nr,artifact_path,read_artifact_raw)
#define RA(nr,artifact_path) R(nr,artifact_path,read_artifact)

#define R(nr,artifact_path,read_artifact_func) \
int CONCAT(vc, nr)() { \
  char *data = NULL; \
  size_t n = read_artifact_func(artifact_path, &data); \
  if (n > 0 && data) { \
    struct flags_t _flags = {0}; \
    struct flags_t *flags = &_flags; \
    uint32_t seed = *(uint32_t*)data; \
    setup_flags(seed, flags); \
    char* flags_t_str = flags_to_struct_string(flags); \
    printf("RF(%d,\ntest_func,\n(&(struct flags_t)%s),\n\"", nr, flags_t_str); \
    size_t data_size = n - sizeof(uint32_t); \
    char *abuf = malloc(data_size * 4 + 1); \
    sprintf_artifact_as_hexstr(abuf, data_size * 4 + 1, data + sizeof(uint32_t), data_size); \
    printf("%s\",\n%zu\n)\n", abuf, data_size); \
    printf("\n\n"); \
    printf("char *data = \"%s\";\n", abuf); \
    printf("%s(&(struct flags_t)%s,data,sizeof(data));\n\n\n", "test_func", flags_t_str); \
    free(abuf); \
    LLVMFuzzerTestOneInput((const uint8_t *)data, n); \
    munmap(data, n); \
  } \
  return n > 0; \
}

#define RF(nr,func,flags,data,n) \
int CONCAT(tc, nr)() { \
  func(flags, data, n); \
  return 0; \
}

#define ARTIFACTS "/home/rivit/workspace/fuzzing/projects/fuzz/libfyaml/artifacts/"

/*
 * One group per finding: the RR() that re-runs the on-disk artifact and
 * prints a fresh RF(), and the RF() it printed - `fuzz2 vc<n>` harvests,
 * `fuzz2 tc<n>` replays without needing the artifact file.
 */

/* gh#330 report2.md - fy_type_info_prefixless_name() NULL deref
 * https://github.com/pantoniou/libfyaml/issues/330
 */
RR(1, ARTIFACTS "id:000012,sig:06,src:000306,time:260652,execs:4799731,op:havoc,rep:15")
RF(1,
test_reflection_c,
(&(struct flags_t){
  .parse_flags = FYPCF_QUIET | FYPCF_COLLECT_DIAG | FYPCF_RESOLVE_DOCUMENT | FYPCF_DISABLE_MMAP_OPT | FYPCF_DISABLE_RECYCLING | FYPCF_KEEP_COMMENTS | FYPCF_DISABLE_ACCELERATORS | FYPCF_DISABLE_BUFFERING | FYPCF_SLOPPY_FLOW_INDENTATION | FYPCF_PREFER_RECURSIVE | FYPCF_YPATH_ALIASES | FYPCF_CREATE_MARKERS | FYPCF_RELAXED_FLOW_DOC | FYPCF_DEFAULT_VERSION_1_3 | FYPCF_JSON_FORCE,
  .emitter_flags = FYECF_STRIP_TAGS | FYECF_STRIP_DOC | FYECF_NO_ENDING_NEWLINE | FYECF_STRIP_EMPTY_KV | FYECF_INDENT_DEFAULT | FYECF_WIDTH_DEFAULT | FYECF_MODE_JSON_COMPACT | FYECF_DOC_START_MARK_OFF | FYECF_DOC_END_MARK_AUTO | FYECF_VERSION_DIR_OFF | FYECF_TAG_DIR_ON,
  .extended_emitter_flags = FYEXCF_COLOR_FORCE | FYEXCF_EXTENDED_INDICATORS | FYEXCF_INDENTED_SEQ_IN_MAP,
  .node_walk_flags = FYNWF_PTR_JSON | FYNWF_PTR_RELJSON | FYNWF_PTR_YPATH,
  .path_parse_flags = FYPPCF_DISABLE_ACCELERATORS,
  .node_style = FYNS_DOUBLE_QUOTED,
  .primitive_type = "unsigned long long",
  .type_info_flags = FYTIF_CONST | FYTIF_INCOMPLETE | FYTIF_UNRESOLVED | FYTIF_MAIN_FILE | FYTIF_SYSTEM_HEADER,
  .cgen_flag = FYCGF_INDENT_TAB | FYCGF_COMMENT_YAML
}),
"\x46\x59\x50\x47\x3d\xeb\x02\x00\x00\x00\x00\x00\x00\x1f\x00\x0e\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x0f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x80\x00\x04\x5e\x18\xf9\xd0\x00\x00\x00\x00\x03\x79\x01\x00\x00\x01\x00\x76\x76\x76\x76\xff\xff\x00\x00\x76\x75\x00\xe3\x1f\xff\x00\x00\x7f\xff\x41\x00\x00\x0d\xff\x20\xff\x60\xff\x7f\x36\x2b\x48\x48\x48\x48\xff\x66\x00\x41\x41\x00\x64\x00\xf5\x00\xbf\xbf\xbf\xbf\x68\x95\x95\x95\x95\x95\x35\x95\x95\x95\x95\x95\x91\x00\x10\x35\x35\x34\x35\x35\x35\x33\x00\x01\x35\x35\x35\x35\x7a\x7d\x65\x00\x00\x00\x68\x63\x75\x48\x35\x35\x35\x35\x00\xf5\x80\xff\x35\x35\x35\x1e\x35\x01\x00\x25\xbf\x01\xff\x00\x47\x55\x00\xf5\x80\x00\x35\x34\x3d\x35\x35\x35\x25\x35\x36\x29\xf3\x35\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x16\x35\x35\x35\x95\x95\x95\x95\x00\x10\x95\x95\x95\x95\x95\x95\x95\x35\x35\x35\x35\xf5\x7c\x35\x35\x35\x36\x19\x35\x35\xf5\x80\x00\xf5\x33\x33\x00\x01\x53\x35\x35\x35\x35\x27\x35\xd7\xe5\xdf\xf5\xf5\xf5\x34\x68\x00\x80\xff\xff\x15\x48\x4a\x69\x48\x48\xff\x00\xbf\xbf\x29\x34\x33\x00\x09\x35\x35\x00\x00\x00\x80\xbf\xfa\x68\x01\x00\x68\x68\xfa\xe6\xfa\x68\x01\x00\x68\x68\x95\x95\x95\x95\x95\x10\x95\x95\x95\x95\x95\x95\x95\x35\x35\x35\x34\x35\x35\x35\x33\x00\x01\x35\x35\x35\x35\x7f\xff\x00\x00\x00\x00\x00\x00\x17\x00\x00\xff\xff\xff\xdd\x00\x00\x00\x00\x00\x00\x00\x00\x2d\xeb\x00\x64\x00\x00\x00\x77\x01\x34\x3d\x3d\x01\x3d\x3d\x3d\x5c\x3d\x3e\xc2\x3d\x3d\x3d\x1f\x3d\x3d\x3d\x3d\x3d\x3d\x3d\x3d\x3d\x3d\x3d\x3d\x00\x00\x00\x00\x21\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x48\x5b\xff\x00\xbf\xbf\xb9\xbf\xbf\xbf\x20\x00\x00\x41\x41\x41\x7a\x64\x35\x35\xfc\x35\x50\x42\x00\x01\x01\x01\x01\x01\x00\x00\x00\x34\x68\x68\x75\x7a\x69\x35\x35\x35\x1c\x00\x80\x35\x0f\x8a\x35\x35",
488
)

/* gh#331 report3.md - fy_type_info_prefixless_name() heap overread
 * https://github.com/pantoniou/libfyaml/issues/331
 */
RR(2, ARTIFACTS "id:000234,sig:06,src:007401,time:30040285,execs:55948756,op:havoc,rep:4")
RF(2,
test_reflection_c,
(&(struct flags_t){
  .parse_flags = FYPCF_QUIET | FYPCF_DISABLE_MMAP_OPT | FYPCF_DISABLE_BUFFERING | FYPCF_SLOPPY_FLOW_INDENTATION | FYPCF_PREFER_RECURSIVE | FYPCF_ALLOW_DUPLICATE_KEYS | FYPCF_CREATE_MARKERS | FYPCF_KEEP_STYLE | FYPCF_RELAXED_FLOW_DOC | FYPCF_DEFAULT_VERSION_1_1 | FYPCF_JSON_AUTO,
  .emitter_flags = FYECF_SORT_KEYS | FYECF_STRIP_DOC | FYECF_NO_ENDING_NEWLINE | FYECF_STRIP_EMPTY_KV | FYECF_EXTENDED_CFG | FYECF_INDENT_DEFAULT | FYECF_WIDTH_DEFAULT | FYECF_MODE_ORIGINAL | FYECF_DOC_START_MARK_ON | FYECF_DOC_END_MARK_AUTO | FYECF_VERSION_DIR_AUTO | FYECF_TAG_DIR_ON,
  .extended_emitter_flags = FYEXCF_COLOR_NONE | FYEXCF_INDENTED_SEQ_IN_MAP | FYEXCF_PRESERVE_FLOW_LAYOUT,
  .node_walk_flags = FYNWF_PTR_JSON | FYNWF_PTR_RELJSON | FYNWF_PTR_YPATH,
  .path_parse_flags = 0,
  .node_style = FYNS_FLOW,
  .primitive_type = "long long",
  .type_info_flags = FYTIF_VOLATILE | FYTIF_RESTRICT | FYTIF_ELABORATED | FYTIF_ANONYMOUS | FYTIF_ANONYMOUS_RECORD_DECL | FYTIF_UNRESOLVED,
  .cgen_flag = FYCGF_INDENT_TAB | FYCGF_COMMENT_YAML
}),
"\x46\x59\x50\x47\x66\x00\x00\x00\x00\x00\x00\x00\x13\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x54\x00\x00\x00\x00\x00\x00\x01\x73\x00\x00\x00\x00\x00\x00\x00\x47\x00\x00\x00\x00\x00\x00\x00\x66\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xfb\x02\x34\x80\x00\x00\x00\x35\x35\x16\x16\x16\x16\x16\x16\x16\x16\x16\x16\x16\x16\xaf\x16\x16\x16\x16\x16\x16\x16\x16\x16\x16\x16\x16\x16\x16\x16\x16\x16\x16\x16\x16\x16\x16\x16\x16\x16\x16\xb5\xb5\xb5\xb5\xb5\xb5\xb5\xb5\xb5\xb5\xb5\xb5\xb5\xb5\xb5\xb5\xb5\xb5\xb5\xb5\xb5\xb5\xb5\xb5\xb5\xb5\xb5\xb5\xb5\xb5\xb5\xb5\xb5\x7e\x7e\x7e\x7e\x7e\x7e\x7e\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x6a\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x15\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x74\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x8b\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x74\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x5a\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x67\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x20\x00\x75\x75\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\xff\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x0a\x0a\x0a\x0a\x7c\x0d\x0a\x0a\x0a\x2d\x2d\x2d\xf5\xad\xad\x85\x52\x7a\x35\x31\x35\x35\x35\x00\x00\x68\x5c\x41\x41\xc3\x47\x66\x66\x35\x66\x35\x35\xca\x35\x31\x76\x75\x00\x00\x7f\xff\x35\x35\xdd\xdd\xdd\x00\x02\x00\x00\xdd\x00\x00\x00\x00\x54\x00\x00\x00\x00\x00\x00\x01\x73\x00\x00\x00\x00\x00\x00\x00\x47\x00\xff\x00\x00\x00\x00\x00\x66\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xfb\x02\x34\x80\x00\x00\x00\x35\x35\x16\x16\x16\x16\x16\x16\x16\x65\x65\x65\x65\x65\x6e\x6e\x6e\x6e\x6e\x6e\x6e\x6e\x6e\x6e\x6e\x6e\x6e\x6e\x6e\x6e\x6e\x6e\x6e\x6e\x6e\x6e\x6e\x6e\x6e\x6e\x6e\x6e\x6e\x6e\x6e\x65\x65\x65\x65\x65\x65\x64\x65\x66\x65\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x65\x65\x65\x65\x65\x65\x65\x65\x65\x65\x65\x65\x65\x65\x65\x65\x65\x65\x65\x65\x65\x65\x65\x65\x65\x65\x65\x65\x36\x35\x35\x31\x35\x35\x35\x00\x00\x68\x41\x41\x41\xc3\x47\x41\x50\x66\x7a\x68\x68\x8a\x7a\x77\x65\x00\xff\x00\x68\x68\x75",
843
)

/* gh#332 report4.md - fy_decl_p_from_id() signed overflow
 * https://github.com/pantoniou/libfyaml/issues/332
 */
RR(3, ARTIFACTS "id:000022,sig:06,src:000432,time:1267062,execs:19265557,op:havoc,rep:4")
RF(3,
test_reflection_c,
(&(struct flags_t){
  .parse_flags = FYPCF_QUIET | FYPCF_DISABLE_MMAP_OPT | FYPCF_DISABLE_BUFFERING | FYPCF_SLOPPY_FLOW_INDENTATION | FYPCF_PREFER_RECURSIVE | FYPCF_ALLOW_DUPLICATE_KEYS | FYPCF_CREATE_MARKERS | FYPCF_KEEP_STYLE | FYPCF_RELAXED_FLOW_DOC | FYPCF_DEFAULT_VERSION_1_1 | FYPCF_JSON_AUTO,
  .emitter_flags = FYECF_SORT_KEYS | FYECF_STRIP_DOC | FYECF_NO_ENDING_NEWLINE | FYECF_STRIP_EMPTY_KV | FYECF_EXTENDED_CFG | FYECF_INDENT_DEFAULT | FYECF_WIDTH_DEFAULT | FYECF_MODE_ORIGINAL | FYECF_DOC_START_MARK_ON | FYECF_DOC_END_MARK_AUTO | FYECF_VERSION_DIR_AUTO | FYECF_TAG_DIR_ON,
  .extended_emitter_flags = FYEXCF_COLOR_NONE | FYEXCF_INDENTED_SEQ_IN_MAP | FYEXCF_PRESERVE_FLOW_LAYOUT,
  .node_walk_flags = FYNWF_PTR_JSON | FYNWF_PTR_RELJSON | FYNWF_PTR_YPATH,
  .path_parse_flags = 0,
  .node_style = FYNS_FLOW,
  .primitive_type = "long long",
  .type_info_flags = FYTIF_VOLATILE | FYTIF_RESTRICT | FYTIF_ELABORATED | FYTIF_ANONYMOUS | FYTIF_ANONYMOUS_RECORD_DECL | FYTIF_UNRESOLVED,
  .cgen_flag = FYCGF_INDENT_TAB | FYCGF_COMMENT_YAML
}),
"\x46\x59\x50\x47\x66\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x47\x00\x00\x00\x00\x00\x00\x01\x73\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xfb\x01\x35\x80\x02\x00\x00\x35\x35\x35\x35\xdd\xd9\x5e\x5e\x5e\x5e\x5e\x5e\x5e\x5e\x5e\x5e\x5e\x5e\x5e\x5e\x5e\x5e\x5e\x5e\x5e\x5e\x5e\x5e\x5e\x5e\x5e\x5e\x5e\x5e\x5e\x5e\x5e\x5e\x5e\x5e\x5e\x5e\x5e\x5e\x5e\x5e\x5e\x5e\x5e\x80\x00\x00\x00\x66\x66\x64\x41\x66\x66\x41\x68\x00\x00\x31\x35\x35\x35\x00\x90\x90\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x43\x41\x41\x41\x41\x02\x00\x41\x41\x41\x41\x41\x41\x41\x35\x00\x00\x68\x5c\x41\x41\xc3\x47\x66\x66\x35\x66\x66\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x45\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x4b\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x34\x41\x41\x41\x41\x41\x41\x41\x41\x41\x4f\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\xb1\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x42\x27\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x7e\xb2\x90\x35\x35\x38\x35\xad\xad\xad\xad\x65\x52\x7a\x35\x31\x35\x35\x34\xed\x00\x68\x5c\x50\x46\x59\x50\x66\x41\x68\x00\x00\x31\x35\x35\x35\x00\x00\x68\x5c\x20\x41\xc3\x47\x66\x59\x35\x66\x66\x66\x6a\xff\xff\x41\xff\x65\x36\x35\x35\x31\x35\x35\x35\x00\x00\x68\x41\x41\x41\xc3\x47\x41\x50\x66\x7a\x68\x68\x8a\x7a\x77\x65\x00\x00\x00\x68\x68\x75",
497
)

/* gh#333 report5.md - fy_type_p_from_id() signed overflow
 * https://github.com/pantoniou/libfyaml/issues/333
 */
RR(4, ARTIFACTS "id:000034,sig:06,src:000496,time:1270369,execs:15020741,op:havoc,rep:14")
RF(4,
test_reflection_c,
(&(struct flags_t){
  .parse_flags = FYPCF_QUIET | FYPCF_COLLECT_DIAG | FYPCF_RESOLVE_DOCUMENT | FYPCF_DISABLE_MMAP_OPT | FYPCF_DISABLE_RECYCLING | FYPCF_KEEP_COMMENTS | FYPCF_DISABLE_ACCELERATORS | FYPCF_DISABLE_BUFFERING | FYPCF_SLOPPY_FLOW_INDENTATION | FYPCF_PREFER_RECURSIVE | FYPCF_YPATH_ALIASES | FYPCF_CREATE_MARKERS | FYPCF_RELAXED_FLOW_DOC | FYPCF_DEFAULT_VERSION_1_3 | FYPCF_JSON_FORCE,
  .emitter_flags = FYECF_STRIP_TAGS | FYECF_STRIP_DOC | FYECF_NO_ENDING_NEWLINE | FYECF_STRIP_EMPTY_KV | FYECF_INDENT_DEFAULT | FYECF_WIDTH_DEFAULT | FYECF_MODE_JSON_COMPACT | FYECF_DOC_START_MARK_OFF | FYECF_DOC_END_MARK_AUTO | FYECF_VERSION_DIR_OFF | FYECF_TAG_DIR_ON,
  .extended_emitter_flags = FYEXCF_COLOR_FORCE | FYEXCF_EXTENDED_INDICATORS | FYEXCF_INDENTED_SEQ_IN_MAP,
  .node_walk_flags = FYNWF_PTR_JSON | FYNWF_PTR_RELJSON | FYNWF_PTR_YPATH,
  .path_parse_flags = FYPPCF_DISABLE_ACCELERATORS,
  .node_style = FYNS_DOUBLE_QUOTED,
  .primitive_type = "unsigned long long",
  .type_info_flags = FYTIF_CONST | FYTIF_INCOMPLETE | FYTIF_UNRESOLVED | FYTIF_MAIN_FILE | FYTIF_SYSTEM_HEADER,
  .cgen_flag = FYCGF_INDENT_TAB | FYCGF_COMMENT_YAML
}),
"\x46\x59\x50\x47\x3e\x00\x02\x00\x01\x00\x00\x00\x00\x1f\x00\x0e\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x0f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\x00\xff\xff\x80\x00\x04\x41\x50\x5e\x18\xf9\xf0\x00\x80\x00\x00\x03\x79\x01\x00\x00\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x06\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x8e\x41\x41\x41\x72\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x58\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x50\x41\x30\x41\x41\x41\x41\x41\x41\x41\x41\x42\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x7e\xb2\x90\x35\x35\x38\x35\xad\xad\xad\xad\x65\x52\x7a\x35\x31\x35\x35\x34\xed\x00\x68\x5c\x41\x41\xc3\x47\x66\x66\x41\x50\x46\x00\x00\xff\xff\x68\x00\x00\x31\x35\x35\x35\x00\x00\x68\x5c\x20\x41\xc3\x47\x7a\x00\x00\x00\x01\x66\x6a\xff\xff\x2e\xff\x65\x36\x35\x35\x31\x35\x35\x35\x00\x00\x68\x41\x41\x40\xc3\x47\x41\x50\x66\x7a\x68\x58\x8a\x7a\x77\x65\x00\x20\x00\x68\x68\x75",
397
)

/* gh#334 report6.md - fy_type_generate_c_declaration() stack overread
 * https://github.com/pantoniou/libfyaml/issues/334
 */
RR(5, ARTIFACTS "id:000306,sig:06,src:003577,time:49519273,execs:66794732,op:havoc,rep:8")
RF(5,
test_reflection_c,
(&(struct flags_t){
  .parse_flags = FYPCF_QUIET | FYPCF_DISABLE_MMAP_OPT | FYPCF_DISABLE_BUFFERING | FYPCF_SLOPPY_FLOW_INDENTATION | FYPCF_PREFER_RECURSIVE | FYPCF_ALLOW_DUPLICATE_KEYS | FYPCF_CREATE_MARKERS | FYPCF_KEEP_STYLE | FYPCF_RELAXED_FLOW_DOC | FYPCF_DEFAULT_VERSION_1_1 | FYPCF_JSON_AUTO,
  .emitter_flags = FYECF_SORT_KEYS | FYECF_STRIP_DOC | FYECF_NO_ENDING_NEWLINE | FYECF_STRIP_EMPTY_KV | FYECF_EXTENDED_CFG | FYECF_INDENT_DEFAULT | FYECF_WIDTH_DEFAULT | FYECF_MODE_ORIGINAL | FYECF_DOC_START_MARK_ON | FYECF_DOC_END_MARK_AUTO | FYECF_VERSION_DIR_AUTO | FYECF_TAG_DIR_ON,
  .extended_emitter_flags = FYEXCF_COLOR_NONE | FYEXCF_INDENTED_SEQ_IN_MAP | FYEXCF_PRESERVE_FLOW_LAYOUT,
  .node_walk_flags = FYNWF_PTR_JSON | FYNWF_PTR_RELJSON | FYNWF_PTR_YPATH,
  .path_parse_flags = 0,
  .node_style = FYNS_FLOW,
  .primitive_type = "long long",
  .type_info_flags = FYTIF_VOLATILE | FYTIF_RESTRICT | FYTIF_ELABORATED | FYTIF_ANONYMOUS | FYTIF_ANONYMOUS_RECORD_DECL | FYTIF_UNRESOLVED,
  .cgen_flag = FYCGF_INDENT_TAB | FYCGF_COMMENT_YAML
}),
"\x46\x59\x50\x47\x66\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x54\x00\x00\x00\x00\x00\x00\x01\x73\x00\x00\x00\x00\x00\x00\x00\x47\x00\x00\x00\x00\x00\x00\x00\x66\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xfb\x02\x34\x80\x00\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x16\x16\xb5\xb5\xb5\xb5\xb5\xb5\xb5\xb5\xb5\xb5\xb5\xb5\xb5\xb5\xb5\xb5\xb5\xb5\xb5\xb5\xb5\xb5\xb5\xb5\xb5\xb5\xb5\xb5\xb5\xb5\xb5\xb5\xb5\x7e\x7e\x7e\x7e\x7e\x16\x7e\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x75\x75\x75\x75\x95\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\xe8\x03\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x74\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x28\x0a\x00\x10\x00\x00\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x08\x0a\x0a\x0a\x0a\x0a\x0d\x82\x00\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x24\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x6b\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x00\x00\x35\x35\x16\x16\x16\x7e\x16\x16\x16\x16\x16\x16\x7e\x7e\x7e\x7e\x7e\x7e\x7e\x7e\x7e\x7e\x7e\x7e\x7e\x7e\x7e\x7e\x7e\xfe\x7e\x7e\x7e\x7e\x7e\x7e\x7e\x7e\x7e\x7e\x7e\x7e\x7e\x7e\x7e\x7e\x7e\x7e\x7e\x7e\x7e\x7e\x7e\x7e\x64\x7e\x7e\x7e\x7e\x7e\x7e\x7e\x7e\x7e\x7e\x7e\x7e\x7e\x7e\x7e\x7e\x7e\x7e\x7e\x7e\x7e\x7e\x7e\x7e\x7e\x7e\x7e\x7e\x7e\x7e\x7e\x7e\x7e\x7e\x7e\x7e\x7e\x7e\x7e\x7e\x7e\x7e\x7e\x7e\x84\x15\x15\x59\x59\x59\x59\x59\x59\x59\x59\x59\x59\x59\x59\x59\x59\x59\x59\x59\x59\x59\x59\x59\x59\x59\x59\x59\x59\x59\x59\x59\x59\x59\x59\x59\x59\x59\x59\x59\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x89\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x8a\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x59\x59\x59\x59\x59\x59\x59\x59\x59\x59\x59\x59\x59\x59\x59\x59\x59\x59\x5a\x59\x59\x59\x59\x59\x59\x59\x59\x59\x59\x59\x59\x59\x59\x59\x00\x00\x00\x20\x59\x59\x59\x59\x59\x59\x59\x59\x59\x59\x59\x59\x59\x59\x59\x59\x59\x59\x15\x15\x15\x15\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x00\x04\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x39\x30\x33\x31\x37\x32\x38\x39\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x66\x66\x41\x50\x46\x00\x00\x66\x41\x68\x00\x00\x31\x35\x35\x35\x00\x00\x68\x5c\x20\x41\xc3\x47\x66\x66\x35\x66\x66\x66\x6a\xff\xff\x41\xff\x65\x65\x65\x65\x65\x65\x65\x65\x65\x65\x65\x65\x65\x65\x65\x65\x65\x65\x65\x65\x65\x65\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x34\x4e\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x79\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\x75\xb9\xb9\xb9\xb9\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x20\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x4b\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x42\x42\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x00\xeb\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x90\x90\x90\xb2\x90\x35\x35\x38\x35\xad\xad\xad\xad\x65\x52\x7a\x35\x31\x35\x35\x35\x00\x00\x68\x5c\x41\x41\xc3\x47\x66\x66\x35\x66\x35\x35\xca\x35\x31\x76\x75\x00\x00\x7f\xff\x35\x35\xdd\xdd\xdd\x00\x02\x00\x00\xdd\xc1\xdd\xdd\xdd\xa6\x66\x66\x66\x35\x41\x50\x46\x59\x50\x47\x66\x00\x41\x41\x41\x7a\x41\xbe\x50\x64\x41\x66\x66\x41\x68\x00\x00\x68\x68\x75\x7a\x7d\x65\x00\x00\x00\x68\x41\x41\x41\xc3\x47\x66\x66\x66\x6a\xff\xff\x41\xff\x65\x65\x65\x65\x65\x65\x65\x65\x65\x65\x65\x65\x65\x65\x65\x65\x65\x64\x65\x66\x65\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x65\x65\x65\x65\x65\x65\x65\x65\x65\x65\x65\x65\x65\x65\x65\x65\x65\x65\x65\x65\x65\x65\x65\x65\x65\x65\x65\x65\x36\x35\x35\x31\x35\x35\x35\x00\x00\x68\x41\x41\x41\xc3\x47\x41\x50\x66\x7a\x68\x68\x8a\x7a\x77\x65\x00\xff\x00\x68\x68\x75",
2370
)

/* gh#335 report7.md - fy_decl_create() strdup heap overread
 * https://github.com/pantoniou/libfyaml/issues/335
 */
RR(6, ARTIFACTS "id:000037,sig:06,src:000551,time:3885696,execs:39731922,op:havoc,rep:7")
RF(6,
test_reflection_c,
(&(struct flags_t){
  .parse_flags = FYPCF_QUIET | FYPCF_DISABLE_MMAP_OPT | FYPCF_DISABLE_BUFFERING | FYPCF_SLOPPY_FLOW_INDENTATION | FYPCF_PREFER_RECURSIVE | FYPCF_ALLOW_DUPLICATE_KEYS | FYPCF_CREATE_MARKERS | FYPCF_KEEP_STYLE | FYPCF_RELAXED_FLOW_DOC | FYPCF_DEFAULT_VERSION_1_1 | FYPCF_JSON_AUTO,
  .emitter_flags = FYECF_SORT_KEYS | FYECF_STRIP_DOC | FYECF_NO_ENDING_NEWLINE | FYECF_STRIP_EMPTY_KV | FYECF_EXTENDED_CFG | FYECF_INDENT_DEFAULT | FYECF_WIDTH_DEFAULT | FYECF_MODE_ORIGINAL | FYECF_DOC_START_MARK_ON | FYECF_DOC_END_MARK_AUTO | FYECF_VERSION_DIR_AUTO | FYECF_TAG_DIR_ON,
  .extended_emitter_flags = FYEXCF_COLOR_NONE | FYEXCF_INDENTED_SEQ_IN_MAP | FYEXCF_PRESERVE_FLOW_LAYOUT,
  .node_walk_flags = FYNWF_PTR_JSON | FYNWF_PTR_RELJSON | FYNWF_PTR_YPATH,
  .path_parse_flags = 0,
  .node_style = FYNS_FLOW,
  .primitive_type = "long long",
  .type_info_flags = FYTIF_VOLATILE | FYTIF_RESTRICT | FYTIF_ELABORATED | FYTIF_ANONYMOUS | FYTIF_ANONYMOUS_RECORD_DECL | FYTIF_UNRESOLVED,
  .cgen_flag = FYCGF_INDENT_TAB | FYCGF_COMMENT_YAML
}),
"\x46\x59\x50\x47\x66\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x54\x00\x00\x00\x00\x00\x00\x01\x73\x00\x00\x00\x00\x00\x00\x00\x47\x00\x00\x00\x00\x00\x00\x00\x66\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xfb\x02\x34\x80\x00\x00\x00\x35\x35\x35\x35\x35\x35\x35\x7e\x7e\x7e\x7e\x7e\x7e\x7e\x7e\x7e\x7e\x69\x7e\x7e\x7e\x7e\x7e\x7e\x7e\x7e\x7e\x7e\x7e\x7e\x7e\x7e\x7e\x7e\x7e\x7e\x7e\x7e\x7e\x7e\x7e\xb5\xb5\xb5\xb5\xb5\xb5\xb5\xb5\xb5\xb5\xb5\xb5\xb5\xb5\xb5\xb5\xb5\xb5\xb5\xb5\xb5\xb5\xb5\xb5\xb5\xb5\xb5\xb5\xb5\xb5\xb5\xb5\xb5\x7e\x7e\x7e\x7e\x7e\x7e\x7e\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x00\x64\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x12\x12\x12\x12\x12\x12\x12\x12\x12\x12\x12\x12\x12\x12\x12\x12\x12\x12\x12\x12\x12\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x65\x65\x65\x65\x65\x65\x65\x65\x65\x65\x65\x65\x65\x65\x65\x65\x65\x65\x65\x65\x65\x65\x65\x65\x66\x65\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x65\x65\x65\x65\x65\x65\x65\x65\x65\x65\x65\x65\x65\x65\x65\x65\x65\x65\x65\x65\x65\x65\x65\x65\x65\x65\x65\x65\x36\x35\x35\x31\x35\x35\x35\x00\x00\x68\x41\x41\x41\xc3\x47\x41\x50\x66\x7a\x68\x68\x8a\x7a\x77\x65\x00\xff\x00\x68\x68\x75",
611
)

/* gh#TBD report2.md - fy_token_iter_start() leaks the grown atom
 * iterator chunk array when an iterator is re-armed
 * https://github.com/pantoniou/libfyaml/issues/337
 */
RR(7, ARTIFACTS "leak-cc2c85b1ba82002dad6d4d8b2fbc525a7adbc2ae")
RF(7,
test_parse_with_flags,
(&(struct flags_t){
  .parse_flags = FYPCF_QUIET | FYPCF_DISABLE_ACCELERATORS | FYPCF_DISABLE_BUFFERING | FYPCF_YPATH_ALIASES | FYPCF_RELAXED_FLOW_DOC | FYPCF_KEEP_ANCHORS | FYPCF_ENABLE_CACHE | FYPCF_DEFAULT_VERSION_AUTO | FYPCF_JSON_AUTO,
  .emitter_flags = FYECF_STRIP_LABELS | FYECF_STRIP_EMPTY_KV | FYECF_INDENT_DEFAULT | FYECF_WIDTH_132 | FYECF_MODE_JSON | FYECF_DOC_START_MARK_ON | FYECF_DOC_END_MARK_OFF | FYECF_VERSION_DIR_AUTO | FYECF_TAG_DIR_AUTO,
  .extended_emitter_flags = FYEXCF_EXTENDED_INDICATORS | FYEXCF_INDENTED_SEQ_IN_MAP | FYEXCF_PRESERVE_FLOW_LAYOUT,
  .node_walk_flags = FYNWF_PTR_JSON | FYNWF_PTR_RELJSON | FYNWF_PTR_YPATH | FYNWF_URI_ENCODED,
  .path_parse_flags = FYPPCF_DISABLE_RECYCLING | FYPPCF_DISABLE_ACCELERATORS,
  .node_style = 4294967295,
  .primitive_type = "char",
  .type_info_flags = FYTIF_VOLATILE | FYTIF_ELABORATED | FYTIF_ANONYMOUS_DEP | FYTIF_UNRESOLVED | FYTIF_SYSTEM_HEADER,
  .cgen_flag = FYCGF_INDENT_TAB | FYCGF_COMMENT_RAW
}),
"\x27\x27\x27\x27\x27\x27\x27\x27\x27\x27\x27\x27\x27\x27\x27\x27\x27\x27\x27\x0a\x0a\x2d\x0a\x2a\x0a\x2d\x0a\x0a\x2d\x0a\x2d\x0a\x2d\x0a\x2d\x0a\x0a\x0a\x2d\x0a\x2d\x61\x0a\x3a\x2d\x27\x27\x27\x27\x27\x27\x27\x27\x27\x27\x27\x27\x27\x27\x27\x27\x27\x27\x27\x27\x27\x27\x27\x27\x27\x27\x27\x27\x27\x27\x27\x27\x27\x27\x27\x27\x27\x27\x27\x27\x27\x0a\x0a\x2d\x0a\x2a\x0a\x2d\x0a\x0a\x2d\x0a\x2d\x0a\x2d\x0a\x2d\x0a\x0a\x0a\x2d\x0a\x2d\x0a\x2d\x0a",
111
)

/* duplicate of gh#330 (see RR(1)) - second artifact hitting the same
 * fy_type_info_prefixless_name() NULL name: UBSan "applying non-zero offset 7
 * to null pointer" at fy-reflection.c:4035, then SEGV in fprintf()
 * https://github.com/pantoniou/libfyaml/issues/330
 */
RR(8, ARTIFACTS "id:000005,sig:06,src:024994,time:96350147,execs:91170280,op:havoc,rep:6")

RF(8,
test_reflection_c,
(&(struct flags_t){
  .parse_flags = FYPCF_COLLECT_DIAG | FYPCF_KEEP_COMMENTS | FYPCF_DISABLE_DEPTH_LIMIT | FYPCF_DISABLE_BUFFERING | FYPCF_SLOPPY_FLOW_INDENTATION | FYPCF_PREFER_RECURSIVE | FYPCF_ALLOW_DUPLICATE_KEYS | FYPCF_KEEP_STYLE | FYPCF_RELAXED_FLOW_DOC | FYPCF_ENABLE_CACHE | FYPCF_DEFAULT_VERSION_1_2 | FYPCF_JSON_NONE,
  .emitter_flags = FYECF_SORT_KEYS | FYECF_STRIP_TAGS | FYECF_INDENT_DEFAULT | FYECF_WIDTH_DEFAULT | FYECF_MODE_BLOCK | FYECF_DOC_START_MARK_AUTO | FYECF_DOC_END_MARK_ON | FYECF_VERSION_DIR_OFF | FYECF_TAG_DIR_ON,
  .extended_emitter_flags = FYEXCF_COLOR_NONE | FYEXCF_PRESERVE_FLOW_LAYOUT,
  .node_walk_flags = FYNWF_PTR_JSON | FYNWF_URI_ENCODED,
  .path_parse_flags = FYPPCF_QUIET | FYPPCF_DISABLE_RECYCLING | FYPPCF_DISABLE_ACCELERATORS,
  .node_style = FYNS_ANY,
  .primitive_type = "short",
  .type_info_flags = FYTIF_VOLATILE | FYTIF_ELABORATED | FYTIF_ANONYMOUS | FYTIF_INCOMPLETE,
  .cgen_flag = FYCGF_INDENT_TAB | FYCGF_COMMENT_RAW
}),
"\x46\x59\x50\x47\x7f\xe5\x01\x00\x00\x1f\x01\x01\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x01\x6e\x7b\x81\x81\x81\x81\x81\x81\xfe\xfe\xf0\xfd\xfe\xfe\xfe\xfe\xfe\xfe\xfe\xfe\xfe\x59\x90\x01\x00\x5c\x6e\x01\x01\x76\x5e\x5e\x58\x66\x66\x66\x66\x66\x66\x66\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xad\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\x5e\x66\x75\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcd\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\x20\x00\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\x01\x01\x01\x01\x01\x01\x01\x5c\x51\x44\x5c\x21\x21\x7a\x73\x21\xb8\xeb\x77\x01\x72\xb8\x00\x80\x9d\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x01\x01\x01\x01\x04\x01\x21\x01\x01",
472
)

int main(int argc, char **argv) {
  if (argc < 2) {
    printf("Usage: %s <testcase>\n", argv[0]);
    return 1;
  }
  void *handle = dlopen(NULL, RTLD_NOW);
  if (!handle) {
    printf("dlopen failed: %s\n", dlerror());
    return 1;
  }

  void *tc_handle = dlsym(handle, argv[1]);
  if (!tc_handle) {
    printf("dlsym failed: %s\n", dlerror());
    return 1;
  }
  dlclose(handle);
  return ((int (*)())tc_handle)();
}

#endif


// TODO: parse path moze #embed yamla jakiegos duzego i bez split + parse path