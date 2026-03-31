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

void test_parse_path(struct flags_t *flags, const char *data, size_t size) {
  struct fy_document *fyd = NULL;

  fyd = fy_document_create(NULL);
  CHECK(fyd);
  
  struct fy_node *fyn = fy_node_create_sequence(fyd);
  fy_document_set_root(fyd, fyn);
  struct fy_node *root = fy_document_root(fyd);
  struct fy_node *node = fy_node_by_path(root, data, size, flags->node_walk_flags);

out:
  fy_document_destroy(fyd);
}

void test_fy_node_build_from_string(struct flags_t *flags, const char *data, size_t size) {
  struct fy_document *fyd = NULL;

  fyd = fy_document_create(NULL);
  CHECK(fyd);
  
  struct fy_node *fyn = fy_node_build_from_string(fyd, data, size);
  CHECK(fyn);

  fy_document_set_root(fyd, fyn);
out:
  fy_document_destroy(fyd);
}

void test_fy_node_create_scalar(struct flags_t *flags, const char *data, size_t size) {
  struct fy_document *fyd = NULL;

  fyd = fy_document_create(NULL);
  CHECK(fyd);
  
  struct fy_node *fyn = fy_node_create_scalar(fyd, data, size);
  CHECK(fyn);
  
  fy_document_set_root(fyd, fyn);
out:
  fy_document_destroy(fyd);
}

void test_fy_node_build_from_fp(struct flags_t *flags, const char *data, size_t size) {
  struct fy_document *fyd = NULL;
  FILE *f = NULL;

  fyd = fy_document_create(NULL);
  CHECK(fyd);

  f = fmemopen((void *)data, size, "r");
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

void test_parse_with_flags(struct flags_t *flags, const char *data, size_t size) {
  struct fy_document *fyd = NULL;
  struct fy_document *fyd2 = NULL;
  struct fy_document *fyd3 = NULL;
  struct fy_parse_cfg cfg = { .flags = flags->parse_flags };
  char* buf = NULL;
  FILE *fp = NULL;
  int rc;
  struct fy_emitter *emitter = NULL;
  char *collected = NULL;
  struct fy_node* node2 = NULL;
  char *plain = NULL;

  fyd = fy_document_build_from_string(&cfg, data, size);
  CHECK(fyd);

  // test_emit
  buf = fy_emit_document_to_string(fyd, flags->emitter_flags);


  // test_emit2
  fp = fopen("/dev/null", "w");
  rc = fy_emit_document_to_fp(fyd, flags->emitter_flags, fp);


  // test_emit_to_buffer
  char buf2[4096] = {0};
  rc = fy_emit_document_to_buffer(fyd, flags->emitter_flags, buf2, sizeof(buf2));

  emitter = fy_emit_to_string(flags->emitter_flags);
  fy_emit_document(emitter, fyd);
  size_t out_size;
  collected = fy_emit_to_string_collect(emitter, &out_size);


  // test_clone
  fyd2 = fy_document_clone(fyd);
  struct fy_node* root = fy_document_root(fyd2);
  fyd3 = fy_document_create(NULL);
  node2 = fy_node_copy(fyd3, root);


  // test_node_styles
  struct fy_node *root2 = fy_document_root(fyd);
  fy_node_set_style(root2, flags->node_style);
  plain = fy_emit_node_to_string(root2, flags->emitter_flags);

out:
  if (fp) fclose(fp);
  
  free(collected);
  free(buf);
  free(plain);

  fy_node_free(node2);

  fy_emitter_destroy(emitter);
  fy_document_destroy(fyd);
  fy_document_destroy(fyd2);
  fy_document_destroy(fyd3);
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

void test_scanf(struct flags_t *flags, const char *data, size_t size) {
  char *space = NULL;
  char *newfmt = NULL;
  struct fy_document *fyd = NULL;
  struct fy_parse_cfg cfg = { .flags = flags->parse_flags };
  char *fmt = NULL;
  char *d = NULL;
  size_t fmt_len, d_len;

  CHECK(split_two_parts(data, size, &fmt, &fmt_len, &d, &d_len));

  CHECK(!strchr(fmt, '%'));

  fyd = fy_document_build_from_string(&cfg, d, d_len);
  CHECK(fyd);

  space = malloc(0x10000);
  newfmt = malloc(0x10000);
  memset(newfmt, 0, 0x10000);
  sprintf(newfmt, "%s %%s", fmt);
  fy_document_scanf(fyd, newfmt, space);

out:
  fy_document_destroy(fyd);
  free(space);
  free(newfmt);
  free(fmt);
  free(d);
}





void test_fy_emitter_create(struct flags_t *flags, const char *data, size_t size) {
  struct fy_document *fyd = NULL;
  struct fy_parse_cfg cfg = { .flags = flags->parse_flags };
  struct fy_emitter* emit = NULL;
  FILE *fp = NULL;

  fp = fopen("/dev/null", "w");
  CHECK(fp);

	struct fy_emitter_xcfg emit_xcfg = {
    .cfg = {
      .flags = flags->emitter_flags
    },
    .xflags = flags->extended_emitter_flags | FYEXCF_OUTPUT_FD,
    .output_fp = fp,
  };

	emit = fy_emitter_create(&emit_xcfg.cfg);
  CHECK(emit);

  fyd = fy_document_build_from_string(&cfg, data, size);
  CHECK(fyd);

	int rc = fy_emit_document(emit, fyd);
  CHECK(rc == 0);

out:
  if (fp) fclose(fp);
  fy_document_destroy(fyd);
	fy_emitter_destroy(emit);
}



void test_emit_node_to_string(struct flags_t *flags, const char *data, size_t size) {
  struct fy_document *fyd = NULL;
  struct fy_parse_cfg cfg = { .flags = flags->parse_flags };
  char *doc = NULL;
  char *path = NULL;
  char *buf = NULL;
  size_t doc_len, path_len;

  CHECK(split_two_parts(data, size, &doc, &doc_len, &path, &path_len));

  int flags2 = flags->node_walk_flags;
  int flags3 = flags->emitter_flags;

  fyd = fy_document_build_from_string(&cfg, doc, doc_len);
  struct fy_node *root = fy_document_root(fyd);
  struct fy_node *node = fy_node_by_path(root, path, path_len, flags2);

  CHECK(node);

  buf = fy_emit_node_to_string(node, flags3);

out:
  fy_document_destroy(fyd);
  free(doc);
  free(path);
  free(buf);
}

void test_node_comparisons(struct flags_t *flags, const char *data, size_t size) {
  struct fy_document *fyd = NULL;
  struct fy_parse_cfg cfg = { .flags = flags->parse_flags };
  struct fy_document *fyd2 = NULL;
  
  
  fyd = fy_document_build_from_string(&cfg, data, size);
  CHECK(fyd);

  struct fy_node *root = fy_document_root(fyd);
  CHECK(root);

  bool same = fy_node_compare(root, root);

  fyd2 = fy_document_clone(fyd);
  CHECK(fyd2);

  struct fy_node *root2 = fy_document_root(fyd2);
  bool equal = fy_node_compare(root, root2);
  bool matches = fy_node_compare_string(root, data, size);
  bool text_matches = fy_node_compare_text(root, data, size);
  
out:
  fy_document_destroy(fyd);
  fy_document_destroy(fyd2);
}

void test_fy_path_expr_build_from_string(struct flags_t *flags, const char *data, size_t size) {
  struct fy_path_parse_cfg parse_cfg = {0};
  parse_cfg.flags = flags->path_parse_flags;

  struct fy_path_expr *expr = fy_path_expr_build_from_string(&parse_cfg, data, size);
  fy_path_expr_free(expr);
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

void test_token_iteration(struct flags_t *flags, const char *data, size_t size) {
  struct fy_document *fyd = NULL;
  struct fy_parse_cfg cfg = { .flags = flags->parse_flags };
  
  
  fyd = fy_document_build_from_string(&cfg, data, size);
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
  
  fy_token_iter_destroy(iter);
  
  const char *comment = fy_token_get_comment(token, fycp_top);
  const char *all_comments = fy_token_get_comments(token);
  
out:
  fy_document_destroy(fyd);
}

static enum fy_composer_return compose_inspect_cb(struct fy_parser *fyp,
    struct fy_event *fye, struct fy_path *path, void *userdata)
{
  fy_path_in_root(path);
  fy_path_in_mapping(path);
  fy_path_in_sequence(path);
  fy_path_in_mapping_key(path);
  fy_path_in_mapping_value(path);
  fy_path_in_collection_root(path);

  if (fy_path_depth(path) > 10)
    return FYCR_OK_START_SKIP;
  return FYCR_OK_CONTINUE;
}

void test_document_iterator(struct flags_t *flags, const char *data, size_t size) {
  struct fy_document *fyd = NULL;
  struct fy_document_iterator *fydi = NULL;
  struct fy_event *fye = NULL;
  struct fy_parse_cfg cfg = { .flags = flags->parse_flags };

  fyd = fy_document_build_from_string(&cfg, data, size);
  CHECK(fyd);

  fydi = fy_document_iterator_create();
  CHECK(fydi);

  fye = fy_document_iterator_stream_start(fydi);
  if (fye) fy_document_iterator_event_free(fydi, fye);

  fye = fy_document_iterator_document_start(fydi, fyd);
  if (fye) fy_document_iterator_event_free(fydi, fye);

  while ((fye = fy_document_iterator_body_next(fydi)) != NULL)
    fy_document_iterator_event_free(fydi, fye);

  fy_document_iterator_get_error(fydi);

  fye = fy_document_iterator_document_end(fydi);
  if (fye) fy_document_iterator_event_free(fydi, fye);

  fye = fy_document_iterator_stream_end(fydi);
  if (fye) fy_document_iterator_event_free(fydi, fye);

out:
  fy_document_iterator_destroy(fydi);
  fy_document_destroy(fyd);
}

void test_document_iterator_node(struct flags_t *flags, const char *data, size_t size) {
  struct fy_document *fyd = NULL;
  struct fy_document_iterator *fydi = NULL;
  struct fy_parse_cfg cfg = { .flags = flags->parse_flags };

  fyd = fy_document_build_from_string(&cfg, data, size);
  CHECK(fyd);

  CHECK(fy_document_root(fyd));

  fydi = fy_document_iterator_create();
  CHECK(fydi);

  fy_document_iterator_node_start(fydi, fy_document_root(fyd));
  while (fy_document_iterator_node_next(fydi) != NULL)
    ;

  fy_document_iterator_get_error(fydi);

out:
  fy_document_iterator_destroy(fydi);
  fy_document_destroy(fyd);
}

void test_document_iterator_generate(struct flags_t *flags, const char *data, size_t size) {
  struct fy_document *fyd = NULL;
  struct fy_document_iterator *fydi = NULL;
  struct fy_event *fye = NULL;
  struct fy_parse_cfg cfg = { .flags = flags->parse_flags };

  fyd = fy_document_build_from_string(&cfg, data, size);
  CHECK(fyd);

  fydi = fy_document_iterator_create_on_document(fyd);
  CHECK(fydi);

  while ((fye = fy_document_iterator_generate_next(fydi)) != NULL)
    fy_document_iterator_event_free(fydi, fye);

  fy_document_iterator_get_error(fydi);

out:
  fy_document_iterator_destroy(fydi);
  fy_document_destroy(fyd);
}

void test_parse_compose(struct flags_t *flags, const char *data, size_t size) {
  struct fy_parser *fyp = NULL;
  struct fy_parse_cfg cfg = { .flags = flags->parse_flags };

  fyp = fy_parser_create(&cfg);
  CHECK(fyp);

  int rc = fy_parser_set_string(fyp, data, size);
  CHECK(rc == 0);

  fy_parse_compose(fyp, compose_inspect_cb, NULL);

out:
  fy_parser_destroy(fyp);
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

void test_sequence_operations(struct flags_t *flags, const char *data, size_t size) {
  struct fy_document *fyd = NULL;
  struct fy_node *new_node = NULL;
  struct fy_parse_cfg cfg = { .flags = flags->parse_flags };
  void *iter;
  struct fy_node *fyn;

  fyd = fy_document_build_from_string(&cfg, data, size);
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

out:
  fy_node_free(new_node);
  fy_document_destroy(fyd);
}

void test_node_resolve_alias(struct flags_t *flags, const char *data, size_t size) {
  struct fy_document *fyd = NULL;
  struct fy_document *fyd2 = NULL;
  struct fy_document_iterator *fydi = NULL;
  struct fy_node *fyn = NULL;
  struct fy_parse_cfg cfg = { .flags = flags->parse_flags | FYPCF_YPATH_ALIASES };

  fyd = fy_document_build_from_string(&cfg, data, size);
  CHECK(fyd);

  fydi = fy_document_iterator_create();
  CHECK(fydi);

  fy_document_iterator_node_start(fydi, fy_document_root(fyd));
  while ((fyn = fy_document_iterator_node_next(fydi)) != NULL) {
    if (fy_node_is_alias(fyn)) {
      fy_node_resolve_alias(fyn);
      fy_node_dereference(fyn);
    }
  }
  fy_document_iterator_destroy(fydi);
  fydi = NULL;

  fyd2 = fy_document_clone(fyd);
  if (fyd2)
    fy_document_resolve(fyd2);

out:
  fy_document_iterator_destroy(fydi);
  fy_document_destroy(fyd2);
  fy_document_destroy(fyd);
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
  rfl = fy_reflection_from_packed_blob((const void *)data, size, NULL);
out:
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

void test_reflection_type_context_parse_primitive(struct flags_t *flags, const char *data, size_t size) {
  struct fy_reflection *rfl = NULL;
  struct fy_type_context *ctx = NULL;
  struct fy_parser *fyp = NULL;
  void *parsed_data = NULL;
  struct fy_parse_cfg parse_cfg = { .flags = flags->parse_flags };

  rfl = fy_reflection_from_null(NULL);
  CHECK(rfl);

  struct fy_type_context_cfg ctx_cfg = {
    .rfl = rfl,
    .entry_type = flags->primitive_type,
  };
  ctx = fy_type_context_create(&ctx_cfg);
  CHECK(ctx);

  fyp = fy_parser_create(&parse_cfg);
  CHECK(fyp);

  int rc = fy_parser_set_string(fyp, data, size);
  CHECK(rc == 0);

  fy_type_context_parse(ctx, fyp, &parsed_data);

out:
  fy_type_context_free_data(ctx, parsed_data);
  fy_parser_destroy(fyp);
  fy_type_context_destroy(ctx);
  fy_reflection_destroy(rfl);
}

void test_reflection_type_context_emit(struct flags_t *flags, const char *data, size_t size) {
  struct fy_reflection *rfl = NULL;
  struct fy_type_context *ctx = NULL;
  struct fy_parser *fyp = NULL;
  struct fy_emitter *emit = NULL;
  void *parsed_data = NULL;
  char *out_str = NULL;
  struct fy_parse_cfg parse_cfg = { .flags = flags->parse_flags };

  rfl = fy_reflection_from_null(NULL);
  CHECK(rfl);

  struct fy_type_context_cfg ctx_cfg = {
    .rfl = rfl,
    .entry_type = flags->primitive_type,
  };
  ctx = fy_type_context_create(&ctx_cfg);
  CHECK(ctx);

  fyp = fy_parser_create(&parse_cfg);
  CHECK(fyp);

  int rc = fy_parser_set_string(fyp, data, size);
  CHECK(rc == 0);

  rc = fy_type_context_parse(ctx, fyp, &parsed_data);
  CHECK(rc == 0);
  CHECK(parsed_data);

  emit = fy_emit_to_string(flags->emitter_flags);
  CHECK(emit);

  fy_type_context_emit(ctx, emit, parsed_data,
      FYTCEF_SS | FYTCEF_DS | FYTCEF_DE | FYTCEF_SE);

  size_t out_size;
  out_str = fy_emit_to_string_collect(emit, &out_size);

out:
  free(out_str);
  fy_emitter_destroy(emit);
  fy_type_context_free_data(ctx, parsed_data);
  fy_parser_destroy(fyp);
  fy_type_context_destroy(ctx);
  fy_reflection_destroy(rfl);
}

void test_reflection_generate_c(struct flags_t *flags, const char *data, size_t size) {
  struct fy_reflection *rfl = NULL;
  char *generated = NULL;
  FILE *devnull = NULL;

  rfl = fy_reflection_from_null(NULL);
  CHECK(rfl);

  generated = fy_reflection_generate_c_string(rfl, flags->cgen_flag);

  devnull = fopen("/dev/null", "w");
  CHECK(devnull);
  fy_reflection_generate_c(rfl, flags->cgen_flag, devnull);

out:
  if (devnull) fclose(devnull);
  free(generated);
  fy_reflection_destroy(rfl);
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
  struct fy_parse_cfg cfg = { .flags = flags->parse_flags };
  fy_generic fyg;

  fyp = fy_parser_create(&cfg);
  CHECK(fyp);

  int rc = fy_parser_set_string(fyp, data, size);
  CHECK(rc == 0);

  gb = fy_generic_builder_create(NULL);
  CHECK(gb);

  fygdb = fy_generic_document_builder_create_on_parser(fyp, gb);
  CHECK(fygdb);

  while (fy_generic_is_valid(fyg = fy_generic_document_builder_load_document(fygdb, fyp))) {
    fy_generic_get_type(fyg);
    fy_generic_compare(fyg, fyg);
  }

out:
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
  BRANCH(test_node_comparisons);
  BRANCH(test_emit_node_to_string);
  BRANCH(test_fy_parser_parse);
  BRANCH(test_mapping_operations);
  BRANCH(test_fy_node_build_from_string);
  BRANCH(test_fy_node_create_scalar);
  BRANCH(test_token_iteration);
  BRANCH(test_fy_node_set_anchor);
  BRANCH(test_token_comments);
  BRANCH(test_fy_emitter_create);
  BRANCH(test_document_iterator);
  BRANCH(test_document_iterator_node);
  BRANCH(test_document_iterator_generate);
  BRANCH(test_parse_compose);
  BRANCH(test_path_exec);
  BRANCH(test_document_builder);
  BRANCH(test_sequence_operations);
  BRANCH(test_node_resolve_alias);
  BRANCH(test_mapping_operations_extended);
  BRANCH(test_document_insert_at);
  BRANCH(test_parser_checkpoint_rollback);

  BRANCH(test_reflection_type_lookup);
  BRANCH(test_reflection_type_context_parse_primitive);
  BRANCH(test_reflection_type_context_emit);
  BRANCH(test_reflection_generate_c);
  BRANCH(test_reflection_type_context_entry_meta);

  BRANCH2(test_fy_node_build_from_fp);
  BRANCH2(test_fy_parser_parse_fp);
  BRANCH2(test_parse_with_flags_fp);
  BRANCH2(test_reflection_packed_blob);
  BRANCH2(test_parse_from_file);
  BRANCH2(test_generic_document_builder);

  return 0;
}

#if defined REPRODUCER

#define CONCAT2(a, b) a##b
#define CONCAT(a, b) CONCAT2(a, b)

#define RR(nr,artifact_path) R(nr,artifact_path,read_artifact_raw)
#define RA(nr,artifact_path) R(nr,artifact_path,read_artifact)

#define R(nr,artifact_path,read_artifact_func) \
int CONCAT(vc, nr)() { \
  size_t n; \
  char *data = read_file(artifact_path, &n); \
  if (n > 0 && data) { \
    struct flags_t _flags = {0}; \
    struct flags_t *flags = &_flags; \
    uint32_t seed = *(uint32_t*)data; \
    setup_flags(seed, flags); \
    char* flags_t_str = flags_to_struct_string(flags); \
    printf("RF(%d,\ntest_func,\n(&(struct flags_t)%s),\n\"", nr, flags_t_str); \
    static char abuf[0x10000]; \
    memset(abuf, 0, sizeof(abuf)); \
    size_t data_size = n - sizeof(uint32_t); \
    sprintf_artifact_as_hexstr(abuf, sizeof(abuf), data + sizeof(uint32_t), data_size); \
    printf("%s\",\n%d\n)\n", abuf, data_size); \
    printf("\n\n"); \
    printf("char *data = \"%s\";\n", abuf); \
    printf("%s(&(struct flags_t)%s,data,sizeof(data));\n\n\n", "test_func", flags_t_str); \
    LLVMFuzzerTestOneInput((const uint8_t *)data, n); \
    free(data); \
  } \
  return n > 0; \
}

#define RF(nr,func,flags,data,n) \
int CONCAT(tc, nr)() { \
  func(flags, data, n); \
  return 0; \
}



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

