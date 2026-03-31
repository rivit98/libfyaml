#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>
#include <unistd.h>
#include <sys/mman.h>

#include <libfyaml.h>
#include "fuzz_utils.h"

static enum fy_composer_return compose_inspect_cb(struct fy_parser *fyp,
    struct fy_event *fye, struct fy_path *path, void *userdata)
{
  (void)fyp;
  (void)fye;
  (void)userdata;

  USE(fy_path_in_root(path));
  USE(fy_path_in_collection_root(path));

  char *ptext = fy_path_get_text(path);
  free(ptext);

  struct fy_path_component *last = fy_path_last_not_collection_root_component(path);
  if (last) {
    char *ctext = fy_path_component_get_text(last);
    free(ctext);
    if (fy_path_component_is_mapping(last)) {
      fy_document_destroy(fy_path_component_mapping_get_complex_key(last)); /* caller-owned */
    }
  }

  if (fy_path_depth(path) > 10)
    return FYCR_OK_START_SKIP;
  return FYCR_OK_CONTINUE;
}

static int set_comment_on_scalars(struct fy_node *fyn, const char *comment,
                                  size_t comment_len, int budget) {
  struct fy_node_pair *pair;
  struct fy_node *child;
  void *iter;

  if (!fyn || budget <= 0)
    return budget;

  if (fy_node_is_scalar(fyn)) {
    struct fy_token *token = fy_node_get_scalar_token(fyn);
    if (!token)
      return budget;
    fy_token_set_comment(token, fycp_top, comment, comment_len);
    fy_token_set_comment(token, fycp_right, comment, comment_len);
    fy_token_set_comment(token, fycp_bottom, comment, comment_len);
    fy_token_get_comment(token, fycp_top);
    fy_token_get_comment(token, fycp_right);
    fy_token_get_comment(token, fycp_bottom);
    USE(fy_token_get_comments(token));
    /* overwrite an existing comment, and remove one (text == NULL) */
    fy_token_set_comment(token, fycp_right, comment, comment_len);
    fy_token_set_comment(token, fycp_bottom, NULL, 0);
    return budget - 1;
  }

  if (fy_node_is_sequence(fyn)) {
    iter = NULL;
    while (budget > 0 && (child = fy_node_sequence_iterate(fyn, &iter)) != NULL)
      budget = set_comment_on_scalars(child, comment, comment_len, budget);
    return budget;
  }

  if (fy_node_is_mapping(fyn)) {
    iter = NULL;
    while (budget > 0 && (pair = fy_node_mapping_iterate(fyn, &iter)) != NULL) {
      budget = set_comment_on_scalars(fy_node_pair_key(pair), comment, comment_len, budget);
      budget = set_comment_on_scalars(fy_node_pair_value(pair), comment, comment_len, budget);
    }
  }

  return budget;
}

void test_parse_path(struct flags_t *flags, const char *data, size_t size) {
  struct fy_node *new_node = NULL;
  struct fy_document *fyd = NULL;
  struct fy_document *work = NULL;

  fyd = corpus_document();
  CHECK(fyd);

  /* Resolving is read-only, and most inputs stop here - so it happens against
   * the shared fixture, before anything is cloned. */
  struct fy_node *root = fy_document_root(fyd);
  CHECK(fy_node_by_path(root, data, size, flags->node_walk_flags));

  /*
   * The insert below does not add to its target, it OVERWRITES it: with a
   * scalar source, "source overwrites target" (fy_node_insert, libfyaml-core.h)
   * - and a path that resolves to the root replaces the whole document with the
   * scalar. The fixture outlives this exec, so the damage would be inherited by
   * every later iteration of the persistent loop: degraded path coverage,
   * varying edge counts for identical inputs, and crashes that do not replay.
   *
   * So the insert runs on a clone, which is destroyed here. The path is
   * resolved a second time inside it because fy_node_insert() branches on the
   * target's parent - a node copied out on its own would take a different path
   * through the function than the one the fuzzer reached.
   */
  work = fy_document_clone(fyd);
  CHECK(work);

  struct fy_node *node = fy_node_by_path(fy_document_root(work), data, size, flags->node_walk_flags);
  CHECK(node);

  new_node = fy_node_build_from_string(work, "inserted", FY_NT);
  CHECK(new_node);

  fy_node_insert(node, new_node);

out:
  fy_node_free(new_node);
  fy_document_destroy(work);
}


void test_token_iteration(struct fy_document *fyd) {
  CHECK(fyd);

  struct fy_node *root = fy_document_root(fyd);
  CHECK(root);
  CHECK(fy_node_is_scalar(root));

  struct fy_token *token = fy_node_get_scalar_token(root);
  CHECK(token);

  size_t len;
  USE(fy_token_get_text(token, &len));
  USE(fy_token_get_text0(token));
  USE(fy_token_get_text_length(token));
  
  struct fy_token_iter *iter = fy_token_iter_create(token);
  CHECK(iter);

  char buf[256];
  USE(fy_token_iter_read(iter, buf, sizeof(buf) - 1));
  
  int c = fy_token_iter_getc(iter);
  if (c != -1) {
    fy_token_iter_ungetc(iter, c);
  }
  
  int utf8_char = fy_token_iter_utf8_get(iter);
  if (utf8_char != -1) {
    fy_token_iter_utf8_unget(iter, utf8_char);
  }
  
  USE(fy_token_iter_peekc(iter));
  USE(fy_token_iter_utf8_peek(iter));
  
  fy_token_iter_finish(iter);

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

  fy_token_get_comments(token);

  fy_token_start_mark(token);
  fy_token_end_mark(token);
  fy_token_style_start_mark(token);
  fy_token_style_end_mark(token);
  fy_token_scalar_style(token);
  fy_token_scalar_is_null(token);
  fy_scalar_token_get_style(token);

out:
  return;
}

/*
 * fy_node_sequence_sort() is the only sort entry point without a default
 * comparator: fy-doc.c:6287 returns -1 on a NULL @cmp before it touches the
 * sequence, so fy_node_sequence_sort(root, NULL, NULL) never sorted anything.
 * fy_node_mapping_sort() and fy_node_sort() DO substitute a default
 * (fy-doc.c:6172), so NULL stays correct for those two.
 *
 * This must stay a consistent total preorder. glibc's qsort_r reads past the
 * end of its array when a comparator is inconsistent, and the ASAN report
 * lands in the library with the harness nowhere near the top frame - so it
 * may depend only on node content, never on a counter, a pointer value, a
 * clock or the fuzzer input.
 *
 * fy_node_get_scalar() returns NULL for collections, which sorts every
 * sequence and mapping after every scalar and equal among themselves - a
 * preorder, which is all qsort needs.
 */
static int seq_cmp_scalar(struct fy_node *fyn_a, struct fy_node *fyn_b, void *arg) {
  const char *ta, *tb;
  size_t la = 0, lb = 0;
  int rc;

  (void)arg;

  if (fyn_a == fyn_b)
    return 0;
  if (!fyn_a)
    return 1;
  if (!fyn_b)
    return -1;

  ta = fy_node_get_scalar(fyn_a, &la);
  tb = fy_node_get_scalar(fyn_b, &lb);
  if (!ta || !tb)
    return !ta && !tb ? 0 : (!ta ? 1 : -1);

  rc = memcmp(ta, tb, la < lb ? la : lb);
  if (rc)
    return rc < 0 ? -1 : 1;
  return la < lb ? -1 : la > lb ? 1 : 0;
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
  fy_node_sequence_sort(root, seq_cmp_scalar, NULL);

  iter = NULL;
  while ((fyn = fy_node_sequence_iterate(root, &iter)) != NULL)
    ;


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


void test_mapping_operations_extended(struct fy_document *fyd, const char *data, size_t size) {
  struct fy_node *removed_val = NULL;
  struct fy_node *fyn_scalar = NULL;
  void *iter;
  struct fy_node_pair *pair;

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
  fy_node_mapping_lookup_by_string(root, data, size);
  fy_node_mapping_lookup_key_by_string(root, data, size);
  fy_node_mapping_lookup_pair_by_string(root, data, size);

  fy_node_mapping_sort(root, NULL, NULL);

  // test_fy_node_build_from_string
  fyn_scalar = fy_node_create_scalar(fyd, data, size);
  struct fy_node *key_node = fy_node_build_from_string(fyd, data, size);
  if (key_node) {
    removed_val = fy_node_mapping_remove_by_key(root, key_node);
    fy_node_free(key_node);
  }


  /* extra mapping/pair accessors (fy-doc.c) */
  fy_node_mapping_is_empty(root);
  fy_node_mapping_get_by_index(root, 0);
  fy_node_mapping_lookup_pair_by_simple_key(root, data, size);
  fy_node_mapping_lookup_value_by_simple_key(root, data, size);
  size_t slen;
  fy_node_mapping_lookup_scalar_by_simple_key(root, &slen, data, size);
  fy_node_mapping_lookup_scalar0_by_simple_key(root, data, size);
  fy_node_mapping_lookup_value_by_string(root, data, size);
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
  fy_node_free(fyn_scalar);
}


void test_parse_with_flags(struct flags_t *flags, const char *data, size_t size) {
  struct fy_document *fyd = NULL;
  struct fy_document *fyd2 = NULL;
  struct fy_document *fyd3 = NULL;
  struct fy_parse_cfg cfg = { .flags = flags->parse_flags };
  char* buf = NULL;
  struct fy_emitter *emitter = NULL;
  struct fy_emitter* emit = NULL;
  char *collected = NULL;
  struct fy_node* node2 = NULL;
  char *plain = NULL;
  struct fy_document *fyd4 = NULL;
  struct fy_document *fydblk = NULL;
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

  /* caller-owned, like every other fy_*_build_from_string() here */
  size_t consumed;
  fydblk = fy_block_document_build_from_string(&cfg, data, size, &consumed);


  // test_node_comparisons
  {
    struct fy_node *root2 = fy_document_root(fyd);
    if (root2) {
      USE(fy_node_compare(root2, root2));
      fyd4 = fy_document_clone(fyd);
      if(fyd4) {
        struct fy_node *root3 = fy_document_root(fyd4);
        USE(fy_node_compare(root2, root3));
        USE(fy_node_compare_string(root2, data, size));
        USE(fy_node_compare_text(root2, data, size));
      }
    }
  }

  set_comment_on_scalars(fy_document_root(fyd), data, size, 10);

  fy_node_set_style(fy_document_root(fyd), flags->node_style);
  fy_node_set_anchor(fy_document_root(fyd), data, size);

  // test_emit
  {
    buf = fy_emit_document_to_string(fyd, flags->emitter_flags);
    USE(fy_emit_document_to_fp(fyd, flags->emitter_flags, null_fp));

    emitter = fy_emit_to_string(flags->emitter_flags);
    fy_emit_document(emitter, fyd);
    size_t out_size;
    collected = fy_emit_to_string_collect(emitter, &out_size);
  }


  // test_fy_emitter_create
  {
    emit = fy_emitter_create(&emit_xcfg.cfg);
    if(emit) {
      USE(fy_emit_document(emit, fyd));
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
  test_mapping_operations_extended(fyd, data, size);


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
  fy_document_destroy(fydblk);
}

void test_path_exec(struct flags_t *flags, struct fy_path_expr *expr) {
  struct fy_path_exec *fypx = NULL;
  struct fy_node *fyn = NULL;
  void *iter;
  struct fy_document *fyd = NULL;
  struct fy_path_exec_cfg xcfg = { .flags = flags->path_exec_flags };

  fyd = corpus_document();
  CHECK(fyd);

  fypx = fy_path_exec_create(&xcfg);
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

    test_path_exec(flags, expr);
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

void test_fy_parser_parse_fp(struct flags_t *flags, const char *data, size_t size) {
  struct fy_parser *fyp = NULL;
  struct fy_parser_checkpoint *fypchk = NULL;
  struct fy_document_builder *fydb = NULL;
  struct fy_event *fyev = NULL;
  struct fy_parse_cfg cfg = { .flags = flags->parse_flags };
  struct fy_document *fyd = NULL;
  struct fy_document *fyd2 = NULL;
  struct fy_node *fyn = NULL;
  FILE *f = NULL;
  int rc;

  f = fmemopen((void *)data, size, "r");
  CHECK(f);

  fyp = fy_parser_create(&cfg);
  CHECK(fyp);

  rc = fy_parser_set_input_fp(fyp, NULL, f);
  if (rc == 0) {
    /* pull one event so the checkpoint is taken mid-stream */
    fyev = fy_parser_parse(fyp);
    if (fyev) fy_parser_event_free(fyp, fyev);

    fypchk = fy_parser_checkpoint_create(fyp);
    if (fypchk) {
      for (int i = 0; i < 2; i++) {
        fyev = fy_parser_parse(fyp);
        if (!fyev) break;
        fy_parser_event_free(fyp, fyev);
      }
      fy_parser_rollback(fyp, fypchk);
      fy_parser_checkpoint_destroy(fypchk);
      fypchk = NULL;
    }

    while ((fyev = fy_parser_parse(fyp)) != NULL) {
      dump_testsuite_event(fyp, fyev);
      fy_event_get_comments(fyev);
      fy_parser_event_free(fyp, fyev);
    }

    fy_parse_compose(fyp, compose_inspect_cb, NULL);
    fy_parser_get_mode(fyp);
  }

  /* reuse the parser for the document builder over the same input */
  fy_parser_reset(fyp);

  rewind(f);
  if (fy_parser_set_input_fp(fyp, NULL, f) == 0) {
    fydb = fy_document_builder_create_on_parser(fyp);
    if (fydb) {
      while ((fyd = fy_document_builder_load_document(fydb, fyp)) != NULL) {
        fy_document_destroy(fyd);
        fyd = NULL;
      }
    }
  }

  rewind(f);
  fyd2 = fy_document_create(NULL);
  if (fyd2) {
    fyn = fy_node_build_from_fp(fyd2, f);
    fy_document_set_root(fyd2, fyn);
  }

out:
  fy_parser_checkpoint_destroy(fypchk);
  fy_document_builder_destroy(fydb);
  fy_document_destroy(fyd);
  fy_document_destroy(fyd2);
  fy_parser_destroy(fyp);
  if (f) fclose(f);
}

void test_reflection_packed_blob(struct flags_t *flags, const char *data, size_t size) {
  struct fy_reflection *rfl = NULL;
  size_t blob_size = 0;
  void *blob = NULL;
  struct fy_reflection *rfl2 = NULL;
  char *generated = NULL;


  rfl = fy_reflection_from_packed_blob((const void *)data, size, NULL);
  CHECK(rfl);

  generated = fy_reflection_generate_c_string(rfl, flags->cgen_flag);

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
    fy_type_info_get_kind(ti);
    fy_type_info_get_size(ti);
    fy_type_info_get_align(ti);
    fy_type_info_lookup_field_by_enum_value(ti, (intmax_t)flags->type_info_flags); // just random flag
    
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

  fy_type_info_lookup(rfl, flags->primitive_type);

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
  free(generated);
  fy_reflection_destroy(rfl2);
  fy_reflection_destroy(rfl);
}


void test_reflection_type_context_entry_meta(struct flags_t *flags, const char *data, size_t size) {
  struct fy_reflection *rfl = NULL;
  struct fy_type_context *ctx = NULL;
  struct fy_parser *fyp = NULL;
  void *parsed_data = NULL;
  struct fy_emitter *emit = NULL;
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

  rc = fy_type_context_parse(ctx, fyp, &parsed_data);
  if (rc == 0 && parsed_data) {
    emit = fy_emit_to_string(flags->emitter_flags);
    if(emit) {
      rc = fy_type_context_emit(ctx, emit, parsed_data,
          FYTCEF_SS | FYTCEF_DS | FYTCEF_DE | FYTCEF_SE);
  
      if (rc == 0) {
        size_t out_size;
        char *out_str = fy_emit_to_string_collect(emit, &out_size);
        free(out_str);
      }
    }
  }

out:
  fy_type_context_free_data(ctx, parsed_data);
  fy_parser_destroy(fyp);
  fy_type_context_destroy(ctx);
  fy_emitter_destroy(emit);
  fy_reflection_destroy(rfl);
  free(meta_str);
  free(yaml_str);
}


void test_generic_document_builder(struct flags_t *flags, const char *data, size_t size) {
  struct fy_parser *fyp = NULL;
  struct fy_generic_builder *gb = NULL;
  struct fy_generic_document_builder *fygdb = NULL;
  struct fy_generic_iterator *fygi = NULL;
  struct fy_parse_cfg cfg = { .flags = flags->parse_flags };
  const struct fy_alloc_recipe *arecipe;
  struct fy_allocator *alloc = NULL, *alloc_parent = NULL;
  fy_generic fyg;

  fyp = fy_parser_create(&cfg);
  CHECK(fyp);

  int rc = fy_parser_set_string(fyp, data, size);
  CHECK(rc == 0);

  arecipe = &fy_alloc_recipes[flags->allocator_recipe];
  alloc = make_recipe_allocator(arecipe, &alloc_parent);
  CHECK(alloc || arecipe->kind == FY_ALLOC_RECIPE_DEFAULT || !alloc_parent);

  struct fy_generic_builder_cfg gb_cfg = {
    .flags = flags->generic_builder_flags,
    .allocator = alloc,
    .parent = NULL,
    .estimated_max_size = arecipe->size,
  };
  gb = fy_generic_builder_create(&gb_cfg);
  CHECK(gb);

  struct fy_generic_document_builder_cfg gdb_cfg = {0};
  gdb_cfg.parse_cfg = cfg;
  gdb_cfg.gb = gb;
  gdb_cfg.flags = flags->generic_doc_builder_flags;
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
  make_recipe_allocator_free(alloc, alloc_parent);
  fy_parser_destroy(fyp);
}

/* documents: the parser, the document builder and the generic builder */
void test_yaml(struct flags_t *flags, const char *data, size_t size) {
  T(test_parse_with_flags);
  T2(test_fy_parser_parse_fp);
  T2(test_generic_document_builder);
}

/* path and ypath expressions, walked against the shared corpus document */
void test_path(struct flags_t *flags, const char *data, size_t size) {
  T(test_parse_path);
  T(test_fy_path_expr_build_from_string);
} 

/* packed reflection blobs (FYPG) */
void test_blob(struct flags_t *flags, const char *data, size_t size) {
  T2(test_reflection_packed_blob);
}

/* a meta document, a newline, then a YAML document */
void test_meta(struct flags_t *flags, const char *data, size_t size) {
  T(test_reflection_type_context_entry_meta);
}

/*
 * Called by libAFLDriver once, before __afl_manual_init() starts the deferred
 * fork server (aflpp_driver.c: "Do any other expensive one-time
 * initialization here"), so the corpus fixture is parsed in the parent.
 *
 * Built lazily instead, it was parsed inside whichever input ran first in each
 * forked child - 24 KB of YAML whose parser edges were then credited to that
 * input and to no other. Identical inputs got different coverage depending on
 * where they landed in the persistent loop, which is instability by
 * construction. Pre-fork the parse happens once per campaign and its edges
 * belong to no exec at all.
 */
int LLVMFuzzerInitialize(int *argc, char ***argv) {
  (void)argc;
  (void)argv;

  corpus_document();
  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size <= sizeof(uint32_t)) return 0;

  struct flags_t _flags = {0};
  struct flags_t *flags = &_flags;
  uint32_t seed = *(uint32_t*)data;
  setup_flags(seed, flags);
  data += sizeof(uint32_t);
  size -= sizeof(uint32_t);

  G(test_yaml);
  G(test_path);
  G(test_blob);
  G(test_meta);

  if (__builtin_expect(tc_filter != NULL, 0) && !tc_filter_matched) {
    fprintf(stderr, "TC=%s does not name any test case\n", tc_filter);
    exit(1);
  }

  /*
   * Per-input leak check, and the one thing that did not survive the move off
   * libFuzzer for free: -detect_leaks=1 used to run LSAN after every input,
   * while a persistent-mode fuzzer only reaches LSAN's atexit handler once per
   * ~1000 inputs. afl-cc defines __AFL_LEAK_CHECK() only for an AFL_USE_LSAN
   * build (recoverable check, _exit(23) on a leak, which AFL saves as a
   * crash); it expands to nothing everywhere else, so this line costs the
   * other builds nothing. See fuzzer/build.sh's lsan variant.
   */
#ifdef __AFL_LEAK_CHECK
  __AFL_LEAK_CHECK();
#endif

  return 0;
}

#if defined REPRODUCER


#define CONCAT2(a, b) a##b
#define CONCAT(a, b) CONCAT2(a, b)


#define RR(nr,artifact_path) R(nr,artifact_path,read_artifact_raw)
#define RA(nr,artifact_path) R(nr,artifact_path,read_artifact_raw)

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
    fflush(stdout); \
    free(abuf); \
    LLVMFuzzerTestOneInput((const uint8_t *)data, n); \
    munmap(data, n); \
  } \
  return n > 0; \
}

/* arms allocation failure injection the way T_RUN() does - fuzz_alloc_fail.h */
#define RF(nr,func,flags,data,n) \
int CONCAT(tc, nr)() { \
  struct flags_t *_rf_flags = (flags); \
  alloc_fail_arm(FLAGS_ALLOC_FAIL_NTH(_rf_flags)); \
  func(_rf_flags, data, n); \
  alloc_fail_disarm(); \
  return 0; \
}


/* gh#TBD report1.md - fy_atom_iter_format() reads the uninitialized
 * pending_lb[0] (src/lib/fy-atom.c:1124) for a clipped block scalar holding
 * only blank lines at EOF (" >\n  "). MSAN-only: the asan+ubsan fuzz2
 * replays this silently; use ./fuzzer/build/repro-msan/fuzz2 tc1. */
RA(1, "/home/rivit/workspace/fuzzing/projects/fuzz/libfyaml/artifacts/id:000002,sig:06,src:000097,time:165057,execs:38940,op:havoc,rep:1")

/* MSAN */
// https://github.com/pantoniou/libfyaml/issues/350
RF(1,
test_parse_with_flags,
(&(struct flags_t){
  .parse_flags = FYPCF_QUIET | FYPCF_COLLECT_DIAG | FYPCF_RESOLVE_DOCUMENT | FYPCF_DISABLE_MMAP_OPT | FYPCF_DISABLE_RECYCLING | FYPCF_KEEP_COMMENTS | FYPCF_SLOPPY_FLOW_INDENTATION | FYPCF_YPATH_ALIASES | FYPCF_ALLOW_DUPLICATE_KEYS | FYPCF_KEEP_ANCHORS | FYPCF_DEFAULT_VERSION_AUTO | FYPCF_JSON_NONE,
  .emitter_flags = FYECF_SORT_KEYS | FYECF_STRIP_LABELS | FYECF_STRIP_DOC | FYECF_STRIP_EMPTY_KV | FYECF_INDENT_DEFAULT | FYECF_WIDTH_132 | FYECF_MODE_FLOW_ONELINE | FYECF_DOC_START_MARK_OFF | FYECF_DOC_END_MARK_ON | FYECF_VERSION_DIR_OFF | FYECF_TAG_DIR_ON,
  .extended_emitter_flags = FYEXCF_COLOR_NONE | FYEXCF_EXTENDED_INDICATORS | FYEXCF_PRESERVE_FLOW_LAYOUT,
  .node_walk_flags = FYNWF_PTR_JSON | FYNWF_PTR_RELJSON | FYNWF_PTR_YPATH | FYNWF_URI_ENCODED,
  .path_parse_flags = FYPPCF_QUIET | FYPPCF_DISABLE_ACCELERATORS,
  .path_exec_flags = FYPXCF_DISABLE_RECYCLING,
  .generic_doc_builder_flags = FYGDBF_DISABLE_DIRECTORY | FYGDBF_KEEP_COMMENTS | FYGDBF_CREATE_MARKERS | FYGDBF_PYYAML_COMPAT | FYGDBF_KEEP_STYLE,
  .generic_builder_flags = FYGBCF_DUPLICATE_KEYS_DISABLED | FYGBCF_SCOPE_LEADER | FYGBCF_SCHEMA_PYTHON,
  .allocator_recipe = 2, /* linear 4K */
  .node_style = FYNS_FOLDED,
  .primitive_type = "unsigned long long",
  .type_info_flags = FYTIF_CONST | FYTIF_VOLATILE | FYTIF_RESTRICT | FYTIF_ELABORATED | FYTIF_INCOMPLETE | FYTIF_UNRESOLVED,
  .cgen_flag = FYCGF_INDENT_TAB | FYCGF_COMMENT_YAML
}),
"\x20\x3e\x0a\x20\x20",
5
)

/* gh#TBD report3.md - a top-level block scalar whose first line is indented
 * less than its indentation indicator ("|9\n[\x01 # comment"): the scanner
 * over-counts storage_hint, so fy_token_get_text() reports 13 bytes while
 * fy_token_prepare_text() only writes the first 5, leaving an 8-byte
 * uninitialized tail (measured 2026-09-17 with __msan_test_shadow() on the
 * returned buffer). Only read when the generic builder's allocator dedups:
 * FYAST_PER_OBJ_FREE_DEDUP hashes the full declared length. Also surfaces in
 * fy_generic_string_compare's memcmp; that is the other artifact,
 * id:000000,sig:06,src:000018,time:103532. MSAN-only;
 * use ./fuzzer/build/repro-msan/fuzz2 tc3. */
RA(3, "/home/rivit/workspace/fuzzing/projects/fuzz/libfyaml/artifacts/id:000001,sig:06,src:000018,time:128779,execs:24482,op:havoc,rep:4")

/* MSAN */
// https://github.com/pantoniou/libfyaml/issues/349
RF(3,
test_generic_document_builder,
(&(struct flags_t){
  .parse_flags = FYPCF_QUIET | FYPCF_COLLECT_DIAG | FYPCF_RESOLVE_DOCUMENT | FYPCF_DISABLE_RECYCLING | FYPCF_DISABLE_ACCELERATORS | FYPCF_KEEP_STYLE | FYPCF_KEEP_ANCHORS | FYPCF_ENABLE_CACHE | FYPCF_DEFAULT_VERSION_AUTO | FYPCF_JSON_AUTO,
  .emitter_flags = FYECF_STRIP_LABELS | FYECF_STRIP_TAGS | FYECF_STRIP_DOC | FYECF_EXTENDED_CFG | FYECF_INDENT_DEFAULT | FYECF_WIDTH_INF | FYECF_MODE_DEJSON | FYECF_DOC_START_MARK_OFF | FYECF_DOC_END_MARK_AUTO | FYECF_VERSION_DIR_OFF | FYECF_TAG_DIR_AUTO,
  .extended_emitter_flags = FYEXCF_COLOR_FORCE | FYEXCF_VISIBLE_WS | FYEXCF_EXTENDED_INDICATORS,
  .node_walk_flags = FYNWF_FOLLOW | FYNWF_PTR_RELJSON | FYNWF_URI_ENCODED,
  .path_parse_flags = FYPPCF_DISABLE_ACCELERATORS,
  .path_exec_flags = FYPXCF_QUIET,
  .generic_doc_builder_flags = FYGDBF_DISABLE_DIRECTORY | FYGDBF_CREATE_MARKERS | FYGDBF_PYYAML_COMPAT | FYGDBF_KEEP_STYLE | FYGDBF_KEEP_FAILSAFE_STR,
  .generic_builder_flags = FYGBCF_DUPLICATE_KEYS_DISABLED | FYGBCF_SCOPE_LEADER | FYGBCF_CREATE_TAG | FYGBCF_SCHEMA_YAML1_2_CORE,
  .allocator_recipe = 10, /* auto per-obj-free dedup */
  .node_style = FYNS_DOUBLE_QUOTED,
  .primitive_type = "long double",
  .type_info_flags = FYTIF_CONST | FYTIF_VOLATILE | FYTIF_ELABORATED | FYTIF_ANONYMOUS | FYTIF_ANONYMOUS_RECORD_DECL | FYTIF_ANONYMOUS_GLOBAL | FYTIF_INCOMPLETE | FYTIF_UNRESOLVED | FYTIF_SYSTEM_HEADER,
  .cgen_flag = FYCGF_INDENT_TAB | FYCGF_COMMENT_RAW
}),
"\x7c\x39\x0a\x5b\x01\x20\x23\x20\x63\x6f\x6d\x6d\x65\x6e\x74\x00\x00\x04\x00\x5b\x5b\x5d\x3a\x5d\x5d",
25
)

/* report4.md */
RA(4, "/home/rivit/workspace/fuzzing/projects/fuzz/libfyaml/artifacts/id:000003,src:011836,time:1418582,execs:1190692,op:havoc,rep:1")

/* ASAN timeout */
// https://github.com/pantoniou/libfyaml/issues/347
RF(4,
test_parse_with_flags,
(&(struct flags_t){
  .parse_flags = FYPCF_COLLECT_DIAG | FYPCF_DISABLE_ACCELERATORS | FYPCF_PREFER_RECURSIVE | FYPCF_CREATE_MARKERS | FYPCF_KEEP_STYLE | FYPCF_ENABLE_CACHE | FYPCF_DEFAULT_VERSION_1_3 | FYPCF_JSON_AUTO,
  .emitter_flags = FYECF_SORT_KEYS | FYECF_OUTPUT_COMMENTS | FYECF_STRIP_LABELS | FYECF_STRIP_TAGS | FYECF_STRIP_DOC | FYECF_STRIP_EMPTY_KV | FYECF_INDENT_DEFAULT | FYECF_WIDTH_DEFAULT | FYECF_MODE_JSON_TP | FYECF_DOC_START_MARK_ON | FYECF_DOC_END_MARK_OFF | FYECF_VERSION_DIR_OFF | FYECF_TAG_DIR_OFF,
  .extended_emitter_flags = FYEXCF_COLOR_NONE | FYEXCF_COLOR_FORCE,
  .node_walk_flags = FYNWF_FOLLOW | FYNWF_PTR_JSON | FYNWF_PTR_RELJSON | FYNWF_PTR_YPATH,
  .path_parse_flags = FYPPCF_DISABLE_RECYCLING,
  .path_exec_flags = FYPXCF_QUIET | FYPXCF_DISABLE_RECYCLING,
  .generic_doc_builder_flags = FYGDBF_KEEP_COMMENTS | FYGDBF_CREATE_MARKERS,
  .generic_builder_flags = FYGBCF_DEDUP_ENABLED | FYGBCF_CREATE_TAG | FYGBCF_SCHEMA_PYTHON,
  .allocator_recipe = 1, /* malloc */
  .node_style = FYNS_SINGLE_QUOTED,
  .primitive_type = "unsigned short",
  .type_info_flags = FYTIF_CONST | FYTIF_ELABORATED | FYTIF_ANONYMOUS_RECORD_DECL | FYTIF_UNRESOLVED | FYTIF_MAIN_FILE,
  .cgen_flag = FYCGF_INDENT_TAB | FYCGF_COMMENT_YAML
}),
"\x3c\x3c\x3a\x0a\x2d\x0a\x2d\x0a\x2d\x0a\x2d\x0a\x2d\x0a\x2d\x0a\x2d\x0a\x2d\x0a\x2d\x0a\x2d\x0a\x20\x2a\x2f\x25\x64\x2d\x0a\x2d\x0a\x20\x2a\x2f\x25\x64\x0a\x34\x20\x3c\x3c\x3a\x20\x2a\x2f\x25\x62\x22\x6a\x6b\x6b\x6b\x6b\x6b\x6b\x5a\x20",
59
)

/* gh#TBD report5.md - the C generator's enum probing adds 1 to a field value
 * of INT64_MAX while tracking the next implicit enumerator, overflowing
 * intmax_t (src/reflection/fy-reflection.c:4758 and again at :4810). Reached
 * from a packed blob (FYPG) whose enum field carries sval = INT64_MAX.
 * UBSAN-only; use ./fuzzer/build/repro/fuzz2 tc5. */
RA(5, "/home/rivit/workspace/fuzzing/projects/fuzz/libfyaml/artifacts/id:000000,sig:06,src:000460,time:28490,execs:235337,op:havoc,rep:1")

/* UBSAN */
// https://github.com/pantoniou/libfyaml/issues/348
RF(5,
test_reflection_packed_blob,
(&(struct flags_t){
  .parse_flags = FYPCF_DISABLE_MMAP_OPT | FYPCF_DISABLE_RECYCLING | FYPCF_KEEP_COMMENTS | FYPCF_SLOPPY_FLOW_INDENTATION | FYPCF_PREFER_RECURSIVE | FYPCF_ALLOW_DUPLICATE_KEYS | FYPCF_CREATE_MARKERS | FYPCF_KEEP_STYLE | FYPCF_RELAXED_FLOW_DOC | FYPCF_KEEP_ANCHORS | FYPCF_DEFAULT_VERSION_AUTO | FYPCF_JSON_AUTO,
  .emitter_flags = FYECF_SORT_KEYS | FYECF_OUTPUT_COMMENTS | FYECF_NO_ENDING_NEWLINE | FYECF_INDENT_DEFAULT | FYECF_WIDTH_DEFAULT | FYECF_MODE_PRETTY | FYECF_DOC_START_MARK_ON | FYECF_DOC_END_MARK_ON | FYECF_VERSION_DIR_ON | FYECF_TAG_DIR_ON,
  .extended_emitter_flags = FYEXCF_COLOR_FORCE | FYEXCF_VISIBLE_WS | FYEXCF_INDENTED_SEQ_IN_MAP,
  .node_walk_flags = FYNWF_FOLLOW | FYNWF_PTR_JSON | FYNWF_PTR_RELJSON | FYNWF_PTR_YPATH,
  .path_parse_flags = FYPPCF_DISABLE_RECYCLING,
  .path_exec_flags = FYPXCF_QUIET,
  .generic_doc_builder_flags = FYGDBF_DISABLE_DIRECTORY | FYGDBF_KEEP_COMMENTS | FYGDBF_KEEP_FAILSAFE_STR,
  .generic_builder_flags = FYGBCF_SCOPE_LEADER | FYGBCF_CREATE_TAG | FYGBCF_SCHEMA_YAML1_1_FAILSAFE,
  .allocator_recipe = 9, /* auto per-obj-free */
  .node_style = FYNS_FLOW,
  .primitive_type = "unsigned char",
  .type_info_flags = FYTIF_VOLATILE | FYTIF_ELABORATED | FYTIF_ANONYMOUS | FYTIF_ANONYMOUS_GLOBAL | FYTIF_INCOMPLETE | FYTIF_UNRESOLVED,
  .cgen_flag = FYCGF_INDENT_TAB | FYCGF_COMMENT_YAML
}),
"\x46\x59\x50\x47\x01\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x12\x00\x00\x00\x00\x00\x00\x00\x09\x00\x00\x00\x00\x00\x00\x00\x2d\x00\x00\x00\x00\x00\x00\x00\x5c\x00\x00\x00\x00\x00\x00\x00\x00\x16\x01\x16\x04\x16\x08\x1a\x00\x01\x01\x1a\x00\x01\x00\x38\x01\x00\x02\x01\x01\x00\x01\x00\x07\x00\x07\x05\x00\x07\x01\x03\x0f\x13\x01\x01\x01\x0f\x00\x07\x00\x07\x28\x00\x07\x01\x04\x01\x13\x07\x01\x05\x32\x36\x01\x01\x02\x32\x00\x07\x01\x03\x0f\x13\x00\x66\x6f\x6f\x00\x66\x6f\x6f\x5f\x76\x61\x6c\x75\x65\x00\x62\x61\x72\x00\x7b\x6e\x75\x6c\x6c\x2d\x00\x00\x00\x00\x46\x59\x50\x47\x0a\x0a\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x62\x61\x7a\x00\x7b\x6e\x75\x6c\x6c\x2d\x61\x6c\x6c\x6f\x77\x65\x64\x3a\x20\x74\x72\x75\x65\x2c\x20\x72\x65\x71\x75\x69\x72\x65\x64\x3a\x20\x66\x61\x6c\x73\x65\x7d\x00",
219
)

/* gh#TBD report6.md - SAME defect as report3.md / issue 349, different
 * trigger: fy_token_prepare_text() allocates the scanner's storage_hint but
 * writes fewer bytes, so fy_token_get_text() hands out an uninitialized tail
 * (src/lib/fy-token.c:937/977). Here a folded block scalar whose content
 * holds a NUL (">\0lu") gives text_len 3 with only 2 bytes written; issue 349
 * is the indentation-indicator trigger (13 declared, 5 written). The value
 * reaches fy_generic_collection_op_prepare_iov() instead of the dedup hash.
 * Filed separately because 349 was already submitted. MSAN-only;
 * use ./fuzzer/build/repro-msan/fuzz2 tc6. */
RA(6, "/home/rivit/workspace/fuzzing/projects/fuzz/libfyaml/artifacts/id:000006,sig:00,src:000130,time:83813,execs:257777,op:havoc,rep:3,+san")

/* MSAN */
// https://github.com/pantoniou/libfyaml/issues/351
RF(6,
test_generic_document_builder,
(&(struct flags_t){
  .parse_flags = FYPCF_QUIET | FYPCF_RESOLVE_DOCUMENT | FYPCF_DISABLE_MMAP_OPT | FYPCF_DISABLE_RECYCLING | FYPCF_SLOPPY_FLOW_INDENTATION | FYPCF_ALLOW_DUPLICATE_KEYS | FYPCF_KEEP_STYLE | FYPCF_KEEP_ANCHORS | FYPCF_DEFAULT_VERSION_1_3 | FYPCF_JSON_AUTO,
  .emitter_flags = FYECF_OUTPUT_COMMENTS | FYECF_STRIP_TAGS | FYECF_STRIP_DOC | FYECF_INDENT_DEFAULT | FYECF_WIDTH_DEFAULT | FYECF_MODE_JSON_ONELINE | FYECF_DOC_START_MARK_AUTO | FYECF_DOC_END_MARK_OFF | FYECF_VERSION_DIR_OFF | FYECF_TAG_DIR_OFF,
  .extended_emitter_flags = FYEXCF_COLOR_NONE | FYEXCF_COLOR_FORCE | FYEXCF_EXTENDED_INDICATORS | FYEXCF_INDENTED_SEQ_IN_MAP | FYEXCF_PRESERVE_FLOW_LAYOUT,
  .node_walk_flags = FYNWF_FOLLOW | FYNWF_PTR_JSON | FYNWF_PTR_RELJSON | FYNWF_PTR_YPATH,
  .path_parse_flags = FYPPCF_QUIET | FYPPCF_DISABLE_RECYCLING,
  .path_exec_flags = FYPXCF_QUIET | FYPXCF_DISABLE_RECYCLING,
  .generic_doc_builder_flags = FYGDBF_PYYAML_COMPAT | FYGDBF_KEEP_FAILSAFE_STR,
  .generic_builder_flags = FYGBCF_CREATE_TAG | FYGBCF_SCHEMA_YAML1_2_JSON,
  .allocator_recipe = 3, /* linear 256K */
  .node_style = FYNS_FLOW,
  .primitive_type = "unsigned int",
  .type_info_flags = FYTIF_ELABORATED | FYTIF_ANONYMOUS_DEP | FYTIF_INCOMPLETE,
  .cgen_flag = FYCGF_INDENT_TAB | FYCGF_COMMENT_YAML,
  .alloc_fail_nth = 0
}),
"\x0a\x3e\x00\x6c\x75",
5
)

/* gh#TBD report7.md - ypath alias resolution leaks the fy_walk_result it
 * clones at src/lib/fy-walk.c:5178 when the nested fy_path_expr_execute()
 * errors out. 144 bytes in 3 objects, one per public entry point the harness
 * calls: fy_document_resolve() (main.c:444), fy_node_resolve_alias() (:460)
 * and fy_node_dereference() (:461). Library-internal throughout - the walk
 * results never reach the caller, and fy_document_destroy() already drains
 * the pxdd recycle list (fy-walk.c:5450), so this is not harness ownership.
 * Needs detect_leaks=1: ASAN_OPTIONS=detect_leaks=1 fuzzer/build/repro/fuzz2 tc7. */
RA(7, "/home/rivit/workspace/fuzzing/projects/fuzz/libfyaml/artifacts/id:000002,sig:00,sync:main,src:020925")

/* ASAN leak */
// https://github.com/pantoniou/libfyaml/issues/352
RF(7,
test_parse_with_flags,
(&(struct flags_t){
  .parse_flags = FYPCF_QUIET | FYPCF_KEEP_COMMENTS | FYPCF_DISABLE_ACCELERATORS | FYPCF_DISABLE_BUFFERING | FYPCF_SLOPPY_FLOW_INDENTATION | FYPCF_YPATH_ALIASES | FYPCF_KEEP_STYLE | FYPCF_KEEP_ANCHORS | FYPCF_DEFAULT_VERSION_1_2 | FYPCF_JSON_AUTO,
  .emitter_flags = FYECF_SORT_KEYS | FYECF_STRIP_LABELS | FYECF_STRIP_TAGS | FYECF_STRIP_EMPTY_KV | FYECF_INDENT_DEFAULT | FYECF_WIDTH_INF | FYECF_MODE_MANUAL | FYECF_DOC_START_MARK_OFF | FYECF_DOC_END_MARK_OFF | FYECF_VERSION_DIR_AUTO | FYECF_TAG_DIR_OFF,
  .extended_emitter_flags = FYEXCF_VISIBLE_WS | FYEXCF_EXTENDED_INDICATORS | FYEXCF_INDENTED_SEQ_IN_MAP,
  .node_walk_flags = FYNWF_FOLLOW | FYNWF_PTR_JSON | FYNWF_PTR_RELJSON | FYNWF_PTR_YPATH | FYNWF_URI_ENCODED,
  .path_parse_flags = FYPPCF_DISABLE_ACCELERATORS,
  .path_exec_flags = FYPXCF_DISABLE_ACCELERATORS,
  .generic_doc_builder_flags = FYGDBF_DISABLE_DIRECTORY | FYGDBF_KEEP_COMMENTS | FYGDBF_CREATE_MARKERS | FYGDBF_PYYAML_COMPAT | FYGDBF_KEEP_STYLE | FYGDBF_KEEP_FAILSAFE_STR,
  .generic_builder_flags = FYGBCF_DEDUP_ENABLED | FYGBCF_SCOPE_LEADER | FYGBCF_SCHEMA_YAML1_1,
  .allocator_recipe = 11, /* auto single-linear-range */
  .node_style = FYNS_PLAIN,
  .primitive_type = "int",
  .type_info_flags = FYTIF_CONST | FYTIF_VOLATILE | FYTIF_RESTRICT | FYTIF_ELABORATED | FYTIF_ANONYMOUS | FYTIF_INCOMPLETE | FYTIF_SYSTEM_HEADER,
  .cgen_flag = FYCGF_INDENT_TAB | FYCGF_COMMENT_RAW,
  .alloc_fail_nth = 0
}),
"\x23\x20\x10\x20\x0d\x20\x2d\x20\x4a\x2f\x2a\x2a\x20\x0d\x20\x2d\x20\x20\x4a\x2f\x37\x7c\x62\x2a\x2f\x2a\x29\x36\x36\x30\x42\x2f\x36\x20\x0d\x0d\x20\x2d\x20\x4a\x2f\x2a\x2a\x2f\x36\x32\x0d\x20\x2d\x20\x0d\x20\x2d\x20\x2d\x20\x2a\x2f\x37\x3c\x2a\x2f\x20\x0d\x20\x2d\x20\x2a\x2f\x37\x3c\x62\x2a\x2f\x2a\x2a\x2f\x61\x6c\x6c\x28\x73\x75\x6d\x28\x2f\x2a\x39\x31\x38\x32\x32\x34\x6b\x22\x61\x22\x26\x26\x29\x3d\x3d\x6b\x22\x61\x22\x26\x26\x29\x3d\x3d\x22\x61\x22\x20\x0d\x20\x2d\x20\x2a\x2f\x37\x37\x3c\x62\x2a\x2f\x2a\x2a\x2f\x36\x2f\x42\x2f\x36\x20\x0d\x20\x2d\x20\x2a\x2f\x37\x3c\x62\x2a\x2f\x2a\x2a\x2f\x36\x2f\x42\x0a",
154
)

/* gh#TBD report8.md - c_generate_type_with_fields() recurses into itself at
 * src/reflection/fy-reflection.c:4789 for every field flagged
 * FYTIF_ANONYMOUS_RECORD_DECL, with no depth limit. A packed blob whose
 * anonymous record decl refers back to its own type recurses until the stack
 * is gone (246 frames in the artifact). Note the run also trips issue 348's
 * signed overflow at :4758 first - UBSAN does not abort, so read past it.
 * Run with the stack a report should assume:
 * (ulimit -s 8192; ./fuzzer/build/repro/fuzz2 tc8) */
RA(8, "/home/rivit/workspace/fuzzing/projects/fuzz/libfyaml/artifacts/id:000388,sig:11,src:017374,time:9763434,execs:65200425,op:havoc,rep:1")

/* ASAN stack overflow */
// https://github.com/pantoniou/libfyaml/issues/353
RF(8,
test_reflection_packed_blob,
(&(struct flags_t){
  .parse_flags = FYPCF_QUIET | FYPCF_DISABLE_MMAP_OPT | FYPCF_KEEP_COMMENTS | FYPCF_DISABLE_DEPTH_LIMIT | FYPCF_YPATH_ALIASES | FYPCF_ALLOW_DUPLICATE_KEYS | FYPCF_RELAXED_FLOW_DOC | FYPCF_DEFAULT_VERSION_1_3 | FYPCF_JSON_FORCE,
  .emitter_flags = FYECF_SORT_KEYS | FYECF_OUTPUT_COMMENTS | FYECF_STRIP_TAGS | FYECF_NO_ENDING_NEWLINE | FYECF_EXTENDED_CFG | FYECF_INDENT_DEFAULT | FYECF_WIDTH_132 | FYECF_MODE_DEJSON | FYECF_DOC_START_MARK_AUTO | FYECF_DOC_END_MARK_ON | FYECF_VERSION_DIR_AUTO | FYECF_TAG_DIR_OFF,
  .extended_emitter_flags = FYEXCF_INDENTED_SEQ_IN_MAP,
  .node_walk_flags = FYNWF_FOLLOW | FYNWF_PTR_JSON | FYNWF_PTR_RELJSON | FYNWF_PTR_YPATH,
  .path_parse_flags = FYPPCF_QUIET | FYPPCF_DISABLE_RECYCLING,
  .path_exec_flags = FYPXCF_DISABLE_RECYCLING | FYPXCF_DISABLE_ACCELERATORS,
  .generic_doc_builder_flags = FYGDBF_DISABLE_DIRECTORY,
  .generic_builder_flags = FYGBCF_SCOPE_LEADER | FYGBCF_CREATE_TAG | FYGBCF_SCHEMA_YAML1_1_PYYAML,
  .allocator_recipe = 3, /* linear 256K */
  .node_style = FYNS_FLOW,
  .primitive_type = "unsigned int",
  .type_info_flags = FYTIF_CONST | FYTIF_RESTRICT | FYTIF_ELABORATED | FYTIF_ANONYMOUS_GLOBAL | FYTIF_ANONYMOUS_DEP,
  .cgen_flag = FYCGF_INDENT_TAB | FYCGF_COMMENT_NONE,
  .alloc_fail_nth = 0
}),
"\x46\x59\x50\x47\x02\x00\x01\x00\x00\x00\x00\x00\x00\x14\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0c\x00\x00\x00\x00\x00\x00\x00\x2f\x00\x00\x00\x00\x00\x00\x00\x0d\x00\x00\x00\x00\x00\x00\x00\x41\x00\x00\x00\x00\x00\x00\x00\x33\x00\x00\xff\xf6\x38\x39\x35\x00\x1a\x00\x01\x08\x1a\x00\x01\x00\x3c\x01\x01\x08\x16\x07\x1a\x00\x01\x03\x19\x04\x01\x04\x1a\x05\x00\x27\x1c\x06\x00\x07\x9a\xe7\x24\x01\x04\x98\x0e\x04\x01\x27\x98\x64\x07\x00\x07\x16\x07\x05\x01\x02\x01\x00\x01\x01\x03\x08\x00\x07\x00\x07\x0c\x00\x05\x01\x05\x0e\x00\x05\x01\x06\x12\x00\x05\x01\x07\x18\x00\x01\x01\xf4\x1d\x01\x07\x01\x0a\x21\x00\x07\x01\x09\x0e\x00\x07\x00\x80\x25\x00\x07\x01\x09\x27\x00\x07\x01\x09\x2a\x00\x07\x01\x09\x2e\x00\x00\x75\x77\x6e\x74\x70\xba\xba\xba\xba\xba\xba\xba\xba\xba\xba\xba\xba\xba\xba\xba\xba\xba\xba\xba\xba\xba\xba\xba\xba\xba\xba\xba\xba\xba\xba\xba\x07\x05\x01\x13\x01\x03\x03\x00\x21\x01\x0a\x2e\x00\x00\x75",
228
)

/* gh#TBD report9.md - c_generate_type_with_fields() walks ti->fields for
 * i < ti->count without checking that ti->fields is non-NULL, so a packed
 * blob declaring a field count with no field array dereferences NULL at
 * src/reflection/fy-reflection.c:4769. Distinct from issue 348, which is the
 * signed overflow at :4758/:4810 in the same function.
 * UBSAN; use ./fuzzer/build/repro/fuzz2 tc9. */
RA(9, "/home/rivit/workspace/fuzzing/projects/fuzz/libfyaml/artifacts/id:000457,sig:11,src:017885,time:15627693,execs:114605454,op:trim,rep:1")

/* UBSAN */
// https://github.com/pantoniou/libfyaml/issues/354
RF(9,
test_reflection_packed_blob,
(&(struct flags_t){
  .parse_flags = FYPCF_QUIET | FYPCF_DISABLE_MMAP_OPT | FYPCF_KEEP_COMMENTS | FYPCF_DISABLE_DEPTH_LIMIT | FYPCF_YPATH_ALIASES | FYPCF_ALLOW_DUPLICATE_KEYS | FYPCF_RELAXED_FLOW_DOC | FYPCF_DEFAULT_VERSION_1_3 | FYPCF_JSON_FORCE,
  .emitter_flags = FYECF_SORT_KEYS | FYECF_OUTPUT_COMMENTS | FYECF_STRIP_TAGS | FYECF_NO_ENDING_NEWLINE | FYECF_EXTENDED_CFG | FYECF_INDENT_DEFAULT | FYECF_WIDTH_132 | FYECF_MODE_DEJSON | FYECF_DOC_START_MARK_AUTO | FYECF_DOC_END_MARK_ON | FYECF_VERSION_DIR_AUTO | FYECF_TAG_DIR_OFF,
  .extended_emitter_flags = FYEXCF_INDENTED_SEQ_IN_MAP,
  .node_walk_flags = FYNWF_FOLLOW | FYNWF_PTR_JSON | FYNWF_PTR_RELJSON | FYNWF_PTR_YPATH,
  .path_parse_flags = FYPPCF_QUIET | FYPPCF_DISABLE_RECYCLING,
  .path_exec_flags = FYPXCF_DISABLE_RECYCLING | FYPXCF_DISABLE_ACCELERATORS,
  .generic_doc_builder_flags = FYGDBF_DISABLE_DIRECTORY,
  .generic_builder_flags = FYGBCF_SCOPE_LEADER | FYGBCF_CREATE_TAG | FYGBCF_SCHEMA_YAML1_1_PYYAML,
  .allocator_recipe = 3, /* linear 256K */
  .node_style = FYNS_FLOW,
  .primitive_type = "unsigned int",
  .type_info_flags = FYTIF_CONST | FYTIF_RESTRICT | FYTIF_ELABORATED | FYTIF_ANONYMOUS_GLOBAL | FYTIF_ANONYMOUS_DEP,
  .cgen_flag = FYCGF_INDENT_TAB | FYCGF_COMMENT_NONE,
  .alloc_fail_nth = 0
}),
"\x46\x59\x50\x47\x02\x00\x01\x00\x00\x00\x00\x00\x00\x14\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0c\x00\x00\x00\x00\x00\x00\x00\x2f\x00\x00\x00\x00\x00\x00\x00\x0d\x00\x00\x00\x00\x00\x00\x00\x41\x00\x00\x00\x00\x00\x00\x00\x33\x00\x00\xff\xf6\x38\x39\x35\x00\x1a\x00\x01\x08\x19\x01\x01\x00\x3c\x01\x01\x08\x16\x07\x1a\x00\x01\x03\x19\x04\x01\x04\x1a\x05\x00\x27\x1c\x06\x00\x07\x9b\x26\x24\x01\x04\x98\x19\x05\x00\x27\x98\xe7\x07\x00\x07\x16\x07\x05\x01\x02\x01\x00\x01\x15\x03\x08\x00\x07\x00\x07\x0c\x00\x05\x01\x05\x0e\x00\x05\x01\x06\x12\x00\x05\x01\x07\x18\x00\x01\x01\xf4\x1d\x00\x07\x01\x0a\x21\x00\x07\x01\x08\xf5\x00\x07\x00\x80\x25\x00\x07\x01\x09\x27\x00\x07\x01\x09\x2a\x00\x07\x01\x09\x2e\x00\x00\x75\x77\x6e\x74\x70\x70\x00\x62\x00\x00\x00\x00\x00\x1a\x00\x00\x08\x1a\x00\x01\x00\x00\x00\x00\x00\x00\x00\x2d\x00\x00\x00\x00\x00\x00\x00\x70\x00\x00\x00\x33\x35\x38\x00\x80\x25\x00\x07\x01\x06\x02\x01",
228
)

/* gh#TBD report10.md - c_generate_collect_co_dependents() writes past the end
 * of its co-dependent array at src/reflection/fy-reflection.c:4660 (8-byte
 * heap WRITE overflow) when a packed blob yields more co-dependents than the
 * array was sized for. Reached from c_generate_typedef(). Distinct from the
 * other fy-reflection findings: this one corrupts the heap.
 * use ./fuzzer/build/repro/fuzz2 tc10. */
RA(10, "/home/rivit/workspace/fuzzing/projects/fuzz/libfyaml/artifacts/id:000059,sig:06,src:002908,time:343562,execs:1642504,op:trim,rep:12")

/* ASAN */
// https://github.com/pantoniou/libfyaml/issues/355
RF(10,
test_reflection_packed_blob,
(&(struct flags_t){
  .parse_flags = FYPCF_DISABLE_MMAP_OPT | FYPCF_DISABLE_RECYCLING | FYPCF_KEEP_COMMENTS | FYPCF_SLOPPY_FLOW_INDENTATION | FYPCF_PREFER_RECURSIVE | FYPCF_ALLOW_DUPLICATE_KEYS | FYPCF_CREATE_MARKERS | FYPCF_KEEP_STYLE | FYPCF_RELAXED_FLOW_DOC | FYPCF_KEEP_ANCHORS | FYPCF_DEFAULT_VERSION_AUTO | FYPCF_JSON_AUTO,
  .emitter_flags = FYECF_SORT_KEYS | FYECF_OUTPUT_COMMENTS | FYECF_NO_ENDING_NEWLINE | FYECF_INDENT_DEFAULT | FYECF_WIDTH_DEFAULT | FYECF_MODE_PRETTY | FYECF_DOC_START_MARK_ON | FYECF_DOC_END_MARK_ON | FYECF_VERSION_DIR_ON | FYECF_TAG_DIR_ON,
  .extended_emitter_flags = FYEXCF_COLOR_FORCE | FYEXCF_VISIBLE_WS | FYEXCF_INDENTED_SEQ_IN_MAP,
  .node_walk_flags = FYNWF_FOLLOW | FYNWF_PTR_JSON | FYNWF_PTR_RELJSON | FYNWF_PTR_YPATH,
  .path_parse_flags = FYPPCF_DISABLE_RECYCLING,
  .path_exec_flags = FYPXCF_QUIET,
  .generic_doc_builder_flags = FYGDBF_DISABLE_DIRECTORY | FYGDBF_KEEP_COMMENTS | FYGDBF_KEEP_FAILSAFE_STR,
  .generic_builder_flags = FYGBCF_SCOPE_LEADER | FYGBCF_CREATE_TAG | FYGBCF_SCHEMA_YAML1_1_FAILSAFE,
  .allocator_recipe = 9, /* auto per-obj-free */
  .node_style = FYNS_FLOW,
  .primitive_type = "unsigned char",
  .type_info_flags = FYTIF_VOLATILE | FYTIF_ELABORATED | FYTIF_ANONYMOUS | FYTIF_ANONYMOUS_GLOBAL | FYTIF_INCOMPLETE | FYTIF_UNRESOLVED,
  .cgen_flag = FYCGF_INDENT_TAB | FYCGF_COMMENT_YAML,
  .alloc_fail_nth = 0
}),
"\x46\x59\x50\x47\x01\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0c\x00\x00\x00\x00\x00\x00\x00\x2f\x00\x00\x00\x00\x00\x00\x00\x0d\x00\x00\x00\x00\x00\x00\x00\x41\x00\x00\x00\x00\x00\x00\x00\x33\x00\x00\x00\x00\x00\x00\x00\x00\x1a\x00\x00\x08\x1a\x00\x01\x00\x19\x01\x01\x01\x16\x02\x1a\x00\x01\x02\x19\x04\x01\x0a\x19\x05\x00\x27\x19\x06\x01\x06\x98\xeb\xfb\x01\x04\x99\x09\x05\x00\x27\x98\xfa\x06\x00\x07\x16\x07\x05\x01\x02\x01\x00\x01\x01\x03\x08\x00\x07\x00\x07\x0c\x00\x05\x01\x05\x0e\x00\x05\x01\x06\x13\x00\x05\x01\x07\x18\x00\x01\x01\x0b\x1d\x00\x07\x01\x02\x21\x00\x07\x01\x08\x0e\x00\x07\x00\x27\x25\x00\x07\x01\x06\x27\x00\x07\x01\x09\x2a\x00\x07\x01\x0a\x2e\x00\x00\x75\x69\x6e\x74\x70\x70\x00\x62\x61\x72\x00\x62\x00\x62\x61\x72\x70\x00\x63\x69\x6e\x74\x00\x00\x63\x00\x63\x63\x00\x6f\x6f\x00\x61\x70\x70\x69\x6e\x74\x69\x00\x66\x63\x63\x63\x00\x63\x63\x63\x63\x00",
227
)

/* gh#TBD report11.md - fy_path_expr_execute() never frees its fwr_args[]
 * entries. The out:/err_out: block (src/lib/fy-walk.c:5211-5216) frees
 * output1/output2/input1/input2/input but not the nargs results collected at
 * :5184, so an error part-way through the argument loop leaks every argument
 * already evaluated. 336 bytes in 6 objects here, allocated at :4999 through
 * fy_path_exec_walk_result_create(). Related to but distinct from issue 352,
 * which is the cloned input at :5178 - different object, different missing
 * free. Needs detect_leaks=1:
 * ASAN_OPTIONS=detect_leaks=1 fuzzer/build/repro/fuzz2 tc11. */
RA(11, "/home/rivit/workspace/fuzzing/projects/fuzz/libfyaml/artifacts/id:000000,sig:00,sync:main,src:019145")

/* ASAN leak */
// https://github.com/pantoniou/libfyaml/issues/356
RF(11,
test_parse_with_flags,
(&(struct flags_t){
  .parse_flags = FYPCF_QUIET | FYPCF_DISABLE_MMAP_OPT | FYPCF_DISABLE_RECYCLING | FYPCF_DISABLE_DEPTH_LIMIT | FYPCF_DISABLE_ACCELERATORS | FYPCF_PREFER_RECURSIVE | FYPCF_YPATH_ALIASES | FYPCF_ENABLE_CACHE | FYPCF_DEFAULT_VERSION_1_1 | FYPCF_JSON_AUTO,
  .emitter_flags = FYECF_SORT_KEYS | FYECF_OUTPUT_COMMENTS | FYECF_STRIP_TAGS | FYECF_NO_ENDING_NEWLINE | FYECF_STRIP_EMPTY_KV | FYECF_INDENT_DEFAULT | FYECF_WIDTH_DEFAULT | FYECF_MODE_FLOW | FYECF_DOC_START_MARK_AUTO | FYECF_DOC_END_MARK_OFF | FYECF_VERSION_DIR_AUTO | FYECF_TAG_DIR_AUTO,
  .extended_emitter_flags = FYEXCF_COLOR_NONE | FYEXCF_PRESERVE_FLOW_LAYOUT,
  .node_walk_flags = FYNWF_PTR_JSON | FYNWF_PTR_RELJSON | FYNWF_PTR_YPATH,
  .path_parse_flags = FYPPCF_QUIET,
  .path_exec_flags = FYPXCF_DISABLE_RECYCLING | FYPXCF_DISABLE_ACCELERATORS,
  .generic_doc_builder_flags = FYGDBF_DISABLE_DIRECTORY | FYGDBF_CREATE_MARKERS | FYGDBF_PYYAML_COMPAT,
  .generic_builder_flags = FYGBCF_DUPLICATE_KEYS_DISABLED | FYGBCF_SCHEMA_YAML1_2_CORE,
  .allocator_recipe = 5, /* mremap mmap 64K x1.5 */
  .node_style = FYNS_ANY,
  .primitive_type = "long double",
  .type_info_flags = FYTIF_VOLATILE | FYTIF_RESTRICT | FYTIF_ANONYMOUS_GLOBAL | FYTIF_UNRESOLVED | FYTIF_MAIN_FILE | FYTIF_SYSTEM_HEADER,
  .cgen_flag = FYCGF_INDENT_TAB | FYCGF_COMMENT_RAW,
  .alloc_fail_nth = 0
}),
"\x2a\x24\x28\x73\x75\x6d\x28\x33\x36\x3e\x2f\x74\x72\x65\x65\x2f\x62\x72\x61\x6e\x63\x68\x2f\x62\x37\x22\x6e\x61\x6d\x65\x22\x29",
32
)

/* gh#TBD report12.md - double free -> use-after-free of fy_path_expr.
 * evaluate_new() hands exprl/exprr to push_operand_lr() (fy-walk.c:3054),
 * which links them into expr->children (:2285/:2299) and, on its own error
 * path, frees the lot with fy_path_expr_free(expr) (:2320). evaluate_new()
 * never NULLs its copies, so its err_out frees them a second time
 * (:3342-3343). Reached through the public fy_node_by_path(). No allocation
 * failure needed - reproduces 3/3 in the -O0 repro build.
 * TC=test_path ./fuzzer/build/repro/fuzz2 tc12 */
RA(12, "/home/rivit/workspace/fuzzing/projects/fuzz/libfyaml/artifacts_test_path/id:000009,sig:06,src:000004,time:5504,execs:18098,op:havoc,rep:2")

/* ASAN */
// https://github.com/pantoniou/libfyaml/issues/357
RF(12,
test_parse_path,
(&(struct flags_t){
  .parse_flags = FYPCF_COLLECT_DIAG | FYPCF_RESOLVE_DOCUMENT | FYPCF_DISABLE_MMAP_OPT | FYPCF_DISABLE_RECYCLING | FYPCF_YPATH_ALIASES | FYPCF_KEEP_ANCHORS | FYPCF_ENABLE_CACHE | FYPCF_DEFAULT_VERSION_1_1 | FYPCF_JSON_FORCE,
  .emitter_flags = FYECF_STRIP_DOC | FYECF_STRIP_EMPTY_KV | FYECF_INDENT_DEFAULT | FYECF_WIDTH_DEFAULT | FYECF_MODE_JSON_COMPACT | FYECF_DOC_START_MARK_OFF | FYECF_DOC_END_MARK_AUTO | FYECF_VERSION_DIR_OFF | FYECF_TAG_DIR_OFF,
  .extended_emitter_flags = FYEXCF_COLOR_NONE | FYEXCF_INDENTED_SEQ_IN_MAP | FYEXCF_PRESERVE_FLOW_LAYOUT,
  .node_walk_flags = FYNWF_PTR_JSON | FYNWF_PTR_RELJSON | FYNWF_PTR_YPATH | FYNWF_URI_ENCODED,
  .path_parse_flags = FYPPCF_QUIET,
  .path_exec_flags = FYPXCF_QUIET | FYPXCF_DISABLE_RECYCLING | FYPXCF_DISABLE_ACCELERATORS,
  .generic_doc_builder_flags = FYGDBF_CREATE_MARKERS | FYGDBF_KEEP_FAILSAFE_STR,
  .generic_builder_flags = FYGBCF_DEDUP_ENABLED | FYGBCF_SCOPE_LEADER | FYGBCF_CREATE_TAG | FYGBCF_SCHEMA_YAML1_1,
  .allocator_recipe = 3, /* linear 256K */
  .node_style = 4294967295,
  .primitive_type = "unsigned char",
  .type_info_flags = FYTIF_CONST | FYTIF_ELABORATED | FYTIF_ANONYMOUS | FYTIF_ANONYMOUS_RECORD_DECL | FYTIF_ANONYMOUS_GLOBAL | FYTIF_INCOMPLETE | FYTIF_UNRESOLVED | FYTIF_SYSTEM_HEADER,
  .cgen_flag = FYCGF_INDENT_TAB | FYCGF_COMMENT_RAW,
  .alloc_fail_nth = 19
}),
"\x2e\x2f\x2f\x2f\x6b\x65\x79",
7
)

/* gh#TBD report13.md - (int)args[0]->number at fy-walk.c:2563 converts a
 * double to int with no range check, so a ypath index that evaluates to
 * infinity is UB ("inf is outside the range of representable values of type
 * int"). TC=test_path ./fuzzer/build/repro/fuzz2 tc13 */
RA(13, "/home/rivit/workspace/fuzzing/projects/fuzz/libfyaml/artifacts_test_path/id:000558,sig:06,src:010512,time:11762108,execs:17951612,op:havoc,rep:3")

/* UBSAN */
// https://github.com/pantoniou/libfyaml/issues/358
RF(13,
test_fy_path_expr_build_from_string,
(&(struct flags_t){
  .parse_flags = FYPCF_QUIET | FYPCF_COLLECT_DIAG | FYPCF_DISABLE_MMAP_OPT | FYPCF_SLOPPY_FLOW_INDENTATION | FYPCF_CREATE_MARKERS | FYPCF_DEFAULT_VERSION_AUTO | FYPCF_JSON_NONE,
  .emitter_flags = FYECF_SORT_KEYS | FYECF_OUTPUT_COMMENTS | FYECF_STRIP_DOC | FYECF_INDENT_DEFAULT | FYECF_WIDTH_DEFAULT | FYECF_MODE_ORIGINAL | FYECF_DOC_START_MARK_AUTO | FYECF_DOC_END_MARK_OFF | FYECF_VERSION_DIR_OFF | FYECF_TAG_DIR_ON,
  .extended_emitter_flags = FYEXCF_COLOR_NONE | FYEXCF_COLOR_FORCE | FYEXCF_PRESERVE_FLOW_LAYOUT,
  .node_walk_flags = FYNWF_FOLLOW | FYNWF_PTR_RELJSON,
  .path_parse_flags = FYPPCF_QUIET | FYPPCF_DISABLE_ACCELERATORS,
  .path_exec_flags = FYPXCF_DISABLE_RECYCLING | FYPXCF_DISABLE_ACCELERATORS,
  .generic_doc_builder_flags = FYGDBF_KEEP_COMMENTS | FYGDBF_KEEP_STYLE,
  .generic_builder_flags = FYGBCF_DEDUP_ENABLED | FYGBCF_SCHEMA_YAML1_2_JSON,
  .allocator_recipe = 5, /* mremap mmap 64K x1.5 */
  .node_style = FYNS_ANY,
  .primitive_type = "int",
  .type_info_flags = FYTIF_VOLATILE | FYTIF_ELABORATED | FYTIF_ANONYMOUS_DEP | FYTIF_UNRESOLVED | FYTIF_MAIN_FILE | FYTIF_SYSTEM_HEADER,
  .cgen_flag = FYCGF_INDENT_TAB | FYCGF_COMMENT_NONE,
  .alloc_fail_nth = 723
}),
"\x2f\x2a\x2a\x7b\x7d\x28\x79\x28\x28\x28\x28\x28\x28\x28\x2f\x28\x48\x6c\x32\x65\x2d\x39\x39\x74\x73\x2f\x69\x6e\x64\x65\x78\x28\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x29\x6c\x26\x26\x5a\x29\x4f\x2f\x2f\x2f\xd0\x4c\xe2\x8e",
960
)

/* gh#TBD report14.md - heap-use-after-free of struct fy_token_comment.
 * fy_token_set_comment()'s removal branch unlinks the node only when it is
 * the list head: the else arm assigns to the local tk_prev instead of
 * tk_prev->next (fy-token.c:1199), so a comment removed from the middle of
 * fyt->token_comment is freed (:1205) while still linked. Every later walk
 * of that list reads freed memory - fy_token_clean_rl (:81),
 * fy_token_comment_handle (:1932), fy_token_get_comment (:1026) - and the
 * nodes behind it are leaked. Reached through the public
 * fy_token_set_comment(). NO allocation failure needed.
 * Reproduces under fuzzer/build/asan/fuzz, NOT under fuzz2 tc14: fuzz_flags.h
 * was edited after the campaign binaries were built, so this seed now derives
 * different flags. report14.md's standalone reproducer is the authoritative one. */
RA(14, "/home/rivit/workspace/fuzzing/projects/fuzz/libfyaml/artifacts_test_yaml/id:000496,sig:06,src:022947,time:181569134,execs:239675812,op:havoc,rep:1")

/* ASAN */
// https://github.com/pantoniou/libfyaml/issues/359
RF(14,
test_parse_with_flags,
(&(struct flags_t){
  .parse_flags = FYPCF_QUIET | FYPCF_COLLECT_DIAG | FYPCF_KEEP_COMMENTS | FYPCF_DISABLE_DEPTH_LIMIT | FYPCF_DISABLE_ACCELERATORS | FYPCF_SLOPPY_FLOW_INDENTATION | FYPCF_YPATH_ALIASES | FYPCF_ALLOW_DUPLICATE_KEYS | FYPCF_KEEP_STYLE | FYPCF_KEEP_ANCHORS | FYPCF_ENABLE_CACHE | FYPCF_DEFAULT_VERSION_1_3 | FYPCF_JSON_NONE,
  .emitter_flags = FYECF_SORT_KEYS | FYECF_STRIP_LABELS | FYECF_STRIP_TAGS | FYECF_STRIP_DOC | FYECF_NO_ENDING_NEWLINE | FYECF_STRIP_EMPTY_KV | FYECF_INDENT_DEFAULT | FYECF_WIDTH_DEFAULT | FYECF_MODE_DEJSON | FYECF_DOC_START_MARK_AUTO | FYECF_DOC_END_MARK_OFF | FYECF_VERSION_DIR_ON | FYECF_TAG_DIR_OFF,
  .extended_emitter_flags = FYEXCF_COLOR_FORCE | FYEXCF_VISIBLE_WS | FYEXCF_EXTENDED_INDICATORS | FYEXCF_INDENTED_SEQ_IN_MAP,
  .node_walk_flags = FYNWF_PTR_JSON | FYNWF_PTR_RELJSON | FYNWF_PTR_YPATH,
  .path_parse_flags = FYPPCF_DISABLE_ACCELERATORS,
  .path_exec_flags = FYPXCF_QUIET | FYPXCF_DISABLE_RECYCLING | FYPXCF_DISABLE_ACCELERATORS,
  .generic_doc_builder_flags = FYGDBF_DISABLE_DIRECTORY | FYGDBF_CREATE_MARKERS | FYGDBF_KEEP_FAILSAFE_STR,
  .generic_builder_flags = FYGBCF_SCOPE_LEADER | FYGBCF_SCHEMA_YAML1_2_CORE,
  .allocator_recipe = 6, /* mremap malloc 16K x2 */
  .node_style = FYNS_FLOW,
  .primitive_type = "unsigned int",
  .type_info_flags = FYTIF_RESTRICT | FYTIF_ANONYMOUS_RECORD_DECL | FYTIF_ANONYMOUS_DEP | FYTIF_UNRESOLVED,
  .cgen_flag = FYCGF_INDENT_TAB | FYCGF_COMMENT_YAML,
  .alloc_fail_nth = 0
}),
"\x2d\x0a\x5c",
3
)

/* gh#TBD report15.md - NULL dereference on an allocation-failure path.
 * fy_tag_directive_token_handle0()/prefix0() return NULL when their
 * malloc() fails (fy-token.c:357/407), and
 * fy_document_state_tag_directive_iterate() stores that NULL into the tag it
 * returns (fy-docstate.c:474-475). fy_document_state_tag_directives() then
 * strlen()s both without a check (fy-docstate.c:502) -> SEGV, and UBSAN
 * flags the nonnull violation first. Dominant signature of the campaign
 * (~22k crashes). Reached through the public
 * fy_document_state_tag_directives().
 * tc15 needs the injected allocation failure. It does NOT fire under fuzz2:
 * fuzz_flags.h was edited after the campaign binaries were built, so this
 * seed now derives alloc_fail_nth = 0. The artifact still fires under
 * fuzzer/build/asan/fuzz; report15.md's standalone reproducer is the
 * authoritative one. */
RA(15, "/home/rivit/workspace/fuzzing/projects/fuzz/libfyaml/artifacts_test_yaml/id:000012,sig:11,src:000043,time:179919170,execs:134103779,op:havoc,rep:4")

/* ASAN+UBSAN */
// https://github.com/pantoniou/libfyaml/issues/360
RF(15,
test_generic_document_builder,
(&(struct flags_t){
  .parse_flags = FYPCF_DISABLE_MMAP_OPT | FYPCF_KEEP_COMMENTS | FYPCF_DISABLE_DEPTH_LIMIT | FYPCF_DISABLE_ACCELERATORS | FYPCF_SLOPPY_FLOW_INDENTATION | FYPCF_PREFER_RECURSIVE | FYPCF_ALLOW_DUPLICATE_KEYS | FYPCF_CREATE_MARKERS | FYPCF_KEEP_ANCHORS | FYPCF_DEFAULT_VERSION_1_1 | FYPCF_JSON_AUTO,
  .emitter_flags = FYECF_OUTPUT_COMMENTS | FYECF_NO_ENDING_NEWLINE | FYECF_EXTENDED_CFG | FYECF_INDENT_DEFAULT | FYECF_WIDTH_DEFAULT | FYECF_MODE_JSON_ONELINE | FYECF_DOC_START_MARK_AUTO | FYECF_DOC_END_MARK_OFF | FYECF_VERSION_DIR_ON | FYECF_TAG_DIR_ON,
  .extended_emitter_flags = FYEXCF_COLOR_FORCE | FYEXCF_EXTENDED_INDICATORS | FYEXCF_PRESERVE_FLOW_LAYOUT,
  .node_walk_flags = 0,
  .path_parse_flags = FYPPCF_DISABLE_RECYCLING,
  .path_exec_flags = FYPXCF_QUIET,
  .generic_doc_builder_flags = FYGDBF_KEEP_COMMENTS | FYGDBF_CREATE_MARKERS | FYGDBF_PYYAML_COMPAT | FYGDBF_KEEP_STYLE | FYGDBF_KEEP_FAILSAFE_STR,
  .generic_builder_flags = FYGBCF_DEDUP_ENABLED | FYGBCF_SCOPE_LEADER | FYGBCF_CREATE_TAG | FYGBCF_SCHEMA_JSON,
  .allocator_recipe = 6, /* mremap malloc 16K x2 */
  .node_style = FYNS_FLOW,
  .primitive_type = "short",
  .type_info_flags = FYTIF_CONST | FYTIF_ANONYMOUS_RECORD_DECL | FYTIF_ANONYMOUS_GLOBAL | FYTIF_UNRESOLVED,
  .cgen_flag = FYCGF_INDENT_TAB | FYCGF_COMMENT_RAW,
  .alloc_fail_nth = 0
}),
"\x6c",
1
)

/* gh#TBD report16.md - use-after-free (and NULL deref) in one line.
 * fy_parse_document_create()'s err_out calls fy_parse_document_destroy(),
 * which free()s fyd (fy-doc.c:455 -> :387), and then reads fyd->diag two
 * lines later (fy-doc.c:457). When err_out is taken before the malloc at
 * :406 - the FYP_TOKEN_ERROR_CHECK at :402 - fyd is still NULL and the same
 * line is a NULL dereference instead. Reached through the public
 * fy_document_build_from_string().
 * ./build-repro/fuzz2 tc16 reproduces it. */
RA(16, "/home/rivit/workspace/fuzzing/projects/fuzz/libfyaml/artifacts_test_yaml/id:000027,sig:06,src:002939,time:179938432,execs:116180152,op:havoc,rep:3")

/* ASAN */
// https://github.com/pantoniou/libfyaml/issues/361
RF(16,
test_parse_with_flags,
(&(struct flags_t){
  .parse_flags = FYPCF_RESOLVE_DOCUMENT | FYPCF_DISABLE_MMAP_OPT | FYPCF_DISABLE_RECYCLING | FYPCF_DISABLE_DEPTH_LIMIT | FYPCF_DISABLE_BUFFERING | FYPCF_SLOPPY_FLOW_INDENTATION | FYPCF_PREFER_RECURSIVE | FYPCF_CREATE_MARKERS | FYPCF_KEEP_STYLE | FYPCF_RELAXED_FLOW_DOC | FYPCF_DEFAULT_VERSION_1_3 | FYPCF_JSON_NONE,
  .emitter_flags = FYECF_SORT_KEYS | FYECF_STRIP_TAGS | FYECF_NO_ENDING_NEWLINE | FYECF_EXTENDED_CFG | FYECF_INDENT_DEFAULT | FYECF_WIDTH_132 | FYECF_MODE_PRETTY | FYECF_DOC_START_MARK_ON | FYECF_DOC_END_MARK_OFF | FYECF_VERSION_DIR_ON | FYECF_TAG_DIR_OFF,
  .extended_emitter_flags = FYEXCF_INDENTED_SEQ_IN_MAP,
  .node_walk_flags = FYNWF_FOLLOW | FYNWF_URI_ENCODED,
  .path_parse_flags = FYPPCF_DISABLE_RECYCLING,
  .path_exec_flags = FYPXCF_QUIET | FYPXCF_DISABLE_RECYCLING,
  .generic_doc_builder_flags = FYGDBF_KEEP_COMMENTS | FYGDBF_PYYAML_COMPAT | FYGDBF_KEEP_FAILSAFE_STR,
  .generic_builder_flags = FYGBCF_SCOPE_LEADER | FYGBCF_CREATE_TAG | FYGBCF_SCHEMA_YAML1_1,
  .allocator_recipe = 3, /* linear 256K */
  .node_style = FYNS_PLAIN,
  .primitive_type = "double",
  .type_info_flags = FYTIF_CONST | FYTIF_VOLATILE | FYTIF_RESTRICT | FYTIF_ANONYMOUS_GLOBAL | FYTIF_ANONYMOUS_DEP | FYTIF_UNRESOLVED | FYTIF_MAIN_FILE | FYTIF_SYSTEM_HEADER,
  .cgen_flag = FYCGF_INDENT_TAB | FYCGF_COMMENT_YAML,
  .alloc_fail_nth = 23
}),
"\x3a",
1
)

/* gh#TBD report17.md - NULL dereference on an allocation-failure path.
 * FYDBS_MAP_KEY does fynp = fy_node_pair_alloc(fyd); assert(fynp);
 * fynp->key = fyn (fy-docbuilder.c:492-494). assert() is compiled out under
 * NDEBUG, which is what RelWithDebInfo builds, so a failed allocation stores
 * through NULL. Reached through the public fy_document_build_from_string().
 * tc17 needs the injected allocation failure. It does NOT fire under fuzz2:
 * fuzz_flags.h was edited after the campaign binaries were built, so this
 * seed now derives alloc_fail_nth = 0. The artifact still fires under
 * fuzzer/build/asan/fuzz; report17.md's standalone reproducer is the
 * authoritative one. */
RA(17, "/home/rivit/workspace/fuzzing/projects/fuzz/libfyaml/artifacts_test_yaml/id:000211,sig:11,src:016563,time:180345938,execs:266407648,op:havoc,rep:4")

/* ASAN+UBSAN */
// https://github.com/pantoniou/libfyaml/issues/362
RF(17,
test_fy_parser_parse_fp,
(&(struct flags_t){
  .parse_flags = FYPCF_COLLECT_DIAG | FYPCF_DISABLE_MMAP_OPT | FYPCF_KEEP_COMMENTS | FYPCF_DISABLE_DEPTH_LIMIT | FYPCF_DISABLE_ACCELERATORS | FYPCF_PREFER_RECURSIVE | FYPCF_RELAXED_FLOW_DOC | FYPCF_ENABLE_CACHE | FYPCF_DEFAULT_VERSION_1_1 | FYPCF_JSON_AUTO,
  .emitter_flags = FYECF_SORT_KEYS | FYECF_OUTPUT_COMMENTS | FYECF_STRIP_LABELS | FYECF_STRIP_TAGS | FYECF_STRIP_DOC | FYECF_STRIP_EMPTY_KV | FYECF_INDENT_DEFAULT | FYECF_WIDTH_INF | FYECF_MODE_FLOW_COMPACT | FYECF_DOC_START_MARK_ON | FYECF_DOC_END_MARK_AUTO | FYECF_VERSION_DIR_ON | FYECF_TAG_DIR_OFF,
  .extended_emitter_flags = FYEXCF_COLOR_NONE | FYEXCF_VISIBLE_WS | FYEXCF_EXTENDED_INDICATORS | FYEXCF_INDENTED_SEQ_IN_MAP | FYEXCF_PRESERVE_FLOW_LAYOUT,
  .node_walk_flags = FYNWF_PTR_JSON | FYNWF_PTR_RELJSON | FYNWF_PTR_YPATH | FYNWF_URI_ENCODED,
  .path_parse_flags = FYPPCF_QUIET | FYPPCF_DISABLE_RECYCLING | FYPPCF_DISABLE_ACCELERATORS,
  .path_exec_flags = FYPXCF_QUIET,
  .generic_doc_builder_flags = 0,
  .generic_builder_flags = FYGBCF_DEDUP_ENABLED | FYGBCF_CREATE_TAG | FYGBCF_SCHEMA_YAML1_2_FAILSAFE,
  .allocator_recipe = 10, /* auto per-obj-free dedup */
  .node_style = FYNS_FLOW,
  .primitive_type = "long",
  .type_info_flags = FYTIF_ELABORATED | FYTIF_ANONYMOUS_RECORD_DECL | FYTIF_ANONYMOUS_GLOBAL | FYTIF_ANONYMOUS_DEP,
  .cgen_flag = FYCGF_INDENT_TAB | FYCGF_COMMENT_NONE,
  .alloc_fail_nth = 0
}),
"\x3c\x4e\x55\x4c\x4c\x3c\x3a\x0a\x2d\x0a\x2d\x0a\x2d\x0a\x2d\x0a\x2d\x0a\x2d\x0a\x0a\x0a\x0a\x65\x6c\x65\x63\x74\x28\x06\x01\x06\x31\x4f\x38\x31\x31\x31\x34\x72\x3d",
41
)

/* gh#TBD report18.md - size_t underflow -> negative-size-param memcpy.
 * fy_tag_token_suffix() computes suffix_len = tag_len - prefix_len guarded
 * only by assert()s (fy-token.c:784-787), which NDEBUG removes. When a
 * failed allocation leaves tag_len shorter than prefix_len the difference
 * wraps, and fy_tag_token_short() then malloc()s handle_len + suffix_len + 1
 * (:888, allocation-size-too-big) and memcpy()s suffix_len bytes (:892,
 * negative-size-param). Reached through the public fy_tag_token_short(),
 * which fy-tool.c:3271 also calls.
 * tc18 needs the injected allocation failure. It does NOT fire under fuzz2:
 * fuzz_flags.h was edited after the campaign binaries were built, so this
 * seed now derives alloc_fail_nth = 0. The artifact still fires under
 * fuzzer/build/asan/fuzz; report18.md's standalone reproducer is the
 * authoritative one. */
RA(18, "/home/rivit/workspace/fuzzing/projects/fuzz/libfyaml/artifacts_test_yaml/id:000305,sig:06,src:006089,time:2917796,execs:1526848,op:havoc,rep:2")

/* ASAN */
// https://github.com/pantoniou/libfyaml/issues/363
RF(18,
test_fy_parser_parse_fp,
(&(struct flags_t){
  .parse_flags = FYPCF_COLLECT_DIAG | FYPCF_RESOLVE_DOCUMENT | FYPCF_DISABLE_MMAP_OPT | FYPCF_DISABLE_RECYCLING | FYPCF_DISABLE_ACCELERATORS | FYPCF_SLOPPY_FLOW_INDENTATION | FYPCF_RELAXED_FLOW_DOC | FYPCF_KEEP_ANCHORS | FYPCF_ENABLE_CACHE | FYPCF_DEFAULT_VERSION_1_1 | FYPCF_JSON_NONE,
  .emitter_flags = FYECF_SORT_KEYS | FYECF_STRIP_LABELS | FYECF_STRIP_TAGS | FYECF_STRIP_DOC | FYECF_NO_ENDING_NEWLINE | FYECF_STRIP_EMPTY_KV | FYECF_EXTENDED_CFG | FYECF_INDENT_DEFAULT | FYECF_WIDTH_DEFAULT | FYECF_MODE_JSON | FYECF_DOC_START_MARK_OFF | FYECF_DOC_END_MARK_ON | FYECF_VERSION_DIR_AUTO | FYECF_TAG_DIR_AUTO,
  .extended_emitter_flags = FYEXCF_COLOR_NONE | FYEXCF_VISIBLE_WS | FYEXCF_EXTENDED_INDICATORS | FYEXCF_INDENTED_SEQ_IN_MAP | FYEXCF_PRESERVE_FLOW_LAYOUT,
  .node_walk_flags = FYNWF_FOLLOW | FYNWF_PTR_JSON | FYNWF_PTR_RELJSON | FYNWF_PTR_YPATH | FYNWF_URI_ENCODED,
  .path_parse_flags = FYPPCF_QUIET | FYPPCF_DISABLE_ACCELERATORS,
  .path_exec_flags = FYPXCF_DISABLE_RECYCLING | FYPXCF_DISABLE_ACCELERATORS,
  .generic_doc_builder_flags = FYGDBF_KEEP_COMMENTS | FYGDBF_CREATE_MARKERS | FYGDBF_KEEP_STYLE | FYGDBF_KEEP_FAILSAFE_STR,
  .generic_builder_flags = FYGBCF_DEDUP_ENABLED | FYGBCF_SCOPE_LEADER | FYGBCF_SCHEMA_YAML1_1_PYYAML,
  .allocator_recipe = 9, /* auto per-obj-free */
  .node_style = FYNS_DOUBLE_QUOTED,
  .primitive_type = "unsigned long",
  .type_info_flags = FYTIF_CONST | FYTIF_VOLATILE | FYTIF_ANONYMOUS | FYTIF_ANONYMOUS_RECORD_DECL | FYTIF_ANONYMOUS_DEP | FYTIF_MAIN_FILE | FYTIF_SYSTEM_HEADER,
  .cgen_flag = FYCGF_INDENT_TAB | FYCGF_COMMENT_NONE,
  .alloc_fail_nth = 0
}),
"\x65\x64\x65\x26\x3a\x64\x65\x26\x3a\x0a\x5b\x26\x3a\x0a\x21",
15
)

/* gh#TBD report19.md - 88-byte leak of struct fy_diag.
 * fy_parse_setup() creates the diag (fy-parse.c:790) and does not release it
 * when a later step fails - fy_document_state_default() here - so
 * fy_parser_create() returns NULL with the diag still allocated. Reached
 * through the public fy_parser_create().
 * ./build-repro/fuzz2 tc19 reproduces it. */
RA(19, "/home/rivit/workspace/fuzzing/projects/fuzz/libfyaml/artifacts_test_yaml/id:000079,sig:00,src:000322,time:179936109,execs:7743496,op:havoc,rep:1")

/* LSAN */
// https://github.com/pantoniou/libfyaml/issues/364
RF(19,
test_fy_parser_parse_fp,
(&(struct flags_t){
  .parse_flags = FYPCF_DISABLE_MMAP_OPT | FYPCF_DISABLE_ACCELERATORS | FYPCF_DISABLE_BUFFERING | FYPCF_SLOPPY_FLOW_INDENTATION | FYPCF_YPATH_ALIASES | FYPCF_CREATE_MARKERS | FYPCF_KEEP_STYLE | FYPCF_DEFAULT_VERSION_1_3 | FYPCF_JSON_FORCE,
  .emitter_flags = FYECF_OUTPUT_COMMENTS | FYECF_STRIP_TAGS | FYECF_STRIP_DOC | FYECF_NO_ENDING_NEWLINE | FYECF_STRIP_EMPTY_KV | FYECF_INDENT_DEFAULT | FYECF_WIDTH_DEFAULT | FYECF_MODE_FLOW | FYECF_DOC_START_MARK_ON | FYECF_DOC_END_MARK_AUTO | FYECF_VERSION_DIR_ON | FYECF_TAG_DIR_AUTO,
  .extended_emitter_flags = FYEXCF_COLOR_NONE | FYEXCF_PRESERVE_FLOW_LAYOUT,
  .node_walk_flags = FYNWF_PTR_JSON | FYNWF_PTR_RELJSON | FYNWF_PTR_YPATH,
  .path_parse_flags = FYPPCF_QUIET | FYPPCF_DISABLE_RECYCLING,
  .path_exec_flags = 0,
  .generic_doc_builder_flags = FYGDBF_KEEP_COMMENTS,
  .generic_builder_flags = FYGBCF_DUPLICATE_KEYS_DISABLED | FYGBCF_SCOPE_LEADER | FYGBCF_SCHEMA_YAML1_1,
  .allocator_recipe = 13, /* dedup/malloc default bits */
  .node_style = FYNS_DOUBLE_QUOTED,
  .primitive_type = "long double",
  .type_info_flags = FYTIF_VOLATILE | FYTIF_ELABORATED | FYTIF_ANONYMOUS | FYTIF_ANONYMOUS_RECORD_DECL | FYTIF_ANONYMOUS_DEP | FYTIF_INCOMPLETE | FYTIF_UNRESOLVED,
  .cgen_flag = FYCGF_INDENT_TAB | FYCGF_COMMENT_YAML,
  .alloc_fail_nth = 6
}),
"\x0a",
1
)

/* gh#TBD report20.md - 4.5 KB leaked over 4 objects.
 * When fy_token_queue_simple_internal() fails mid-scan (fy-parse.c:194) the
 * parser tears down without releasing the token it was building, the reader
 * buffer opened by fy_reader_input_open() (fy-input.c:681), or the
 * fy_input queued by fy_parse_input_append() (fy-parse.c:62). One
 * reproducer covers four of the campaign's leak signatures. Reached through
 * the public fy_parser_parse().
 * ./build-repro/fuzz2 tc20 reproduces it. */
RA(20, "/home/rivit/workspace/fuzzing/projects/fuzz/libfyaml/artifacts_test_path/id:000913,sig:06,src:000223,time:55793527,execs:88148181,op:havoc,rep:4")

/* LSAN */
// https://github.com/pantoniou/libfyaml/issues/365
RF(20,
test_fy_parser_parse_fp,
(&(struct flags_t){
  .parse_flags = FYPCF_RESOLVE_DOCUMENT | FYPCF_DISABLE_MMAP_OPT | FYPCF_DISABLE_RECYCLING | FYPCF_KEEP_COMMENTS | FYPCF_DISABLE_BUFFERING | FYPCF_SLOPPY_FLOW_INDENTATION | FYPCF_KEEP_STYLE | FYPCF_KEEP_ANCHORS | FYPCF_ENABLE_CACHE | FYPCF_DEFAULT_VERSION_1_1 | FYPCF_JSON_FORCE,
  .emitter_flags = FYECF_SORT_KEYS | FYECF_NO_ENDING_NEWLINE | FYECF_STRIP_EMPTY_KV | FYECF_INDENT_DEFAULT | FYECF_WIDTH_INF | FYECF_MODE_JSON_COMPACT | FYECF_DOC_START_MARK_OFF | FYECF_DOC_END_MARK_ON | FYECF_VERSION_DIR_OFF | FYECF_TAG_DIR_OFF,
  .extended_emitter_flags = FYEXCF_COLOR_NONE | FYEXCF_INDENTED_SEQ_IN_MAP | FYEXCF_PRESERVE_FLOW_LAYOUT,
  .node_walk_flags = FYNWF_URI_ENCODED,
  .path_parse_flags = FYPPCF_DISABLE_RECYCLING | FYPPCF_DISABLE_ACCELERATORS,
  .path_exec_flags = FYPXCF_QUIET | FYPXCF_DISABLE_RECYCLING,
  .generic_doc_builder_flags = FYGDBF_KEEP_COMMENTS | FYGDBF_CREATE_MARKERS | FYGDBF_PYYAML_COMPAT | FYGDBF_KEEP_FAILSAFE_STR,
  .generic_builder_flags = FYGBCF_DEDUP_ENABLED | FYGBCF_CREATE_TAG | FYGBCF_SCHEMA_YAML1_2_CORE,
  .allocator_recipe = 1, /* malloc */
  .node_style = 4294967295,
  .primitive_type = "long long",
  .type_info_flags = FYTIF_VOLATILE | FYTIF_RESTRICT | FYTIF_ANONYMOUS | FYTIF_ANONYMOUS_DEP | FYTIF_SYSTEM_HEADER,
  .cgen_flag = FYCGF_INDENT_TAB | FYCGF_COMMENT_RAW,
  .alloc_fail_nth = 14
}),
"\x2f\x2f\x2f\x2f\x2f\x30",
6
)

int main(int argc, char **argv) {
  return fuzz_replay_main(argc, argv);
}

#endif /* REPRODUCER */

