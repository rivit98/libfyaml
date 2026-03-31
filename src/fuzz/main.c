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

/* report1.md */
RA(1, "/home/rivit/workspace/fuzzing/projects/fuzz/libfyaml/artifacts_test_yaml/id:000356,sig:11,src:018026,time:43953218,execs:17366982,op:havoc,rep:2")

/* UBSAN */
// https://github.com/pantoniou/libfyaml/issues/418
RF(1,
test_parse_with_flags,
(&(struct flags_t){
  .parse_flags = FYPCF_QUIET | FYPCF_COLLECT_DIAG | FYPCF_DISABLE_MMAP_OPT | FYPCF_DISABLE_RECYCLING | FYPCF_KEEP_COMMENTS | FYPCF_DISABLE_DEPTH_LIMIT | FYPCF_DISABLE_BUFFERING | FYPCF_SLOPPY_FLOW_INDENTATION | FYPCF_PREFER_RECURSIVE | FYPCF_YPATH_ALIASES | FYPCF_ALLOW_DUPLICATE_KEYS | FYPCF_CREATE_MARKERS | FYPCF_RELAXED_FLOW_DOC | FYPCF_KEEP_ANCHORS | FYPCF_ENABLE_CACHE | FYPCF_DEFAULT_VERSION_1_1 | FYPCF_JSON_AUTO,
  .emitter_flags = FYECF_SORT_KEYS | FYECF_STRIP_LABELS | FYECF_STRIP_TAGS | FYECF_STRIP_DOC | FYECF_NO_ENDING_NEWLINE | FYECF_EXTENDED_CFG | FYECF_INDENT_DEFAULT | FYECF_WIDTH_INF | FYECF_MODE_FLOW_ONELINE | FYECF_DOC_START_MARK_ON | FYECF_DOC_END_MARK_AUTO | FYECF_VERSION_DIR_ON | FYECF_TAG_DIR_AUTO,
  .extended_emitter_flags = FYEXCF_COLOR_NONE | FYEXCF_EXTENDED_INDICATORS,
  .node_walk_flags = FYNWF_PTR_JSON | FYNWF_URI_ENCODED,
  .path_parse_flags = FYPPCF_DISABLE_ACCELERATORS,
  .path_exec_flags = FYPXCF_QUIET | FYPXCF_DISABLE_RECYCLING,
  .generic_doc_builder_flags = FYGDBF_PYYAML_COMPAT | FYGDBF_KEEP_FAILSAFE_STR,
  .generic_builder_flags = FYGBCF_SCOPE_LEADER | FYGBCF_CREATE_TAG | FYGBCF_SCHEMA_YAML1_2_CORE,
  .allocator_recipe = 10, /* auto per-obj-free dedup */
  .node_style = FYNS_SINGLE_QUOTED,
  .primitive_type = "double",
  .type_info_flags = FYTIF_CONST | FYTIF_VOLATILE | FYTIF_RESTRICT | FYTIF_INCOMPLETE | FYTIF_MAIN_FILE | FYTIF_SYSTEM_HEADER,
  .cgen_flag = FYCGF_INDENT_TAB | FYCGF_COMMENT_RAW,
  .alloc_fail_nth = 363
}),
"\x2a\x2f\x73\x65\x6c\x65\x63\x74\x28\x2d\x30\x38\x31\x28\x29\x3d\x3d\x22\x22\x29\x5b\x0a\x7b\x7b\x21\x0a\x67\x5b",
28
)

/* report1.md, same root cause reached from fy_token_get_scalar_path_key() */
RA(2, "/home/rivit/workspace/fuzzing/projects/fuzz/libfyaml/artifacts_test_yaml/id:000295,sig:06,src:016861,time:5484944,execs:4792605,op:havoc,rep:1")

/* UBSAN */
RF(2,
test_parse_with_flags,
(&(struct flags_t){
  .parse_flags = FYPCF_COLLECT_DIAG | FYPCF_DISABLE_ACCELERATORS | FYPCF_SLOPPY_FLOW_INDENTATION | FYPCF_YPATH_ALIASES | FYPCF_ALLOW_DUPLICATE_KEYS | FYPCF_CREATE_MARKERS | FYPCF_RELAXED_FLOW_DOC | FYPCF_ENABLE_CACHE | FYPCF_DEFAULT_VERSION_1_1 | FYPCF_JSON_AUTO,
  .emitter_flags = FYECF_STRIP_TAGS | FYECF_STRIP_DOC | FYECF_NO_ENDING_NEWLINE | FYECF_STRIP_EMPTY_KV | FYECF_EXTENDED_CFG | FYECF_INDENT_DEFAULT | FYECF_WIDTH_DEFAULT | FYECF_MODE_DEJSON | FYECF_DOC_START_MARK_ON | FYECF_DOC_END_MARK_ON | FYECF_VERSION_DIR_OFF | FYECF_TAG_DIR_OFF,
  .extended_emitter_flags = FYEXCF_COLOR_NONE | FYEXCF_COLOR_FORCE | FYEXCF_EXTENDED_INDICATORS | FYEXCF_INDENTED_SEQ_IN_MAP | FYEXCF_PRESERVE_FLOW_LAYOUT,
  .node_walk_flags = FYNWF_FOLLOW | FYNWF_PTR_JSON | FYNWF_PTR_RELJSON | FYNWF_PTR_YPATH,
  .path_parse_flags = FYPPCF_QUIET | FYPPCF_DISABLE_RECYCLING,
  .path_exec_flags = FYPXCF_DISABLE_ACCELERATORS,
  .generic_doc_builder_flags = FYGDBF_CREATE_MARKERS | FYGDBF_PYYAML_COMPAT | FYGDBF_KEEP_STYLE,
  .generic_builder_flags = FYGBCF_DEDUP_ENABLED | FYGBCF_SCHEMA_AUTO,
  .allocator_recipe = 1, /* malloc */
  .node_style = 4294967295,
  .primitive_type = "unsigned long",
  .type_info_flags = FYTIF_RESTRICT | FYTIF_ELABORATED | FYTIF_MAIN_FILE,
  .cgen_flag = FYCGF_INDENT_TAB | FYCGF_COMMENT_YAML,
  .alloc_fail_nth = 386
}),
"\x3a\x20\x2a\x2f\x2a\x2a\x77\x0d\x2d\x2d\x2d\x20\x0e\x21\x73\x74\x72\x20\x2a\x2f\x2f\x2a\x2f\x55\x66\x3a\x7a\x3a\x0d\x3a\x3a\x20\x2a\x2d\x0a\x2f\x35\x2a\x2f\x2d\x33\x0a",
42
)

/* report2.md */
RA(3, "/home/rivit/workspace/fuzzing/projects/fuzz/libfyaml/artifacts_test_blob/id:000154,sig:11,src:000855,time:29209631,execs:188952860,op:havoc,rep:2")

/* hang (no sanitizer report) */
// https://github.com/pantoniou/libfyaml/issues/419
RF(3,
test_reflection_packed_blob,
(&(struct flags_t){
  .cgen_flag = FYCGF_INDENT_TAB | FYCGF_COMMENT_NONE,
  .alloc_fail_nth = 0
}),
"\x46\x59\x50\x47\x01\x00\x01\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x07\x00\x00\x00\x00\x00\x00\x00\x05\x00\x00\x00\x00\x00\x00\x00\x19\x00\x00\x00\x00\x00\x00\x00\x0f\x00\x00\x00\x00\x00\x00\x00\x00\x16\x01\x96\x11\x03\x16\x03\x01\x01\x00\x01\x00\x07\x00\x07\x05\x00\x01\x01\x02\x07\x00\x07\x01\x00\x0b\x00\x07\x01\x01\x0d\x00\x00\x62\x61\x72\x00\x78\x00\x66\x6f\x6f\x00\x61\x00\x62\x00",
111
)

int main(int argc, char **argv) {
  return fuzz_replay_main(argc, argv);
}

#endif /* REPRODUCER */
