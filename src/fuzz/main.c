#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>
#include <unistd.h>
#include <sys/mman.h>

#include <libfyaml.h>
#include <libfyaml/libfyaml-composer.h>
#include "fuzz_utils.h"

struct compose_state {
  bool text_unsafe;
};

static enum fy_composer_return compose_inspect_cb(struct fy_parser *fyp,
    struct fy_event *fye, struct fy_path *path, void *userdata)
{
  struct compose_state *cs = userdata;

  (void)fyp;
  (void)fye;

  USE(fy_path_in_root(path));
  USE(fy_path_in_collection_root(path));
  USE(fy_path_in_mapping(path));
  USE(fy_path_in_mapping_key(path));
  USE(fy_path_in_mapping_value(path));
  USE(fy_path_in_sequence(path));
  USE(fy_path_last_component(path));

  struct fy_path_component *last = fy_path_last_not_collection_root_component(path);
  if (last && fy_path_component_is_mapping(last)) {
    struct fy_token *skey = fy_path_component_mapping_get_scalar_key(last);
    size_t sklen = 1;

    if (skey)
      fy_token_get_text(skey, &sklen);
    USE(fy_path_component_mapping_get_scalar_key_tag(last));
    /*
     * NOT caller-owned, whatever the header leaves unsaid: the component
     * destroys a completed complex key itself (fy_path_component_clear_state(),
     * fy-path.c). Destroying it here was a double free that never ran only
     * because the compose pass used to get an exhausted stream.
     */
    if (fy_path_component_mapping_get_complex_key(last) || !sklen)
      cs->text_unsafe = true;
  }
  if (last && fy_path_component_is_sequence(last))
    USE(fy_path_component_sequence_get_index(last));

  free(fy_path_get_text(path));
  if (last)
    free(fy_path_component_get_text(last));

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

  /* the unresolved twin: with FYNWF_FOLLOW, paths that go through aliases */
  struct fy_document *yfyd = corpus_ypath_document();
  if (yfyd)
    USE(fy_node_by_path(fy_document_root(yfyd), data, size, flags->node_walk_flags));

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
  corpus_documents_release_path_data();
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
  struct fy_document *fydflow = NULL;
  struct fy_node *inserted = NULL;
  struct fy_diag *diag = NULL;

  struct fy_emitter_xcfg emit_xcfg = {
    .cfg = {
      .flags = flags->emitter_flags
    },
    .xflags = flags->extended_emitter_flags | FYEXCF_OUTPUT_FD,
    .output_fp = null_fp,
  };

  /*
   * Render diagnostics instead of letting the default diag drop them: colours,
   * source lines and positions are what fy_diag_vreport() and
   * fy_diag_error_atom_display() spend most of their code on (fy-diag.c).
   * Into null_fp, so nothing reaches a terminal.
   */
  {
    struct fy_diag_cfg dcfg;

    fy_diag_cfg_default(&dcfg);
    dcfg.fp = null_fp;
    dcfg.level = (enum fy_error_type)(FYET_INFO + FLAGS_AUX(flags, AUX_DIAG_LEVEL, 2));
    dcfg.colorize = FLAGS_AUX(flags, AUX_DIAG_COLOR, 1);
    dcfg.show_source = FLAGS_AUX(flags, AUX_DIAG_SOURCE, 1);
    dcfg.show_position = FLAGS_AUX(flags, AUX_DIAG_POSITION, 1);
    dcfg.show_type = FLAGS_AUX(flags, AUX_DIAG_TYPE, 1);
    dcfg.show_module = FLAGS_AUX(flags, AUX_DIAG_MODULE, 1);
    diag = fy_diag_create(&dcfg);
    cfg.diag = diag;
  }

  fyd = fy_document_build_from_string(&cfg, data, size);
  CHECK(fyd);

  /* caller-owned, like every other fy_*_build_from_string() here */
  size_t consumed;
  fydblk = fy_block_document_build_from_string(&cfg, data, size, &consumed);
  fydflow = fy_flow_document_build_from_string(&cfg, data, size, &consumed);


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
  /* a valid tag first, then the input as one; @data outlives fyd (T() frees
   * it after this function returns), which is all the no-copy API asks */
  fy_node_set_tag(fy_document_root(fyd), "!!str", FY_NT);
  fy_node_set_tag(fy_document_root(fyd), data, size);

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


  // test_node_insert: merge a copy of the untouched clone into the resolved
  // one, at the root's first child - or the root itself when it has none
  //
  if (fyd2 && fyd4 && fy_document_root(fyd2)) {
    struct fy_node *target = fy_document_root(fyd2);
    struct fy_node *child = NULL;

    if (fy_node_is_sequence(target))
      child = fy_node_sequence_get_by_index(target, 0);
    else if (fy_node_is_mapping(target) && fy_node_mapping_get_by_index(target, 0))
      child = fy_node_pair_value(fy_node_mapping_get_by_index(target, 0));

    inserted = fy_node_copy(fyd2, fy_document_root(fyd4));
    if (inserted)
      fy_node_insert(child ? child : target, inserted);
  }


  // test_document_iterator_node
  {
    struct fy_node *fyn = NULL;
    struct fy_node *root = fy_document_root(fyd);
    unsigned int nwalked = 0;

    fydi = fy_document_iterator_create();
    if (fydi) {
      fy_document_iterator_node_start(fydi, root);
      while ((fyn = fy_document_iterator_node_next(fydi)) != NULL) {
        if (fy_node_is_alias(fyn)) {
          fy_node_resolve_alias(fyn);
          fy_node_dereference(fyn);
        }

        /*
         * Path round trip on real descendants - root-to-root, the only pair
         * the accessors below ever got, skips most of each function. The
         * first few nodes only: every call walks up to the root.
         */
        if (nwalked++ < 16) {
          char *npath = fy_node_get_path(fyn);
          if (npath) {
            USE(fy_node_by_path(root, npath, FY_NT, flags->node_walk_flags));
            free(npath);
          }
          free(fy_node_get_path_relative_to(root, fyn));
          USE(fy_node_get_nearest_child_of(root, fyn));
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
  fy_node_free(inserted);   /* refused (-1) when fy_node_insert() attached it */
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
  fy_document_destroy(fydflow);
  fy_diag_unref(diag);
}

/*
 * Walk a result's address back down from @root: fy_node_get_path() writes the
 * YAML-path form, fy_node_by_path() reads it in whichever FYNWF_PTR_* mode the
 * seed picked. Bounded - a "/**" result set has every node in the corpus.
 */
#define PATH_RESULTS_CHECKED 4

static void test_path_result_addresses(struct flags_t *flags, struct fy_node *root,
                                       struct fy_node *fyn)
{
  char *path = fy_node_get_path(fyn);
  if (path) {
    USE(fy_node_by_path(root, path, FY_NT, flags->node_walk_flags));
    free(path);
  }
  free(fy_node_get_path_relative_to(root, fyn));
  free(fy_node_get_parent_address(fyn));
}

void test_path_exec(struct flags_t *flags, struct fy_path_expr *expr) {
  struct fy_path_exec *fypx = NULL;
  struct fy_node *fyn = NULL, *first = NULL, *root, *yroot;
  void *iter;
  struct fy_document *fyd = NULL, *yfyd = NULL;
  struct fy_path_exec_cfg xcfg = { .flags = flags->path_exec_flags };
  int count;

  fyd = corpus_document();
  CHECK(fyd);
  yfyd = corpus_ypath_document();
  CHECK(yfyd);
  root = fy_document_root(fyd);
  yroot = fy_document_root(yfyd);

  fypx = fy_path_exec_create(&xcfg);
  CHECK(fypx);

  fy_path_exec_execute(fypx, expr, root);
  iter = NULL;
  count = 0;
  while ((fyn = fy_path_exec_results_iterate(fypx, &iter)) != NULL) {
    if (!first)
      first = fyn;
    if (count++ < PATH_RESULTS_CHECKED)
      test_path_result_addresses(flags, root, fyn);
  }

  /* reset, then the same expression over the unresolved ypath-alias fixture */
  fy_path_exec_reset(fypx);
  fy_path_exec_execute(fypx, expr, yroot);
  iter = NULL;
  count = 0;
  while ((fyn = fy_path_exec_results_iterate(fypx, &iter)) != NULL) {
    if (count++ < PATH_RESULTS_CHECKED && fy_node_is_alias(fyn))
      USE(fy_node_resolve_alias(fyn));   /* cached by corpus_ypath_document() */
  }

  /* and relative to where the first walk landed: .., ^, ./x and friends */
  if (first && first != root) {
    fy_path_exec_reset(fypx);
    fy_path_exec_execute(fypx, expr, first);
    iter = NULL;
    while ((fyn = fy_path_exec_results_iterate(fypx, &iter)) != NULL)
      ;
  }

out:
  fy_path_exec_destroy(fypx);
  corpus_documents_release_path_data();
}

/*
 * The input as the text of an alias, resolved the way a FYPCF_YPATH_ALIASES
 * document resolves its aliases: an anchor name first, else the text parsed
 * as a ypath expression (fy_node_setup_path_expr_data()) and executed from
 * the alias node. The node is never attached, so the fixture is unchanged;
 * fy_node_free() drops the expression it cached.
 */
void test_ypath_alias(struct flags_t *flags, const char *data, size_t size) {
  struct fy_document *fyd = corpus_ypath_document();
  struct fy_node *alias = NULL;
  (void)flags;

  CHECK(fyd);
  alias = fy_node_create_alias_copy(fyd, data, size);
  CHECK(alias);

  USE(fy_node_resolve_alias(alias));
  USE(fy_node_dereference(alias));

out:
  fy_node_free(alias);
  corpus_documents_release_path_data();
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

/* fy-event.c, internal (the parser's own debug dump uses it); linked statically */
char *fy_event_to_string(struct fy_event *fye);

/*
 * Turn a parser event into a free-standing node, the way a hand-rolled
 * document builder would (fy_node_create_from_event() & co, fy-doc.c), and
 * throw it away again. @held keeps the last collection node, so its END event
 * has something to update.
 */
static void node_from_event(struct fy_document *fyd, struct fy_parser *fyp,
                            struct fy_event *fye, struct fy_node **held)
{
  struct fy_node *fyn;

  if (!fyd)
    return;

  switch (fye->type) {
  case FYET_SCALAR:
  case FYET_ALIAS:
    fy_node_free(fy_node_create_from_event(fyd, fyp, fye));
    break;
  case FYET_SEQUENCE_START:
  case FYET_MAPPING_START:
    fyn = fy_node_create_from_event(fyd, fyp, fye);
    if (fyn) {
      fy_node_free(*held);
      *held = fyn;
    }
    break;
  case FYET_SEQUENCE_END:
  case FYET_MAPPING_END:
    fy_node_update_from_event(*held, fyp, fye);
    break;
  default:
    break;
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
  struct fy_document *fydev = NULL;
  struct fy_node *fyn = NULL;
  struct fy_node *held = NULL;
  struct fy_emitter *emit = NULL;
  FILE *f = NULL;
  int rc;

  /*
   * The streaming emitter: every parser event goes straight into it, which is
   * the only way the event-driven half of fy-emit.c runs (the sequence item /
   * mapping key / mapping value state handlers). Extended config, so the
   * seed's xflags apply, into null_fp.
   */
  struct fy_emitter_xcfg ev_xcfg = {
    .cfg = {
      .flags = flags->emitter_flags | FYECF_EXTENDED_CFG,
    },
    .xflags = flags->extended_emitter_flags | FYEXCF_OUTPUT_FILE,
    .output_fp = null_fp,
  };

  f = fmemopen((void *)data, size, "r");
  CHECK(f);

  fyp = fy_parser_create(&cfg);
  CHECK(fyp);

  emit = fy_emitter_create(&ev_xcfg.cfg);
  fydev = fy_document_create(&cfg);

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
      free(fy_event_to_string(fyev));
      node_from_event(fydev, fyp, fyev, &held);
      /* the emitter takes the event, error or not (fy_emit_event_from_parser()) */
      if (emit)
        fy_emit_event_from_parser(emit, fyp, fyev);
      else
        fy_parser_event_free(fyp, fyev);
    }
    fy_parser_get_mode(fyp);
  }

  /*
   * The composer gets the stream from the start. Run straight after the loop
   * above it saw an exhausted parser and composed nothing, which left
   * fy-composer.c and fy-path.c almost entirely uncovered.
   */
  fy_parser_reset(fyp);
  rewind(f);
  if (fy_parser_set_input_fp(fyp, NULL, f) == 0) {
    struct compose_state cs = { .text_unsafe = false };

    fy_parse_compose(fyp, compose_inspect_cb, &cs);
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
  fy_node_free(held);
  fy_document_destroy(fydev);
  /* queued events go back to the parser that made them - emitter first */
  fy_emitter_destroy(emit);
  fy_parser_destroy(fyp);
  if (f) fclose(f);
}

/*
 * A callback input source that hands the parser at most @chunk bytes per
 * call, so the reader's refill path (fy_reader_input_try_pull()) runs across
 * every token boundary the seed picks.
 */
struct chunked_input {
  const char *data;
  size_t size;
  size_t pos;
  size_t chunk;
};

static ssize_t chunked_input_read(void *user, void *buf, size_t count)
{
  struct chunked_input *ci = user;
  size_t n = ci->size - ci->pos;

  if (n > count)
    n = count;
  if (n > ci->chunk)
    n = ci->chunk;
  memcpy(buf, ci->data + ci->pos, n);
  ci->pos += n;
  return (ssize_t)n;
}

/*
 * One memfd per process for the file input source, made before the fork
 * server starts. -1 when the kernel has none: that source then falls back to
 * the callback one.
 */
static int input_memfd = -1;

__attribute__((constructor)) static void input_memfd_init(void)
{
  input_memfd = memfd_create("fuzz-input", MFD_CLOEXEC);
}

/*
 * The parser's other input sources (fy-input.c), one per exec picked by the
 * seed, plus the parser calls that only make sense mid-stream: counting and
 * skipping a collection's items, both by checkpoint and rollback.
 */
void test_parser_input_sources(struct flags_t *flags, const char *data, size_t size) {
  /* FYPCF_ENABLE_CACHE on a file input writes a cache entry to disk */
  struct fy_parse_cfg cfg = { .flags = flags->parse_flags & ~FYPCF_ENABLE_CACHE };
  struct chunked_input ci = {
    .data = data,
    .size = size,
    .chunk = 1 + FLAGS_AUX(flags, AUX_INPUT_CHUNK, 6),
  };
  struct fy_parser *fyp = NULL;
  struct fy_event *fye;
  char path[64];
  char *copy;
  unsigned int collections = 0;
  bool rollback_ok = false;
  int rc = -1;

  fyp = fy_parser_create(&cfg);
  CHECK(fyp);

  switch (FLAGS_AUX(flags, AUX_INPUT_SOURCE, 2)) {
  case 1:
    /* the parser takes the string, and frees it - unless it never got it */
    copy = malloc(size ? size : 1);
    CHECK(copy);
    memcpy(copy, data, size);
    rc = fy_parser_set_malloc_string(fyp, copy, size);
    if (rc)
      free(copy);
    /* the only source the rollback bug below leaves alone: all in memory */
    rollback_ok = true;
    break;
  case 2:
  case 3:
    if (input_memfd >= 0 && ftruncate(input_memfd, 0) == 0 &&
        pwrite(input_memfd, data, size, 0) == (ssize_t)size) {
      snprintf(path, sizeof(path), "/proc/self/fd/%d", input_memfd);
      rc = fy_parser_set_input_file(fyp, path);
      break;
    }
    /* fallthrough */
  default:
    rc = fy_parser_set_input_callback(fyp, &ci, chunked_input_read);
    break;
  }
  CHECK(rc == 0);

  while ((fye = fy_parser_parse(fyp)) != NULL) {
    enum fy_event_type type = fye->type;

    fy_parser_event_free(fyp, fye);

    if ((type == FYET_SEQUENCE_START || type == FYET_MAPPING_START) &&
        collections++ < 3) {
      USE(type == FYET_SEQUENCE_START ? fy_parser_count_sequence_items(fyp)
                                      : fy_parser_count_mapping_items(fyp));
      if (collections == 2)
        USE(fy_parser_skip(fyp));
    }
  }

out:
  fy_parser_destroy(fyp);
}

/* the packed blob header (fy-packed-backend.c): region sizes, big endian */
#define FYPG_HDR_SIZE   0x40
#define FYPG_HDR_TS     0x18
#define FYPG_HDR_DS     0x28
#define FYPG_HDR_SS     0x30

static uint64_t be64_at(const char *p)
{
  uint64_t v = 0;

  for (int i = 0; i < 8; i++)
    v = (v << 8) | (uint8_t)p[i];
  return v;
}

/*
 * How much of @data the packed blob it starts with spans: the header and its
 * three regions. 0 when @data is no blob, all of it when the regions claim
 * more than there is - the backend then rejects the blob, as it should.
 */
static size_t packed_blob_size(const char *data, size_t size)
{
  uint64_t regions[3];
  size_t n = FYPG_HDR_SIZE;

  if (size < FYPG_HDR_SIZE || memcmp(data, "FYPG", 4))
    return 0;

  regions[0] = be64_at(data + FYPG_HDR_TS);
  regions[1] = be64_at(data + FYPG_HDR_DS);
  regions[2] = be64_at(data + FYPG_HDR_SS);
  for (int i = 0; i < 3; i++) {
    if (regions[i] > size - n)
      return size;
    n += regions[i];
  }
  return n;
}

/* the type info API over every type of @rfl, and its C and blob round trips */
static void reflection_introspect(struct flags_t *flags, struct fy_reflection *rfl)
{
  struct fy_reflection *rfl2 = NULL;
  const struct fy_type_info *ti;
  size_t blob_size = 0;
  void *blob = NULL;
  void *prev = NULL;
  char *generated;

  generated = fy_reflection_generate_c_string(rfl, flags->cgen_flag);
  free(generated);

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

  free(blob);
  fy_reflection_destroy(rfl2);
}

/*
 * An entry type line, a meta document line, then the YAML document: parsed
 * into the entry type's C data, and emitted back. An empty entry line takes
 * the primitive the flags name.
 */
static void reflection_type_context(struct flags_t *flags, struct fy_reflection *rfl,
                                    const char *data, size_t size)
{
  struct fy_type_context *ctx = NULL;
  struct fy_parser *fyp = NULL;
  void *parsed_data = NULL;
  struct fy_emitter *emit = NULL;
  char *entry_type = NULL;
  char *rest = NULL;
  char *meta_str = NULL;
  char *yaml_str = NULL;
  size_t entry_type_len, rest_len, meta_str_len, yaml_str_len;
  struct fy_parse_cfg parse_cfg = { .flags = flags->parse_flags };

  CHECK(split_two_parts(data, size, &entry_type, &entry_type_len, &rest, &rest_len));
  CHECK(split_two_parts(rest, rest_len, &meta_str, &meta_str_len, &yaml_str, &yaml_str_len));

  struct fy_type_context_cfg ctx_cfg = {
    .rfl = rfl,
    .entry_type = entry_type_len ? entry_type : flags->primitive_type,
    .entry_meta = meta_str_len ? meta_str : NULL,
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
  free(entry_type);
  free(rest);
  free(meta_str);
  free(yaml_str);
}

/*
 * An optional packed FYPG blob, then an entry type, a meta document and a YAML
 * document, the first two a line each. The blob's reflection - or the null backend's primitives when
 * there is none - is walked through the type info API, then becomes the type
 * context the YAML document is parsed into.
 */
void test_reflection_type_context(struct flags_t *flags, const char *data, size_t size) {
  size_t blob_size = packed_blob_size(data, size);
  struct fy_reflection *rfl = NULL;

  if (blob_size)
    rfl = fy_reflection_from_packed_blob((const void *)data, blob_size, NULL);
  else
    rfl = fy_reflection_from_null(NULL);
  CHECK(rfl);

  reflection_introspect(flags, rfl);

  if (blob_size < size)
    reflection_type_context(flags, rfl, data + blob_size, size - blob_size);

  fy_reflection_clear_all_markers(rfl);
  fy_reflection_prune_unmarked(rfl);

out:
  fy_reflection_destroy(rfl);
}


/* fy-generic.c, internal (fy-cache.c's snapshot path); linked statically */
const void *fy_generic_builder_linearize(struct fy_generic_builder *gb, fy_generic *vp, size_t *sizep);

/* FYGBOP_FILTER / _MAP / _REDUCE callbacks. Content only, like seq_cmp_scalar(). */
static bool gop_keep_scalar(struct fy_generic_builder *gb, fy_generic v)
{
  enum fy_generic_type t = fy_generic_get_type(v);

  (void)gb;
  return t != FYGT_SEQUENCE && t != FYGT_MAPPING;
}

static fy_generic gop_to_string(struct fy_generic_builder *gb, fy_generic v)
{
  return fy_gb_to_string(gb, v);
}

static fy_generic gop_last_int(struct fy_generic_builder *gb, fy_generic acc, fy_generic v)
{
  fy_generic n = fy_gb_to_int(gb, v);

  return fy_generic_is_valid(n) ? n : acc;
}

/*
 * The fy_generic_op_args() opcodes the fy_gb_*() helpers in
 * test_generic_document_builder() do not reach (fy-generic-op.c). @in is a
 * parsed document or a sequence built around one; most opcodes reject the
 * wrong collection type early, which is a path worth having too.
 */
static void generic_ops(struct flags_t *flags, struct fy_generic_builder *gb, fy_generic in,
                        fy_generic key, fy_generic item)
{
  struct fy_generic_op_args a;
  /*
   * Twice the count each op is given: on a mapping @in, common.count is in
   * pairs (fy_op_common_args), so an op reads 2 * count items.
   */
  fy_generic pair[4] = { key, item, key, item };
  fy_generic path[6] = { key, fy_gb_int_type_create_out_of_place(gb, 0), item,
                         key, item, item };

#define GOP(_op, ...) do { \
    memset(&a, 0, sizeof(a)); \
    __VA_ARGS__; \
    USE(fy_generic_op_args(gb, (_op), in, &a)); \
  } while (0)

  GOP(FYGBOPF_SORT);
  GOP(FYGBOPF_FILTER, a.filter.fn = gop_keep_scalar);
  GOP(FYGBOPF_MAP, a.map_filter.fn = gop_to_string);
  GOP(FYGBOPF_REDUCE, a.reduce.fn = gop_last_int; a.reduce.acc = item);
  GOP(FYGBOPF_SLICE, a.slice.start = 1; a.slice.end = SIZE_MAX);
  GOP(FYGBOPF_SLICE_PY, a.slice_py.start = -2; a.slice_py.end = -1);
  GOP(FYGBOPF_TAKE, a.take.n = 2);
  GOP(FYGBOPF_DROP, a.drop.n = 1);
  GOP(FYGBOPF_FIRST);
  GOP(FYGBOPF_LAST);
  GOP(FYGBOPF_REST);
  GOP(FYGBOPF_GET, a.common.count = 1; a.common.items = pair);
  {
    size_t n = 0;

    fy_generic_collection_get_items(in, &n);
    GOP(FYGBOPF_GET_AT, a.insert_replace_get_set_at.idx = 0);
  }
  GOP(FYGBOPF_GET_AT_PATH, a.common.count = 2; a.common.items = path);
  GOP(FYGBOPF_SET, a.common.count = 2; a.common.items = pair);
  GOP(FYGBOPF_SET_AT, a.insert_replace_get_set_at.idx = 0;
                      a.common.count = 1; a.common.items = pair);
  GOP(FYGBOPF_SET_AT_PATH | FYGBOPF_CREATE_PATH, a.common.count = 3; a.common.items = path);
  GOP(FYGBOPF_JOIN, a.common.count = 2; a.common.items = pair);
  GOP(FYGBOPF_CONVERT, a.convert.type = FYGT_STRING);
  /* report4.md again: FYGBOP_CONVERT to int goes through fy_gb_to_int() */
  GOP(FYGBOPF_CONVERT, a.convert.type = FYGT_INT);
  GOP(FYGBOPF_CREATE_SEQ | FYGBOPF_FILTER_NULL | FYGBOPF_SORT_CREATE,
      a.common.count = 2; a.common.items = pair);
  GOP(FYGBOPF_CREATE_MAP | FYGBOPF_SORT_CREATE, a.common.count = 1; a.common.items = pair);

#undef GOP
}

/*
 * FYGBOP_PARSE and FYGBOP_EMIT over the raw input, with seed-picked flags:
 * the generic decoder and encoder (fy-generic-decoder.c, -encoder.c) are
 * reachable only through these. A directory-carrying parse result also feeds
 * the generic iterator's event generator (fy_generic_iterator_generate_next(),
 * fygi_event_create()), which needs a vdir.
 */
static void generic_parse_emit(struct flags_t *flags, struct fy_generic_builder *gb,
                               const char *data, size_t size)
{
  struct fy_generic_op_args a;
  struct fy_generic_iterator *fygi;
  struct fy_event *fye;
  fy_generic in, parsed, emitted;
  bool dir = FLAGS_AUX(flags, AUX_GOP_DIRECTORY, 1);
  static const enum fy_op_parse_flags parse_bits[] = {
    FYOPPF_MULTI_DOCUMENT,
    FYOPPF_CREATE_MARKERS, FYOPPF_KEEP_STYLE, FYOPPF_KEEP_FAILSAFE_STR,
    FYOPPF_SLOPPY_FLOW_INDENTATION, FYOPPF_RELAXED_FLOW_DOC, FYOPPF_KEEP_ANCHORS,
  };
  static const enum fy_op_emit_flags emit_bits[] = {
    FYOPEF_MULTI_DOCUMENT, FYOPEF_NO_ENDING_NEWLINE, FYOPEF_OUTPUT_COMMENTS,
    FYOPEF_EMIT_EVENTS, FYOPEF_AUTO_ANCHOR,
  };
  unsigned int pbits = FLAGS_AUX(flags, AUX_GOP_PARSE_BITS, array_elements(parse_bits));
  unsigned int ebits = FLAGS_AUX(flags, AUX_GOP_EMIT_BITS, array_elements(emit_bits));
  unsigned int i;

  in = fy_gb_string_size_create(gb, data, size);
  if (fy_generic_is_invalid(in))
    return;

  /* never FYOPPF_ENABLE_CACHE (a disk write per exec) or FYOPPF_TRACE (output) */
  memset(&a, 0, sizeof(a));
  a.parse.flags = FYOPPF_INPUT_TYPE_STRING |
                  FYOPPF_MODE(FLAGS_AUX(flags, AUX_GOP_PARSE_MODE, 3) % 6) |
                  (dir ? 0 : FYOPPF_DISABLE_DIRECTORY);
  for (i = 0; i < array_elements(parse_bits); i++)
    if (pbits & (1u << i))
      a.parse.flags |= parse_bits[i];
  a.parse.flags |= FYOPPF_COLLECT_DIAG | FYOPPF_KEEP_COMMENTS;
  parsed = fy_generic_op_args(gb, FYGBOPF_PARSE, in, &a);
  if (fy_generic_is_invalid(parsed))
    return;

  /* only string output: the others write to stdout, stderr or a file */
  memset(&a, 0, sizeof(a));
  a.emit.flags = FYOPEF_OUTPUT_TYPE_STRING |
                 FYOPEF_MODE(FLAGS_AUX(flags, AUX_GOP_EMIT_MODE, 3) % 6) |
                 FYOPEF_STYLE(FLAGS_AUX(flags, AUX_GOP_EMIT_STYLE, 3) % 6) |
                 FYOPEF_INDENT(FLAGS_AUX(flags, AUX_GOP_EMIT_INDENT, 3) % 7) |
                 FYOPEF_WIDTH(FLAGS_AUX(flags, AUX_GOP_EMIT_WIDTH, 2)) |
                 FYOPEF_COLOR(FLAGS_AUX(flags, AUX_GOP_EMIT_COLOR, 2) % 3) |
                 (dir ? 0 : FYOPEF_DISABLE_DIRECTORY);
  for (i = 0; i < array_elements(emit_bits); i++)
    if (ebits & (1u << i))
      a.emit.flags |= emit_bits[i];
  {
    emitted = fy_generic_op_args(gb, FYGBOPF_EMIT, parsed, &a);
    USE(emitted);
  }

  if (!dir)
    return;

  struct fy_generic_iterator_cfg icfg = {
    .flags = FYGICF_WANT(FLAGS_AUX(flags, AUX_GITER_WANT, 2) % 3) |
             (FLAGS_AUX(flags, AUX_GITER_STRIP, 5) << 3),   /* STRIP_LABELS..FAILSAFE_STR */
    .vdir = parsed,
    .schema = FYGS_AUTO,
  };
  if (FLAGS_AUX(flags, AUX_GITER_ANCHOR, 1))
    icfg.flags |= FYGICF_AUTO_ANCHOR;
  fygi = fy_generic_iterator_create_cfg(&icfg);
  if (!fygi)
    return;
  while ((fye = fy_generic_iterator_generate_next(fygi)) != NULL)
    fy_generic_iterator_event_free(fygi, fye);
  fy_generic_iterator_get_error(fygi);
  fy_generic_iterator_destroy(fygi);
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

  generic_parse_emit(flags, gb, data, size);

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

      generic_ops(flags, gb, fyg, key, str1);
      generic_ops(flags, gb, seq, num, str1);

      /* scalar conversions (fy-generic.c) */
      USE(fy_gb_to_int(gb, fyg));
      USE(fy_gb_to_float(gb, fyg));
      USE(fy_gb_to_bool(gb, fyg));
      USE(fy_gb_to_string(gb, fyg));
      USE(fy_gb_to_int(gb, str1));
      USE(fy_gb_to_float(gb, str1));
      USE(fy_gb_to_bool(gb, str1));
    }

    /*
     * A child builder over this one: values already living in the parent
     * are recognised by fy_gb_internalize_core() and not copied, the half of
     * it a lone builder never reaches.
     */
    {
      struct fy_generic_builder_cfg cgb_cfg = {
        .flags = flags->generic_builder_flags,
        .parent = gb,
      };
      struct fy_generic_builder *cgb = fy_generic_builder_create(&cgb_cfg);

      if (cgb) {
        fy_generic cv = fy_gb_internalize(cgb, fyg);
        fy_gb_create_sequence(cgb, cv, fyg);
        USE(fy_gb_to_string(cgb, fyg));
        fy_generic_builder_destroy(cgb);
      }
    }

    /* one contiguous image of the builder's arenas, pointers relocated into
     * it (fy_generic_relocate()); the image belongs to the builder */
    {
      fy_generic lv = fyg;
      size_t lsize = 0;

      if (fy_generic_builder_linearize(gb, &lv, &lsize) && fy_generic_is_valid(lv)) {
        fy_generic_compare(fyg, lv);
        fy_generic_dump_primitive(null_fp, 0, lv);
      }
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
  T2(test_parser_input_sources);
  T2(test_generic_document_builder);
}

/* path and ypath expressions, walked against the shared corpus document */
void test_path(struct flags_t *flags, const char *data, size_t size) {
  T(test_parse_path);
  T(test_fy_path_expr_build_from_string);
  T(test_ypath_alias);
}

/* reflection: an optional packed FYPG blob, an entry type line, a meta line, a YAML document */
void test_reflection(struct flags_t *flags, const char *data, size_t size) {
  T(test_reflection_type_context);
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
/*
 * One throwaway exec before the fork server starts. Every first-time path
 * then belongs to no exec at all: the TC_SKIP()/G() name caches (a strcmp()
 * on the first exec of each forked child, a byte load after), libc's lazily
 * allocated stdio buffers and locale data, the library's one-time setup.
 * Without it the first input of every child took edges no later one did.
 */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static void warmup_exec(void)
{
  /* all-zero seed: no allocation failure armed (setup_flags()) */
  static const uint8_t in[] = { 0, 0, 0, 0, '{', 'a', ':', ' ', '[', '1', ']', '}', '\n' };

  LLVMFuzzerTestOneInput(in, sizeof(in));
}

int LLVMFuzzerInitialize(int *argc, char ***argv) {
  (void)argc;
  (void)argv;

  corpus_document();
  corpus_ypath_document();
  warmup_exec();
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
  G(test_reflection);

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

int main(int argc, char **argv) {
  return fuzz_replay_main(argc, argv);
}

#endif /* REPRODUCER */

// path group finished - 13.10.2026
// reflection group finished - 21.10.2026
// yaml group finished - 24.10.2026


