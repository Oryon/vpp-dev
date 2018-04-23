
#include <srlb/srlb-lru.h>
#include <vppinfra/pool.h>

const char *srlb_lru_cat_strings[SRLB_LRU_CAT_N] = {
#define _(a,b) [SRLB_LRU_CAT_##a] = b,
  foreach_srlb_lru_cat
#undef _
};

#define srlb_lru_enqueue_first(lru, e) \
  (e)->previous = 0; \
  (e)->next = pool_elt_at_index((lru)->elts, 0)->next; \
  pool_elt_at_index((lru)->elts, 0)->next = (e) - (lru)->elts; \
  pool_elt_at_index((lru)->elts, (e)->next)->previous = (e) - (lru)->elts;

#define srlb_lru_enqueue_last(lru, e) \
  (e)->previous = pool_elt_at_index((lru)->elts, 0)->previous; \
  (e)->next = 0; \
  pool_elt_at_index((lru)->elts, 0)->previous = (e) - (lru)->elts; \
  pool_elt_at_index((lru)->elts, (e)->previous)->next = (e) - (lru)->elts;

#define srlb_lru_enqueue_before(lru, e, a) \
  (e)->previous = pool_elt_at_index((lru)->elts, (a) - (lru)->elts)->previous; \
  (e)->next = (a) - (lru)->elts; \
  pool_elt_at_index((lru)->elts, (a) - (lru)->elts)->previous = (e) - (lru)->elts; \
  pool_elt_at_index((lru)->elts, (e)->previous)->next = (e) - (lru)->elts;

#define srlb_lru_dequeue(lru, e) \
  pool_elt_at_index((lru)->elts, (e)->next)->previous = (e)->previous; \
  pool_elt_at_index((lru)->elts, (e)->previous)->next = (e)->next;

#define srlb_lru_last(lru) \
  pool_elt_at_index((lru)->elts, \
                    pool_elt_at_index((lru)->elts, 0)->previous)

static void srlb_lru_renumber_categories (srlb_lru_t *lru)
{
  u32 size = 0;
  srlb_lru_elem_t *e;
  srlb_lru_cat_t cat = 0;
  for (cat = 0 ; cat < SRLB_LRU_CAT_N; cat++)
    {
      srlb_lru_elem_t *bubble = pool_elt_at_index(lru->elts,
                                                   lru->categories[cat].elt_index);
      srlb_lru_dequeue(lru, bubble);
    }

  cat = 0;
  _srlb_lru_foreach_all(lru, e)
    {
      size += e->size;
      while (cat != SRLB_LRU_CAT_N &&
          size >= lru->categories[cat].cumulated_size)
        {
          srlb_lru_elem_t *bubble = pool_elt_at_index(lru->elts,
                                                       lru->categories[cat].elt_index);
          srlb_lru_enqueue_before(lru, bubble, e);
          lru->categories[cat].spare_bytes = lru->categories[cat].cumulated_size + e->size - size;
          cat++;
        }
      e->category = cat;
    }

  /* Some categories bubbles may have been left */
  for ( ; cat < SRLB_LRU_CAT_N; cat ++)
    {
      srlb_lru_elem_t *bubble = pool_elt_at_index(lru->elts,
                                                   lru->categories[cat].elt_index);
      srlb_lru_enqueue_last(lru, bubble);
      lru->categories[cat].spare_bytes = lru->categories[cat].cumulated_size - size;
    }
}

void srlb_lru_init (srlb_lru_t *lru,
                     u32 category_sizes[SRLB_LRU_CAT_N],
                     uword hash_size)
{
  srlb_lru_elem_t *e;
  u32 total = 0;
  srlb_lru_cat_t cat;

  lru->elts = 0;
  lru->hash_size = hash_size;
  hash_size = hash_size / sizeof(flowhash_entry_8_4_t);

  lru->hash = flowhash_alloc_8_4(hash_size, hash_size / 16);
  pool_get(lru->elts, e);
  ASSERT(e == pool_elt_at_index(lru->elts, 0));
  e->hash_index = FLOWHASH_INVALID_ENTRY_INDEX;
  e->next = 0;
  e->previous = 0;
  e->category = ~0;
  e->size = 0;

  flowhash_value(lru->hash, FLOWHASH_INVALID_ENTRY_INDEX)->list_index = 0;

  for (cat = 0; cat < SRLB_LRU_CAT_N; cat++)
    {
      pool_get(lru->elts, e);
      srlb_lru_enqueue_last(lru, e);
      e->category = cat;
      e->hash_index = FLOWHASH_INVALID_ENTRY_INDEX;
      e->size = 0;
      total += category_sizes[cat];
      lru->categories[cat].cumulated_size = total;
      lru->categories[cat].elt_index = e - lru->elts;
    }

  srlb_lru_renumber_categories(lru);
}

void srlb_lru_terminate (srlb_lru_t *lru)
{
  flowhash_free_8_4(lru->hash);
  pool_free(lru->elts);
}

void srlb_lru_resize (srlb_lru_t *lru, u32 sizes[SRLB_LRU_CAT_N])
{
  u32 total = 0;
  srlb_lru_cat_t cat;
  for (cat = 0; cat < SRLB_LRU_CAT_N; cat++)
    {
      total += sizes[cat];
      lru->categories[cat].cumulated_size = total;
    }

  /* Renumber categories */
  srlb_lru_renumber_categories(lru);
}

void srlb_lru_lookup (srlb_lru_t *lru, u64 key,
                       u32 *hash_index)
{
  flowhash_lkey_8_4_t k;
  k.key = key;
  flowhash_get_8_4(lru->hash, &k, flowhash_hash_8_4(&k), 1, hash_index);
  *hash_index = (flowhash_is_timeouted(lru->hash, *hash_index, 1)) ?
      FLOWHASH_INVALID_ENTRY_INDEX : *hash_index;
}

void srlb_lru_lookup_and_promote (srlb_lru_t *lru,
                                  u64 key, u32 size,
                                  u32 *hash_index,
                                  srlb_lru_cat_t *previous_category)
{
  flowhash_lkey_8_4_t k;
  srlb_lru_elem_t *e;
  k.key = key;
  flowhash_get_8_4(lru->hash, &k, flowhash_hash_8_4(&k), 1, hash_index);
  if (PREDICT_FALSE(flowhash_is_overflow(*hash_index)))
    {
      *previous_category = SRLB_LRU_CAT_N;
      return;
    }
  else if (PREDICT_TRUE(flowhash_timeout(lru->hash, *hash_index) == 1))
    {
      /* Entry already exists */
      u32 list_index = flowhash_value(lru->hash, *hash_index)->list_index;
      e = pool_elt_at_index(lru->elts, list_index);
      *previous_category = e->category;
    }
  else
    {
      /* Recycle last element */
      u32 list_index = pool_elt_at_index(lru->elts, 0)->previous;
      e = pool_elt_at_index(lru->elts, list_index);

      /* If the last element is part of the LRU, we cannot remove.
       * So we allocate a new element. */
      if (PREDICT_FALSE(e->category != SRLB_LRU_CAT_N))
        {
          pool_get(lru->elts, e);
          list_index = e - lru->elts;
          srlb_lru_enqueue_last(lru, e);
          e->category = SRLB_LRU_CAT_N;
        }
      else
        {
          /* Invalidate the new  */
          flowhash_timeout(lru->hash, e->hash_index) = 0;
        }

      e->hash_index = *hash_index;
      e->size = size;

      /* Set current value and timeout */
      flowhash_value(lru->hash, *hash_index)->list_index = list_index;
      flowhash_timeout(lru->hash, *hash_index) = 1;

      *previous_category = SRLB_LRU_CAT_N;
    }

  srlb_lru_dequeue(lru, e);
  srlb_lru_enqueue_first(lru, e);

  srlb_lru_cat_t cat, max_cat = e->category;
  e->category = 0;
  for (cat = 0; cat < max_cat; cat++)
    {
      u32 shift = e->size;

      /* There is enough spare space in the category to absorb the
       * addition of the new one. */
      if (lru->categories[cat].spare_bytes >= shift)
        {
          lru->categories[cat].spare_bytes -= shift;
          continue;
        }

      /* Let's absorb what we can. */
      shift -= lru->categories[cat].spare_bytes;

      /* Now let's shift elements from one category to another */
      srlb_lru_elem_t *thresh = pool_elt_at_index(lru->elts,
                                                   lru->categories[cat].elt_index);
      while (thresh->previous != 0)
        {
          /* Swap two elements */
          srlb_lru_elem_t *prev = pool_elt_at_index(lru->elts, thresh->previous);
          prev->next = thresh->next;
          thresh->next = thresh->previous;
          thresh->previous = prev->previous;
          prev->previous = lru->categories[cat].elt_index;

          srlb_lru_elem_t *n = pool_elt_at_index(lru->elts, prev->next);
          n->previous = thresh->next;

          n = pool_elt_at_index(lru->elts, thresh->previous);
          n->next = lru->categories[cat].elt_index;

          /* Move to next category */
          prev->category++;

          /* Remove from LRU if moved after last category. */
          if (PREDICT_FALSE(prev->category == SRLB_LRU_CAT_N))
            {
              flowhash_timeout(lru->hash, prev->hash_index) = 0;
              prev->hash_index = FLOWHASH_INVALID_ENTRY_INDEX;
            }

          /* The previous element is big enough to absorb what remains
           * of the shift. It will be our next. */
          if (prev->size >= shift)
            {
              lru->categories[cat].spare_bytes = prev->size - shift;
              break;
            }

          shift -= prev->size;
        }
    }
}

u8 *format_srlb_lru_category (u8 * s, va_list * va)
{
  srlb_lru_cat_t cat = va_arg (*va, int);
  return (cat >= ARRAY_LEN(srlb_lru_cat_strings))?
      format (s, "invalid"):
      format(s, "%s", srlb_lru_cat_strings[cat]);
}

uword unformat_sixcn_lru_category(unformat_input_t * input, va_list * args)
{
  srlb_lru_cat_t *cat = va_arg (*args, srlb_lru_cat_t *);
  for (*cat = 0; *cat < ARRAY_LEN(srlb_lru_cat_strings); *cat += 1)
    if (unformat(input, srlb_lru_cat_strings[*cat]))
      return 1;

  return 0;
}

#define FORMAT_NEWLINE(s, i) format(s, "\n%U", format_white_space, i)
#define FORMAT_WNL(s, i, ...) format(FORMAT_NEWLINE(s, i), __VA_ARGS__)

u8 *format_srlb_lru_entry_with_verbosity(u8 * s, va_list * va)
{
  srlb_lru_t *lru = va_arg (*va, srlb_lru_t *);
  srlb_lru_elem_t *e = va_arg (*va, srlb_lru_elem_t *);
  int v = va_arg (*va, int);
  u64 id;
  int indent = format_get_indent (s);

  if (e->hash_index == FLOWHASH_INVALID_ENTRY_INDEX)
    s = format(s, "empty %U", format_srlb_lru_category, e->category);
  else
    {
      id = flowhash_key(lru->hash, e->hash_index)->key;
      s = format(s, "%U %dB %U", format_half_ip6_address, id, e->size,
                 format_srlb_lru_category, e->category);
    }

  if (v >= 1)
    {
      s = FORMAT_WNL(s, indent, "  hash-index: %u prev: %u next: %u",
                     e->hash_index, e->previous, e->next);
    }

  return s;
}

u8 *format_srlb_lru_with_verbosity(u8 * s, va_list * va)
{
  srlb_lru_cat_t i;
  uword prev;
  uword indent;

  srlb_lru_t *lru = va_arg (*va, srlb_lru_t *);
  int v = va_arg (*va, int);

  indent = format_get_indent (s);

  s = format(s, "hash-size: %U", format_memory_size, flowhash_memory_size(lru->hash));
  s = FORMAT_WNL(s, indent, "pool-elements: %U", format_memory_size, pool_elts(lru->elts));
  s = FORMAT_WNL(s, indent, "hash-collision-counter: %lu", lru->hash->collision_lookup_counter);
  s = FORMAT_WNL(s, indent, "hash-not_enough_buckets-counter: %lu", lru->hash->not_enough_buckets_counter);

  prev = 0;
  for (i = 0; i < SRLB_LRU_CAT_N; i++)
    {
      s = FORMAT_WNL(s, indent, "  %U: %U", format_srlb_lru_category, i,
                     format_memory_size, lru->categories[i].cumulated_size - prev);
      prev = lru->categories[i].cumulated_size;
    }

  if (v >= 1)
    {
      s = FORMAT_WNL(s, indent, "elements:");
      srlb_lru_elem_t *e;
      srlb_lru_foreach(lru, e)
        s = FORMAT_WNL(s, indent, "  [%u] %U", e - lru->elts, format_srlb_lru_entry_with_verbosity, lru, e, v - 1);
    }

  return s;
}
