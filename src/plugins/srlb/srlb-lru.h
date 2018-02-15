/*
 * Copyright (c) 2017 Cisco and/or its affiliates.
 *
 *
 * This structure implements a Least Recently Used cache.
 *
 */

#include <vppinfra/types.h>
#include <vppinfra/pool.h>
#include <vppinfra/xxhash.h>
#include <vppinfra/crc32.h>

#ifndef SRC_PLUGINS_SRLB_SRLB_LRU_H_
#define SRC_PLUGINS_SRLB_SRLB_LRU_H_

#ifdef __included_flowhash_template_h__
#undef __included_flowhash_template_h__
#endif

#if defined (__SSE4_2__)
#include <immintrin.h>
#endif

#include <vppinfra/clib.h>

typedef struct { u64 key; } flowhash_skey_8_4_t;

typedef flowhash_skey_8_4_t flowhash_lkey_8_4_t;

typedef struct { u32 list_index; } flowhash_value_8_4_t;

#define FLOWHASH_TYPE _8_4
#include <vppinfra/flowhash_template.h>
#undef FLOWHASH_TYPE

static_always_inline
u32 flowhash_hash_8_4(flowhash_lkey_8_4_t *k)
{
#ifdef clib_crc32c_uses_intrinsics
  return clib_crc32c ((u8 *) &k->key, 8);
#else
  return clib_xxhash (k->key);
#endif
}



static_always_inline
u8 flowhash_cmp_key_8_4(flowhash_skey_8_4_t *a,
                        flowhash_lkey_8_4_t *b)
{
  return a->key != b->key;
}

static_always_inline
void flowhash_cpy_key_8_4(flowhash_skey_8_4_t *dst,
			  flowhash_lkey_8_4_t *src)
{
  dst->key = src->key;
}

#define foreach_srlb_lru_cat \
  _(HOT, "hot") \
  _(WARM, "warm") \
  _(MILD, "mild") \
  _(COLD, "cold")

typedef enum {
#define _(a,b) SRLB_LRU_CAT_##a,
  foreach_srlb_lru_cat
#undef _
  SRLB_LRU_CAT_N
} __attribute__ ((packed)) srlb_lru_cat_t;

extern const char *srlb_lru_cat_strings[SRLB_LRU_CAT_N];

typedef struct {
        u32 previous;
        u32 next;
        u32 size;
        u32 hash_index;
        srlb_lru_cat_t category;
} srlb_lru_elem_t;

typedef struct {
	/**
	 * Pool of chained elements in the LRU.
	 */
	srlb_lru_elem_t *elts;

	/**
	 * Hash table used to find an element in the LRU.
	 */
	flowhash_8_4_t *hash;

	struct {
	  /* Number of elements in the category and previous ones. */
	  u32 cumulated_size;

	  /* Index of the threshold element */
	  u32 elt_index;

	  /* Space not used in the current category */
	  u32 spare_bytes;
	} categories[SRLB_LRU_CAT_N];

	uword hash_size;
} srlb_lru_t;


/**
 * @brief Returns the estimated hash size from an element count.
 */
#define srlb_lru_elts_to_hash_size(elts) \
  ((elts) * sizeof(flowhash_entry_8_4_t))

/**
 * @brief Initializes an LRU structure.
 */
void srlb_lru_init (srlb_lru_t *lru,
                     u32 category_sizes[SRLB_LRU_CAT_N],
                     uword hash_size);

/*
 * @brief Terminates an LRU structure.
 */
void srlb_lru_terminate (srlb_lru_t *lru);

/**
 * @brief Resizes an LRU structure.
 */
void srlb_lru_resize (srlb_lru_t *lru, u32 sizes[SRLB_LRU_CAT_N]);

/**
 * Hash index value returned when no entry could be found, nor created.
 */
#define SRLB_LRU_INVALID_HASH_INDEX FLOWHASH_INVALID_ENTRY_INDEX

/**
 * @brief Lookup key in the lru.
 */
void srlb_lru_lookup (srlb_lru_t *lru, u64 key, u32 *hash_index);

/**
 * @brief Lookup and add/promote key in the lru.
 * The size parameter is only used when inserted for the first time,
 * and ignored afterward.
 */
void srlb_lru_lookup_and_promote (srlb_lru_t *lru,
                                   u64 key, u32 size,
                                   u32 *hash_index,
                                   srlb_lru_cat_t *previous_category);

#define _srlb_lru_foreach_all(lru, e) \
  for (e = pool_elt_at_index((lru)->elts, pool_elt_at_index((lru)->elts, 0)->next); \
      e != pool_elt_at_index((lru)->elts, 0); \
      e = pool_elt_at_index((lru)->elts, (e)->next))

/**
 * @brief Iterates over all LRU entries (Dummy entries included).
 */
#define srlb_lru_foreach(lru, e) \
   _srlb_lru_foreach_all(lru, e) \
     if ( (e)->hash_index != FLOWHASH_INVALID_ENTRY_INDEX )

/**
 * @brief Returns the size of the LRU cache.
 */
#define srlb_lru_size(lru) \
  lru->categories[SRLB_LRU_CAT_N - 1].cumulated_size;

#define srlb_get_elt(lru, hash_index) \
    pool_elt_at_index((lru)->elts, \
                      flowhash_value((lru)->hash, hash_index)->list_index)

u8 *format_srlb_lru_entry_with_verbosity (u8 * s, va_list * va);
u8 *format_srlb_lru_with_verbosity (u8 * s, va_list * va);
uword unformat_srlb_lru_sizes (unformat_input_t * input, va_list * args);

u8 *format_srlb_lru_category (u8 * s, va_list * va);
uword unformat_srlb_lru_category (unformat_input_t * input, va_list * args);

u8 * format_half_ip6_address (u8 * s, va_list * va);
uword unformat_half_ip6_address (unformat_input_t * input, va_list * args);

#endif /* SRC_PLUGINS_SRLB_SRLB_LRU_H_ */
