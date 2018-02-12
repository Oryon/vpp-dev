
#include <vppinfra/clib.h>

typedef struct {
  /** Object size is computed based on the destination address lower
   * order 64 bits as: (((addr.low & mask) * 2^exp) + add).
   * exp can also be negative, in which case the shift uses >> operand. */
  u64 os_mask;
  i32 os_exp;
  i64 os_add;

  /** The filter will only accept most popular data up to this threshold. */
  u32 threshold;

  /** Maximum number of entries in the LRU filter */
  u32 entries;

  /** Policy index used to identify the policy.
   * When a new policy is created, the value is set by
   * srlb_sa_lru_config. */
  u32 opaque_index;

#define SRLB_SA_LRU_FLAGS_DEL                  1
#define SRLB_SA_LRU_FLAGS_OPAQUE_INDEX_SET     2
#define SRLB_SA_LRU_FLAGS_THRESHOLD_SET        4
#define SRLB_SA_LRU_FLAGS_OBJECT_SIZE_SET      8
#define SRLB_SA_LRU_FLAGS_ENTRIES_SET          16
  u8 flags;
} srlb_sa_lru_config_args_t;

int srlb_sa_lru_config (srlb_sa_lru_config_args_t *args);
