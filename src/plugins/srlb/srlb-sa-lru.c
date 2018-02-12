/**
 * Server Agent accept policy based on LRU filtering.
 */

#include <srlb/srlb-lru.h>
#include <srlb/srlb-sa.h>

#include <srlb/srlb-sa-policies.h>
#include <srlb/srlb-lru.h>

#define SRLB_SA_LRU_POLICY_NAME "lru"
#define SRLB_SA_LRU_POLICY_DESCRIPTION "Least Recently Used filter"

typedef struct {
  u64 os_mask;
  i8  os_exp;
  i64  os_add;
  u32 threshold;
  u32 entries;
  srlb_lru_t lru;
  u32 conf_recount;
} srlb_sa_lru_policy_t;

typedef struct {
  srlb_sa_lru_policy_t *policies;
  u32 policy_index;
} srlb_sa_lru_main_t;

static srlb_sa_lru_main_t srlb_sa_lru_main;

static int srlb_sa_ap_lru_accept_fn(u32 ai_index,
                                    u32 remaining_choices,
                                    u64 vip_low)
{
  srlb_sa_lru_main_t *lrum = &srlb_sa_lru_main;
  srlb_lru_cat_t previous_category;
  u32 hash_index;
  u32 opaque = srlb_sa_main.ais[ai_index].policy_opaque;
  srlb_sa_lru_policy_t *lru = pool_elt_at_index(lrum->policies, opaque);
  u64 size = vip_low & lru->os_mask;
  if (lru->os_exp < 0)
    size >>= lru->os_exp;
  else
    size <<= lru->os_exp;
  size += lru->os_add;

  srlb_lru_lookup_and_promote(&lru->lru, vip_low, size, &hash_index,
                              &previous_category);

  u8 accept = previous_category == 0 || remaining_choices == 0;
  SRLB_SA_LOG_DATA("ai_index: %d remaining_choices: %d vip_low: %U category: %U -> %s",
                   ai_index, remaining_choices,
                   format_half_ip6_address, vip_low,
                   format_srlb_lru_category, previous_category,
                   accept?"accept":"reject");

  return !accept;
}

int srlb_sa_ap_lru_conf_ai_fn(u32 ai_index, u8 is_del)
{
  srlb_sa_lru_main_t *lrum = &srlb_sa_lru_main;
  u32 opaque = srlb_sa_main.ais[ai_index].policy_opaque;
  srlb_sa_lru_policy_t *lru = pool_elt_at_index(lrum->policies, opaque);
  lru->conf_recount += is_del?-1:+1;
  return 0;
}

int srlb_sa_lru_config (srlb_sa_lru_config_args_t *args)
{
  srlb_sa_lru_main_t *lrum = &srlb_sa_lru_main;
  srlb_sa_lru_policy_t *lru;

  if (args->flags & SRLB_SA_LRU_FLAGS_DEL)
    {
      /* Deletion */
      if (!(args->flags & SRLB_SA_LRU_FLAGS_OPAQUE_INDEX_SET))
        return VNET_API_ERROR_INVALID_ARGUMENT;

      if (pool_is_free_index(lrum->policies, args->opaque_index))
        return VNET_API_ERROR_NO_SUCH_ENTRY;

      lru = pool_elt_at_index(lrum->policies, args->opaque_index);
      if (lru->conf_recount)
        return VNET_API_ERROR_INSTANCE_IN_USE;

      srlb_lru_terminate(&lru->lru);
      pool_put(lrum->policies, lru);
    }
  else if (args->flags & SRLB_SA_LRU_FLAGS_OPAQUE_INDEX_SET)
    {
      /* Update */
      return VNET_API_ERROR_UNIMPLEMENTED;
    }
  else
    {
      /* Addition */
      if (!(args->flags & SRLB_SA_LRU_FLAGS_OBJECT_SIZE_SET) ||
          !(args->flags & SRLB_SA_LRU_FLAGS_THRESHOLD_SET) ||
          !(args->flags & SRLB_SA_LRU_FLAGS_ENTRIES_SET))
        return VNET_API_ERROR_INVALID_ARGUMENT;

      if (args->os_exp >= 64 || args->os_exp <= -64)
        return VNET_API_ERROR_INVALID_ARGUMENT;

      pool_get(lrum->policies, lru);
      lru->threshold = args->threshold;
      lru->os_mask = args->os_mask;
      lru->os_add = args->os_add;
      lru->os_exp = args->os_exp;
      lru->entries = args->entries;

      u32 cats[SRLB_LRU_CAT_N] = { [0] = lru->threshold };
      srlb_lru_init(&lru->lru, cats,
                    srlb_lru_elts_to_hash_size(lru->entries));

      args->opaque_index = lru - lrum->policies;
    }

  return 0;
}

clib_error_t * srlb_sa_lru_init (vlib_main_t * vm)
{
  srlb_sa_lru_main_t *lrum = &srlb_sa_lru_main;
  lrum->policies = 0;

  srlb_sa_accept_policy_t policy;
  policy.accept = srlb_sa_ap_lru_accept_fn;
  policy.conf_ai = srlb_sa_ap_lru_conf_ai_fn;
  policy.description = SRLB_SA_LRU_POLICY_DESCRIPTION;
  policy.name = SRLB_SA_LRU_POLICY_NAME;
  srlb_sa_accept_policy_register(&policy, &lrum->policy_index);

  return NULL;
}

VLIB_INIT_FUNCTION (srlb_sa_lru_init);

static clib_error_t *
srlb_sa_lru_command_fn (vlib_main_t * vm,
                      unformat_input_t * input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  srlb_sa_lru_config_args_t args = {};
  clib_error_t *error = NULL;
  int rv;

  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, "Missing arguments 🍱");

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat(line_input, "size %U %d %ld",
                   unformat_half_ip6_address, &args.os_mask, &args.os_exp, &args.os_add)) {
          args.flags |= SRLB_SA_LRU_FLAGS_OBJECT_SIZE_SET;
      } else if (unformat(line_input, "threshold %u", &args.threshold)) {
          args.flags |= SRLB_SA_LRU_FLAGS_THRESHOLD_SET;
      } else if (unformat(line_input, "entries %u", &args.entries)) {
          args.flags |= SRLB_SA_LRU_FLAGS_ENTRIES_SET;
      } else if (unformat(line_input, "index %u", &args.opaque_index)) {
                args.flags |= SRLB_SA_LRU_FLAGS_OPAQUE_INDEX_SET;
      } else if (unformat(line_input, "del")) {
          args.flags |= SRLB_SA_LRU_FLAGS_DEL;
      } else {
          error = clib_error_return (0, "parse error: '%U'",
                                     format_unformat_error, line_input);
          goto done;
      }
    }

  if ((rv = srlb_sa_lru_config(&args)))
    error = clib_error_return (0, "srlb_sa_lru_config returned %d", rv);

  if (!(args.flags & SRLB_SA_LRU_FLAGS_OPAQUE_INDEX_SET))
    vlib_cli_output(vm, "opaque_index: %u", args.opaque_index);

done:
  unformat_free (line_input);
  return error;
}

VLIB_CLI_COMMAND (srlb_sa_lru_command, static) =
    {
	.path = "srlb sa lru-policy ",
	.short_help = "srlb sa lru-policy "
	    "[size <ip6-address-mask> <exp> <add>] "
	    "[threshold <threshold>] "
	    "[entries <n>] "
	    "[index <n>] "
	    "[del]",
	    .function = srlb_sa_lru_command_fn,
    };

#define FORMAT_NEWLINE(s, i) format(s, "\n%U", format_white_space, i)
#define FORMAT_WNL(s, i, ...) format(FORMAT_NEWLINE(s, i), __VA_ARGS__)

u8 *format_srlb_sa_lru_policy_with_verbosity (u8 *s, va_list * args)
{
  srlb_sa_lru_policy_t *lru = va_arg (*args, srlb_sa_lru_policy_t *);
  int verbosity = va_arg (*args, int);
  uword i = format_get_indent (s);

  s = format(s, "threshold: %d", lru->threshold);
  s = FORMAT_WNL(s, i, "mask: %U", format_half_ip6_address, &lru->os_mask);
  s = FORMAT_WNL(s, i, "add: %d", lru->os_add);
  s = FORMAT_WNL(s, i, "exp: %d", lru->os_exp);
  s = FORMAT_WNL(s, i, "entries: %d", lru->entries);
  s = FORMAT_WNL(s, i, "references: %d", lru->conf_recount);

  if (verbosity >= 1)
    {
      s = FORMAT_WNL(s, i, "lru:", lru->entries);
      s = FORMAT_WNL(s, i, "  %U", format_srlb_lru_with_verbosity,
                     &lru->lru, verbosity - 1);
    }
  return s;
}

static clib_error_t *
show_srlb_sa_lru_command_fn (vlib_main_t * vm,
                             unformat_input_t * input, vlib_cli_command_t * cmd)
{
  srlb_sa_lru_main_t *lrum = &srlb_sa_lru_main;
  u8 *s = 0;
  int v = 0;
  u32 index = ~0;
  u8 all = 0;
  unformat_input_t _line_input, *line_input = &_line_input;

  if (unformat_user (input, unformat_line_input, line_input))
    {
      while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
        {
          if (unformat (line_input, "%U", unformat_verbosity, &v))
            ;
          else if (unformat (line_input, "%u", &index))
            ;
          else if (unformat (line_input, "all"))
            all = 1;
          else
            {
              clib_error_t *error = clib_error_return (0, "unknown input `%U'",
                                                       format_unformat_error, line_input);
              unformat_free (line_input);
              return error;
            }
        }
      unformat_free (line_input);
    }

  if (index != ~0)
    {
      if (pool_is_free_index(lrum->policies, index))
        return clib_error_return (0, "Invalid index 🍱");

      srlb_sa_lru_policy_t *lru =
          pool_elt_at_index(lrum->policies, index);
      s = format(s, "[%d] %U\n", lru - lrum->policies,
                 format_srlb_sa_lru_policy_with_verbosity, lru, v);
    }
  else if (all)
    {
      srlb_sa_lru_policy_t *lru;
      pool_foreach(lru, lrum->policies, {
          s = format(s, "[%d] %U\n", lru - lrum->policies,
                     format_srlb_sa_lru_policy_with_verbosity, lru, v);
      });
    }
  else
    {
      s = format(s, "policy_index: %d\n", lrum->policy_index);
      s = format(s, "policies: %d", pool_elts(lrum->policies));
    }

  vlib_cli_output(vm, "%v", s);
  vec_free(s);
  return NULL;
}

VLIB_CLI_COMMAND (show_srlb_sa_lru_command, static) =
    {
        .path = "show srlb sa lru-policy ",
        .short_help = "show srlb sa lru-policy "
            "[index <n>|all] [verbose|v<n>] ",
            .function = show_srlb_sa_lru_command_fn,
    };
