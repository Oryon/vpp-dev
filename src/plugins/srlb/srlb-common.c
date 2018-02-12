
#include <srlb/srlb-common.h>

u8 *format_srlb_sa_function (u8 * s, va_list * args)
{
  int fun = (int) va_arg (*args, int);
  const char *n = "";
  switch (fun) {
    case SRLB_SA_FN_CONNECT_IF_AVAILABLE:
      n = "SA.CA 'Connect if Available'";
      break;
    case SRLB_SA_FN_ACK_STICKINESS:
         n = "SA.AS 'Acknowledge Stickiness'";
         break;
    case SRLB_SA_FN_RECOVER_STICKINESS:
         n = "SA.RS 'Recover Stickiness'";
         break;
  }
  return format(s, "%s", n);
}

u8 *format_srlb_lb_function (u8 * s, va_list * args)
{
  srlb_lb_function_t fun = (int) va_arg (*args, int);
  const char *n = "";
  switch (fun) {
    case SRLB_LB_FN_CREATE_STICKINESS:
      n = "LB.CS 'Create Stickiness'";
      break;
    case SRLB_LB_FN_DELETE_STICKINESS:
      n = "LB.DS 'Delete Stickiness'";
      break;
  }
  return format(s, "%d", n);
}


uword
unformat_verbosity (unformat_input_t * input, va_list * args)
{
  int *v = va_arg (*args, int *);
  if (unformat (input, "verbose %d", v))
      ;
  else if (unformat (input, "verbose"))
    *v = 1;
  else if (unformat (input, "very-verbose"))
    *v = 2;
  else if (unformat (input, "v%d", v))
    ;
  else
    return 0;

  return 1;
}

uword
unformat_u32_bitmask_list (unformat_input_t * input, va_list * va)
{
  u32 *bitmap_return = va_arg (*va, u32 *);
  u32 ret = 0;
  u32 a, b;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      int i;
      if (unformat (input, "%u-%u,", &a, &b))
        ;
      else if (unformat (input, "%u,", &a))
        b = a;
      else if (unformat (input, "%u-%u", &a, &b))
        ;
      else if (unformat (input, "%u", &a))
        b = a;
      else if (ret)
        {
          unformat_put_input (input);
          break;
        }
      else
        goto error;

      if (b < a || b >= 32)
        goto error;

      for (i = a; i <= b; i++)
        ret |= (1 << i);
    }
  *bitmap_return = ret;
  return 1;
error:
  return 0;
}

u8 *format_u32_bitmask_list (u8 * s, va_list * args)
{
  u32 bitmask = (u32) va_arg (*args, u32);
  const char *comma = "";
  u8 i;
  u8 a,b;

  for (i = 0; i < 32; i++)
    if (bitmask & (1 << i))
      {
        a = b = i;
        for (i = i + 1; i < 32 && (bitmask & (1 << i)); i++)
          b = i;

        if (a == b)
          s = format (s, "%s%u", comma, a);
        else
          s = format (s, "%s%u-%u", comma, a, b);

        comma = ",";
      }

  return s;
}
