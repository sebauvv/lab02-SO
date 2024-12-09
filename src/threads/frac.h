#ifndef THREADS_FRAC_H
#define THREADS_FRAC_H

/** I HAVE PROVIDED NECCESSARY TEST FOR THIS LIB. 
 * SEE root/src/tests/threads/mlfqs-frac.c FOR TEST CASES */

#include <debug.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>

/**< fractional part of frac_t. */
#define FRAC_F (1 << 14)

/** Fixed point number if 17-14 representation.
   See https://pkuflyingpig.gitbook.io/pintos/appendix/4.4bsd-scheduler
   for detailed implementation. OVERFLOW WILL NOT BE CHECKED! */
typedef struct frac 
  {
    int dat;   /**< place to hold the fractional number */
  } 
frac_t;

/** zero in fractional repr */
static const frac_t FRAC_ZERO = {0};
/** max frac number, equivalent to 131071.99 */
static const frac_t FRAC_MAX  = {2147483647};
/** min frac number, equivalent to -131072 */
static const frac_t FRAC_MIN  = {1 << 31};
/** one hundred (useful in thread scheduling) */
static const frac_t FRAC_HUNDRED = {100 * FRAC_F};

/** convert an integer to frac_t */
static frac_t UNUSED
frac_from_int (int val)
{
  frac_t ret;
  ret.dat = val * FRAC_F;
  return ret;
}

/** return \\frac{a}{b} */
static frac_t UNUSED
frac_const (int a, int b)
{
  frac_t ret;
  ret.dat = ((int64_t) a) * FRAC_F / b; 
  return ret;
}

/** convert fractional number to integer (round toward 0) */
static int UNUSED
frac_to_int (frac_t fr)
{
  return fr.dat / FRAC_F;
}

/** convert fractional number to integer (round to nearest) */
static int UNUSED
frac_round_int (frac_t fr)
{
  return fr.dat > 0 ? (fr.dat + FRAC_F / 2) / FRAC_F
                    : (fr.dat - FRAC_F / 2) / FRAC_F;
}

/** compute the sum of two fractional number */
static frac_t UNUSED
frac_add (frac_t first, frac_t second)
{
  frac_t ret;
  ret.dat = first.dat + second.dat;
  return ret;
}

/** compute the sum of fractional and int */
static frac_t UNUSED
frac_add_int (frac_t first, int second)
{
  frac_t ret;
  ret.dat = first.dat + second * FRAC_F;
  return ret;
}

/** compute the difference of two fractional number */
static frac_t UNUSED
frac_sub (frac_t first, frac_t second)
{
  frac_t ret;
  ret.dat = first.dat - second.dat;
  return ret;
}

/** compute the product of two fractional number */
static frac_t UNUSED
frac_mult (frac_t first, frac_t second)
{
  frac_t ret;
  ret.dat = ((int64_t) first.dat) * (second.dat) / FRAC_F; 
  return ret;
}

/** compute the division of fist, second, will check second != 0 */
static frac_t UNUSED
frac_div (frac_t first, frac_t second)
{
  ASSERT (second.dat != 0);
  frac_t ret;
  ret.dat = ((int64_t) first.dat) * FRAC_F / (second.dat);
  return ret;
}

/** return true if first > second */
static bool UNUSED
frac_cmp_g (frac_t first, frac_t second)
{
  return first.dat > second.dat;
}

/** return true if first < second */
static bool UNUSED
frac_cmp_l (frac_t first, frac_t second)
{
  return first.dat < second.dat;
}

#endif /**< threads/frac.h */
