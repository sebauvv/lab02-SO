/** Test the correctness of fractional arithmetic package. */

#include "threads/frac.h"
#include "tests.h"
#include <stdio.h>
#include "tests/threads/tests.h"
#include "threads/init.h"
#include "threads/synch.h"
#include "threads/thread.h"

/** Test the addition of fractional numbers. */
void
test_mlfqs_frac_add (void)
{
  frac_t x;
  frac_t y;
  int z;
  frac_t res;

  /* test 1 + 1 = 2. */
  x = frac_from_int (1);
  y = frac_from_int (1);
  res = frac_add (x, y);
  ASSERT (frac_round_int (res) == 2);

  /* test \frac{3}{5} + \frac{7}{5} = 2 */
  x = frac_const (3, 5);
  y = frac_const (7, 5);
  res = frac_add (x, y);
  ASSERT (frac_round_int (res) == 2);

  /* test \frac{12}{5} + 10 = 12.4 \approx 12 */
  x = frac_const (12, 5);
  z = 10;
  res = frac_add_int (x, z);
  ASSERT (frac_round_int (res) == 12);
  ASSERT (frac_to_int (res) == 12);

  /* test \frac{67}{31} + \frac{-231}{23} \approx -7.882 */
  x = frac_const (67, 31);
  y = frac_const (-231, 23);
  res = frac_add (x, y);
  ASSERT (frac_round_int (res) == -8);

  /* OK */
  pass ();
}

/** Test the substraction of frac numbers */
void
test_mlfqs_frac_sub (void)
{
  frac_t x;
  frac_t y;
  int z;
  frac_t res;

  /* test 1 - 1 = 0. */
  x = frac_from_int (1);
  y = frac_from_int (1);
  res = frac_sub (x, y);
  ASSERT (frac_round_int (res) == 0);

  /* test \frac{3}{5} - \frac{7}{5} = -0.8 */
  x = frac_const (3, 5);
  y = frac_const (7, 5);
  res = frac_sub (x, y);
  ASSERT (frac_round_int (res) == -1);

  /* test \frac{-12}{5} - 10 = -12.4 \approx -12 */
  x = frac_const (-12, 5);
  z = 10;
  res = frac_sub (x, frac_const (z, 1));
  ASSERT (frac_round_int (res) == -12);

  /* test \frac{67}{31} - \frac{-231}{23} \approx 12.205 */
  x = frac_const (67, 31);
  y = frac_const (-231, 23);
  res = frac_sub (x, y);
  ASSERT (frac_round_int (res) == 12);

  /* OK */
  pass ();
}

/** Test \\frac{x1}{y1}\\times\\frac{x2}{y2}\\approx res */
static void 
mlfqs_frac_mult_helper (int x1, int y1, int x2, int y2, int res)
{
  ASSERT (y1 > 0 && y2 > 0);
  frac_t x = frac_const (x1, y1);
  frac_t y = frac_const (x2, y2);
  frac_t actual = frac_mult (x, y);

  ASSERT (frac_round_int (actual) == res);
  /* OK, TEST PASSED */
}

/* Test the multiplication of frac */
void
test_mlfqs_frac_mult (void)
{
  /* Test 1 * 1 = 1 */
  mlfqs_frac_mult_helper (1, 1, 2, 2, 1);
  /* Test 1 * (-1) = -1 */
  mlfqs_frac_mult_helper (1, 1, -20, 20, -1);

  /* Test 4 * 7 = 28 */
  mlfqs_frac_mult_helper (12, 3, 147, 21, 28);
  /* Test 13 * (-61) = -793 */
  mlfqs_frac_mult_helper (52, 4, -183, 3, -793);
  /* Test (-2.4) * (-6.3) = 15.12 */
  mlfqs_frac_mult_helper (-12, 5, -63, 10, 15);

  /* Test zero */
  ASSERT (frac_round_int (frac_mult (FRAC_ZERO, FRAC_MAX)) == 0);
  ASSERT (frac_round_int (frac_mult (FRAC_MIN, FRAC_ZERO)) == 0);
  ASSERT (frac_round_int (frac_mult (FRAC_ZERO, FRAC_ZERO)) == 0);

  /* OK */
  pass ();
}

/** Test \\frac{x1}{y1}\\div\\frac{x2}{y2}\\approx res */
static void 
mlfqs_frac_div_helper (int x1, int y1, int x2, int y2, int res)
{
  ASSERT (y1 > 0 && y2 > 0);
  frac_t x = frac_const (x1, y1);
  frac_t y = frac_const (x2, y2);
  frac_t actual = frac_div (x, y);

  ASSERT (frac_round_int (actual) == res);
  /* OK, TEST PASSED */
}

/* Test the division of frac */
void
test_mlfqs_frac_div (void)
{
  /* Test 1 / 1 = 1 */
  mlfqs_frac_div_helper (1, 1, 2, 2, 1);
  /* Test 1 / (-1) = -1 */
  mlfqs_frac_div_helper (1, 1, -20, 20, -1);
  /* Test (-19) / 6 \approx -3 */
  mlfqs_frac_div_helper (-38, 2, 54, 9, -3);

  /* Test 444 / 7 \approx 63 */
  mlfqs_frac_div_helper (888, 2, 56, 8, 63);
  /* Test 137 / (-61) = -2.25 */
  mlfqs_frac_div_helper (137, 1, -122, 2, -2);
  /* Test (-22.4) / (-6.3) = 3.56 */
  mlfqs_frac_div_helper (-112, 5, -63, 10, 4);

  /* Test zero */
  ASSERT (frac_round_int (frac_div (FRAC_ZERO, FRAC_MAX)) == 0);
  ASSERT (frac_round_int (frac_div (FRAC_ZERO, FRAC_MIN)) == 0);

  /* OK */
  pass ();
}

/** Test \frac{x}{y} round zero res */
static void
mlfqs_to_int_helper (int x, int y, int res)
{
  ASSERT (y != 0);
  ASSERT (frac_to_int (frac_const (x, y)) == res);
}

/** Test \frac{x}{y} round res */
static void
mlfqs_round_int_helper (int x, int y, int res)
{
  ASSERT (y > 0);
  ASSERT (frac_round_int (frac_const (x, y)) == res);
}

/** Test conversion to integer */
void
test_mlfqs_to_int (void)
{
  /* start testing */
  mlfqs_to_int_helper (2, 1, 2);
  mlfqs_to_int_helper (-3, 1, -3);
  mlfqs_to_int_helper (0, 1, 0);
  mlfqs_to_int_helper (8, 5, 1);
  mlfqs_to_int_helper (-8, 5, -1);
  mlfqs_to_int_helper (112, 5, 22);
  mlfqs_to_int_helper (-112, 5, -22);
  mlfqs_to_int_helper (1, 60, 0);
  mlfqs_round_int_helper (1, 60, 0);
  mlfqs_round_int_helper (59, 60, 1);
  
  /* OK */
  pass ();
}

/** Test all arithmetics */
void
test_mlfqs_frac_mixed (void)
{
  /* Coefficients used in test */
  const frac_t u = frac_const (59, 60);
  const frac_t v = frac_const (1, 60);
  frac_t x;
  frac_t y;
  frac_t res;  /**< mock thread_load_avg in threads/thread.c */
  frac_t ret;  /**< mock return value from thread_get_load_avg. */

  /** You may have spotted that I'm mocking the process of
     thread_update_load_avg. Good eyes! */

  x = frac_const (0, 1);
  y = frac_const (60, 1);
  res = frac_add (frac_mult (x, u), frac_mult (y, v));
  ret = frac_mult (res, FRAC_HUNDRED);
  ASSERT (frac_round_int (res) == 1);
  ASSERT (frac_round_int (ret) == 100);

  /* update load avg! */
  x = res;
  y = frac_const (60, 1);
  res = frac_add (frac_mult (x, u), frac_mult (y, v));
  ret = frac_mult (res, FRAC_HUNDRED);
  ASSERT (frac_round_int (res) == 2);

  pass ();
}
