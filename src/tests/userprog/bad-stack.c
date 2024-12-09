/** Since you have implemented lazy allocation on stack space, what if
  I set some weird value to esp and treat kernel into thinking that page
  should be allocated? */

#include "tests/lib.h"
#include "tests/main.h"

void
test_main (void)
{
  /** This stack pointer is not valid now! At least it is below 0x804800,
     i.e. the code segment! */
  asm volatile ("movl $0x400, %esp");
  int *invalid_ptr = 0x400;

  for (int i = 0; i < 10; ++i) {
    /** Should not success! */
    invalid_ptr [i] = i * 2;
  }

  exit (0);
}
