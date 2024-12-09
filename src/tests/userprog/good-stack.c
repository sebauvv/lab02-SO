/** Write to a buffer that is on stack. But: the kernel
   should realize that it is on the stack! */

#include "tests/lib.h"
#include "tests/main.h"

void
test_main (void)
{
  /* This user buffer spans across pages */
  char buf[4096];

  int fd = open ("good-stack");
  if (fd < 0) {
    exit (1);
  }

  /** should not be killed */
  read (fd, buf, 4096);
}
