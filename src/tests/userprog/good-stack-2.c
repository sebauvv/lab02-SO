/** Almost the same as good-stack, but a lot larger! */

#include "tests/lib.h"
#include "tests/main.h"

void
test_main (void)
{
  /* This user buffer spans across pages */
  char buf[16384];

  int fd = open ("good-stack-2");
  if (fd < 0) {
    exit (1);
  }

  /** should not be killed */
  read (fd, buf, 4096);
  read (fd, buf, 4096);
  read (fd, buf, 8192);

  /* OK */
}
