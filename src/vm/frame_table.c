#include <string.h>

#include "vm-util.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"

/** +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
 *                          Frame Tables
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+- */

/** Initialize a frame table. */
void 
frametb_init (struct frame_table *ftb)
{
#ifdef ROBUST
  ASSERT (ftb != NULL);
#endif
  memset (ftb, 0, sizeof (struct frame_table));
}

/** Get a page from frame table, if not find, return NULL.
 * @param zero if set to 1, then zero out the entire allocated page.
 */
void *
frametb_get_page (struct frame_table *ftb, void *uaddr, int zero)
{
#ifdef ROBUST
  ASSERT (ftb != NULL);
  ASSERT (uaddr != NULL);
  ASSERT (ftb->free_ptr >= 0 && ftb->free_ptr <= NFRAME);
#endif
  if (ftb->free_ptr == NFRAME) {
    /* Cannot record more pages! */
    return NULL;
  }
  void *page = palloc_get_page (PAL_USER | (zero != 0 ? PAL_ZERO : 0));
  if (page != NULL) {
    /* Record the address of the page */
    ftb->pages[ftb->free_ptr] = page;
    ftb->upages[ftb->free_ptr] = pg_round_down (uaddr);
    ftb->free_ptr++;
  }

  return page; 
}

/** Free the entire frame table. */
void 
frametb_free (struct frame_table *ftb)
{
#ifdef ROBUST
  ASSERT (ftb != NULL);
#endif
  struct thread *cur = thread_current ();
  uint32_t *pagedir = cur->pagedir;
  struct process_meta *meta = cur->meta;

  for (int i = 0; i < NFRAME; ++i)
    {
      if (ftb->pages[i] != NULL) {
        palloc_free_page (ftb->pages[i]);

        /* Unmap the page in the pagedir */
        if (ftb->upages[i] != NULL) {
          pagedir_clear_page (pagedir, ftb->upages[i]);
        }
      }
    }
}
