#include <stdio.h>
#include <stdlib.h>
#include <random.h>
#include <string.h>

#include "threads/pte.h"
#include "threads/vaddr.h"
#include "threads/interrupt.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "vm-util.h"


/** +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
 *                       Virtual Memory Utility 
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+- */

/** Evict a slot from frame table. */
static unsigned int 
vm_evict (struct thread *cur)
{
  /* Fetch vm members */
  struct process_meta *meta = cur->meta;
  struct frame_table *ftb = &meta->frametb;
  struct swap_table_root *stb = meta->swaptb;
  uint32_t *pgtbl = cur->pagedir;

  /* Use random eviction policy. */
  if (ftb->free_ptr <= 1)
    PANIC ("user pool out of page");
  unsigned int slot;
select:  /* Pin the page on top of stack(i.e. don't evict it) */
  slot = random_ulong () % (unsigned)ftb->free_ptr;
  if (slot == 0U)
    goto select;
  ASSERT (slot < (unsigned)ftb->free_ptr);
  void *uaddr = ftb->upages[slot];

  /* Check the dirty bit of the old page, and write to somewhere */
  if (pagedir_is_writable (cur->pagedir, uaddr))
    {
      /* Write to swap device, first find 8 sectors */
      unsigned int sector = swaptb_alloc_sec ();

      /* Create mapping in the swap table */
      if (!swaptb_map (stb, uaddr, sector))
        PANIC ("Should not fail swap table mapping: at %p", uaddr);

      /* Write to disk, done. */ 
      swaptb_write_page (sector, ftb->pages[slot]);
    }
  else
    {
      /* Ignore(can be load again from file mapping table )*/
    }

  /* Clear the mapping in page directory(Why?). */
  pagedir_clear_page (pgtbl, uaddr);

  /* Clear in the frame table. */
  ftb->upages[slot] = NULL;
  return slot;
}

/** 
 * Allocate a page private to the process. Will NOT make the mapping in the
 * page directory.
 * @param zero if true, initialize the allocated page with 0.
 * @param uaddr user virtual address for the page.
 */
void *
vm_alloc_page (int zero, void *uaddr)
{
  struct thread *cur = thread_current ();
  struct process_meta *meta = cur->meta;
#ifdef ROBUST
  ASSERT (meta != NULL);
  ASSERT (uaddr != NULL);
#endif

  /* Try frame table first */
  void *page = frametb_get_page (&meta->frametb, uaddr, zero);
  if (page != NULL) {
    /* Success! */
    return page;
  }

  /* Must evict a page for allocation */
  unsigned int slot = vm_evict (cur);
#ifdef ROBUST
  ASSERT ((int)slot < meta->frametb.free_ptr);
#endif

  /* Record new user address in frame table. */
  meta->frametb.upages[slot] = pg_round_down (uaddr);

  /* Check and initialize the page */
  if (zero)
    memset (meta->frametb.pages[slot], 0, PGSIZE);

  /* NOTE: This method do not create mapping in pagedir! */
  return meta->frametb.pages[slot];
}

/** Fetch a user page(used on a page fault, will create mapping in pagedir).
 * @return NULL is upage is not a valid user page. else will never
 * return null, rather, find the page and load into frame table.
 */
void *
vm_fetch_page (void *upage)
{
  if (upage == NULL || !is_user_vaddr (upage)) {
    goto vm_not_found;
  }

  /* Fetch vm members */
  struct thread *cur = thread_current ();
  struct process_meta *meta = cur->meta;
  struct frame_table *ftb = &meta->frametb;
  struct swap_table_root *swaptb = meta->swaptb;

  /* Here I do not want to do the following:
    The reason is obvious, on a page fault, the page will definitely not
    be in the page directory. */
#if 0
  void *ret = pagedir_get_page (upage);
  if (ret)
    return ret;
#endif
  /* Try the swap device first. Why? Just consider the following scenario:
    1. a page is located in the bss area;
    2. it was evicted at some time, for it's dirty, it was written to swap dev;
    3. both the swap table and file mapping table contains a copy of the page,
      but only that in the swap table is up-to-date. */
  
  unsigned int *ste = swaptb_lookup (swaptb, upage);
  if (ste != NULL && (*ste & STE_V) != 0)
    {
      /* Get the sector no */
      unsigned sec = ste_get_blockno (*ste);

      /* Allocate a page */
      void *page = vm_alloc_page (0, upage);
      ASSERT (page != NULL); 

      /* Read the content, and free the swap device */
      swaptb_read_page (sec, page);
      swaptb_free_sec (sec);

      /* Install the page */
      pagedir_set_page (cur->pagedir, upage, page, 1);

      /* Manually unmap the page in the swap table */
      *ste = 0x0;

      return page;
    }
  
  /* Not successful, try file mapping instead. */
  struct map_file *mf = map_file_lookup (meta->map_file_rt, upage);
  if (mf == NULL)
    goto vm_not_found;
  void *page = vm_alloc_page (0, upage);
  if (map_file_init_page (mf, page))
    {
      /* Record the mapping in the pagedir */
      pagedir_set_page (cur->pagedir, upage, page, mf->writable);
      return page;
    }
  else 
    {
      /* Clear the page in the mapping */
      for (int i = 0; i < ftb->free_ptr; ++i) {
        if (ftb->pages[i] == page)
          {
            ftb->upages[i] = NULL;
          }
      }
    }

vm_not_found:
  return NULL;
}
