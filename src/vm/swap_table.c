#include <string.h>
#include <debug.h>

#include "lib/kernel/bitmap.h"
#include "devices/block.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "vm-util.h"

/** +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
 *                          Helper functions
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+- */

/** For swap table to keep track of used disk spaces. */
static struct bitmap *swap_table_bitmap;

/** Avoid concurrent access to bitmap */
static struct lock stb_bitmap_lock __attribute__((unused));

/** Allocate a consecutive 8 disk blocks to store a memory page,
   Pay attention to how to translate from page index to block no:
   page_idx * 8 => blockno.
 */
static unsigned int
swap_table_alloc_page (void)
{
#ifdef ROBUST
  // validate parameters
  ASSERT (swap_table_bitmap != NULL);
#endif
  for (unsigned i = 0; i < SWAP_PAGES; ++i)
    {
      if (!bitmap_test (swap_table_bitmap, i))
        {
          /* Mark the page as used */
          bitmap_set (swap_table_bitmap, i, 1);
          return i;
        }
    }
  return (unsigned)-1;
}

/** Free a consecutive 8 disk blocks to store a memory page,
   Pay attention to how to translate from page index to block no:
   page_idx * 8 => blockno.
 */
static unsigned int
swap_table_free_page (unsigned int page_idx)
{
#ifdef ROBUST
  // validate parameters
  ASSERT (swap_table_bitmap != NULL);
  ASSERT (page_idx < SWAP_PAGES);
  /* Avoid double free */
  ASSERT (bitmap_test (swap_table_bitmap, page_idx));
#endif
  // free the bit in the map
  bitmap_set (swap_table_bitmap, page_idx, 0);
  return 0;
}

/**
 * Allocate an swap table entry. Panic if cannot allocate.
 */
static inline unsigned int
swap_table_alloc_ste (void)
{
  unsigned int ret = swap_table_alloc_page ();
  /* Add the valid bit */
  return ret | STE_V;
}

/** Free a swap table entry. This is called by swaptb_free. */
static inline void
swap_table_free_ste (unsigned int ste)
{
#ifdef ROBUST
  ASSERT ((ste & STE_V) != 0);
#endif
  swap_table_free_page (ste >> 0x3U);
}

/* Free a swap table directory page. */
static void
swaptb_free_dir (struct swap_table_dir *dir)
{
#ifdef ROBUST
  ASSERT (dir != NULL);
#endif
  unsigned int entry;
  for (int i = 0; i < 1024; ++i)
    {
      /* Get entry */
      entry = dir->entries[i];
      if ((entry & STE_V) != 0)
        {
          swap_table_free_ste (entry);
        }
    }

  /* Free the page occupied by dir */ 
  palloc_free_page ((void *) dir);
}

/** Returns the root index  */
static inline unsigned int
swaptb_root_idx (void *uaddr)
{
#ifndef ROBUST
  return ((unsigned int) uaddr) >> 22U;
#else
  unsigned ret = ((unsigned int) uaddr) >> 22U;
  ASSERT (ret < 1024U);
  return ret;
#endif
}
/** Returns the directory index */
static inline unsigned int
swaptb_dir_idx (void *uaddr)
{
#ifndef ROBUST
  return (((unsigned int) uaddr) << 10U) >> 22U;
#else
  unsigned ret = (((unsigned int) uaddr) << 10U) >> 22U;
  ASSERT (ret < 1024U);
  return ret;
#endif
}

/** 
 * Walk down the swap table for an entry.
 * @param alloc set to 0 if only lookup, set to 1 if allocate entry.
 */
static unsigned int *
swaptb_walk (struct swap_table_root *rt, void *uaddr, int alloc)
{
#ifdef ROBUST
  ASSERT (rt != NULL);
#endif
  struct swap_table_dir *dir;
  unsigned int idx;

  /* Now at root page */
  idx = swaptb_root_idx (uaddr);
  dir = rt->dirs[idx];

  /* directory page not found */
  if (dir == NULL)
    {
      if (alloc) {
        /* Try to install page! */
        void *page = palloc_get_page (0);
        if (page == NULL)
          return NULL;
        memset (page, 0, PGSIZE);
        rt->dirs[idx] = page;
      } else {
        /* Not found */
        return NULL;
      }
    }
  dir = rt->dirs[idx];
  ASSERT (dir != NULL);

  /* Now at directory page */
  idx = swaptb_dir_idx (uaddr);
  return &(dir->entries[idx]);
}

/** +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
 *                          Swap Tables Method
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+- */

unsigned int 
swaptb_alloc_sec (void)
{
#ifdef ROBUST
  unsigned int sec = swap_table_alloc_page (); 
  ASSERT (sec < SWAP_PAGES);
  return sec * 8;
#else
  return 8U * swap_table_alloc_page ();
#endif
}

void 
swaptb_free_sec (unsigned int sec)
{
#ifdef ROBUST
  ASSERT ((sec & 0x7) == 0);
  swap_table_free_page (sec / 8U);
#else
  swap_table_free_page (sec / 8U);
#endif
}

/** Initialize virtual memory */
void 
vm_init (void)
{
#ifdef ROBUST
  /* Validate macro SECTORS_PER_PAGE */
  STATIC_ASSERT (PGSIZE == (SECTORS_PER_PAGE * BLOCK_SECTOR_SIZE));

  /* Test the size of swap table root and directory */
  STATIC_ASSERT (sizeof (struct swap_table_root) == PGSIZE);
  STATIC_ASSERT (sizeof (struct swap_table_dir) == PGSIZE);

  /* Test the size of map file root and directory page */
  STATIC_ASSERT (sizeof (struct map_file_rt) == PGSIZE);
  STATIC_ASSERT (sizeof (struct map_file_dir) == PGSIZE);
#endif

  /* Create a bitmap that supports a swap disk 
    of 16 MB(= 4 * 1024 memory pages), this bitmap is 0.5 KB */
  swap_table_bitmap = bitmap_create (SWAP_PAGES);
  ASSERT (swap_table_bitmap != NULL);

  /** Initially all swap pages is not used(free) */
  for (unsigned int i = 0; i < SWAP_PAGES; ++i)
    {
      bitmap_set (swap_table_bitmap, i, 0);
    }
  
  lock_init (&stb_bitmap_lock);
}

/** Return an initialized swap table, NULL if failure */
struct swap_table_root *
swaptb_create (void)
{
  void *page = palloc_get_page (0);
  if (page != NULL) {
    memset (page, 0, PGSIZE);
  }

  return page;
}

/** Free the space of a swap table and remove reference in the device. */
void 
swaptb_free (struct swap_table_root *rt)
{
#ifdef ROBUST
  /* Validate parameters */
  ASSERT (rt != NULL);
#endif
  struct swap_table_dir *dir;

  for (int i = 0; i < 1024; ++i)
    {
      /* Get directory page */
      dir = rt->dirs[i];
      if (dir == NULL) {
        continue;
      }

      /* Free the directory. */
      swaptb_free_dir (dir);
    }
  
  /* Free the root page. */
  palloc_free_page (rt);
}

/** Given an user address, look up the swap table entry. */
unsigned int *
swaptb_lookup (struct swap_table_root *rt, void *uaddr)
{
  return swaptb_walk (rt, uaddr, 0);
}

/** Returns 1 if maps successfully, 
   0 if cannot allocate pages or mapping already exists. */
int 
swaptb_map (struct swap_table_root *rt, void *uaddr, unsigned int blk)
{
  unsigned int *ste = swaptb_walk (rt, uaddr, 1);
#ifdef ROBUST
  if (ste == NULL)
    {
      /* Report kernel page loss */
      PANIC ("Kernel outof memory!!!");
    }
  if ((*ste & STE_V) != 0)
    {
      return 0;
    }
#else
  if (ste == NULL || (*ste & STE_V) != 0)
    {
      return 0;
    }
#endif  /**< ROBUST */
  ASSERT ((blk & 0X7) == 0);
  *ste = STE_V | blk; 
  return 1;
}

/** Returns 1 if unmap is successful, 0 if the mapping does not exist
   at user virtual address uaddr. */
int 
swaptb_unmap (struct swap_table_root *rt, void *uaddr)
{
  unsigned int *ste = swaptb_walk (rt, uaddr, 0);
  if (ste == NULL || (*ste & STE_V) == 0)
    {
      return 0;
    }
  *ste = 0x0;
  return 1;
}

/** returns the number of pages that resides in swap device. */
unsigned int 
swaptb_count (struct swap_table_root *rt)
{
  unsigned int ret = 0;

  struct swap_table_dir *dir;
  for (int i = 0; i < 1024; ++i)
    {
      dir = rt->dirs[i];
      if (dir == NULL)
        continue;
      for (int j = 0; j < 1024; ++j)
        if (dir->entries[j] & STE_V)
          ret += 1;
    }

  return ret;
}
