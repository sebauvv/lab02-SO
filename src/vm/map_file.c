#include "userprog/pagedir.h"
#include "vm-util.h"
#include <string.h>

/** +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
 *                      Memory Mapping files
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+- */

/**
 * @return the index into directory pages of a user virtual address.
 */
static inline unsigned int
mf_root_index (void *uaddr)
{
#ifndef ROBUST
  return (unsigned int)(uaddr) >> 22;
#else
  unsigned int ret = (unsigned int)(uaddr) >> 22;
  ASSERT (ret < 1024);
  return ret;
#endif // ROBUST
}

static inline void
mf_validate (struct map_file *mf)
{
  ASSERT (mf->fobj != NULL && mf->read_bytes <= PGSIZE);
}

/**
 * @return the index into map_file pointers of a user virtual address.
 */
static inline unsigned int
mf_dir_index (void *uaddr) {
#ifndef ROBUST
  return ((unsigned int)(uaddr) << 10) >> 22;
#else
  unsigned ret = ((unsigned int)(uaddr) << 10) >> 22;
  ASSERT (ret < 1024);
  return ret;
#endif // ROBUST
}

/** Initialize the file mapping table. */
void *
map_file_init ()
{
  // file map table reside in kernel space.
  void *rt = palloc_get_page (0);
  if (rt != NULL) {
    memset (rt, 0, PGSIZE);
  }
  
  // no directory page should be allocated for now!
  return rt;
}

/** 
 * Destroy the file mapping table. 
 * @param rt root of mapping table allocated by map_file_init().
 */
void 
map_file_clear (void *rt)
{
  if (rt == NULL) { return; }

  // rt is pointer to pointer to directory pages.
  void **dirptr = rt;
  for (int i = 0; i < 1024; ++i) {
    struct map_file **entries = dirptr[i]; 
    if (entries == NULL) {
      // empty entry
      continue;
    }

    // walk deeper and retrive the map file info
    struct map_file *entry;
    for (int j = 0; j < 1024; ++j) {
      entry = entries[j];
      if (entry != NULL) {
        file_close (entry->fobj);
        free (entry);
      }
    }

    // release the directory pages
    palloc_free_page (dirptr[i]);
  }

  // release the root page.
  palloc_free_page (rt);
}

/**
 * Lookup a file mapping in the mapping table.
 * @param rt root of the mapping table.
 * @param uaddr user virtual page(address)
 */
struct map_file *
map_file_lookup (void *rt, void *uaddr)
{
  if (rt == NULL) {
    PANIC ("map file table not initialized");
  }
  unsigned int idx = mf_root_index (uaddr);

  /** Now at root page */
  void **dirptr = rt;
  struct map_file **entries = dirptr[idx];
  if (entries == NULL) {
    return NULL;
  }

  /** Now at directory page */
  idx = mf_dir_index (uaddr);
  return entries[idx];
}

/**
 * Create a file mapping.
 * @param mf struct map_file allocated by malloc.
 * @param uaddr user virtual page
 * @return false if failure, in this case will free(mf).
 */
bool 
map_file (void *rt, struct map_file *mf, void *uaddr)
{
  if (rt == NULL) {
    PANIC ("map file table not initialized");
  }
  unsigned int idx = mf_root_index (uaddr);

  /** Now at root page */
  void **dirptr = rt;

  struct map_file **entries = dirptr[idx];
  if (entries == NULL) {
    /* page is missing, install */
    void *pg = palloc_get_page (0);
    if (pg == NULL) {
      free (mf);
      return false;
    }
    memset (pg, 0, PGSIZE);
    dirptr[idx] = pg;
    entries = dirptr[idx];
  }
  ASSERT (entries != NULL);

  /* Now at directory level, install page */
  idx = mf_dir_index (uaddr);
  if (entries[idx] != NULL) {
    /* Already installed */
    free (mf);
    return false;
  }
  entries[idx] = mf;

  /* Success */
  return true;
}

/** Given the map file obj, fill the content of a user page. */
int
map_file_fill_page (struct map_file *mf, void *upage)
{
  /* Validate parameter */
  if (mf == NULL || upage == NULL) {
    return false;
  }
  mf_validate (mf);

  /* Allocate one kernel page */
  void *kpage = palloc_get_page (PAL_USER);
  if (kpage == NULL) {
    return false;
  }

  /* Read bytes from file */
  if (mf->read_bytes != 0)
    {
      int bytes = file_read_at (mf->fobj, kpage, mf->read_bytes, mf->offset);
      if (bytes != mf->read_bytes) {
        free (kpage);
        return false;
      }
    }

  /* Fill the rest to zero */
  int zero_bytes = PGSIZE - mf->read_bytes;
  if (zero_bytes != 0) {
    memset (kpage + mf->read_bytes, 0, zero_bytes);
  }

  /* Create the file mapping */
  int ret = pagedir_set_page (thread_current ()->pagedir, 
                               upage, kpage, mf->writable);
  if (!ret) {
    free (kpage);
  }
  return ret;
}

/**
 * Initialize a page using the info in the mf.
 * @return 1 on success, 0 if failure(device crash, etc.)
 */
int 
map_file_init_page (struct map_file *mf, void *kpage)
{
  /* Validate parameter */
  if (mf == NULL || kpage == NULL) {
    return false;
  }
  mf_validate (mf);

  /* Read bytes from file */
  if (mf->read_bytes != 0)
    {
      int bytes = file_read_at (mf->fobj, kpage, mf->read_bytes, mf->offset);
      if (bytes != mf->read_bytes) {
        free (kpage);
        return false;
      }
    }

  /* Fill the rest to zero */
  int zero_bytes = PGSIZE - mf->read_bytes;
  if (zero_bytes != 0) {
    memset (kpage + mf->read_bytes, 0, zero_bytes);
  }

  /* Success */
  return true;
}
