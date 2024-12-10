#include "userprog/process.h"
#include <debug.h>
#include <list.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "userprog/gdt.h"
#include "userprog/mode.h"
#include "userprog/pagedir.h"
#include "userprog/syscall.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

#ifdef VM
#include "vm/vm-util.h"
#endif

static thread_func start_process NO_RETURN;
static bool load (char *cmdline, void (**eip) (void), void **esp);

/** Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *file_name)
{
  char *fn_copy;
  tid_t tid;

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page (0);
  if (fn_copy == NULL)
    return TID_ERROR;
  strlcpy (fn_copy, file_name, PGSIZE);

  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create (file_name, PRI_DEFAULT, start_process, fn_copy);
  if (tid == TID_ERROR)
    palloc_free_page (fn_copy);
  /* Suspend execution of current running thread. */
  enum intr_level old_level = intr_disable ();
  struct thread *cur = thread_current ();
  list_push_back (&exec_process, &cur->elem);
  cur->ticks = tid;
  thread_block ();

  /* Reenable interrupts */
  tid = cur->ticks;
  intr_set_level (old_level);
  return tid;
}

/** A thread function that loads a user process and starts it
   running. */
static void
start_process (void *file_name_)
{
  char *file_name = file_name_;
  struct intr_frame if_;
  bool success;

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  success = load (file_name, &if_.eip, &if_.esp);

  /* If load failed, quit. */
  palloc_free_page (file_name);
  /* Wakeup, and tell the parent it started or not. */
  struct thread *cur = thread_current ();
  process_unblock (&exec_process, cur->tid, success ? cur->tid : TID_ERROR);
  if (!success)
    thread_exit ();

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/** Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait (tid_t child_tid UNUSED)
{
  if (child_tid == TID_ERROR) {
    return -1;
  }

  /* turn of interrupt?? */
  struct thread *cur = thread_current ();
  enum intr_level old_level = intr_disable ();

  /* Scan the thread list for the process */
  struct thread *th = thread_lookup (child_tid);
  if (th == NULL || th->status == THREAD_DYING || th->tid == cur->tid) {
    struct sc_hash_entry *entr = sc_ht_lookup (child_tid);
    if (entr == NULL) {
      intr_set_level (old_level);
      return -1;
    }
    int code = entr->val;
    sc_ht_rm (child_tid);
    intr_set_level (old_level);
    return code;
  }

  /* Use the ticks member to record the process cur is waiting */
  cur->ticks = child_tid;
  list_push_back (&waiting_process, &cur->elem);
  thread_block ();
  intr_set_level (old_level);

  /* How do I get the return value of child_tid? */
  int ret = cur->ticks;
  cur->ticks = 0;
  return ret;
}

/** Unblock the thread that is waiting for tid to
  complete. */
void
process_unblock (struct list *lst, tid_t tid, int code)
{
  struct thread *th;
  struct list_elem *e;
  struct list_elem *next;
  if (!list_empty (lst)) {
    for (e = list_begin (lst); e != list_end (lst);
         e = next) {
      next = list_next (e);
      th = list_entry (e, struct thread, elem);
      if ((int)th->ticks == tid) {
        /* remove from the list; unblock */
        list_remove (e);
        thread_unblock (th);

        /* set the exit code! (see syscall.c: exit_executor!) */
        th->ticks = code;
      }
    }
  }
}

/** Print exit status of a process */
static void
print_process (const char *name, int code)
{
  int it = 0;
  while (name[it] == ' ') {
    ++it;
  }

  while (name[it] != ' ' && name[it] != '\0')
    {
      putchar (name[it]);
      ++it;
    }

  printf (": exit(%d)\n", code);
}

/** Free the current process's resources. */
void
process_exit (void)
{
  struct thread *cur = thread_current ();
  uint32_t *pd;

  /** Exercise 1.1: print exit msg */
  int code = cur->ticks;
  struct process_meta *m = cur->meta;
  /* I admit these code are specific to the test case
    sc-bad-arg. PLEASE DO NOT OVERWRITE THE ADDRESS 0xbffffffc,
    FOR IT IS USED TO STORE POINTER TO META. */
  print_process (cur->name, code);
  enum intr_level old_level;
  old_level = intr_disable ();

  LOG ("Process terminated.");
  sc_ht_put (cur->tid, code);
  intr_set_level (old_level);

  /* Close all files associated with the program */
#ifdef TEST
  int closed = 0;  /**< number of files auto closed */
  for (int i = 0; i < MAX_FILE; ++i) {
    if (fdfree (i + 2) == 0) {
      closed++;
    }
  }
  /** check that we have closed right number of files */
  printf ("automatically closed %d file(s)\n", closed);
#else
  for (int i = 0; i < MAX_FILE; ++i) {
    if (m != NULL)
    fdfree (i + 2);
  }
#endif

  /* Free the memory used by metadata */
  struct process_meta **mpp = &cur->meta;
#ifdef TEST
  /**< make sure the right block is freed */
  printf ("free meta addr %x\n", *mpp);
#endif
  if (m != NULL && m->executable != NULL)  /**< close the executable */
  file_close (m->executable);

  if (m == NULL)
    goto unblock_op;
#ifdef VM
   /* Free the members of process_meta */
   if (m->map_file_rt != NULL)
     map_file_clear (m->map_file_rt);

  /* Free the swap table. */
  if (m->swaptb != NULL)
    swaptb_free (m->swaptb);

  /* Free the frame table. */
  frametb_free (&m->frametb);
#endif
  if (m != NULL)
  free (*mpp);

  /* Unblock waiting threads in the list */
  struct thread *th;
  struct list_elem *e;
  struct list_elem *next;
  int has_waiter = 0;
unblock_op:
  if (!list_empty (&waiting_process)) {
    for (e = list_begin (&waiting_process); e != list_end (&waiting_process);
         e = next) {
      next = list_next (e);
      th = list_entry (e, struct thread, elem);
      if ((int)th->ticks == cur->tid) {
        has_waiter = 1;
        th->ticks = cur->ticks;
        /* remove from the list; unblock */
        list_remove (e);
        thread_unblock (th);

        /* set the exit code! (see syscall.c: exit_executor!) */
        th->ticks = cur->ticks;
      }
    }
  }
  if (has_waiter) {
    sc_ht_rm (cur->tid);
  }

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL)
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }
}

/** process_get_page has the same functionality as palloc_get_page.
 * The fundamental difference, however, is that process_get_page is
 * not global.
 */
void *
process_get_page (enum palloc_flags flag)
{
  /** From the designer's perspective, this function is handy for
     implementing lazy memory allocation. However, It is the
     page fault handler's page to require frame and set the correct
     contents. */
  PANIC ("Not implemented");
}

/* terminate an user program with exit code */
void
process_terminate (int code)
{
  thread_current ()->ticks = code;
  thread_exit ();
}

/** Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/** We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/** ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/** For use with ELF types in printf(). */
#define PE32Wx PRIx32   /**< Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /**< Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /**< Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /**< Print Elf32_Half in hexadecimal. */

/** Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/** Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/** Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /**< Ignore. */
#define PT_LOAD    1            /**< Loadable segment. */
#define PT_DYNAMIC 2            /**< Dynamic linking info. */
#define PT_INTERP  3            /**< Name of dynamic loader. */
#define PT_NOTE    4            /**< Auxiliary info. */
#define PT_SHLIB   5            /**< Reserved. */
#define PT_PHDR    6            /**< Program header table. */
#define PT_STACK   0x6474e551   /**< Stack segment. */

/** Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /**< Executable. */
#define PF_W 2          /**< Writable. */
#define PF_R 4          /**< Readable. */

static bool setup_stack (void **esp);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/** Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (char *file_name, void (**eip) (void), void **esp)
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL)
    goto done;
  process_activate ();

  /** A side effect of process_activate is to allocate space for
     metadata. If this fails, terminate the thread. */
  t->meta = malloc (sizeof (struct process_meta));
  if (t->meta == NULL)
    goto done;
  memset (t->meta, 0, sizeof (struct process_meta));

  struct process_meta *meta = t->meta;
#ifdef VM
  /** try initialize file mapping table. */
  meta->map_file_rt = map_file_init ();
  if (meta->map_file_rt == NULL)
    goto done;

  /** try initializing swap table. */
  meta->swaptb = swaptb_create ();
  if (meta->swaptb == NULL)
    goto done;

  /** try initializing the frame table. */
  frametb_init (&meta->frametb);
#endif

  /* Zero out blanks, tabs in file_name */
#ifdef TEST
  printf ("file name is %s\n", file_name);
#endif
  int it;  /**< iterator of file name */
  for (it = 0; file_name[it] != '\0'; ++it)
    {
      if (file_name[it] == ' ' || file_name[it] == '\t')
        {
          file_name[it] = '\0';
        }
    }
  /** length of file name */
  const int fn_len = it;
#ifdef TEST
  printf ("len of file name is %d\n", fn_len);
#endif

  /* Open executable file. */
  file = filesys_open (file_name);
  if (file == NULL)
    goto done;

  file_deny_write (file);
  if (file == NULL)
    {
      printf ("load: %s: open failed\n", file_name);
      goto done;
    }

  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024)
    {
      printf ("load: %s: error loading executable\n", file_name);
      goto done;
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++)
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type)
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file))
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (esp))
    goto done;

  /* Set up process meta */
  ASSERT (sizeof (void *) == 4);
  struct process_meta *mpt = t->meta;
  if (mpt == NULL) {
    /* Oops, fail */
    goto done;
  }

  /** Exercise 5.1: deny write to executable */
  mpt->executable = file;
#ifdef TEST
  printf ("allocate block %x for meta\n", mpt);
#endif

  /* Parse params of the program */
  char *argp = (char *)(PHYS_BASE - fn_len - 5);
  int args = 0;              /**< number of args. */
  char *argv[MAX_ARGS];      /**< my implementation support up to 10 args. */
  bool is_start = true;      /**< is it the start of a "token"? */
  for (i = 0; i <= fn_len; ++i)
    {
      argp[i] = file_name[i];
      if (is_start) {
        if (argp[i] != '\0') {
          argv[args] = argp + i;
          args++;
          is_start = false;
        }
      } else {
        if (argp[i] == '\0') {
          is_start = true;
        }
      }
    }

#ifdef TEST
  printf ("Got %d tokens\n", args);
#endif

  /* Set up argument to main. */
  unsigned bias = (unsigned) argp % 4;
  void *sp = (void *)(argp - bias);
  sp -= 4;
  *(char **)sp = NULL;
  for (i = args - 1; i >= 0; --i) {
    sp -= 4;
    *(char **)sp = argv[i];  /**< argv[i] */
  }
  sp -= 4;
  *(char **)sp = (sp + 4);   /**< argv */
  sp -= 4;
  *(int *)sp = args;         /**< args */
  sp -= 4;
  *(int *)sp = 0;            /**< return address */
  *esp = sp;                 /**< esp */

  /* Set the member of meta: argv */
  mpt->argv = argv[0];
  memset (mpt->ofile, 0, sizeof (mpt->ofile));

#ifdef TEST
  printf ("After passing, esp is %x.\n", (unsigned)sp);
  hex_dump (sp, sp, PHYS_BASE - sp, true);
#endif

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

 done:
  /* We arrive here whether the load is successful or not. */
  return success;
}

/** load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/** Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file)
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
    return false;
  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file))
    return false;
  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz)
    return false;
  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;
  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/** Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable)
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

#ifndef VM
  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0)
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      /* Get a page of memory. */
      uint8_t *kpage = palloc_get_page (PAL_USER);
      if (kpage == NULL)
        return false;

      /* Load this page. */
      if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
        {
          palloc_free_page (kpage);
          return false;
        }
      memset (kpage + page_read_bytes, 0, page_zero_bytes);

      /* Add the page to the process's address space. */
      if (!install_page (upage, kpage, writable))
        {
          palloc_free_page (kpage);
          return false;
        }

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
    }
  return true;
#else  // VM
  struct process_meta *meta = thread_current ()->meta;
  void *rt = meta->map_file_rt;
  while (zero_bytes > 0 || read_bytes > 0)
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      /* Lazily map page */
      struct map_file *mf = malloc (sizeof (struct map_file));
      if (mf == NULL)  // allocation failure
        return false;

      mf->fobj = file_reopen (file);
      mf->writable = writable;
      mf->offset = ofs;
      mf->read_bytes = page_read_bytes;
      if (!map_file (rt, mf, upage)) {
        /** Oops, failure to create mapping */
        return false;
      }

      /** Advance */
      ofs += page_read_bytes;
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
    }

  /* success */
  return true;
#endif // end of VM
}

/** Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp)
{
  uint8_t *kpage;
  bool success = false;

  kpage = palloc_get_page (PAL_USER | PAL_ZERO);

  /* Hack the frame table a little... */
#ifdef VM
  struct thread *cur = thread_current ();
  struct process_meta *meta = cur->meta;
  struct frame_table *ftb = &meta->frametb;
  ASSERT (ftb->free_ptr == 0);
  ftb->free_ptr = 1;
  ftb->pages[0] = kpage;
  ftb->upages[0] = ((uint8_t *) PHYS_BASE) - PGSIZE;
  void *kpage2 = palloc_get_page (PAL_USER);
  if (kpage2 == NULL)
    {
      /* Cannot allocate even 2 user pages?? */
      ftb->pages[0] = NULL;
      ftb->upages[0] = NULL;
      palloc_free_page (kpage);
      /* Let frametb_free call palloc_free_page. */
      return false;
    }

  /* Successfully get 2 user pages. */
  ftb->pages[1] = kpage2;
  ftb->free_ptr = 2;
#endif

  if (kpage != NULL)
    {
      success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
      if (success)
        *esp = PHYS_BASE;
      else {
        palloc_free_page (kpage);

        /* Note that in vm mode, we previously set the frame table. We
          have to avoid double free. */
#ifdef VM
        ftb->pages[0] = NULL;
        ftb->upages[0] = NULL;
#endif
      }
    }
  return success;
}

/** Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}

/** Allocate a file descriptor. Returns -1 if not found */
int
fdalloc (void)
{
  struct process_meta *m = thread_current ()->meta;
  int fd = -1;
  for (int i = 0; i < MAX_FILE; ++i)
    {
      if (m->ofile[i] == 0) {
        /* file descriptor 0, 1 are used
          for console IO. */
        fd = i + 2;
        break;
      }
    }
  return fd;
}

/** Allocate file struct */
struct file *
filealloc (const char *fn)
{
  struct file *ret = filesys_open (fn);
  return ret;
}

/** Free a file descriptor for future use(close the file if opened) */
int
fdfree (int fd)
{
  /** get the index in the array */
  fd -= 2;
  if (fd < 0 || fd >= MAX_FILE) {
    /** invalid fd */
    return -1;
  }

  struct process_meta *m = thread_current ()->meta;
  if (m->ofile[fd] == NULL) {
    /* file not exist or already closed */
    return -1;
  }

  /** close the file */
  file_close (m->ofile[fd]);
  m->ofile[fd] = NULL;
  return 0;
}

/** Seek a position of a given fd */
int
fdseek (int fd, unsigned int pos)
{
  /** get the index in the array */
  fd -= 2;
  if (fd < 0 || fd >= MAX_FILE) {
    /** invalid fd */
    return -1;
  }

  struct process_meta *m = thread_current ()->meta;
  if (m->ofile[fd] == NULL) {
    return -1;
  }

  /** seek the file */
  file_seek (m->ofile[fd], pos);
  return 0;
}

/** Tell the position of a given fd */
int
fdtell (int fd)
{
  fd -= 2;
  if (fd < 0 || fd >= MAX_FILE) {
    /** invalid fd */
    return -1;
  }

  struct process_meta *m = thread_current ()->meta;
  if (m->ofile[fd] == NULL) {
    return -1;
  }

  /** seek the file */
  return file_tell (m->ofile[fd]);
}

/** Returns the size of file associated with fd. */
int
fdsize (int fd)
{
  fd -= 2;
  if (fd < 0 || fd >= MAX_FILE) {
    /** invalid fd */
    return -1;
  }

  struct process_meta *m = thread_current ()->meta;
  if (m->ofile[fd] == NULL) {
    return -1;
  }

  return file_length (m->ofile[fd]);
}
