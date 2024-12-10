#include "devices/shutdown.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "mode.h"
#include "userprog/pagedir.h"
#include "process.h"
#include "userprog/syscall.h"
#include <debug.h>
#include <list.h>
#include <stdio.h>
#include <string.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/pte.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

#ifdef VM
#include "vm/vm-util.h"
#endif

static void syscall_handler (struct intr_frame *);

/** Look up a key in the htable,
   returns the pointer to that entry.  */
struct sc_hash_entry *
sc_ht_lookup (tid_t key)
{
  if (key < 0) {
    return NULL;
  }

  struct sc_hash_entry *it = sc_htable.buckets[key % SC_HASH_BUCKETS];

  while (it != NULL) {
    if (it->key == key) {
      return it;
    }
    it = it->next;
  }
  return NULL;
}

/** Put a value in the htable,
   if key exists, overwrite existing value */
void
sc_ht_put (tid_t key, int val)
{
  if (key < 0) {
    return;
  }

  struct sc_hash_entry *it = sc_ht_lookup (key);
  if (it != NULL) {
    /* Overwrite */
    it->val = val;
  } else {
    struct sc_hash_entry *head = sc_htable.buckets[key % SC_HASH_BUCKETS];
    it = malloc (sizeof (struct sc_hash_entry));
    it->next = head;
    it->key = key;
    it->val = val;
    sc_htable.buckets[key % SC_HASH_BUCKETS] = it;
  }
}

/** Remove a key in the hash table. */
void
sc_ht_rm (tid_t key)
{
  if (key < 0) {
    return;
  }

  struct sc_hash_entry *prev = NULL;
  struct sc_hash_entry *cur = sc_htable.buckets[key % SC_HASH_BUCKETS];

  while (cur != NULL) {
    if (cur->key == key) {
      /* remove from the linked list, and free the memory */
      if (prev != NULL) {
        prev->next = cur->next;
      } else {
        /* cur is the head in the list */
        sc_htable.buckets[key % SC_HASH_BUCKETS] = cur->next;
      }
      free (cur);
      break;
    }

    /* Start next iteration */
    prev = cur;
    cur = cur->next;
  }
}

/** List of all processes that is waiting for others to finish */
struct list waiting_process;

/** List of all processes that is waiting for return value from exec. */
struct list exec_process;

/** Record return values of some thread(partially fix to process) */
// int retvals[NPROC] UNUSED;

/** Install pages on stack. */
static void
sc_install_stack (uint32_t *pagetable, void *esp, void *start, void *end)
{
  /* Validate arguments */
  ASSERT (start < end);
  if (esp < 0x8048000 || end > PHYS_BASE || start < esp) {
    /* Fail */
    return;
  }

  void *page = pg_round_down (start);
  for (; page < pg_round_up (end); page += PGSIZE)
    {
      void *kaddr = pagedir_get_page (pagetable, page);
      if (kaddr != NULL) {
        continue;
      }

      /* Try allocate and install */
#ifndef VM
      kaddr = palloc_get_page (PAL_USER);
#else
      kaddr = vm_alloc_page (0, page);
#endif
      if (kaddr == NULL) {
        return;
      }
      pagedir_set_page (pagetable, page, kaddr, true);
    }
}

/** Copy at most bytes from user space, return actual bytes copied.
 * @param pagetable pagetable to lookup.
 * @param uaddr start of user address to copy from.
 * @param kbuf kernel buffer.
 * @return 0x80000000 | bytes if page fault.
 */
static unsigned int
copy_from_user (uint32_t *pagetable, void *uaddr, void *kbuf,
                unsigned int bytes)
{
  /* validate parameters */
  ASSERT (pagetable != NULL && kbuf != NULL);
  if (bytes == 0U) {
    return 0U;
  }
  if (!is_user_vaddr (uaddr)) {
    /* Page fault immediately */
    return 0x80000000;
  }

  /* Once loopup a page, and copy only relevant part. */
  void *ptr = pg_round_down (uaddr);  /**< page-aligned address */
  unsigned int left = bytes;  /**< number of bytes left */
  unsigned int pgleft;        /**< bytes left in a page */
  for (; ptr < PHYS_BASE; )
    {
      void *kaddr = pagedir_get_page (pagetable, ptr);
      if (kaddr == NULL) {
#ifndef VM    /* +-+-+-+-+-+-+-+-+-+- not VM +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-*/
        /* encounter page fault, abort(else will crash!) */
        return (bytes - left) | 0x80000000;
#else         /* +-+-+-+-+-+-+-+-+-+- is VM +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-*/
        if (!process_handle_pgfault (ptr, NULL))
          return (bytes - left) | 0x80000000;
        kaddr = pagedir_get_page (pagetable, ptr);
        ASSERT (kaddr != NULL);
#endif        /* +-+-+-+-+-+-+-+-+-+- end VM +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-*/
      }

      kaddr += uaddr - ptr;
      pgleft = PGSIZE - (uaddr - ptr);
      /* HINT: current memory layout:
               |<   pgleft  >|
        +------+------+------+
        |     userpage       |
        +------+------+------+
        ^ptr   ^uaddr

               |< bytes >|
        +------+------+------+
        |     kernelpage     |
        +------+------+------+
               ^kbuf
       */
      /* copy min(pgleft, left) bytes into kernel buf */
      if (pgleft < left) {
        memmove (kbuf, kaddr, pgleft);
        left -= pgleft;
        kbuf += pgleft;
      } else {
        memmove (kbuf, kaddr, left);
        left = 0;
        /* ignore kbuf for now */
        break;
      }

      /* look into next page; update uaddr */
      ptr += PGSIZE;
      uaddr = ptr;
    }

  return bytes - left;
}

/** Copy a string from user(i.e. until meet character '\0'). WARNING:
 * this function requires you to handle error based on return value!
 * @param pagetable pagetable to lookup
 * @param uaddr start of user address
 * @param kbuf kernel buffer
 * @param bufsz kernel buffer size
 * @return 0: success, 1: (about to) overflow buffer, 2: page fault
 */
static int
cpstr_from_user (uint32_t *pagetable, char *uaddr, char *kbuf,
                 unsigned int bufsz)
{
  /* validate parameters */
  ASSERT (pagetable != NULL && kbuf != NULL);
  if (!is_user_vaddr(uaddr)) {
    return 2;
  }

  /* Once loopup a page, and copy only relevant part. */
  char *ptr = pg_round_down (uaddr);  /**< page-aligned address */
  unsigned int pgleft;        /**< bytes left in a page */
  unsigned int bytes = 0;     /**< bytes write to kbuf */
  for (; ptr < PHYS_BASE; )
    {
      void *kaddr = pagedir_get_page (pagetable, ptr);
      if (kaddr == NULL) {
#ifndef VM    /* +-+-+-+-+-+-+-+-+-+- not VM +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-*/
        /* encounter page fault, abort(else will crash!) */
        return 2;
#else         /* +-+-+-+-+-+-+-+-+-+- is VM +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-*/
        if (!process_handle_pgfault (ptr, NULL))
          return 2;
        kaddr = pagedir_get_page (pagetable, ptr);
        ASSERT (kaddr != NULL);  // ok, continue execution
#endif        /* +-+-+-+-+-+-+-+-+-+- end VM +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-*/
      }

      kaddr += uaddr - ptr;
      pgleft = PGSIZE - (uaddr - ptr);

      /* copy until '\0' or end of page is met. */
      for (unsigned i = 0; i < pgleft; ++i) {
        if (bytes == bufsz) {
          /* Overflow detected! */
          return 1;
        }
        *kbuf = *uaddr;
        ++bytes;
        if (*kbuf == '\0') {
          return 0;
        }
        ++kbuf;   ++uaddr;
      }

      /* look into next page; update uaddr */
      ptr += PGSIZE;
      uaddr = ptr;
    }

  /* ok. */
  return 0;
}

/** Copy to user buffer.
 * @param pagetable user page table
 * @param kbuf start of kernel address
 * @param uaddr user buffer
 * @return number of bytes copied to user buffer, 0x80000000 | bytes
 * on page fault(then the program should terminate with -1).
 */
static unsigned int
copy_to_user (uint32_t *pagetable, void *kbuf, void *uaddr,
              unsigned int bytes, void *esp)
{
  /* validate parameters */
  ASSERT (pagetable != NULL && kbuf != NULL);
  if (bytes == 0U) {
    return 0U;
  }
  if (!is_user_vaddr (uaddr)) {
    /* page fault */
    return 0x80000000;
  }

  /* Once loopup a page, and copy only relevant part. */
  void *ptr = pg_round_down (uaddr);  /**< page-aligned address */
  unsigned int left = bytes;  /**< number of bytes left */
  unsigned int pgleft;        /**< bytes left in a page */
  for (; ptr < PHYS_BASE; )
    {
      void *kaddr = pagedir_get_page (pagetable, ptr);
      if (kaddr == NULL) {
#ifndef VM    /* +-+-+-+-+-+-+-+-+-+- not VM +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-*/
        /* encounter page fault, abort(else will crash!) */
        return 0x80000000 | (bytes - left);
#else         /* +-+-+-+-+-+-+-+-+-+- is VM +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-*/
        if (!process_handle_pgfault (ptr, esp))
          return 0x80000000 | (bytes - left);
        kaddr = pagedir_get_page (pagetable, ptr);
        /* Check invalid write */
        ASSERT (kaddr != NULL);  // ok, continue execution
#endif        /* +-+-+-+-+-+-+-+-+-+- end VM +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-*/
      }
      uint32_t *pte = pagedir_lookup (pagetable, ptr);
        if ((*pte & PTE_W) == 0) /* Access violation */
          return 0x80000000 | (bytes - left);

      kaddr += uaddr - ptr;
      pgleft = PGSIZE - (uaddr - ptr);
      /* copy min(pgleft, left) bytes into kernel buf */
      if (pgleft < left) {
        memmove (kaddr, kbuf, pgleft);
        left -= pgleft;
        kbuf += pgleft;
      } else {
        memmove (kaddr, kbuf, left);
        left = 0;
        /* ignore kbuf for now */
        break;
      }

      /* look into next page; update uaddr */
      ptr += PGSIZE;
      uaddr = ptr;
    }

  return bytes - left;
}

void
syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  list_init (&waiting_process);
  list_init (&exec_process);
  for (int i = 0; i < SC_HASH_BUCKETS; ++i) {
    sc_htable.buckets[i] = NULL;
  }

#ifdef VM
  /* Initialize virtual memory system */
  vm_init ();
#endif
}

/** From interrupt frame, get the system call id. */
static int
syscall_id (struct intr_frame *f)
{
  /** How? lib/user/syscall.c gave me the answer:
     Upon a syscall, the macro syscall0, syscall1, syscall2
     handles system call id and arguments in a consistent way:

     +------------+
     |    args    |
     +------------+
     | syscall-id |
     +------------+ <- esp
   */

  /** At first glance, the return value should be *(int *)(f->esp),
     but don't we need address translation here? why?
     > Q1: what is the operating page table at this point?
     > Q2: if the kernel page table is operating, how do we
     read some bytes from user space?

     Ans: this is one line of output from <syscall_handler+15>:
     "intr frame f is c010afb0, f->esp is bffffe88"
     obviosly intr-frame is in kernel space, and f->esp is in user space.
     Hence *(int *)f->esp is safe.

     Well, I admit to have make a mistake in the comments above.
     child-bad program taught me that you should use safe way to
     access user memory.
   */
  if (!is_user_vaddr (f->esp)) {
    thread_current ()->ticks = -1;
    thread_exit ();
  }
  int id;
  struct thread *cur = thread_current ();
  unsigned int bytes;
  bytes = copy_from_user (cur->pagedir, f->esp, &id, sizeof (id));
  if (bytes != sizeof (id)) {
    /** kill */
    thread_current ()->ticks = -1;
    thread_exit ();
  }
  return id;
}

/** From interrupt frame, locate the argument(s) to syscall.
   The return value can be directly passed to syscall executor.
 */
static void *
syscall_args (struct intr_frame *f)
{
  /** The same as we did in syscall_id. */
  return (f->esp + 4);
}

static int
halt_executor (void *args UNUSED)
{
  /* Shut down the machine */
  shutdown_power_off ();

  /* Will not return */
  return 0;
}

static int
exit_executor (void *args)
{
  /* Syscall start */
  struct intr_frame *f = args;
  void *argv = syscall_args (f);

  struct thread *cur = thread_current ();
  int code = -1;  /**< exit code */
  sc_install_stack (cur->pagedir, f->esp, argv, argv + sizeof (int));
  unsigned ret = copy_from_user (cur->pagedir, argv, &code, sizeof(int));
  if (ret != sizeof(int)) {
    process_terminate (-1);
  }
#ifdef TEST
  printf ("system call exit got %x!\n", code);
#endif
  /* Weird idea: use ticks to store the exit code! */
  cur->ticks = code;
  /* Notice that thread_exit () automatically call process_exit(). */
#ifdef USERPROG
  thread_exit ();
#else
  process_exit ();
  thread_exit ();
#endif /**< USERPROG */
  return 0;
}

/** Other syscall executors(see lib/user/syscall.h) */
static int halt_executor (void *args);
static int exit_executor (void *args);
static int exec_executor (void *args);
static int wait_executor (void *args);
static int create_executor (void *args);
static int remove_executor (void *args);
static int open_executor (void *args);
static int filesize_executor (void *args);
static int read_executor (void *args);
static int write_executor (void *args);
static int seek_executor (void *args);
static int tell_executor (void *args);
static int close_executor (void *args);
static int mmap_executor (void *args);
static int munmap_executor (void *args);

/** list of implemented system calls */
static syscall_executor_t syscall_executors[] =
  {
    [SYS_EXIT] exit_executor,
    [SYS_EXEC] exec_executor,
    [SYS_WAIT] wait_executor,
    [SYS_CREATE] create_executor,
    [SYS_OPEN] open_executor,
    [SYS_READ] read_executor,
    [SYS_WRITE] write_executor,
    [SYS_SEEK] seek_executor,
    [SYS_CLOSE] close_executor,
  };

/** Number of implemented system calls(to detect overflow) */
static const unsigned int
syscall_executor_cnt = (sizeof (syscall_executors)
                      / sizeof (syscall_executors[0]));

static void
syscall_handler (struct intr_frame *f UNUSED)
{
  /* Check if the system call is implemented. */
  int id = syscall_id (f);
  if (id >= 0 && id < syscall_executor_cnt)
    {
      syscall_executor_t executor = syscall_executors[id];
      int ret = executor (f);
      /* set the return value of intr_frame. */
      f->eax = ret;
      return;
    }

  /* pintos -p ../../examples/echo -a echo  -- -f -q run 'echo' */
  /* In the process of implementing system calls, there must be some
    you have not implemented! */
#ifdef TEST
  printf ("intr frame f is %x, f->esp is %x\n", (unsigned)f,
                                                (unsigned)(f->esp));
  ASSERT (is_kernel_vaddr ((void *)f));
  ASSERT (is_user_vaddr (f->esp));
  printf ("system call %d!\n", syscall_id (f));
#endif
  thread_current ()->ticks = -1;
  thread_exit ();
}

static int
exec_executor (void *args)
{
  /* Syscall start */
  struct intr_frame *f = args;
  void *argv = syscall_args (f);

  /** note: prototype is
     pid_t exec (const char *file); */
  char *uaddr;
  struct thread *cur = thread_current ();
  unsigned bytes;

  /* parse arguments */
  char buf[256];
  sc_install_stack (cur->pagedir, f->esp, argv, argv + sizeof (uaddr));
  bytes = copy_from_user (cur->pagedir, argv, &uaddr, sizeof (uaddr));
  if (bytes != sizeof (uaddr)) {
    /* Fatal: not able to fetch args. */
    process_terminate (-1);
  }
  /** CAUTION: buffer overflow(may pass tests) */
  sc_install_stack (cur->pagedir, f->esp, uaddr, uaddr + sizeof (buf));
  int ret = cpstr_from_user (cur->pagedir, uaddr, buf, sizeof (buf));

  /* Error handling */
  switch (ret) {
    case 1: {
      /* Overflow */
      return TID_ERROR;
    }
    case 2: {
      /* page fault, no return */
      process_terminate (-1);
    }
  }

  /* check file exists or not */
  for (int i = 0; i < sizeof (buf); ++i) {
    if (buf[i] == ' ') {
      bytes = 1;
      ret = i;
      break;
    }
    if (buf[i] == '\0') {
      ret = i;
      bytes = 0;
      break;
    }
  }
  buf[ret] = '\0';
  struct file *fobj = filesys_open (buf);
  if (fobj == NULL) {
    return -1;
  }
  file_close (fobj);
  if (bytes)
    buf[ret] = ' ';
  return process_execute (buf);
}

static int
wait_executor (void *args)
{
  /* Syscall start */
  struct intr_frame *f = args;
  void *argv = syscall_args (f);

  /** note: prototype is
     int wait (pid_t);  */
  int tid;
  unsigned int bytes;
  struct thread *cur = thread_current ();

  /* parse arguments */
  sc_install_stack (cur->pagedir, f->esp, argv, argv + sizeof (tid));
  bytes = copy_from_user (cur->pagedir, argv, &tid, sizeof (tid));
  if (bytes != sizeof (tid) || tid == TID_ERROR) {
    return -1;
  }

  /* execute */
  return process_wait (tid);
}

static int
create_executor (void *args)
{
  /* Syscall start */
  struct intr_frame *f = args;
  void *argv = syscall_args (f);

  /** Note: syscall prototype:
    bool create (const char *file, unsigned initial_size);
   */
  char kbuf[16];
  struct thread *cur = thread_current ();

  /* parse args */
  char *uaddr;
  unsigned int init_sz;
  unsigned int bytes;
  sc_install_stack (cur->pagedir, f->esp, argv, argv + 8);
  bytes = copy_from_user (cur->pagedir, argv, &uaddr, sizeof (uaddr));
  if (bytes != sizeof (uaddr)) {
    return 0;
  }
  sc_install_stack (cur->pagedir, f->esp, uaddr, uaddr + sizeof (kbuf));
  bytes = cpstr_from_user (cur->pagedir, uaddr, kbuf, sizeof (kbuf));
  switch (bytes) {
    case 1: {
      return 0;
    }
    case 2: {
      process_terminate (-1);
    }
  }
  bytes = copy_from_user (cur->pagedir, argv + 4, &init_sz, sizeof (init_sz));
  if (bytes != sizeof (init_sz)) {
    return 0;
  }

  /* execute */
  return (int) filesys_create (kbuf, init_sz);
}

static int
remove_executor (void *args)
{
  /* Syscall start */
  struct intr_frame *f = args;
  void *argv = syscall_args (f);

  /** Note of syscall prototypes:
    bool remove (const char *file); */
  char kbuf[16];
  struct thread *cur = thread_current ();

  /* parse args */
  char *uaddr;
  unsigned int bytes;
  sc_install_stack (cur->pagedir, f->esp, argv, argv + 4);
  bytes = copy_from_user (cur->pagedir, argv, &uaddr, sizeof (uaddr));
  if (bytes != sizeof (uaddr)) {
    return 0;
  }
  sc_install_stack (cur->pagedir, f->esp, uaddr, uaddr + 4);
  int ret =cpstr_from_user (cur->pagedir, uaddr, kbuf, sizeof (kbuf));

  /* Error handling */
  switch (ret) {
    case 1: {
      /* file length exceed limit */
      return 0;
    }
    case 2: {
      /* page fault, terminate */
      process_terminate (-1);
    }
  }

  /* execute */
  return filesys_remove (kbuf) ? 1 : 0;
}

/** Returns file descriptor if success; -1 on failure */
static int
open_executor (void *args)
{
  /* Syscall start */
  struct intr_frame *f = args;
  void *argv = syscall_args (f);

  char kbuf[16];  /**< file name is at most 14 bytes */
  struct thread *cur = thread_current ();
  int ret;

  /* parse arguments */
  unsigned int len;
  unsigned int uaddr;  /**< user string addr */
  sc_install_stack (cur->pagedir, f->esp, argv, argv + 4);
  len = copy_from_user (cur->pagedir, argv, &uaddr, sizeof (uaddr));
  if (len != sizeof (uaddr)) {
    return -1;
  }
  sc_install_stack (cur->pagedir, f->esp, uaddr, uaddr + sizeof (kbuf));
  ret = cpstr_from_user (cur->pagedir, (void *)uaddr, kbuf, sizeof (kbuf));

  /* Error handling */
  switch (ret) {
    case 1: {
      /* file length exceed limit */
      return -1;
    }
    case 2: {
      /* page fault, terminate */
      process_terminate (-1);
    }
  }

#ifdef TEST
  /**< test the functionality of cpstr_from_user. */
  printf ("open_executor receive %s\n", kbuf);
#endif
  /* Allocate file descriptor(cheaper) */
  ret = fdalloc ();
  if (ret == -1) {
    /* oops, fail! */
    return -1;
  }

  /* Allocate file object(expensive!) */
  struct file *fobj = filealloc (kbuf);
  if (fobj == NULL) {
    /* oops, fail! */
    return -1;
  }

  /* update process meta */
  struct process_meta *m = cur->meta;
  m->ofile[ret - 2] = fobj;

  /* Success! */
  return ret;
}

static int
filesize_executor (void *args)
{
  /* Syscall start */
  struct intr_frame *f = args;
  void *argv = syscall_args (f);

  /** note: prototype is
     int filesize (int fd); */
  struct thread *cur = thread_current ();
  unsigned int bytes;
  int fd;

  /* Parse args */
  sc_install_stack (cur->pagedir, f->esp, argv, argv + 4);
  bytes = copy_from_user (cur->pagedir, argv, &fd, sizeof (fd));
  if (bytes != sizeof (fd)) {
    return -1;
  }

  /* execute */
  return fdsize (fd);
}

static int
read_executor (void *args)
{
  /* Syscall start */
  struct intr_frame *f = args;
  void *argv = syscall_args (f);

  /** note: prototype of write is
     int read (int fd, void *buffer, unsigned length); */
  struct thread *cur = thread_current ();

  unsigned int bytes;
  /* parameters */
  char *ubuf;        /**< user buffer */
  unsigned int len;  /**< length of read */
  int fd;            /**< file descriptor */

  /* parse params(for now, assume fd == 1) */
  sc_install_stack (cur->pagedir, f->esp, argv, argv + 12);
  bytes = copy_from_user (cur->pagedir, argv, &fd, sizeof (fd));
  if (bytes != sizeof (fd) || fd < 0) {
    return -1;
  }
  bytes = copy_from_user (cur->pagedir, argv + 4, &ubuf, sizeof (ubuf));
  if (bytes != sizeof (ubuf)) {
    return -1;
  }
  bytes = copy_from_user (cur->pagedir, argv + 8, &len, sizeof (len));
  if (bytes != sizeof (len)) {
    return -1;
  }

  /* make a kernel buffer, and print to console */
  if (len == 0) {
    return 0;
  }
  char *kbuf = (char *) malloc (len);
  if (kbuf == NULL) {
    return -1;
  }

  unsigned ret = 0;
  if (fd == 0) {
    /* read len bytes from console */
    for (ret = 0; ret < len; ++ret) {
      kbuf[ret] = input_getc ();
      if (kbuf[ret] == '\n' || kbuf[ret] == '\r') {
        kbuf[ret] = '\n';
        ++ret;
        break;
      }
    }
  } else {
    if (fd == 1) {
      /* Read stdout??? IMPOSSIBLE! */
      return -1;
    }
    struct process_meta *m = cur->meta;
    fd -= 2;
    if (fd >= MAX_FILE || fd < 0 || m->ofile[fd] == NULL) {
      /* invalid fd */
      free (kbuf);
      return -1;
    }
    int fret = file_read (m->ofile[fd], kbuf, len);
    if (fret < 0) {
      /* Warning: unsafe conversion from signed to unsigned */
      free (kbuf);
      return -1;
    }
    ret = fret;
  }
  if (ret) {
    /* If ret == 0(unusual condition), then don't have to install stack! */
    // sc_install_stack (cur->pagedir, f->esp, ubuf, ubuf + ret);
  }
  ret = copy_to_user (cur->pagedir, kbuf, ubuf, ret, f->esp);
  free (kbuf);
  if (ret & 0x80000000) {
    /* page fault detected! */
    process_terminate (-1);
  }

  return ret;
}

static int
write_executor (void *args)
{
  /* Syscall start */
  struct intr_frame *f = args;
  void *argv = syscall_args (f);

  /** note: prototype of write is
     int write (int fd, void *buffer, unsigned length); */
  struct thread *cur = thread_current ();

  unsigned int bytes;
  /* parameters */
  char *ubuf;
  unsigned int len;
  int fd;

  /* parse params(for now, assume fd == 1) */
  sc_install_stack (cur->pagedir, f->esp, argv, argv + 12);
  bytes = copy_from_user (cur->pagedir, argv, &fd, sizeof (fd));
  if (bytes != sizeof (fd) || fd < 0) {
    return -1;
  }
  bytes = copy_from_user (cur->pagedir, argv + 4, &ubuf, sizeof (ubuf));
  if (bytes != sizeof (ubuf)) {
    return -1;
  }
  bytes = copy_from_user (cur->pagedir, argv + 8, &len, sizeof (len));
  if (bytes != sizeof (len)) {
    return -1;
  }

  /* make a kernel buffer, and print to console */
  if (len == 0) {
    return 0;
  }
  char *kbuf = (char *) malloc (len + 1);
  if (kbuf == NULL) {
    return -1;
  }
  kbuf[len] = '\0';

  if (len != 0) {
    // sc_install_stack (cur->pagedir, f->esp, ubuf, ubuf + len);
  }
  unsigned ret = copy_from_user (cur->pagedir, ubuf, kbuf, len);
  if (ret & 0x80000000) {
    /* page fault encountered */
    process_terminate (-1);
  }
  if (fd == 1) {
    printf ("%s", kbuf);
  } else {
    if (fd == 0) {
      /* Write stdin ??? IMPOSSIBLE! */
      return -1;
    }
    struct process_meta *m = cur->meta;
    fd -= 2;
    if (fd >= MAX_FILE || fd < 0 || m->ofile[fd] == NULL) {
      /* invalid fd */
      free (kbuf);
      return -1;
    }
    if (!file_writable (m->ofile[fd])) {
      free (kbuf);
      return 0;
    }
    int fret = file_write (m->ofile[fd], kbuf, len);
    if (fret < 0) {
      /* Warning: unsafe conversion from signed to unsigned */
      free (kbuf);
      return -1;
    }
    ret = fret;
  }
  free (kbuf);

  return ret;
}

static int
tell_executor (void *args)
{
  /* Syscall start */
  struct intr_frame *f = args;
  void *argv = syscall_args (f);

  /** Signature:
     unsigned tell (int fd); */
  int fd;
  unsigned bytes;
  struct thread *cur = thread_current ();

  /** parse args */
  sc_install_stack (cur->pagedir, f->esp, argv, argv + 4);
  bytes = copy_from_user (cur->pagedir, argv, &fd, sizeof (fd));
  if (bytes != sizeof (fd) || fd < 2) {
    /** do not support Console IO */
    return -1;
  }

  /** execute */
  return fdtell (fd);
}

static int
seek_executor (void *args)
{
  /* Syscall start */
  struct intr_frame *f = args;
  void *argv = syscall_args (f);

  /** Signature:
     void seek (int fd, unsigned position); */
  int fd;
  unsigned pos;
  unsigned bytes;
  struct thread *cur = thread_current ();

  /** parse args */
  sc_install_stack (cur->pagedir, f->esp, argv, argv + 8);
  bytes = copy_from_user (cur->pagedir, argv, &fd, sizeof (fd));
  if (bytes != sizeof (fd) || fd < 2) {
    /** do not support Console IO */
    return -1;
  }
  bytes = copy_from_user (cur->pagedir, argv + 4, &pos, sizeof (pos));
  if (bytes != sizeof (pos)) {
    return -1;
  }

  /** execute */
  return fdseek (fd, pos);
}

static int
close_executor (void *args)
{
  /* Syscall start */
  struct intr_frame *f = args;
  void *argv = syscall_args (f);

  int fd;
  unsigned bytes;
  struct thread *cur = thread_current ();

  /* parse arguments */
  sc_install_stack (cur->pagedir, f->esp, argv, argv + 4);
  bytes = copy_from_user (cur->pagedir, argv, &fd, sizeof (fd));
  if (bytes != sizeof (fd)) {
    return -1;
  }

  /* close the file descriptor */
  return fdfree (fd);
}
