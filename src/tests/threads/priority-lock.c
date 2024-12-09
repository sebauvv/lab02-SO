/** Tests that lock_release() wakes up the highest-priority thread
   in the waiter list. This test should pass if you have 
   implemented priority donation. If you have not implemented, 
   you can delete the assertions checking priority donation. */

#include <stdio.h>
#include "tests/threads/tests.h"
#include "threads/init.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "devices/timer.h"

static thread_func priority_lock_thread;
static struct lock priority_lock;

/** halt the current running thread for a relatively long time. */
static void
wait_long_time (void) 
{
  /** a little note on why I do not use thread_sleep():
      if we do, it will halt the main thread, and all 
      working thread is in the wait list, then idle thread
      will then take over and halt the CPU! */

  long i = 0;
  while (i < 10000000) {
    ++i;
  }
} 

void
test_priority_lock (void) 
{
  int i;
  
  /* This test does not work with the MLFQS. */
  ASSERT (!thread_mlfqs);

  lock_init (&priority_lock);
  thread_set_priority (PRI_MIN + 1);

  /** main thread hold the lock */
  lock_acquire (&priority_lock);
  msg ("main thread acquires the lock.");

  /* create 10 threads */
  for (i = 0; i < 10; i++) 
    {
      int priority = PRI_DEFAULT - (i + 7) % 10 - 1;
      char name[16];
      snprintf (name, sizeof name, "priority %d", priority);
      thread_create (name, priority, priority_lock_thread, NULL);
    }
  
  /* main thread wait for all 10 threads to be blocked, 
     and release the lock. */
  wait_long_time ();

  /* check that main thread is holding the lock. */
  ASSERT (priority_lock.holder == thread_current ());
  /* simply check that main thread have borrowed priority. */
  ASSERT (thread_get_priority () == 30);
  /* simply check that main thread's actual priority does not change! */
  ASSERT (thread_get_actual_priority () == PRI_MIN + 1);
  /* check the status of the semaphore inside the lock. */
  ASSERT (sema_priority (&priority_lock.semaphore) == 30);

  /* Now the main thread release the lock. */
  msg ("main thread releases the lock.");
  lock_release (&priority_lock);

  /* ideally, the thread would be running in order. */
  wait_long_time ();
}

static void
priority_lock_thread (void *aux UNUSED) 
{
  msg ("Thread %s starting.", thread_name ());
  /* make the thread in the wait list(i.e. blocked) */
  lock_acquire (&priority_lock);
  msg ("Thread priority %d acquires the lock.", thread_current ()->priority);
  
  /* decrease the priority, and release the lock. */
  thread_set_priority (PRI_MIN + 2);
  lock_release (&priority_lock);
}
