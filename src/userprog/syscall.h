#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

/** System call executor type */
typedef int (*syscall_executor_t)(void *);

/** Syscall hashtable entry */
struct sc_hash_entry {
  tid_t                 key;   /**< Hash table key: process id */
  int                   val;   /**< Hash table value: ret val */
  struct sc_hash_entry *next;  /**< pointer to next entry  */
};

struct sc_hash_table {
  struct sc_hash_entry *buckets[SC_HASH_BUCKETS];
} sc_htable;

struct sc_hash_entry *sc_ht_lookup (tid_t key);
void sc_ht_put (tid_t key, int val);
void sc_ht_rm (tid_t key);

void syscall_init (void);

#endif /**< userprog/syscall.h */
