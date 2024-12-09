#ifndef MODE_H
#define MODE_H

#include "threads/vaddr.h"

/**< Set the program in test mode. */
#define TEST

/**< Maximum number of arguments to main */
#define MAX_ARGS 32

/**< Used to distinguish user processes */
#define USERMAGIC 0x2f5e734b

/**< Maximum open file */
#define MAX_FILE 32

/**< Maximum length of file name */
#define MAX_FN_LEN 14

/**< Maximum number of processes */
#define NPROC 1024

/**< Number of syscall hash buckets */
#define SC_HASH_BUCKETS 13

/**< Limit stack size to 8 Mb */
#define STACK_LOW (PHYS_BASE - 0x800000)

#undef TEST

/**< Number of frames for each process */
#define NFRAME 16

#define VM

#endif /**< userprog/mode.h */
