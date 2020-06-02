#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include <stdbool.h>
void syscall_init (void);
void file_lock_acquire(void);
void file_lock_release(void);
bool holding_file_lock(void);
int sys_read(void* esp);
#endif /* userprog/syscall.h */

