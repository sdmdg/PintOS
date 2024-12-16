#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include "filesys/file.h"
#include "threads/synch.h"

void syscall_init (void);

/* Lock to serialize access to the file system. */
struct lock fs_lock;

/* Structure for file descriptor, linking an open file to a descriptor ID. */
struct file_descriptor
{
    struct file *file_ptr;         // Pointer to the file opened by the process.
    int fd;                        // Unique file descriptor ID.
    struct list_elem fd_elem;      // List element for managing file descriptor list.
};

#endif /* userprog/syscall.h */
