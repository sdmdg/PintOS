#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "filesys/file.h"
#include <list.h>
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "devices/input.h"
#include "threads/synch.h"
#include "threads/malloc.h"
#include "filesys/filesys.h"
#include "devices/shutdown.h"

/* Definitions for standard input/output */
#define ERROR_STATUS -1
#define CONSOLE_OUTPUT 1
#define KEYBOARD_INPUT 0

/* Function prototypes for system call handling */
static void syscall_handler(struct intr_frame *);
static void exit_syscall(int status);
static tid_t exec_syscall(const char *file_name_);
static int wait_syscall(tid_t tid);
static bool create_syscall(const char *file, unsigned initial_size);
static bool remove_syscall(const char *file);
static int open_syscall(const char *file);
static int filesize_syscall(int fd);
static int read_syscall(int fd, void *buffer, unsigned size);
static int write_syscall(int fd, const void *buffer, unsigned size);
static void seek_syscall(int fd, unsigned position);
static unsigned tell_syscall(int fd);
static void close_syscall(int fd);

/* Helper functions for user memory validation and file descriptor management */
void validate_pointer(const void *_ptr);
void validate_string(const char *_str);
void validate_buffer(const void *buffer, unsigned size);
int *get_pointer_offset(const void *_ptr, int _k);
struct file_descriptor *get_fd_entry(int fd);

/* Initializes system call handling by setting up interrupt and filesystem lock */
void 
syscall_init(void)
{
  lock_init(&fs_lock);
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}

/* Main system call handler that handles system calls based on the number */
static void
syscall_handler(struct intr_frame *frame UNUSED) 
{
    validate_pointer(frame->esp);
    int syscall_code = *get_pointer_offset(frame->esp, 0);

    switch (syscall_code) {
        case SYS_HALT:
            shutdown_power_off();
            break;

        case SYS_EXIT: {
            int exit_status = *get_pointer_offset(frame->esp, 1);
            exit_syscall(exit_status);
            break;
        }

        case SYS_EXEC: {
            char *filename = *(char **)get_pointer_offset(frame->esp, 1);
            validate_string(filename);
            frame->eax = exec_syscall(filename);
            break;
        }

        case SYS_WAIT: {
            tid_t thread_id = *get_pointer_offset(frame->esp, 1);
            frame->eax = wait_syscall(thread_id);
            break;
        }

        case SYS_CREATE: {
            char *filename = *(char **)get_pointer_offset(frame->esp, 1);
            validate_string(filename);
            unsigned file_size = *((unsigned *)get_pointer_offset(frame->esp, 2));
            frame->eax = create_syscall(filename, file_size);
            break;
        }

        case SYS_REMOVE: {
            char *filename = *(char **)get_pointer_offset(frame->esp, 1);
            validate_string(filename);
            frame->eax = remove_syscall(filename);
            break;
        }

        case SYS_OPEN: {
            char *filename = *(char **)get_pointer_offset(frame->esp, 1);
            validate_string(filename);
            frame->eax = open_syscall(filename);
            break;
        }

        case SYS_FILESIZE: {
            int file_descriptor = *get_pointer_offset(frame->esp, 1);
            frame->eax = filesize_syscall(file_descriptor);
            break;
        }

        case SYS_READ: {
            int file_descriptor = *get_pointer_offset(frame->esp, 1);
            void *buffer = (void *)*get_pointer_offset(frame->esp, 2);
            unsigned size = *((unsigned *)get_pointer_offset(frame->esp, 3));
            validate_buffer(buffer, size);
            frame->eax = read_syscall(file_descriptor, buffer, size);
            break;
        }

        case SYS_WRITE: {
            int file_descriptor = *get_pointer_offset(frame->esp, 1);
            void *buffer = (void *)*get_pointer_offset(frame->esp, 2);
            unsigned size = *((unsigned *)get_pointer_offset(frame->esp, 3));
            validate_buffer(buffer, size);
            frame->eax = write_syscall(file_descriptor, buffer, size);
            break;
        }

        case SYS_SEEK: {
            int file_descriptor = *get_pointer_offset(frame->esp, 1);
            unsigned position = *((unsigned *)get_pointer_offset(frame->esp, 2));
            seek_syscall(file_descriptor, position);
            break;
        }

        case SYS_TELL: {
            int file_descriptor = *get_pointer_offset(frame->esp, 1);
            frame->eax = tell_syscall(file_descriptor);
            break;
        }

        case SYS_CLOSE: {
            int file_descriptor = *get_pointer_offset(frame->esp, 1);
            close_syscall(file_descriptor);
            break;
        }

        default:
            // Handle unrecognized system call
            break;
    }
}

/* Exits the program, setting the exit status */
static void
exit_syscall(int exit_code)
{
    struct thread *current_thread = thread_current();
    current_thread->exit_status = exit_code;
    thread_exit();
}

/* Executes a program */
static tid_t
exec_syscall(const char *program_name)
{
    struct thread *parent_thread = thread_current();
    struct thread *child_thread;
    struct list_elem *elem;

    tid_t child_tid = process_execute(program_name);
    if (child_tid == TID_ERROR)
        return child_tid;

    for (elem = list_begin(&parent_thread->child_list);
         elem != list_end(&parent_thread->child_list);
         elem = list_next(elem))
    {
        child_thread = list_entry(elem, struct thread, child_elem);
        if (child_thread->tid == child_tid)
            break;
    }
    if (elem == list_end(&parent_thread->child_list))
        return ERROR_STATUS;

    sema_down(&child_thread->init_sema);
    if (!child_thread->status_load_success)
        return ERROR_STATUS;

    return child_tid;
}

/* Waits for a child process to finish and returns its exit status */
static int
wait_syscall(tid_t thread_id)
{
    return process_wait(thread_id);
}

/* Creates a file with the specified size and filename */
static bool
create_syscall(const char *filename, unsigned file_size)
{
    lock_acquire(&fs_lock);
    bool created = filesys_create(filename, file_size);
    lock_release(&fs_lock);

    return created;
}

/* Removes a file with the given filename */
static bool
remove_syscall(const char *filename)
{
    lock_acquire(&fs_lock);
    bool removed = filesys_remove(filename);
    lock_release(&fs_lock);

    return removed;
}

/* Opens a file and returns a file descriptor or -1 */
static int
open_syscall(const char *filename)
{
    struct file_descriptor *fd_entry = malloc(sizeof(struct file_descriptor));
    struct file *file_ptr;
    struct thread *current_thread;

    lock_acquire(&fs_lock);
    file_ptr = filesys_open(filename);
    lock_release(&fs_lock);

    if (file_ptr == NULL)
        return ERROR_STATUS;

    current_thread = thread_current();
    fd_entry->fd = current_thread->next_fd++;
    fd_entry->file_ptr = file_ptr;
    list_push_back(&current_thread->open_fd_list, &fd_entry->fd_elem);

    return fd_entry->fd;
}

/* Returns the size of the file associated with the given file descriptor */
static int
filesize_syscall(int fd)
{
    struct file_descriptor *fd_entry = get_fd_entry(fd);
    int size;

    if (fd_entry == NULL)
        return ERROR_STATUS;

    lock_acquire(&fs_lock);
    size = file_length(fd_entry->file_ptr);
    lock_release(&fs_lock);

    return size;
}

/* Reads data from a file into a buffer, or from the console for STDIN */
static int
read_syscall(int fd, void *buffer, unsigned size)
{
    struct file_descriptor *fd_entry;
    int bytes_read = 0;

    if (fd == KEYBOARD_INPUT)
    {
        for (unsigned i = 0; i < size; i++)
        {
            *((uint8_t *)buffer + i) = input_getc();
            bytes_read++;
        }
    }
    else if (fd == CONSOLE_OUTPUT)
        return ERROR_STATUS;
    else
    {
        fd_entry = get_fd_entry(fd);
        if (fd_entry == NULL)
            return ERROR_STATUS;

        lock_acquire(&fs_lock);
        bytes_read = file_read(fd_entry->file_ptr, buffer, size);
        lock_release(&fs_lock);
    }

    return bytes_read;
}

/* Writes data to a file or console, depending on the file descriptor */
static int
write_syscall(int fd, const void *buffer, unsigned size)
{
    struct file_descriptor *fd_entry;
    const char *data = (const char *)buffer;
    int bytes_written = 0;

    if (fd == CONSOLE_OUTPUT)
    {
        putbuf(data, size);
        bytes_written = size;
    }
    else if (fd == KEYBOARD_INPUT)
        return ERROR_STATUS;
    else
    {
        fd_entry = get_fd_entry(fd);
        if (fd_entry == NULL)
            return ERROR_STATUS;

        lock_acquire(&fs_lock);
        bytes_written = file_write(fd_entry->file_ptr, data, size);
        lock_release(&fs_lock);
    }

    return bytes_written;
}

/* Sets the position in a file for the given file descriptor */
static void
seek_syscall(int fd, unsigned position)
{
    struct file_descriptor *fd_entry = get_fd_entry(fd);
    if (fd_entry != NULL)
    {
        lock_acquire(&fs_lock);
        file_seek(fd_entry->file_ptr, position);
        lock_release(&fs_lock);
    }
}

/* Retrieves the current position in a file */
static unsigned
tell_syscall(int fd)
{
    unsigned position = 0;
    struct file_descriptor *fd_entry = get_fd_entry(fd);
    if (fd_entry == NULL)
        return position;

    lock_acquire(&fs_lock);
    position = file_tell(fd_entry->file_ptr);
    lock_release(&fs_lock);

    return position;
}

/* Closes a file associated with a given file descriptor */
static void
close_syscall(int fd)
{
    struct file_descriptor *fd_entry = get_fd_entry(fd);
    if (fd_entry != NULL)
    {
        lock_acquire(&fs_lock);
        file_close(fd_entry->file_ptr);
        lock_release(&fs_lock);

        list_remove(&fd_entry->fd_elem);
        free(fd_entry);
    }
}

/* Validates that a pointer is in user space and mapped to a valid page */
void
validate_pointer(const void *pointer)
{
    struct thread *current_thread = thread_current();

    if (pointer == NULL || is_kernel_vaddr(pointer) || pagedir_get_page(current_thread->pagedir, pointer) == NULL)
        exit_syscall(ERROR_STATUS);
}

/* Validates a null-terminated string in user space */
void
validate_string(const char *str)
{
    validate_pointer((void *)str);
    for (int i = 0; *((char *)str + i) != '\0'; i++)
        validate_pointer((void *)(str + i + 1));
}

/* Validates a buffer in user space */
void
validate_buffer(const void *buffer, unsigned size)
{
    for (unsigned i = 0; i < size; i++)
        validate_pointer((char *)buffer + i);
}

/* Gets a pointer to an offset within a user space structure */
int *
get_pointer_offset(const void *ptr, int offset)
{
    int *result_ptr = (int *)ptr + offset;
    validate_pointer((void *)result_ptr);
    validate_pointer((void *)(result_ptr + 1));
    return result_ptr;
}

/* Searches for and returns a file descriptor associated with a given ID */
struct file_descriptor *
get_fd_entry(int fd)
{
    struct thread *current_thread = thread_current();
    struct file_descriptor *fd_entry;
    struct list_elem *elem;

    for (elem = list_begin(&current_thread->open_fd_list);
         elem != list_end(&current_thread->open_fd_list);
         elem = list_next(elem))
    {
        fd_entry = list_entry(elem, struct file_descriptor, fd_elem);
        if (fd_entry->fd == fd)
            return fd_entry;
    }
    return NULL;
}
