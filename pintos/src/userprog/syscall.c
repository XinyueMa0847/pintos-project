#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/exception.h"
#include "userprog/process.h"
#include "devices/shutdown.h"
static void syscall_handler (struct intr_frame *);


/* Read a byte at user virtual address UADDR, which must be below PHYS_BASE.
  Returns the byte value if successful, -1 if a segfault occured */
static int
get_user (const uint8_t *uaddr)
{
  int result;
  asm ("movl $1f, %0; movzbl %1, %0; 1:"
       : "=&a" (result) : "m" (*uaddr));
  return result;
}

/*Writes BYTE to user address UDST.
UDST must be below PHYS_BASE.
Returns true if successful, false if a segfault occurred. */

static bool
put_user (uint8_t *udst, uint8_t byte)
{
  int error_code;
 asm ("movl $1f, %0; movb %b2, %1; 1:"
     : "=&a" (error_code), "=m" (*udst) : "q" (byte));
 return error_code != -1;
}

/*read ARGCth argument from the stack, it could be an int or another
    pointer*/
static int
read_arg(uint8_t* esp, int* arg)
{
  /*call get_user 4 times to read four consecutive bytes*/
  int b0, b1,b2,b3;
  b0 = get_user(esp);
  b1 = get_user(esp+1);
  b2 = get_user(esp+2);
  b3 = get_user(esp+3);
   
  /*make sure all four bytes are valid*/
  if(b0==-1||b1==-1||b2==-1||b3==-1)
    { return -1;}
  /*construct arg*/
  else
    {
      *arg= ((uint8_t)b0)|((uint8_t)b1<<8)|
	((uint8_t)b2<<16)|((uint8_t)b3<<24);
    }
  return 0;
}

static void
sys_halt(void)
{
  shutdown_power_off();
}

static int
sys_exit(void* esp)
{
  int exit_status;
  if(read_arg((esp+sizeof(int)),&exit_status)==-1)
    {
      thread_exit();
    }
  else{thread_current()->exit_status = exit_status;}
  printf("%s: exit(%d)\n",thread_current()->name, exit_status);
  thread_exit();
  NOT_REACHED();
  return exit_status;
}

static int
sys_wait(void* esp)
{
  int child_tid;
  if(read_arg((esp+sizeof(int)),&child_tid)==-1)
    {
      thread_exit();
    }
  return process_wait((tid_t)child_tid);
}

static int
sys_write(void* esp)
{
  intr_disable();
  intr_enable();
  /* read arguments*/
  int fd,size,buf_ptr;
  if(read_arg((esp+sizeof(int)),&fd)==-1 ||
     read_arg((esp+sizeof(int)*2),&buf_ptr)==-1 ||
     read_arg((esp+sizeof(int)*3),&size)==-1)
    {
      thread_exit();
    }
  if(fd==1){
    putbuf ((const void *)buf_ptr,size);
    return size;
  }
  return 0;
}



void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  if(is_kernel_vaddr(f->esp))
    {
      printf("invalid pointer passed to system call\n");
      thread_exit();
    }
  
   int syscall_num;
  /* validate pointer*/
  if(read_arg(f->esp,&syscall_num)==-1){thread_exit();}
  /*validate syscall number*/
  else
    {
      if(syscall_num<1||syscall_num>19){f->eax=-1;}
      else
  	{
  	  switch(syscall_num)
  	    {
  	      /* Halt the operating system. */
  	    case SYS_HALT:
	      printf("halt()!\n");
  	      shutdown_power_off();
  	      break;
  	    case SYS_EXIT: /* Terminate this process. */
	      //printf("exit()!\n");
  	      f->eax = sys_exit(f->esp);
  	      break;
  	    case SYS_EXEC:                   /* Start another process. */
  	      printf("exec()!");
  	      break;
  	    case SYS_WAIT:                   /* Wait for a child process to die. */
  	      // f->eax = sys_wait(f->esp);
  	      break;
  	    case SYS_CREATE:                 /* Create a file. */
  	      printf("create()!");
  	      break;
  	    case SYS_REMOVE:                 /* Delete a file. */
  	      printf("remove()!");
  	      break;
  	    case SYS_OPEN:                   /* Open a file. */
  	      printf("open()!");
  	      break;
  	    case SYS_FILESIZE:               /* Obtain a file's size. */
  	      printf("filesize()!");
  	      break;
  	    case SYS_READ:                   /* Read from a file. */
  	      printf("read()!");
  	      break;
  	    case SYS_WRITE:                  /* Write to a file. */
  	      //printf("write()!");
  	      f->eax = sys_write(f->esp);
  	      break;
  	    case SYS_SEEK:                   /* Change position in a file. */
  	      printf("seek()!");
  	      break;
  	    case SYS_TELL:                   /* Report current position in a file. */
  	      printf("tell()!");
  	      break;
  	    case SYS_CLOSE:                  /* Close a file. */
  	      printf("close()!");
  	      break;
  	    }
  	}
    }
 
  //printf ("system call!\n");
  //thread_exit ();
}
