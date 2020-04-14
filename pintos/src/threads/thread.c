#include "threads/thread.h"
#include <debug.h>
#include <stddef.h>
#include <random.h>
#include <stdio.h>
#include <string.h>
#include "threads/flags.h"
#include "threads/interrupt.h"
#include "threads/intr-stubs.h"
#include "threads/palloc.h"
#include "threads/switch.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "threads/fixed-points.h" 
#include <limits.h> 	
#ifdef USERPROG
#include "userprog/process.h"
#endif

/* Random value for struct thread's `magic' member.
   Used to detect stack overflow.  See the big comment at the top
   of thread.h for details. */
#define THREAD_MAGIC 0xcd6abf4b

/* [20170765] maximum and minimum of nice value that a thread can have*/
#define NICE_MAX 20
#define NICE_MIN -20

/* List of processes in THREAD_READY state, that is, processes
   that are ready to run but not actually running. */
static struct list ready_list;

/* List of all processes.  Processes are added to this list
   when they are first scheduled and removed when they exit. */
static struct list all_list;

/* [20170765] list of all process in THREAD_BLOCKED state. 
Processes in this list are either sleeping until certain time,
 or waiting for either a lock, sema or cond*/
static struct list sleep_list;


/* Idle thread. */
static struct thread *idle_thread;

/* Initial thread, the thread running init.c:main(). */
static struct thread *initial_thread;

/* Lock used by allocate_tid(). */
static struct lock tid_lock;

/* Stack frame for kernel_thread(). */
struct kernel_thread_frame 
  {
    void *eip;                  /* Return address. */
    thread_func *function;      /* Function to call. */
    void *aux;                  /* Auxiliary data for function. */
  };

/* Statistics. */
static long long idle_ticks;    /* # of timer ticks spent idle. */
static long long kernel_ticks;  /* # of timer ticks in kernel threads. */
static long long user_ticks;    /* # of timer ticks in user programs. */

/* Scheduling. */
#define TIME_SLICE 4            /* # of timer ticks to give each thread. */
static unsigned thread_ticks;   /* # of timer ticks since last yield. */


/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
bool thread_mlfqs;

/* [20170765] Only used in 4.4BSD scheduler*/
static f_p load_avg;		/* the average load of the cpu*/
static int ready_threads;	/* # of threads in ready lists or
                                     threads that are running*/


static void kernel_thread (thread_func *, void *aux);

static void idle (void *aux UNUSED);
static struct thread *running_thread (void);
static struct thread *next_thread_to_run (void);
static void init_thread (struct thread *, const char *name, int priority);
static bool is_thread (struct thread *) UNUSED;
static void *alloc_frame (struct thread *, size_t size);
static void schedule (void);
void thread_schedule_tail (struct thread *prev);
static tid_t allocate_tid (void);
bool priority_compare (const struct list_elem *a, const struct list_elem *b,
			      void *aux UNUSED);
bool sleep_compare (const struct list_elem *a, const struct list_elem *b,
                                   void *aux UNUSED);

/* Initializes the threading system by transforming the code
   that's currently running into a thread.  This can't work in
   general and it is possible in this case only because loader.S
   was careful to put the bottom of the stack at a page boundary.

   Also initializes the run queue and the tid lock.

   After calling this function, be sure to initialize the page
   allocator before trying to create any threads with
   thread_create().

   It is not safe to call thread_current() until this function
   finishes. */
void
thread_init (void) 
{
  ASSERT (intr_get_level () == INTR_OFF);

  lock_init (&tid_lock);
  list_init (&ready_list);
  list_init (&all_list);
  list_init (&sleep_list);

  /* Set up a thread structure for the running thread. */
  initial_thread = running_thread ();
  init_thread (initial_thread, "main", PRI_DEFAULT);
  initial_thread->status = THREAD_RUNNING;
  initial_thread->tid = allocate_tid ();

  /* [20170765] Initialize nice value and recent cpu*/
  initial_thread->nice = 0;
  initial_thread->recent_cpu=0;
}

/* Starts preemptive thread scheduling by enabling interrupts.
   Also creates the idle thread. */
void
thread_start (void) 
{
  /* Create the idle thread. */
  struct semaphore idle_started;
  sema_init (&idle_started, 0);
  thread_create ("idle", PRI_MIN, idle, &idle_started);

  /* Start preemptive thread scheduling. */
  intr_enable ();

  /* Wait for the idle thread to initialize idle_thread. */
  sema_down (&idle_started);
}

/* Called by the timer interrupt handler at each timer tick.
   Thus, this function runs in an external interrupt context. */
void
thread_tick (void) 
{
  struct thread *t = thread_current ();

  /* Update statistics. */
  if (t == idle_thread)
    idle_ticks++;
#ifdef USERPROG
  else if (t->pagedir != NULL)
    user_ticks++;
#endif
  else
    kernel_ticks++;

  /* Enforce preemption. */
  if (++thread_ticks >= TIME_SLICE)
    intr_yield_on_return ();
}

/* Prints thread statistics. */
void
thread_print_stats (void) 
{
  printf ("Thread: %lld idle ticks, %lld kernel ticks, %lld user ticks\n",
          idle_ticks, kernel_ticks, user_ticks);
}

/* Creates a new kernel thread named NAME with the given initial
   PRIORITY, which executes FUNCTION passing AUX as the argument,
   and adds it to the ready queue.  Returns the thread identifier
   for the new thread, or TID_ERROR if creation fails.

   If thread_start() has been called, then the new thread may be
   scheduled before thread_create() returns.  It could even exit
   before thread_create() returns.  Contrariwise, the original
   thread may run for any amount of time before the new thread is
   scheduled.  Use a semaphore or some other form of
   synchronization if you need to ensure ordering.

   The code provided sets the new thread's `priority' member to
   PRIORITY, but no actual priority scheduling is implemented.
   Priority scheduling is the goal of Problem 1-3. 

   [20170765]If thread_mlfq == 0, the advanced scheduler is off, 
    then this function will create a thread with priority 
    specified in the parameter. If the advanced 4.4 BSD scheduler 
    is on, this function will ignore the parameter specified, 
    and inherit priority along with its nice and recent_cpu 
    from its parent. */
tid_t
thread_create (const char *name, int priority,
               thread_func *function, void *aux) 
{
  struct thread *t;
  struct kernel_thread_frame *kf;
  struct switch_entry_frame *ef;
  struct switch_threads_frame *sf;
  tid_t tid;
  enum intr_level old_level;

  ASSERT (function != NULL);

  /* Allocate thread. */
  t = palloc_get_page (PAL_ZERO);
  if (t == NULL)
    return TID_ERROR;

  /* Initialize thread. */
  init_thread (t, name, priority);
  tid = t->tid = allocate_tid ();

  /*parent thread, where the new thread will inherit nice and recent_cpu from*/
  struct thread* parent = thread_current();

  /* Prepare thread for first run by initializing its stack.
     Do this atomically so intermediate values for the 'stack' 
     member cannot be observed. */
  old_level = intr_disable ();

  /* Stack frame for kernel_thread(). */
  kf = alloc_frame (t, sizeof *kf);
  kf->eip = NULL;
  kf->function = function;
  kf->aux = aux;

  /* Stack frame for switch_entry(). */
  ef = alloc_frame (t, sizeof *ef);
  ef->eip = (void (*) (void)) kernel_thread;

  /* Stack frame for switch_threads(). */
  sf = alloc_frame (t, sizeof *sf);
  sf->eip = switch_entry;
  sf->ebp = 0;

   /* [20170765] only used for 4.4 BSD scheduler*/
  if(thread_mlfqs)
    {
      t->nice = parent->nice;
      t->recent_cpu = parent->recent_cpu;
      /*since t inherits nice and recent cpu from parent, it also
	inherits the parent's priority*/
      t->priority = parent->priority;
    }

  intr_set_level (old_level);

  /* Add to run queue. */ //meaning insert to ready_list
  thread_unblock (t);

  //compare priority with the running thread,and preempt if possible
  check_preempt_current();

  return tid;
}

/* Puts the current thread to sleep.  It will not be scheduled
   again until awoken by thread_unblock().

   This function must be called with interrupts turned off.  It
   is usually a better idea to use one of the synchronization
   primitives in synch.h. */
void
thread_block (void) 
{
  ASSERT (!intr_context ());
  ASSERT (intr_get_level () == INTR_OFF);

  thread_current ()->status = THREAD_BLOCKED;
  schedule ();
}

/* Transitions a blocked thread T to the ready-to-run state.
   This is an error if T is not blocked.  (Use thread_yield() to
   make the running thread ready.)

   This function does not preempt the running thread.  This can
   be important: if the caller had disabled interrupts itself,
   it may expect that it can atomically unblock a thread and
   update other data. 
 
 [20170765] when inserting the to-sleep thread to sleep_list,
  it is inserted in the older of the thread's priority, by using
  list_insert_ordered with the comparator "priority_compare".

  After it is in the ready queue, check_preempt_current()
  is called. If thread t has the higher priority than the 
  running thread, it will preempt the current thread immediately. */
void
thread_unblock (struct thread *t) 
{
  enum intr_level old_level;

  ASSERT (is_thread (t));

  old_level = intr_disable ();
  ASSERT (t->status == THREAD_BLOCKED);
  list_insert_ordered(&ready_list,&t->elem,priority_compare,NULL);
  t->status = THREAD_READY;
  t->wake_up_at = INT_MAX;

  //preemption
  check_preempt_current();
  intr_set_level (old_level);
}

/* [20170765] called by timer_sleep(), make the current running 
  thread sleep until TICKS ticks has passed. 
  This function will insert the thread's sleepelem into sleep_list,
  sorted by its priority, and set its waking up time to ticks. 
  Then it will call thread_block to block this thread
  and schedule again.
*/
void thread_sleep(int64_t ticks)
{
  struct thread* cur;
  enum intr_level old_level;

  ASSERT(!intr_context());
  
  cur = thread_current();
  
  old_level = intr_disable();
  if(cur!=idle_thread)
    {
      list_insert_ordered(&sleep_list,&cur->sleepelem,sleep_compare,NULL);
      cur->wake_up_at = ticks;
    }
  thread_block();
  intr_set_level(old_level);
}

/* [20170765] called by timer_interrupt() at every tick to wake up 
any threads if their wake up time has come. That is, the global tick
is larger or equal to the thread's wake up time. 
*/
void thread_wake(int64_t ticks)
{

  if(list_empty(&sleep_list)){return;}
  struct list_elem *e = list_begin(&sleep_list);
  while(e!=list_end(&sleep_list))
    {
      struct thread* sleeping = list_entry(e,struct thread,sleepelem);
      if(ticks>=sleeping->wake_up_at)
	{
	  list_remove(&sleeping->sleepelem);
	  thread_unblock(sleeping);
	}
      e=list_next(e);
    }



}


/* Returns the name of the running thread. */
const char *
thread_name (void) 
{
  return thread_current ()->name;
}

/* Returns the running thread.
   This is running_thread() plus a couple of sanity checks.
   See the big comment at the top of thread.h for details. */
struct thread *
thread_current (void) 
{
  struct thread *t = running_thread ();
  
  /* Make sure T is really a thread.
     If either of these assertions fire, then your thread may
     have overflowed its stack.  Each thread has less than 4 kB
     of stack, so a few big automatic arrays or moderate
     recursion can cause stack overflow. */
  ASSERT (is_thread (t));
  ASSERT (t->status == THREAD_RUNNING);

  return t;
}

/* Returns the running thread's tid. */
tid_t
thread_tid (void) 
{
  return thread_current ()->tid;
}

/* Deschedules the current thread and destroys it.  Never
   returns to the caller. */
void
thread_exit (void) 
{
  ASSERT (!intr_context ());

#ifdef USERPROG
  process_exit ();
#endif

  /* Remove thread from all threads list, set our status to dying,
     and schedule another process.  That process will destroy us
     when it calls thread_schedule_tail(). */
  intr_disable ();
  list_remove (&thread_current()->allelem);
  thread_current ()->status = THREAD_DYING;
  schedule ();
  NOT_REACHED ();
}

/* Yields the CPU.  The current thread is not put to sleep and
   may be scheduled again immediately at the scheduler's whim.
  [20170765]except when thread_yield() is called by lock_acquire().
  In that case the yielding thread will be put to sleep 
  as it is waiting for a lock*/
void
thread_yield (void) 
{
  struct thread *cur = thread_current ();
  enum intr_level old_level;
  
  ASSERT (!intr_context ());

  old_level = intr_disable ();
  if (cur != idle_thread){ 
     list_insert_ordered(&ready_list,&cur->elem,priority_compare,NULL);
  }
   /*[20170765], if current thread is yielding because it is waiting on a lock,
     block it*/ 
  if(cur->wait_on_lock){thread_block();}
  else{
    cur->status = THREAD_READY;
    schedule ();
    intr_set_level (old_level);
  }

}

/* Invoke function 'func' on all threads, passing along 'aux'.
   This function must be called with interrupts off. */
void
thread_foreach (thread_action_func *func, void *aux)
{
  struct list_elem *e;

  ASSERT (intr_get_level () == INTR_OFF);

  for (e = list_begin (&all_list); e != list_end (&all_list);
       e = list_next (e))
    {
      struct thread *t = list_entry (e, struct thread, allelem);
      func (t, aux);
    }
}

/* Sets the current thread's [2017065] base priority to NEW_PRIORITY. 
  [20170765]If advanced scheduler is on, this function is ignored. 
*/
void
thread_set_priority (int new_priority) 
{
  /*users cannot modify priority if in 4.4BSD scheduler*/
  if(thread_mlfqs){return;}

  enum intr_level old_level;
  old_level = intr_disable();

  thread_current()->base_priority = new_priority;

  /* the thread's new priority will be the maximum of 
  its new base priority and the donation it has received*/
  if(thread_current()->priority<new_priority||
		list_empty(&thread_current()->donations))
 {
	thread_current()->priority=new_priority;
 }
  /*sort the ready list again as the priority has been updated*/
  list_sort(&ready_list, &priority_compare,NULL);
  /*if the new priority is the highest, schedule it immediately*/
  check_preempt_current();
  intr_set_level(old_level);
}

/* Returns the current thread's priority. */
int
thread_get_priority (void) 
{
  return thread_current ()->priority;
}

/* [20170765] Sets the current thread's nice value to NICE. */
void
thread_set_nice (int nice UNUSED) 
{
  ASSERT(nice>=NICE_MIN &&nice<=NICE_MAX);
  thread_current()->nice = nice;
	
}

/* [20170765] Returns the thread t's nice value. */
int
thread_get_t_nice (struct thread* t)
{
  /* Not yet implemented. */
  return t->nice;
}
int
thread_get_nice (void)
{
  /* Not yet implemented. */
  return thread_current()->nice;
}

/* Returns 100 times the system load average. */
int
thread_get_load_avg (void) 
{
  /*[20170765]convert load_avg from fixed point to integer*/
  return   f_to_n_nearest(load_avg*100);
}

/* Returns 100 times the current thread's recent_cpu value. */
int
thread_get_t_recent_cpu (struct thread* t)
{
 /*[20170765]convert recent_cpu from fixed point to integer*/
  return f_to_n_nearest(t->recent_cpu*100);
}
int
thread_get_recent_cpu (void)
{
  return f_to_n_nearest(thread_current()->recent_cpu*100);
}

/* [20170765] update the thread t's recent cpu*/
void
thread_set_t_recent_cpu(struct thread* t)
{
  t->recent_cpu = calculate_t_recent_cpu(t);
}

/*Increment the recent_cpu of the current thread's recent_cpu by 1*/
void increment_recent_cpu(void)
{
  thread_current()->recent_cpu = add_x_n(thread_current()->recent_cpu,1);
}

/* [20170765] calculate and return the newest load average*/
f_p calculate_load_avg(void)
{
  f_p term1 = div_x_n(mul_x_n(load_avg,59),60);
  
  /* [20170765] calculate and return the newest recent cpu of the thread t*/
  int ready_threads = list_size(&all_list)-list_size(&sleep_list)-1;
  f_p term2 = div_x_n(n_to_f(ready_threads),60);
  load_avg = add_x_y(term1,term2);
  return load_avg;
}

/* [20170765] Calculate and return the newest priority of the thread t*/
f_p calculate_t_recent_cpu(struct thread* t)
{
  ASSERT(is_thread(t));
  f_p recent_cpu = t->recent_cpu;
  int nice = thread_get_t_nice(t);
  f_p decay = div_x_y(mul_x_n(load_avg,2),mul_x_n(load_avg,2)+n_to_f(1));
  f_p new_recent_cpu = add_x_n(mul_x_y(decay,recent_cpu),nice);
  return new_recent_cpu;
}

/* [20170765] Calculate and return the newest priority of the thread t*/
int calculate_t_priority(struct thread* t)
{
  /*get recent cpu, only integer part*/
  int recent_cpu =thread_get_t_recent_cpu(t)/100;
  int nice = thread_get_t_nice(t);
  int priority = PRI_MAX - (recent_cpu/4)-(nice*2);
  return priority; 
}


/*called by timer interrupt at every tick thus, this functions runs in
  interrupt context.checks if load_ag, recent_cpu and priority needs
  to be upadted and update them.*/
void thread_update_stats(int64_t ticks)
{
  /*this function is only used in mlfqs mode*/
  if(!thread_mlfqs){return;}
  /*increment recent cpu of the running thread, there is no point to
    increment recent cpu of th idle thread*/
  if(thread_current()!=idle_thread){increment_recent_cpu();}
  /*recalculate priority of all threads every 4th tick*/
  if(ticks%TIME_SLICE==0)
    {
      if(ticks%TIME_FREQ==0){load_avg=calculate_load_avg();}
      struct list_elem* e;
      struct thread* t;
      for (e=list_begin(&all_list);e!=list_end(&all_list);e=list_next(e))
	{
	  t = list_entry(e,struct thread, allelem);
	  /*recent_cpu is updated every second*/
	  if(ticks%TIME_FREQ==0)
	    {
	      thread_set_t_recent_cpu(t);
	    }
	  t->priority = calculate_t_priority(t);
	  
	  
	}
      /*sort ready_list again with updated priority*/
      list_sort(&ready_list,priority_compare,NULL);
      intr_yield_on_return();
    }
}


/* Idle thread.  Executes when no other thread is ready to run.

   The idle thread is initially put on the ready list by
   thread_start().  It will be scheduled once initially, at which
   point it initializes idle_thread, "up"s the semaphore passed
   to it to enable thread_start() to continue, and immediately
   blocks.  After that, the idle thread never appears in the
   ready list.  It is returned by next_thread_to_run() as a
   special case when the ready list is empty. */
static void
idle (void *idle_started_ UNUSED) 
{
  struct semaphore *idle_started = idle_started_;
  idle_thread = thread_current ();
  sema_up (idle_started);

  for (;;) 
    {
      /* Let someone else run. */
      intr_disable ();
      thread_block ();

      /* Re-enable interrupts and wait for the next one.

         The `sti' instruction disables interrupts until the
         completion of the next instruction, so these two
         instructions are executed atomically.  This atomicity is
         important; otherwise, an interrupt could be handled
         between re-enabling interrupts and waiting for the next
         one to occur, wasting as much as one clock tick worth of
         time.

         See [IA32-v2a] "HLT", [IA32-v2b] "STI", and [IA32-v3a]
         7.11.1 "HLT Instruction". */
      asm volatile ("sti; hlt" : : : "memory");
    }
}

/* Function used as the basis for a kernel thread. */
static void
kernel_thread (thread_func *function, void *aux) 
{
  ASSERT (function != NULL);

  intr_enable ();       /* The scheduler runs with interrupts off. */
  function (aux);       /* Execute the thread function. */
  thread_exit ();       /* If function() returns, kill the thread. */
}

/* Returns the running thread. */
struct thread *
running_thread (void) 
{
  uint32_t *esp;

  /* Copy the CPU's stack pointer into `esp', and then round that
     down to the start of a page.  Because `struct thread' is
     always at the beginning of a page and the stack pointer is
     somewhere in the middle, this locates the curent thread. */
  asm ("mov %%esp, %0" : "=g" (esp));
  return pg_round_down (esp);
}

/* Returns true if T appears to point to a valid thread. */
static bool
is_thread (struct thread *t)
{
  return t != NULL && t->magic == THREAD_MAGIC;
}

/* Does basic initialization of T as a blocked thread named
   NAME. */
static void
init_thread (struct thread *t, const char *name, int priority)
{
  ASSERT (t != NULL);
  ASSERT (PRI_MIN <= priority && priority <= PRI_MAX);
  ASSERT (name != NULL);

  memset (t, 0, sizeof *t);
  t->status = THREAD_BLOCKED;
  strlcpy (t->name, name, sizeof t->name);
  t->stack = (uint8_t *) t + PGSIZE;
  
  /*20170765 priority passed as argument is ignored if in MLFQS mode*/
  if(!thread_mlfqs)
    {
      t->priority = priority;
      t->base_priority = priority;
    }
  t->magic = THREAD_MAGIC;
  list_push_back (&all_list, &t->allelem);
  /*20170765 sleeping*/
  t->wake_up_at = INT_MAX;
  /*20170765 priority donation*/ 
  list_init(&t->donations);
  list_init(&t->holding_locks);
}

/* Allocates a SIZE-byte frame at the top of thread T's stack and
   returns a pointer to the frame's base. */
static void *
alloc_frame (struct thread *t, size_t size) 
{
  /* Stack data is always allocated in word-size units. */
  ASSERT (is_thread (t));
  ASSERT (size % sizeof (uint32_t) == 0);

  t->stack -= size;
  return t->stack;
}

/* Chooses and returns the next thread to be scheduled.  Should
   return a thread from the run queue, unless the run queue is
   empty.  (If the running thread can continue running, then it
   will be in the run queue.)  If the run queue is empty, return
   idle_thread. */
static struct thread *
next_thread_to_run (void) 
{
  if (list_empty (&ready_list))
    return idle_thread;
  else
    list_sort(&ready_list,priority_compare,NULL);
    return list_entry (list_pop_front (&ready_list), struct thread, elem);
}

/* Completes a thread switch by activating the new thread's page
   tables, and, if the previous thread is dying, destroying it.

   At this function's invocation, we just switched from thread
   PREV, the new thread is already running, and interrupts are
   still disabled.  This function is normally invoked by
   thread_schedule() as its final action before returning, but
   the first time a thread is scheduled it is called by
   switch_entry() (see switch.S).

   It's not safe to call printf() until the thread switch is
   complete.  In practice that means that printf()s should be
   added at the end of the function.

   After this function and its caller returns, the thread switch
   is complete. */
void
thread_schedule_tail (struct thread *prev)
{
  struct thread *cur = running_thread ();
  
  ASSERT (intr_get_level () == INTR_OFF);

  /* Mark us as running. */
  cur->status = THREAD_RUNNING;

  /* Start new time slice. */
  thread_ticks = 0;

#ifdef USERPROG
  /* Activate the new address space. */
  process_activate ();
#endif

  /* If the thread we switched from is dying, destroy its struct
     thread.  This must happen late so that thread_exit() doesn't
     pull out the rug under itself.  (We don't free
     initial_thread because its memory was not obtained via
     palloc().) */
  if (prev != NULL && prev->status == THREAD_DYING && prev != initial_thread) 
    {
      ASSERT (prev != cur);
      palloc_free_page (prev);
    }
}

/* Schedules a new process.  At entry, interrupts must be off and
   the running process's state must have been changed from
   running to some other state.  This function finds another
   thread to run and switches to it.

   It's not safe to call printf() until thread_schedule_tail()
   has completed. */
static void
schedule (void) 
{
  struct thread *cur = running_thread ();
  struct thread *next = next_thread_to_run ();
  struct thread *prev = NULL;

  ASSERT (intr_get_level () == INTR_OFF);
  ASSERT (cur->status != THREAD_RUNNING);
  ASSERT (is_thread (next));

  if (cur != next)
    prev = switch_threads (cur, next);
  thread_schedule_tail (prev);
}

/* Returns a tid to use for a new thread. */
static tid_t
allocate_tid (void) 
{
  static tid_t next_tid = 1;
  tid_t tid;

  lock_acquire (&tid_lock);
  tid = next_tid++;
  lock_release (&tid_lock);

  return tid;
}

/* Offset of `stack' member within `struct thread'.
   Used by switch.S, which can't figure it out on its own. */
uint32_t thread_stack_ofs = offsetof (struct thread, stack);

/*[20170765]* A comparator for elements in sleep_list 
  and semaphore's waiters list*/
bool priority_compare (const struct list_elem *a, const struct list_elem *b,
			      void *aux UNUSED)
{
    return list_entry (a, struct thread, elem)->priority >
      list_entry (b, struct thread, elem)->priority;
}

bool donation_compare (const struct list_elem *a, const struct list_elem *b,
			      void *aux UNUSED)
{
    return list_entry (a, struct thread, d_elem)->priority >
      list_entry (b, struct thread, d_elem)->priority;
}


/*[20170765]A comparator for sleep_list,sorted by wakeup time of the threads*/
bool sleep_compare (const struct list_elem *a, const struct list_elem *b,
                                   void *aux UNUSED)
{
  return list_entry (a, struct thread,sleepelem)->wake_up_at
    > list_entry (b, struct thread, sleepelem)->wake_up_at;
}

/*[20170765] Preempt the current thread if it no longer has higher 
  priority then all ready thread*/
void check_preempt_current(void)
{
  /*no need to preempt if ready list is empty*/
  if(list_empty(&ready_list)){return;}
  struct thread* t = list_entry(list_begin(&ready_list),struct thread,elem);
  if (t->priority
	   > thread_current()->priority)
    {
      if(intr_context()){intr_yield_on_return();}
      else {thread_yield();}
      
    }
}

/*[20170765] Donate priority to thread t, who is the holder of a lock acquired
  This function is recursive in order to support nested donation. It is called
  by a thread waiting on a lock held by t to donate its priority to t, if t is 
  also waiting on a lock, this function will update for the holder of the lock
  that t is waiting on.
*/ 
void donate_priority(struct thread* t)
{
  /*no priority donation in a 4.4BSD scheduler*/
  if(thread_mlfqs){return;}
  /*this function is called by lock_acquire, and should be called with
    interrupts off*/
  ASSERT(!intr_context());
  /*t has to be a holder of a lock*/
  ASSERT(&t->holding_locks);

  /*Set the thread's priority to the highest of the donated 
    and its base priority*/
  if(!list_empty(&t->donations))
    {
      list_sort(&t->donations, donation_compare,NULL);
      struct thread* donator = list_entry(list_front(&t->donations),
					  struct thread, d_elem);
      if (donator->priority > t->base_priority){
	t->priority = donator->priority; 
      }
    }
  else
    {
      t->priority = t->base_priority;
    }

  /*if t is waiting on a lock too, update the holder's priority*/
  if(t->wait_on_lock)
    {
      donate_priority(t->wait_on_lock->holder);
    }
  /*ready_list may be updated*/
  if(t->status == THREAD_READY){list_sort(&ready_list,priority_compare,NULL);}
  
}