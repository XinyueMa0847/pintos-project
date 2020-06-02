#include <stdio.h>
#include "vm/page.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "threads/palloc.h"
#include "filesys/file.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include <stdlib.h>
#include <string.h>
#include "userprog/pagedir.h"
#include "userprog/syscall.h"
#include "devices/block.h"
#include "lib/kernel/bitmap.h"
#include "userprog/process.h"
/* global LRU list */
static struct list lru_list;
static struct list_elem* hand;

/* swap block device */
static struct block *swap_block;

/* swap bitmap */
static struct bitmap *swap_bitmap;

#define NOT_IN_SWAP -1

#define MAX_MMAP_FILE 128
/* manage vm_entry */
struct vm_entry* vm_entry_create(void* vaddr,enum vm_entry_type type,
				 bool writable,struct thread* owner);

void vm_set_basefile(struct vm_entry* entry, struct file* file, 
		     off_t offset);

void vm_set_swap(struct vm_entry* entry, block_sector_t swap_sector);
void vm_entry_destroy(struct vm_entry* entry);

/* hash functions */
vm* vm_init(void);
hash_hash_func vm_hash;
/* unsigned vm_hash(const struct hash_elem *p_, void *aux UNUSED); */
/* bool vm_less(const struct hash_elem *a_, const struct hash_elem *b_, void *aux UNUSED); */
hash_less_func vm_less;
/* hash_action_func free_vm_entry; */
void free_vm_entry (struct hash_elem *e, void *aux UNUSED);


/* handle page fault */
struct vm_entry* find_vme(vm* vm, void* fault_addr);
bool load_page_from_file(void* kpage, struct vm_entry* entry);

void lru_init(void); 		/* initializa lru list */
void lru_insert(struct list_elem* e);
void lru_remove(struct list_elem* e);
struct page* page_create(void* paddr,struct vm_entry* entry);
void * palloc_vm_get_page(enum palloc_flags flags,struct vm_entry* entry);
bool palloc_vm_free_page(void* page);
struct page* choose_victim(void);
void swap_init(void);
bool swap_in_addr(void * addr);
void swap_in(struct vm_entry* entry);
bool swap_out(struct page* victim);
struct vm_entry* expand_stack(void* esp, void* fault_addr);

int mmap(int fd, void* addr);
static mapid_t allocate_mapid(void);
/* create a vm entry */
struct vm_entry* 
vm_entry_create(void* vaddr,enum vm_entry_type type, bool writable,struct thread* owner)
{
  /* ASSERT(is_thread(owner));  is_thread() is a static function */
  struct vm_entry* entry = calloc(1,sizeof *entry); 
  if(entry==NULL){return NULL;}
  entry->vaddr = vaddr;
  entry->writable = writable; 
  entry->type = type; 
  entry->owner = owner;
  /* a page is not in memory until demanded */
  entry->in_memory=false;
  return entry;
}


/* set the basefile of the vm_entry to FILE, the page contains the
   part of the file from OFFSET, in total SIZE bytes of data.*/
void 
vm_set_basefile(struct vm_entry* entry,struct file* file,off_t offset)
{
  ASSERT(file!=NULL);
  entry->basefile.file = file;
  entry->basefile.offset = offset;
}


/* set the entry's swap sector to SWAP_SECTOR */
void vm_set_swap(struct vm_entry* entry, block_sector_t swap_sector)
{
  entry->swap_sector = swap_sector; 
}
/* destroy ENTRY, deallocate its memory */
void vm_entry_destroy(struct vm_entry* entry)
{
  free(entry);
}



/* Return hash value for vm_entry, since each thread maintains its own
   vm_entries, VPN should be a good hash function as it is unique*/
unsigned 
vm_hash(const struct hash_elem *p_, void *aux UNUSED)
{
  struct vm_entry *entry= hash_entry(p_,struct vm_entry, hash_elem);
  return hash_bytes(&entry->vaddr, sizeof(entry->vaddr));
}

/* Comparator for hash table of vm_entry*/
bool 
vm_less(const struct hash_elem *a_, const struct hash_elem *b_, void *aux UNUSED)
{
  const struct vm_entry *a = hash_entry(a_,struct vm_entry, hash_elem);
  const struct vm_entry *b = hash_entry(b_,struct vm_entry, hash_elem);
  return a->vaddr < b->vaddr;
}


 
vm* 
vm_init(){
  vm* vm = calloc(1,sizeof(*vm)) ;
  hash_init(vm,vm_hash, vm_less,NULL);
  return vm;
}


void
free_vm_entry (struct hash_elem *e, void *aux UNUSED)
{
  struct vm_entry* entry = hash_entry(e,struct vm_entry,hash_elem);
  vm_entry_destroy(entry);
}

/* find the vm_entry that corresponds to the fault address. Return
   NULL if such a entry is not found */
struct vm_entry* 
find_vme(vm* vm, void* fault_addr)
{
  if(hash_size(vm)==0)
    return NULL;
  void* vaddr = (void*) pg_round_down(fault_addr);
  struct hash_iterator i;
  hash_first(&i, vm);
  while(hash_next(&i))
    {
      struct vm_entry* entry = hash_entry(hash_cur(&i),struct vm_entry,
					  hash_elem);
      if(entry->vaddr == vaddr)
	{
	  return entry;
	}
    }
  return NULL;
}

bool
load_page_from_file(void* kpage, struct vm_entry* entry)
{
  ASSERT(is_kernel_vaddr(kpage)&&entry!=NULL);

  struct  vm_file file = entry->basefile;
  uint32_t read_bytes = entry->read_bytes > PGSIZE? PGSIZE : entry->read_bytes;
  uint32_t zero_bytes = entry->read_bytes > PGSIZE? 0: PGSIZE-read_bytes;
  off_t ofs = file.offset;

  ASSERT ((read_bytes + zero_bytes) == PGSIZE);
  //ASSERT (ofs % PGSIZE == 0);

  /* Load this page. */
  file_lock_acquire();
  if (file_read_at (file.file, kpage, read_bytes,ofs) != (int)read_bytes)
    {
      palloc_free_page (kpage);
      return false;
    }
  file_lock_release();
  memset (kpage + read_bytes, 0, zero_bytes);
  entry->in_memory = true;
  return true;

}

/******************************************************************************/
/* initialize LRU list */
void lru_init()
{
  list_init(&lru_list);
}

/* insert to lru_list */
void lru_insert(struct list_elem* e)
{
  list_push_back(&lru_list, e);
  if(list_size(&lru_list)==1){
    hand = list_begin(&lru_list);
  }
}

/* remove from lru_list */
void lru_remove (struct list_elem* e)
{
  list_remove(e);
  if(list_empty(&lru_list))
    hand=NULL;
}



struct page* page_create(void* paddr,struct vm_entry* entry)
{
  struct page* page = calloc(1,sizeof(*page));
  if(page==NULL)
    return NULL;
  page->paddr = paddr;
  page->owner = thread_current();
  page->entry = entry;
  return page;
}


/* expand the stack */ 
struct vm_entry*  expand_stack(void* esp,void* fault_addr)
{
  void* limit = PHYS_BASE - 2048*PGSIZE;
  struct vm_entry* new_entry;
  if(!((fault_addr<=esp&&fault_addr>=esp-32)||esp < thread_current()->esp_boundary))
    return NULL;
  else if(thread_current()->esp_boundary <= limit||esp<=limit)
    return NULL;
  else // if(esp < thread_current()->esp_boundary)
    {
      void* cur_bound = thread_current()->esp_boundary;
      //printf("reached here. esp_boundary: %x\n", cur_bound);
      void* new_bound = pg_round_down(fault_addr);
      int cnt = 0;

      void* vaddr = cur_bound;
      while(vaddr >= new_bound)
	{
	  void* kpage = palloc_get_page(PAL_USER|PAL_ZERO);
	  vaddr = cur_bound - cnt*PGSIZE;
	  cnt++;
	  /* if already mapped, return false */
	  //struct thread* t = thread_current();
	  /* if(pagedir_get_page(t->pagedir, vaddr)!=NULL) */
	  /*   {    */
	  /*     return NULL;  */
	  /*   } */
	  new_entry = vm_entry_create(vaddr,VM_ANON, true ,thread_current());
	  hash_insert(thread_current()->vm, &new_entry->hash_elem);
	  install_page(vaddr,kpage,true);
	}
      thread_current()->esp_boundary = new_bound;
      return new_entry;
    }
  return NULL;
}



/******************************************************************************/
struct page* choose_victim(void){
 
  /* choose_victim is only called when palloc fails, thus the lru
     should not be empty. Just in case it is, return NULL*/
  if(list_empty(&lru_list))
    return NULL;
  else if (list_size(&lru_list)==1)
    return list_entry(list_begin(&lru_list), struct page, lru_elem);
  else{
    struct list_elem* end = hand == list_begin(&lru_list)? 
      list_prev(list_end(&lru_list)) : list_prev(hand);
    bool accessed; 
    struct page* victim = NULL; 
    while (1){
      victim = list_entry(hand, struct page, lru_elem);
      accessed = pagedir_is_accessed(victim->owner->pagedir, victim->entry->vaddr);
      if (accessed) 
	{
	  pagedir_set_accessed(victim->owner->pagedir, victim->entry->vaddr,
			       !accessed);
	  if (hand == end) 
	    break;
	  hand = hand == list_prev(list_end(&lru_list))? 
	    list_begin(&lru_list) : list_next(hand);  
	  
	}

      else
	{
	  return victim;
	}
    }
  }
  return NULL;  
}

/* page allocation with swap partition added */ 
void * palloc_vm_get_page(enum palloc_flags flags, struct vm_entry* entry)
{

  while(1){
    void* paddr = palloc_get_page(flags);
    if(paddr!=NULL)
      {
	
	struct page* page = page_create(paddr,entry);
	if (page == NULL)
	  return NULL;
	lru_insert(&page->lru_elem);
	return paddr;
      }
    /* allocation fail, try to swap */ 
    else 
      {
	;
	/* choose victim page */
	struct page*  victim = choose_victim();
	/* swap out */ 
	if (victim==NULL) 
	  return NULL;
	if (!swap_out(victim))
	  return NULL;
      }    
  }
}


/* initialize swap bitmap*/

void swap_init()
{
  swap_block = block_get_role(BLOCK_SWAP);
  
  if(swap_block!= NULL)
    {
      size_t bitmap_size = block_size(swap_block)/(PGSIZE/BLOCK_SECTOR_SIZE);
      swap_bitmap = bitmap_create(bitmap_size);
    }
  else{
    PANIC("Cound't not initialize swap partition");
  }
}

/*since block is smaller than a page, redifine to write a page instead
  of a block */
static void block_write_page(struct block *block, block_sector_t sector, void* buffer){

  size_t cnt = PGSIZE/BLOCK_SECTOR_SIZE; 
  size_t i; 
  for (i=0; i < cnt; i++)
    {
      block_write (block,sector+i,buffer+i*BLOCK_SECTOR_SIZE);
    }
}

static void block_read_page(struct block *block, block_sector_t sector, void* buffer){

  size_t cnt = PGSIZE/BLOCK_SECTOR_SIZE; 
  size_t i; 
  for (i=0; i < cnt; i++)
    {
      block_read (block,sector+i,buffer+i*BLOCK_SECTOR_SIZE);
    }
}



/* free a page */ 
bool palloc_vm_free_page(void* addr)
{
  bool success = false;
  struct list_elem* e; 
  struct page* p; 
  for (e=list_begin(&lru_list);e!=list_end(&lru_list);e=list_next(e))
    {
      p = list_entry(e, struct page, lru_elem);
      if (addr == p->paddr )
	{
	  list_remove(e);
	  success = true;
	  break;
	}
    }
  palloc_free_page(addr);
  free(p);
  return success;
}

bool swap_in_addr(void * addr)
{
  if (is_kernel_vaddr(addr))
      return false;  
  struct vm_entry* e = find_vme(thread_current()->vm, addr);
  /* if such entry cannot be found or it is not in swap partition*/
  if (e==NULL|| e->swap_sector == NOT_IN_SWAP)
    return false;
  swap_in(e);
  return true;
  
}

void swap_in(struct vm_entry* entry)
{
  block_read_page(swap_block,entry->swap_sector, entry->vaddr);
  bitmap_reset(swap_bitmap,entry->swap_sector/(PGSIZE/BLOCK_SECTOR_SIZE));
  entry->swap_sector = NOT_IN_SWAP;
}

bool swap_out(struct page* victim)
{

  ASSERT(victim!=NULL);
  /* mark page as not present */ 
  // which one to clear? entry->vaddr or victim->paddr?
  pagedir_clear_page(victim->owner->pagedir, victim->paddr);
  bool dirty = pagedir_is_dirty(victim->owner->pagedir,victim->entry->vaddr);
  struct vm_entry* entry  =victim->entry;
  /* find a swap slot */
  size_t swap_slot = bitmap_scan_and_flip(swap_bitmap,0,1,false);
  if (swap_slot==BITMAP_ERROR)
    return false;
  entry->swap_sector = swap_slot * (PGSIZE/BLOCK_SECTOR_SIZE);

  /* remove from the LRU list */
  list_remove(&victim->lru_elem)
;
  switch (entry->type)
    {
    case VM_EXE:
      /* if page is dirty, write to swap partition */
      if (dirty){
	block_write_page(swap_block,entry->swap_sector, entry->vaddr);
	palloc_vm_free_page(victim);
      }
      entry->type = VM_ANON;
      break;
    case VM_FILE:
      if(dirty){
	struct vm_file basefile = entry->basefile;
	file_lock_acquire();
	file_write_at(basefile.file,entry->vaddr,PGSIZE,basefile.offset);
	file_lock_release();
      }     
      palloc_vm_free_page(victim);
      break;
    case VM_ANON:
      block_write_page(swap_block,entry->swap_sector, entry->vaddr);
      break;
    }
  return true;

}


int mmap(int fd, void* addr)
{
  mapid_t mapid = -1;
  struct thread* t = thread_current(); 
  if(fd==1||fd==0)
    return -1;
  struct file* file = t->fdt[fd];
  if (file==NULL)
    return -1;
  file_lock_acquire();
  int size = file_length(file);
    file_lock_release();
  if(size ==0)
    return -1;

  int cnt =(int) pg_round_up((const void*)size)/PGSIZE;
  file_lock_acquire();
  file = file_reopen(file);
  file_lock_release();
  if(file==NULL)
    return -1;
  mapid = allocate_mapid();
  if (mapid==-1)
    {
      file_lock_acquire();
      file_close(file);
      file_lock_release();
      return -1;
    }
  struct mmap_file* mfile = malloc(sizeof *mfile);
  int i;
  uint32_t zero_bytes = PGSIZE - (size %PGSIZE);
  off_t ofs = 0;
  struct vm_entry* entries[cnt];
  for (i=0;i<cnt;i++)
    {
      size_t page_read_bytes;
      struct vm_entry* entry = vm_entry_create(addr,VM_FILE,true,t);
      if(entry==NULL)
	break;
      entries[cnt]=entry;
      if (i!=cnt-1)
	{
	  page_read_bytes = PGSIZE;
	  vm_set_basefile(entry,file,ofs);
	  entry->read_bytes = page_read_bytes;
	  entry->zero_bytes = 0;
	  ofs+=page_read_bytes;
	}
      else
	{
	  page_read_bytes = size%PGSIZE;
	  vm_set_basefile(entry,file,ofs);
	  entry->read_bytes = page_read_bytes;
	  entry->zero_bytes = zero_bytes;
	}
      ASSERT(hash_insert(thread_current()->vm, &entry->hash_elem)==NULL);
      list_push_front(mfile->entry_list,&entry->list_elem);
      addr += PGSIZE;
    }
  /* if i<cnt, allocation failed in the middle, free the allocated entries */
  if(i<cnt)
    {
      int j;
      for (j=0;j<i;j++)
	{
	  hash_delete(t->vm,&entries[j]->hash_elem);
	  list_remove(&entries[j]->list_elem);
	  vm_entry_destroy(entries[j]);
	}
      
      file_lock_acquire();
      file_close(file);
      file_lock_release();
      return -1;
    }
  else{
    void* kpage;
    int j;
    for(j=0;j<cnt;j++)
      {
	kpage=palloc_get_page(PAL_USER|PAL_ZERO);
	install_page(entries[j]->vaddr,kpage,entries[j]->writable);
      }
  }
  return mapid;
}

static mapid_t allocate_mapid()
{
  struct list_elem* e;
  struct thread* cur=thread_current();
  mapid_t id = 0;
  for(e=list_begin(&cur->mapped_files);e!=list_end(&cur->mapped_files);e=list_next(e))
    {
      struct mmap_file* mfile = list_entry(e,struct mmap_file, mmap_elem);
      if (mfile==NULL)
	return id;
      id++;
      if (id>=MAX_MMAP_FILE)
	return -1;
    }
  return id;
}

bool munmap(mapid_t mapid)
{
  struct list_elem* e;
  struct thread* cur = thread_current();
  struct mmap_file* mfile;
  for (e=list_begin(&cur->mapped_files);e!=list_end(&cur->mapped_files);e=list_next(e))
    {
      mfile = list_entry(e, struct mmap_file, mmap_elem);
      if (mfile->mapid==mapid)
	break;
    }
  if(mfile==NULL)
    return false;
  struct vm_entry* entry;
  for (e=list_begin( mfile->entry_list);e!=list_end( mfile->entry_list);e=list_next(e))
    {
      /* write back to file */
      file_lock_acquire();
      file_write_at(entry->basefile.file, entry->vaddr,PGSIZE, entry->basefile.offset);
      file_lock_release();
      /* remove */
       entry = list_entry(e, struct vm_entry, list_elem);
       hash_delete(cur->vm,&entry->hash_elem);
       list_remove(e);
       vm_entry_destroy(entry);
    }
  return true;
}
