#include <stdio.h>
#include <hash.h>
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "vm/page.h"

/* type of the page table. */
enum pagetable_type
  {
    TABLE_FRAME,	/* frame table, PFN --> Physical Address*/
    TABLE_PAGE,		/* page table, VPN --> PFN */
    TABLE_SWAP,		/* swap table */
    TABLE_FILE_MAPPING	/* file --> mapped address */
  }


struct pagetable{
  enum pagetable_type type;
  struct hash* hash; 
  
}
