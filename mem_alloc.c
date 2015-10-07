#include "mem_alloc.h"
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdbool.h>

/* memory */
char memory[MEMORY_SIZE]; 

/* Structure declaration for a free block */
typedef struct free_block{
  int size;
  struct free_block *next;
} free_block_s, *free_block_t;

/* Structure declaration for an occupied block */
typedef struct{
  int size; 
} busy_block_s, *busy_block_t; 


/* Pointer to the first free block in the memory */
free_block_t first_free;


#define ULONG(x)((long unsigned int)(x))
#define max(x,y) (x>y?x:y)

// fragmentation statistics
#define STATISTICS_SIZE 6000 // if we measure every 10 msec then it's enough for 10 minutes
int mem_used[STATISTICS_SIZE];
int mem_requested[STATISTICS_SIZE];
bool statistics_on = false;
int stat_counter;
int cur_used, cur_requested;

void statistics_init(void) {
    statistics_on = true;
    memset(mem_used, 0, STATISTICS_SIZE);
    memset(mem_requested, 0, STATISTICS_SIZE);
    stat_counter = 0;
}

void fill_stat(void) {
    if (statistics_on && stat_counter < STATISTICS_SIZE) {
        mem_used[stat_counter] = cur_used;
        mem_requested[stat_counter] = cur_requested;
        ++stat_counter;
    }
}


void memory_init(void) {
    first_free = (free_block_t) memory;
    first_free->size = MEMORY_SIZE;
    first_free->next = NULL;
}

free_block_t find_first_fit(int size) {
    // return a pointer to the first free block which is before a block with enough space

    // we return a pointer to the previous block as we need to change a pointer to next elem in it
    // and out list is one-way and we don't want to go through it in mem_alloc funciton

    size += sizeof(busy_block_s);
    free_block_t current;
    free_block_t prev = (free_block_t) (memory + MEMORY_SIZE);
    // we return this value in case we best_fit is the first_free elem

    for (current = first_free; current != NULL; current = current->next) {
        if (current->size >= size) {
            return prev;
        }
        prev = current;
    }
    // in case we didn't find a block with enough space
    return NULL;
}

free_block_t find_best_fit(int size) {
    // return a pointer to the first free block which is before a block with best fit

    // we return a pointer to the previous block as we need to change a pointer to next elem in it
    // and out list is one-way and we don't want to go through it in mem_alloc funciton

    size += sizeof(busy_block_s);
    free_block_t current;
    free_block_t prev = (free_block_t) (memory + MEMORY_SIZE);
    // we return this value in case we best_fit is the first_free elem

    // variables to contain current best_fit in
    int smallest_dif = MEMORY_SIZE;
    free_block_t best_fit_block = NULL;
    free_block_t prev_best_block;
    for (current = first_free; current != NULL; current = current->next) {
        if (current->size - size < smallest_dif) {
            smallest_dif = current->size - size;
            best_fit_block = current;
            prev_best_block = prev;
        }
        prev = current;
    }
    if (best_fit_block == NULL) {
        // in case we didn't find a block with enough space
        return NULL;
    }
    return prev_best_block;
}

free_block_t find_worst_fit(int size) {
    // return a pointer to the first free block which is before a block with worst fit

    // we return a pointer to the previous block as we need to change a pointer to next elem in it
    // and out list is one-way and we don't want to go through it in mem_alloc funciton

    size += sizeof(busy_block_s);
    free_block_t current;
    free_block_t prev = (free_block_t) (memory + MEMORY_SIZE);
    // we return this value in case we best_fit is the first_free elem

    // variables to contain current worst_fit in
    int smallest_dif = -1;
    free_block_t best_fit_block = NULL;
    free_block_t prev_best_block;
    for (current = first_free; current != NULL; current = current->next) {
        if (current->size - size > smallest_dif) {
            smallest_dif = current->size - size;
            best_fit_block = current;
            prev_best_block = prev;
        }
        prev = current;
    }
    if (best_fit_block == NULL) {
        // in case we didn't find a block with enough space
        return NULL;
    }
    return prev_best_block;
}

char *memory_alloc(int requested_size) {
    if (requested_size <= 0 || requested_size > MEMORY_SIZE - sizeof(busy_block_s)) {
        print_alloc_info(NULL, requested_size);
        return NULL;
    }

    int real_size = (requested_size + sizeof(busy_block_s) >= sizeof(free_block_s) ? requested_size : sizeof(free_block_s) - sizeof(busy_block_s));
    // because we still want to be able to free the block so the minimum amount we can allocate is sizeof(free_block_s)
    // but here we subtract sizeof(busy_block_s) as we don't count it into the size variable

    free_block_t current;
    free_block_t prev = find_first_fit(real_size);
    if (prev == NULL) {
        // can not allocate memory
        print_alloc_info(NULL, real_size);
        return NULL;
    }

    if (prev != (free_block_t) (memory + MEMORY_SIZE)) {
        // normal case
        current = prev->next;
    } else {
        // the case when we can allocate in the very first element of the list of free blocks
        current = first_free;
        prev = NULL;
    }

    int old_free_size = current->size;
    free_block_t old_free_pointer = current->next;
    busy_block_t new_busy = (busy_block_t) current;
    new_busy->size = real_size;

    if (old_free_size >= real_size + sizeof(busy_block_s) + sizeof(free_block_s)) {
        // there is enough space to put free_block_s after our busy_block

        free_block_t new_free = (free_block_t) (ULONG(new_busy) + ULONG(sizeof(busy_block_s) + real_size));
        // some point arithmetics to find a place for a new free_block

        new_free->next = old_free_pointer;
        new_free->size = old_free_size - real_size - sizeof(busy_block_s);
        if (prev == NULL) {
            // we allocate in the very first element of the list of free blocks
            first_free = new_free;
        } else {
            prev->next = new_free;
        }
    } else {
        // there is NOT enough space to put free_block_s after our busy_block
        real_size = old_free_size - sizeof(busy_block_s);
        new_busy->size = real_size;
        if (prev == NULL) {
            // we allocate in the very first element of the list of free blocks
            if (first_free->next != NULL) {
                first_free = first_free->next;
            } else {
                // we don't have more memory
                first_free = NULL;
            }
        } else {
            prev->next = old_free_pointer;
        }
    }

    char *addr = (new_busy != NULL ? (char*) ULONG(new_busy) + ULONG(sizeof(busy_block_s)) : NULL);
    print_alloc_info(addr, real_size);

    if (statistics_on) {
        cur_requested += requested_size;
        cur_used += real_size;
        // but we don't consider external fragmentation here (!)
    }

    return addr;
}


// go through each busy and free block to check if there is corrupted pointer or size
bool checkMemory(){
    busy_block_t check = (busy_block_t) memory; // set check to point to beginning of memory
    free_block_t free_chunk = first_free;
    while (ULONG(check) < ULONG(memory + MEMORY_SIZE)) {
        if (ULONG(check) == ULONG(free_chunk)) {
            // check free block for correct size
            if(free_chunk != NULL && (free_chunk->size < 0 || free_chunk->size > MEMORY_SIZE))
                return false;
            // check free block for pointer to next block within memory bound
            if(free_chunk->next != NULL && (ULONG(free_chunk->next) < ULONG(memory) || ULONG(free_chunk->next) > ULONG(memory + MEMORY_SIZE)))
                return false;                
            
            check = (busy_block_t) (ULONG(check) + ULONG(free_chunk->size));
            free_chunk = free_chunk->next;
        }
        // check busy block for correct size
        if(check->size < 0 || check->size > MEMORY_SIZE)
            return false;
        
        check = (busy_block_t) (ULONG(check + 1) + ULONG(check->size));
    }
    return true;
}


void memory_free(char *p){
    print_free_info(p);

    assert(checkMemory());

    // first check  - if p address is within our memory
    if (p <= memory || p > memory + MEMORY_SIZE) {
        printf("Address out of bound\n");
        return;
    }

    // second check - if p is an address of previously allocated chunk
    // go through each busy block to check if p equals to any
    bool can_free = false;
   
    busy_block_t check = (busy_block_t) memory; // set check to point to beginning of memory
    free_block_t free_chunk = first_free;
    while (ULONG(check) < ULONG(p)) {
        if (ULONG(check) == ULONG(free_chunk)) {
            check = (busy_block_t) (ULONG(check) + ULONG(free_chunk->size));
            free_chunk = free_chunk->next;
        }
        if (ULONG(check) < ULONG(memory + MEMORY_SIZE)) {
            if (ULONG(check + 1) == ULONG(p)) {
                can_free = true;
                break;
            } else {
                check = (busy_block_t) (ULONG(check + 1) + ULONG(check->size));
            }    
        }
    }
    if(!can_free) {
        // we cannot free random address
        printf("Cannot free address %lu - it was not allocated before\n", ULONG(p - memory)); 
        return; 
    }  

    busy_block_t descriptor = (busy_block_t) (ULONG(p) - ULONG(sizeof(busy_block_s)));
    // shift a bit to find the busy_block

    int old_full_size = descriptor->size + sizeof(busy_block_s);
    free_block_t free_descriptor = (free_block_t) descriptor;
    free_descriptor->size = old_full_size;
    free_block_t current, prev_free;

    if (free_descriptor < first_free || first_free == NULL) {
        // our block is located before the first_free block 
        // or first_free does not exist in the moment (all the memory is occupied)
        free_descriptor->next = first_free;
        first_free = free_descriptor;
        prev_free = NULL;
    } else {
        // our block is located AFTER the first_free block
        free_block_t last_free = NULL;
        for (current = first_free; current != NULL; current = current->next) {
            if (current < free_descriptor && current->next > free_descriptor) {
                // we found the right place in the free blocks list
                free_descriptor->next = current->next;
                current->next = free_descriptor;
                prev_free = current;
                break;
            }
            if (current->next == NULL) {
                last_free = current;
            }
        }
        if (last_free != NULL) {
            // if last_free is not NULL that means that we finished the for loop and didn't find a place
            // in the list of free blocks, so we just put a new free block in the end of it
            last_free->next = free_descriptor;
            free_descriptor->next = NULL;
            prev_free = last_free;
        }
    }

    // four options are possible:
    // 1. on the left and on the right from the freed block there are busy blocks
    // 2. there is a busy block on the left and a free block on the right
    // 3. there is a free block on the left and a busy block on the right
    // 4. there are free block on the left and on the right

    if (prev_free == NULL) {
        // our free_block is the first in the list
        if (ULONG(free_descriptor) + ULONG(free_descriptor->size) == ULONG(free_descriptor->next)) {
            free_descriptor->size += free_descriptor->next->size;
            free_descriptor->next = free_descriptor->next->next;
        }
    } else if (free_descriptor->next == NULL) {
        // our free_block is the last in the list
        if (ULONG(prev_free) + ULONG(prev_free->size) == ULONG(free_descriptor)) {
            prev_free->size += free_descriptor->size;
            prev_free->next = free_descriptor->next;
        }
    } else {
        // // our free_block is in the middle of the list
        
        // case #1 - do nothing

        // case #2
        if (ULONG(free_descriptor) + ULONG(free_descriptor->size) == ULONG(free_descriptor->next) &&
            ULONG(prev_free) + ULONG(prev_free->size) != ULONG(free_descriptor)) {
            free_descriptor->size += free_descriptor->next->size;
            free_descriptor->next = free_descriptor->next->next;
        }

        // case #3
        if (ULONG(prev_free) + ULONG(prev_free->size) == ULONG(free_descriptor) &&
            ULONG(free_descriptor) + ULONG(free_descriptor->size) != ULONG(free_descriptor->next)) {
            prev_free->size += free_descriptor->size;
            prev_free->next = free_descriptor->next;
        }

        // case #4
        if (ULONG(free_descriptor) + ULONG(free_descriptor->size) == ULONG(free_descriptor->next) &&
            ULONG(prev_free) + ULONG(prev_free->size) == ULONG(free_descriptor)) {
            prev_free->size += free_descriptor->size + free_descriptor->next->size;
            prev_free->next = free_descriptor->next->next;
        }
    }

    print_free_blocks();

    if (statistics_on) {
        // TODO: add smth here
    }
}


void print_info(void) {
  fprintf(stderr, "Memory : [%lu %lu] (%lu bytes)\n", (long unsigned int) memory, (long unsigned int) (memory+MEMORY_SIZE), (long unsigned int) (MEMORY_SIZE));
  fprintf(stderr, "Free block : %lu bytes; busy block : %lu bytes.\n", ULONG(sizeof(free_block_s)), ULONG(sizeof(busy_block_s))); 
}

void print_free_info(char *addr){
  if(addr)
    fprintf(stderr, "FREE  at : %lu \n", ULONG(addr - memory)); 
  else
    fprintf(stderr, "FREE  at : %lu \n", ULONG(0)); 
}

void print_alloc_info(char *addr, int size){
  if(addr){
    fprintf(stderr, "ALLOC at : %lu (%d byte(s))\n", 
        ULONG(addr - memory), size);
  }
  else{
    fprintf(stderr, "Warning, system is out of memory\n"); 
  }
}

void print_free_blocks(void) {
  free_block_t current; 
  fprintf(stderr, "Begin of free block list :\n"); 
  for(current = first_free; current != NULL; current = current->next)
    fprintf(stderr, "Free block at address %lu, size %u\n", ULONG((char*)current - memory), current->size);
}

char *heap_base(void) {
  return memory;
}


void *malloc(size_t size){
  static int init_flag = 0; 
  if(!init_flag){
    init_flag = 1; 
    memory_init(); 
    //print_info(); 
  }      
  return (void*)memory_alloc((size_t)size); 
}

void free(void *p){
  if (p == NULL) return;
  memory_free((char*)p);
  // print_free_blocks();
}

void *realloc(void *ptr, size_t size){
  if(ptr == NULL)
    return memory_alloc(size); 
  busy_block_t bb = ((busy_block_t)ptr) - 1; 
  printf("Reallocating %d bytes to %d\n", bb->size - (int)sizeof(busy_block_s), (int)size); 
  if(size <= bb->size - sizeof(busy_block_s))
    return ptr; 

  char *new = memory_alloc(size); 
  memcpy(new, (void*)(bb+1), bb->size - sizeof(busy_block_s) ); 
  memory_free((char*)(bb+1)); 
  return (void*)(new); 
}


#ifdef MAIN
int main(int argc, char **argv) {
      /* The main can be changed, it is *not* involved in tests */
    memory_init();
    print_info(); 

    // test 3
    char *a = memory_alloc(20);

    // test if allocator aborts if size in busy_block is <0
    // busy_block_t bug = (busy_block_t) a;
    // bug--;
    // bug->size = -1;

    // test if free block is corrupted
    // char *c = a;
    // c = c+20;
    // free_block_t bug2 = (free_block_t) c;
    // bug2->size = -1;             // size in free block < 0
    // bug2->size = MEMORY_SIZE+1;  // size in free block > memory size
    // bug2->next = ULONG(memory)+ULONG(MEMORY_SIZE+1);    // pointer to next free block is out of band
    // bug2->next = ULONG(memory - 1);     // pointer to next free block is out of band
    memory_free(a);

    /*print_free_blocks();
    int i;
    for( i = 0; i < 10; i++) {
        int size = rand() % 8 + 1;
        // fprintf(stderr, "we want to alloc %d bytes\n", size);
        char *b = memory_alloc(size);
        memory_free(b);
        // print_free_blocks();
    }

    char * a = memory_alloc(15);
    a=realloc(a, 20); 
    memory_free(a);


    a = memory_alloc(10);
    memory_free(a);

    printf("%lu\n",(long unsigned int) (memory_alloc(9)));*/
    return EXIT_SUCCESS;
}
#endif 
