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

#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include "./lib/elf.h"
#include "./lib/dat.h"

#include "elfstuff.h"

void* map(const char *elf_path, unsigned long *size)
{
    int fd;
    char *target;
    struct stat st_buf;

    /* open file pointer */
    fd = open(elf_path, O_RDONLY);
    if (fd < 0) 
    {
        perror("Error opening ELF file.");
        return NULL;
    }

    /* get the size of the file */
    fstat(fd, &st_buf);
    *size = st_buf.st_size;

    /* memory map the file so we can do stuff to it */
    target = mmap(NULL, *size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (MAP_FAILED == target) 
    {
        perror("Error mapping ELF file.");
        return NULL;
    }

    /* clean up */
    close(fd);

    return target;
}

/* Returns -1 on error, 0 when the ELF is a shared library.*/
int get_elf_load_offset(const char *elf_path)
{
    Fhdr fhdr;
    FILE *fp; 
    int rc =-1; 
    int load_addr = -1;
    char *elf_type;
    char *elf_class;

    /* open the file */
    fp = fopen(elf_path, "rb");
    if (NULL == fp) 
    {
        fprintf(stderr, "Couldn't open the ELF at %s.\n", elf_path);
        return -1;
    }

    /* read elf information int fhdr*/
    rc = readelf(fp, &fhdr);
    if (rc < 0)
    {
        fprintf(stderr, "Error parsing elf file %s.\n", elf_path);
        freeelf(&fhdr);
        return -1;
    }

    /* get the load address if exec elf32 or elf64 */
    switch(fhdr.type)
    {
        case ET_EXEC:
            /* This is a hack...not sure if it works haven't tested it */
            if(ELFCLASS32 == fhdr.class)
            {
                printf("[-] Detected 32-bit executable.\n");
                load_addr = 0x08048000;
            }
            else if (ELFCLASS64 == fhdr.class)
            {
                printf("[-] Detected 64-bit executable.\n");
                load_addr = 0x400000;
            }
            else
            {
                elf_class = elfclass(fhdr.class);
                fprintf(stderr, "Unknown ELF class: %s\n", elf_class);
            }
            break;
        case ET_DYN: 
            /* Objdump addresses are relative to the start of the file. */
            printf("[-] Detected ELF type: Shared Object.\n");
            load_addr = 0;
            break;
        case ET_NONE:
        case ET_REL:
        case ET_CORE:
            elf_type = elftype(fhdr.type);
            fprintf(stderr, "Unsupported ELF type: %s\n", elf_type);
            break;
        default: 
            fprintf(stderr, "Unknown ELF type: %d\n", fhdr.type);
            break;
    }

    /* clean up */
    freeelf(&fhdr);
    fclose(fp);
    
    fp = NULL; 
    elf_type = NULL;
    elf_class = NULL;
   
    return load_addr;
}
