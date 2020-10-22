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

#ifndef FLUSHPLUSRELOAD_H
#define FLUSHPLUSRELOAD_H

#define MAX_PROBES    4 /* n-1 i.e. 4 = 5 probes*/
#define MAX_SLOT_SIZE 10000

typedef struct probe {
    unsigned long virt_addr; 
    char *mapped_pointer; 
    char name;
} probe_t;

typedef struct args {
    char *elf_path;
    int threshold;
    unsigned long slot;
    probe_t *probes;
    int probe_index;
} args_t;

int spy(const args_t *args);
void cache_bench();

#endif
