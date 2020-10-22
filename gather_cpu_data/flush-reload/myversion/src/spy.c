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
#include <getopt.h> 
#include <errno.h> 
#include <string.h> 
#include <ctype.h> 

#include "flushplusreload.h"



/* static int verbose_flag; */
extern const char *__progname;

static struct option long_options[] = {
    /*{ "verbose",     no_argument,       &verbose_flag, 1},
    { "brief",       no_argument,       &verbose_flag, 0}, */
    { "help",        no_argument,       0, 'h' },
    { "bench",       no_argument,       0, 'b'}, 
    { "threshold",   required_argument, 0, 't' },
    { "elf",         required_argument, 0, 'e' },
    { "slot",        required_argument, 0, 's' },
    { "probe",       required_argument, 0, 'p' },
    { 0, 0, 0, 0}
};

/* print usage or help info */ 
void usage(const char *msg)
{ 
    if (msg != NULL) 
    {
        printf ("[!] %s\n", msg);
        return;
    }
    printf ("Usage: %s -e ELFPATH -t CYCLES -s CYCLES -p PROBE [-p PROBE ...] [-m]\n", __progname);
    puts   ("    -b, --bench \t\t\tGet cache benchmark and quit.");
    puts   ("    -e, --elf PATH\t\t\tPath to ELF binary to spy on.");
    puts   ("    -t, --threshold CYCLES\t\tMax. L3 latency. (Default: 120)");
    puts   ("    -s, --slot CYCLES\t\t\tSlot duration in cycles.");
    puts   ("    -p, --probe N:0xDEADBEEF\t\tName character : Virtual address.");
}

int check_for_duplicates(int probe_index, const probe_t *probes)
{
    int i = 0;
    int j = 0;
    
    for (i = 0; i < probe_index; i++) 
    {
        for (j = i + 1; j < probe_index; j++) 
        {
            if (probes[i].name == probes[j].name) 
            {
                usage ("Two probes share the same name. This is not allowed.");
                return -1;
            }

            if (probes[i].virt_addr == probes[j].virt_addr) 
            {
                usage ("Two probes share the same virtual address. This is not allowed.");
                return -1;
            }
        }
    }

   return 0;
}

int parse_args(int argc, char **argv, args_t *args)
{
    int opt = 0; 
    char *argstr = NULL; 
    char *probe_token = NULL;

    while((opt = getopt_long (argc, argv, "hbe:t:s:p:", long_options, NULL)) != -1)
    {
        switch(opt)
        {
            case 'h': /* help */
                usage (NULL);
                return -1;
           
            case 'b': /* cache bench */ 
                cache_bench();
                return -1;

            case 'e': /* ELF Path */ 
                args->elf_path = optarg;
                break;

            case 't': /* Threshhold */               
                if (sscanf (optarg, "%10u", &args->threshold) != 1 || args->threshold <= 0)
                {
                    usage ("Bad threshold (must be an integer > 0).");
                    return -1;
                }
                
                if (!(0 < args->threshold && args->threshold < 2000)) 
                {
                    usage ("Bad threshold cycles value. Try 120?");
                    return -1;
                }
               
                break;
            
            case 's': /* Slot */
                if (sscanf (optarg, "%10lu", &args->slot) != 1 || args->slot <= 0 
                || args->slot > MAX_SLOT_SIZE) 
                {
                    usage ("Bad slot size try 1024?");
                    return -1;
                }
    
                break;

            case 'p': /* Probe e.x: A:0xDEADBEEF */ 
                argstr = optarg;
                
                probe_token = strtok(argstr, ",");

                while(probe_token != NULL)
                {
                    printf("[-] Set probe: %s\n", probe_token);
                   
                    if (args->probe_index >= MAX_PROBES)
                    {
                        usage ("You've exceeded the maximum amount of probes.");
                        return -1; 
                    }

                    probe_t *probe = &args->probes[args->probe_index];

                    /* Get probe name */ 
                    if (isalpha (probe_token[0]) && probe_token[1] == ':')
                    {
                        probe->name = probe_token[0];
                    }
                    else
                    {
                        usage ("Probe name must be one character [a-z][A-Z]");
                        return -1;
                    }

                    /* Skip over the colon. */
                    probe_token += 2;

                    if (strlen (probe_token) < 2 || probe_token[0] != '0' || probe_token[1] != 'x') 
                    {
                        usage ("Probe address must be given in hex (starting with 0x)");
                        return -1;
                    }

                    /* Parse the remainder as an integer in hex. */
                    if (sscanf (probe_token, "%10li", &probe->virt_addr) != 1 || probe->virt_addr <= 0) 
                    {
                        usage ("Bad probe address.");
                        return -1;
                    }

                    args->probe_index++; 
                    
                    probe_token = strtok(NULL, ",");
                }

                break;
            
            default:
                usage ("Invalid args.");
                return -1;
        }
    }

    /* see if probes were actually given */              
    if (args->probe_index <= 0)
    {
        usage ("No probes given. -p or --probe");
        return -1; 
    }

    /* check for duplicate names or addresses */
    if(check_for_duplicates (args->probe_index, args->probes) < 0)
    {
        return -1;
    }

    return 0;
}

/* clean up stuff */
void clean_up(args_t *args)
{ 
    free (args->probes);
    args->probes = NULL; 
}

int main(int argc, char **argv)
{
    int rc = -1;
  
    args_t args; 
   
    args.probe_index = 0;
    args.elf_path = NULL;
    args.threshold = 120; /* Default, will work for most systems. See Yarom and Falkner */
    args.slot = 0;
    args.probes = calloc (MAX_PROBES, sizeof (probe_t));
    if (NULL == args.probes)
    {
        perror ("Error allocating probes.\n");
        return -1;
    }

    /* No argumenst given, print help and quit */
    if (argc <= 1)
    { 
        usage (NULL);
        clean_up (&args);
        return 0;
    }

    /* Parse and validate arguments */
    if (0 == parse_args (argc, argv, &args))
    {
        rc = spy (&args);
    }
    
    clean_up (&args);
    
    return rc;
}
