#  Copyright (C) 2020 Assured Information Security, Inc.
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.


import subprocess
import os 
import logging 
import sys 
import common 
import string


PIPE = subprocess.PIPE

# init logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# format output
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

# configuration for console logging
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
ch.setFormatter(formatter)
logger.addHandler(ch)


# Sections of an ELF bin 
SECTIONS = [
   '.interp', '.note.ABI-tag', '.note.gnu.build-id', '.gnu.hash', 
   '.dynsym', '.dynstr', '.gnu.version', '.gnu.version_r',
   '.rela.dyn', '.rela.plt', '.init', '.plt', '.plt.got',
   '.text', '.fini', '.rodata', '.eh_frame_hdr', '.eh_frame', 
   '.init_array', '.fini_array', '.jcr', '.dynamic', '.got', 
   '.got.plt', '.data', '.bss', '.comment', '.shstrtab', 
   '.symtab', '.strtab'
   ]


def load_probes(probe_file): 
    """
    load probe names frome file
    
    :param probe_file: path to file 
    :type probe_file: str """
    probes = common.read_file(probe_file)
    probe_list = list(filter(None, probes))
    return probe_list


def objdump_section(elf_path, section):
    """
    Strip out the text section from the binary 
    
    :param elf_path: Path to ELF file 
    :type elf_path: str
    :param section: section of the bin 
    :type section: str
    :return: bin text section 
    :rtype: str
    """
    assert isinstance(elf_path, str), 'ELF path must be str'
    assert section in SECTIONS, 'Not a vaild section'

    # Print the symbol table entries of the file. (-t)
    # Decode (demangle) low-level symbol names into user-level names. 
    cmd = ['objdump', '-t', '--demangle', elf_path] 
    objdump = subprocess.Popen(cmd, stdout=PIPE)

    fgrep = subprocess.Popen(['fgrep', section], stdin=objdump.stdout, stdout=PIPE)
    objdump.wait()
    objdump.stdout.close()
    
    # get fgrep output
    std_out = fgrep.communicate()[0]
    fgrep.stdout.close() 

    return std_out.decode('utf-8')


def parse_func_names(data): 
    """
    Parse objdump data.
    
    :param data: .text data mostly 
    :type data: str
    """
    name_to_addr = {}
    
    for line in data.split('\n'): 
        parts = line.split()
        if not parts: # empty list
            continue
        addr = parts[0]
        name = parts[-1]
        name_to_addr[name] = addr.lstrip('0')

    return name_to_addr


def get_probe_address(elf_path, probes, section='.text'):
    """
    Get the virtual addr of probes.
   
    :param elf_path: Path to ELF bin 
    :type elf_path: str
    :param probes: name of function
    :type probes: list
    :param section: section of the bin, defaults to '.text'
    :type section: str, optional
    :return: probe name and location
    :rtype: list
    """
    assert len(probes) <= 26, 'Too many probes'

    text_data = objdump_section(elf_path, '.text')
    name_to_addr = parse_func_names(text_data)

    probe_names = list(string.ascii_uppercase)
    name_idx = 0 

    ret = []

    for probe in probes: 
        assert probe in name_to_addr, '{} not found'.format(probe)
        ret.append('{}:0x{}'.format(probe_names[name_idx], name_to_addr[probe]))
        name_idx += 1 

    return ret


def extract_functions(elf_path): 
    """
    Extract info from .text section.
    
    :param elf_path: path to bin
    :type elf_path: str
    :return: function names
    :rtype: dict
    """
    text_data = objdump_section(elf_path, '.text')
    name_to_addr = parse_func_names(text_data)
    return name_to_addr


def combinate_porbes():
    pass


def test_probes(): 
    pass 


def get_hit_record():
    pass
