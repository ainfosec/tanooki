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


import common
import csv
import logging 
import os
import subprocess
import re


# init logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

# format output
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

# configuration for console logging
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
ch.setFormatter(formatter)
logger.addHandler(ch)


FILE_PATH = os.path.dirname(os.path.abspath(__file__))
GDB_SCRIPT_DIR = os.path.join(FILE_PATH, 'gdb_scripts')
GDB_OUTPUT =  os.path.join(GDB_SCRIPT_DIR, 'gdb_output')
GDB_TEXT_SEC = os.path.join(GDB_SCRIPT_DIR, 'sections.gdb')

FILE_HEADER = 'set logging file {} \nset logging on\n'.format(GDB_OUTPUT)
GHIDRA_OFFSET = 0x100000  

IGNORE = [
    'strndup', 
    'calloc',
    'malloc',
    'realloc',
    'free'
]

PIPE = subprocess.PIPE

SECTIONS_GDB="""set logging file {}
set logging on
starti 
info file 
quit
""".format(GDB_OUTPUT)


class GDB():
    def __init__(self, elf_file, probes, arg_list=None): 
        self.elf_file = elf_file
        self.probes = probes
        self.args = arg_list 
        
        # "Private" stuff
        self.__gdb_proc__ = None 
        self.__script__ = FILE_HEADER
        self.__lbn__ = 0 # last break point numbr
        self.__text_start__ = None
        self.__text_end__ = None

        # "Private" magic stuff
        self.__BASE__ = 0x555555554000 #GDB magic number
        self.__GDB_SCRIPT__ = os.path.join(GDB_SCRIPT_DIR, 'script.gdb')
        self.__MAX_COUNT__ = 100000

    def set_args(self, args):
        """
        Set program args.
        
        :param args: target program arguments
        :type args: str
        """
        self.args = args
    
    def set_base_addr(self, base):
        """
        Set magic base addr.
        
        :param base: hex base addr
        :type base: int base 16
        """
        self.__BASE__ = base
    
    def set_ghidra_offset(self, offset):
        """
        Set magic ghidra addr.
        
        :param base: hex base addr
        :type base: int base 16
        """
        self.__GHIDRA_OFFSET__ = offset

    def set_file_name(self, name):
        """
        File name.
        
        :param name: strpt.gdb
        :type name: str
        """
        self.__GDB_SCRIPT__ = name 

    def set_check_num(self, num):
        """
        Set count number.
        
        :param num: max count number
        :type num: int
        """
        self.__MAX_COUNT__ = num 

    def set_text_section(self):
        """
        Pull the .text section out.
        """
        if os.path.exists(GDB_OUTPUT):
            os.remove(GDB_OUTPUT) 

        sections_gdb = os.path.join(GDB_SCRIPT_DIR, 'sections.gdb') 
        if not os.path.exists(sections_gdb):
            common.write_file(SECTIONS_GDB, sections_gdb)

        cmd = ['gdb', '--batch', '--command={}'.format(GDB_TEXT_SEC), self.elf_file]
        gdb = subprocess.Popen(cmd, stdout=PIPE)
        gdb.wait()
        gdb.stdout.close()

        gdb_output = common.read_file(GDB_OUTPUT)

        for line in gdb_output: 
            if '.text' in line: 
                line = line.split()
                self.__text_start__ = line[0] # start addr
                self.__text_end__ = line[2] # end addr
                break
    
    def check_text_bounds(self, addr):
        """
        Check bounds of probe
        
        :param addr: probe addr 
        :type addr: int
        :return: in bounds or not
        :rtype: bool 
        """
        if addr >= self.__text_start__ and addr <= self.__text_end__: 
            return True
        else: 
            return False
    
    def apply_magic(self, addr):
        """
        Assuming these probes came from ghidra
        
        :param addr: probe addr
        :type addr: int
        :return: adjusted addr
        :rtype: int
        """
        return addr + self.__BASE__

    def set_breakpoints(self):
        """
        Set breakpoints in script
        """
        # set breakpoints at every porbe
        for b in self.probes:
            b = hex(self.apply_magic(int(b, 16)))
            if (self.__text_start__ is not None and self.__text_end__ is not None):
                if self.check_text_bounds(b):
                    continue # out of bounds skip
            self.__script__ += 'b *0{}\n'.format(b.lstrip('0'))

    def set_command_pc(self):
        """
        When break point is hit outbupt $pc and cont. 
        """
        self.__script__ += 'commands {}-{}\n'.format(self.__lbn__+1, self.__lbn__ + len(self.probes))
        self.__script__ += '\t silent\n' 
        self.__script__ += '\t info reg $pc\n' 
        self.__script__ += '\t cont\n' 
        self.__script__ += 'end\n'

    def enable_count(self):
        """
        Disable breakpoint after MAX COUNT
        """
        self.__script__ += 'enable count {} {}-{}\n'.format(self.__MAX_COUNT__, 
                                                            self.__lbn__+1, 
                                                            self.__lbn__ + len(self.probes)) 

    def end_script(self):
        """
        End script, write out file.
        """
        common.write_file(self.__script__, self.__GDB_SCRIPT__)

    def set_stop_solib(self):
        """
        stop on solib event
        """
        self.__script__ += 'set stop-on-solib-events 1\n'

    def gdb_command(self, cmd): 
        """
        May need to add in your own commands
        
        :param cmd: gdb command
        :type cmd: str
        """
        self.__script__ += '{}\n'.format(cmd)

    def start_gdb(self):
        """
        Start the gdb script.
        """
        if os.path.exists(GDB_OUTPUT):
            os.remove(GDB_OUTPUT)
        cmd = ['gdb', '--batch', '--command={}'.format(self.__GDB_SCRIPT__), 
                '--args', self.elf_file, self.args]
        self.__gdb_proc__ = subprocess.Popen(cmd, stdout=PIPE, stdin=PIPE)

    def stop_gdb(self):
        """
        Terminate the script 
        """
        self.__gdb_proc__.terminate()
    
    def parse_output(self):
        """
        Parse script output.
        
        :return: list of addr and count
        :rtype: list of tuple
        """
        call_dict = {}
        gdb_out = common.read_file(GDB_OUTPUT)

        for line in gdb_out:
            if 'pc' in line:
                addr = line.split()[1]
                # translate back
                addr = hex(int(addr, 16) - self.__BASE__)
                
                if addr in call_dict:
                    call_dict[addr] += 1
                else: 
                    call_dict[addr] = 1 

        return sorted(call_dict.items(), key=lambda kv: kv[1])


def load_ghidra_fucns(csv_file):
    """
    Load probes from ghidra output.
    
    :param csv_file: ghidra symbol table
    :type csv_file: str
    :return: list of addrs
    :rtype: list
    """
    probes = []
    with open(csv_file, 'r') as csvfile:
        reader = csv.reader(csvfile)
        for row in reader:
            if 'Function' in row: 
                for item in IGNORE: 
                    if item in row:
                        print(row) 
                        continue
                    else:
                        probes.append(hex(int(row[1], 16) - GHIDRA_OFFSET))
    return list(dict.fromkeys(probes)) # remove duplicates
