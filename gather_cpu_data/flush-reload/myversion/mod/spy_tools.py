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
import logging
import os
import sys
import select 
import subprocess 
import time

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


class Spy(): 
    def __init__(self, spy_path, elf_path, threshold, slot, probe_file, sleep_kill):
        self.spy_path = spy_path
        self.elf_path = elf_path 
        self.threshold = str(threshold)
        self.slot = str(slot)
        self.load_probes(probe_file)
        self.sleep_kill = sleep_kill

        # "Private" stuff
        self.__proc__ = None
        self.__data__ = None
        self.__info__ = None
        self.__error__ = None

    def start_program(self):
        """
        Start the program with arguments. 
        Do nothing if process is already running.
        """
        if self.__proc__ is None: 
            self.__proc__ = subprocess.Popen([self.spy_path, 
                                            '-e', self.elf_path, 
                                            '-t', self.threshold, 
                                            '-s', self.slot, 
                                            '-p', self.probes],
                                            stdout=PIPE,
                                            stderr=PIPE,
                                            universal_newlines=True)
        else:
            logger.warn('Process exists. Doing nothing.')

    def stop_program(self): 
        """
        Send sig term and delete all data.
        Do nothing if proc is not running. 
        """
        if self.__proc__ is not None: 
            self.__proc__.terminate()
        else:
            logger.warn('Process does not exist. Doing nothing.')

    def clean_up(self):
        self.__proc__.stdout.close()
        self.__proc__.stderr.close()
        self.__data__ = None # delete all data 
        self.__proc__ = None

    def add_probes(self, probe_list):
        """
        Add probes to probe list.
        
        :param probe_list: List of probe addrs
        :type probe_list: list of strs 
        """
        self.probes = ','.join(probe_list)

    def load_probes(self, probe_file): 
        """
        Load probes from file. 
        Remove empty lines.
        
        :param probe_file: Probe file path
        :type probe_file: str
        """
        probes = common.read_file(probe_file)
        probe_list = list(filter(None, probes))
        self.add_probes(probe_list)
    
    def parse_output(self, stdout, stderr): 
        """
        While the process is still running or time has not run out 
        parse the input.
        
        :raises RuntimeError: If [!] in stdout 
        :raises RuntimeError: If data in stderr
        """
        if stderr: 
            # somthing happened dump everything 
            self.__error__ = stderr
            self.__info__ = stdout
            if self.__error__ or self.__info__: 
                raise RuntimeError('{} {}'.format(self.__error__, self.__info__))

        for line in stdout.split('\n'): 
            # info not data make sure to follow this convension
            if line.startswith('[-]'):
                logger.debug(line)
            # usage problem 
            elif line.startswith('[!]'):
                self.__info__ = line 
                raise RuntimeError(self.__info__)
            else: 
                self.__data__ = line # its actual probe data
                break
        
    def get_data(self): 
        """
        return probe data.

        They spy program will terminate when it got the data. 
        Then communite will grab stdout and stderr.

        :return: probe data from spy program
        :rtype: str
        """
        try: 
            std_out, std_err = self.__proc__.communicate(timeout=self.sleep_kill)
            self.parse_output(std_out, std_err)
        except subprocess.TimeoutExpired: 
            self.stop_program()

        return self.__data__


class TargetElf(): 
    def __init__(self, elf_path): 
        self.elf_path = elf_path
        self.elf_args = None

        # "Private" stuff
        self.__proc__ = None

    def start_program(self):
        """
        Start target program. Do nothing if 
        process is already running do nothing.
        """
        if self.__proc__ is None: 
            args = self.gen_args()
            self.__proc__ = subprocess.Popen(self.gen_args(),
                                            stdout=PIPE,
                                            stderr=PIPE)
        else:
            logger.warn('Process exists already. Doing nothing.')

    def stop_program(self):
        """
        Stop program. Do nothing if process is 
        not running.
        """
        if self.__proc__ is not None: 
            self.__proc__.stdout.close()
            self.__proc__.stderr.close()
            self.__proc__.terminate()
            self.__proc__ = None
        else:
            logger.warn('Process does not exist. Doing nothing.')
    
    def gen_args(self): 
        """
        Set arguments of the program.
        Append path and args together.
        
        :raises ValueError: If no args are set 
        :return: args
        :rtype: list
        """
        args = []
        if self.elf_args is not None:
            args.append(self.elf_path)
            args.append(self.elf_args)
            return args
        else: 
            raise ValueError("No ELF args")
    
    def set_args(self, args):
        """
        Send a list or string 
        
        :param args: list or str
        :type args: list or str
        """
        self.elf_args = args
    
    def wait_for_output(self):
        """
        Wait for stdout output.
        """
        p = select.poll()
        p.register(self.__proc__.stdout, select.POLLIN)
        start_time = time.time() 

        while True: 
            if p.poll(1):  #if somthing in stdout
                time.sleep(1)  #it not a perfect soluntion
                break


class CacheBench():
    def __init__(self, spy_path):
        self.spy_path = spy_path

        # "Private" stuff
        self.__proc__ = None 
    
    def start_program(self): 
        """
        Run spy in bench mode. 
        Do nothing if process is already running.
        """
        if self.__proc__ is None: 
            self.__proc__ = subprocess.Popen([self.spy_path, '-b'], stdout=PIPE)
        else:
            logger.warn('Process exists. Doing nothing.')

    def stop_program(self): 
        """
        Send sig term and delete all data.
        Do nothing if proc is not running. 
        """
        if self.__proc__ is not None: 
            self.__proc__.stdout.close()
            self.__proc__.stderr.close()
            self.__proc__.terminate()
            self.__proc__ = None
        else:
            logger.warn('Process does not exist. Doing nothing.')

    def get_output(self): 
        """
        Get the output from this mode.
        """
        return str(self.__proc__.communicate()[0]).split('\\n')


def system_load(): 
    """
    Grab informaiton from /proc/loadavg

    :return: loadavg info 
    :rtype: str
    """
    cat = subprocess.Popen(['cat', '/proc/loadavg'], stdout=PIPE)
    std_out = cat.communicate()[0]
    std_out = std_out.decode('utf-8')
    return std_out.rstrip()


def cpu_info(): 
    """
    Grab information from lscpu.
    Need infomation about the make and model 
    of the CPU, and cache.
    
    :return: lscpu inforamtion 
    :rtype: str
    """
    cpu_info = subprocess.Popen(['lscpu'], stdout=PIPE)
    std_out = cpu_info.communicate()[0]
    return std_out.decode('utf-8')


def collect_html(url):
    """
    grab html info 
    """
    wget = subprocess.Popen(['wget', '-q', '-O', '-', url], stdout=PIPE)
    std_out = wget.communicate()[0]
    return std_out.decode('utf-8')
