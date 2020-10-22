#! /usr/bin/env python3

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


import argparse 
import hashlib
import logging 
import sys
import time
import os
import re
import concurrent.futures

# my modules 
FILE_PATH = os.path.dirname(os.path.abspath(__file__))
MOD_PATH = os.path.join(FILE_PATH, './mod')
sys.path.append(MOD_PATH)
import bin_tools
import common
import spy_tools
import gdb_tools


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

MAX_SLEEP = 100000
MAX_CHECK= 100000


def gather_data(args):
    """
    Gather training data.
    
    :param args: args for gather_data
    :type args: Namespace
    """
    target_binary = args.target_binary
    input_list = args.input_list 
    probe_file = args.probe_file
    samples = args.samples
    train_dir = args.train_dir
    sleep_kill = args.sleep_kill
    spy_binary = args.spy_binary
    threshold = args.threshold
    slot = args.slot
    
    # do some checks
    try: 
        if spy_binary is not None: 
            assert os.path.exists(spy_binary), 'spy_binary must exist'
        else: 
            spy_binary = os.path.join(FILE_PATH, 'spy')
            assert os.path.exists(spy_binary), 'spy_binary must exist, please make it.'
        assert os.path.exists(target_binary), 'run_binary must exist'
        assert os.path.exists(input_list), 'input_list must exist'
        assert os.path.exists(probe_file), 'probe_file must exist'
        assert os.path.exists(train_dir), 'train_dir must exist'
        assert samples > 0, 'samples must be greater than zero'
        assert sleep_kill > 0, 'sleep_kill must be greater than zero'
        assert threshold > 0, 'threshold must be greater than zero'
        assert slot > 0, 'slot must be greater than zero'
    except AssertionError as err:
        logger.error('Failed check: {}'.format(err)) 
        return 

    session_path = common.grab_next_session(train_dir)
  
    inputs = common.read_file(input_list) 
    
    # paths
    metadata_path = os.path.join(session_path, '01_METADATA')
    sess_info_path = os.path.join(session_path, '02_SESSION_INFO')
    cpu_info_path = os.path.join(session_path, '03_CPU_INFO')

    common.write_file(spy_tools.cpu_info(), cpu_info_path)

    # Create instances of spy and target elf
    spy = spy_tools.Spy(spy_binary, target_binary, threshold, slot, probe_file, sleep_kill)
    run_bin = spy_tools.TargetElf(target_binary)

    index = 1
    for target_input in inputs:
        # generate hash and write to METADATA file
        target_hash = common.gen_sha256_hash(target_input)
       
        metadata = '{}: {}\n'.format(target_hash, target_input)
        sess_info = '{} : '.format(target_hash)
      
        common.write_file(metadata, metadata_path, mode='a')
        common.write_file(sess_info, sess_info_path, mode='a')

        logger.info('Sampling[{}/{}]: {}\n'.format(index, len(inputs), target_input))
        
        index += 1 
        sucsess = 0

        # Set target bin args 
        run_bin.set_args(target_input) 

        for sample in range(0, samples): 
            logger.debug('\t {}\n'.format(sample + 1))
            
            # start the spy program 
            spy.start_program()
            
            # start the target program
            run_bin.start_program()

            # get the data
            data = spy.get_data()
            spy.clean_up()

            # stop the target prog
            run_bin.stop_program()

            if data:
                output = '{}_{}'.format(target_hash, sucsess)
                output_path = os.path.join(session_path, output)
                common.write_file(data, output_path)
                sucsess += 1
            else: 
                logger.warning("Missed")
       
        # good to know what's in your data set 
        sess_info = '[{}/{}] : {}\n'.format(sucsess, samples, spy_tools.system_load())
        common.write_file(sess_info, sess_info_path, mode='a')


def fix_missing(args):
    """
    Fill in gaps in your data set.
    
    :param args: args for fix_missing 
    :type args: Namespace
    """
    target_binary = args.target_binary
    meta_data = args.meta_data
    session_data = args.session_data
    probe_file = args.probe_file
    sleep_kill = args.sleep_kill
    spy_binary = args.spy_binary
    threshold = args.threshold
    slot = args.slot
    session_dir = args.session_dir

    # do some checks
    try: 
        if spy_binary is not None: 
            assert os.path.exists(spy_binary), 'spy_binary must exist'
        else: 
            spy_binary = os.path.join(FILE_PATH, 'spy')
            assert os.path.exists(spy_binary), 'spy_binary must exist, please make it.'
        assert os.path.exists(target_binary), 'run_binary must exist'
        assert os.path.exists(probe_file), 'probe_file must exist'
        assert sleep_kill > 0, 'sleep_kill must be greater than zero'
        assert threshold > 0, 'threshold must be greater than zero'
        assert slot > 0, 'slot must be greater than zero'
        assert os.path.exists(meta_data), 'meta_data must exist'
        assert os.path.exists(session_data), 'session_data must exist'
        assert os.path.exists(session_dir), 'session_dir must exist'
    except AssertionError as err: 
        logger.error('Failed check: {}'.format(err)) 
        return 

    meta = common.read_file(meta_data)
    sess = common.read_file(session_data) 

    # turn meta into a dict 
    meta_dict = {}
    for m in meta: 
        m = m.split(': ')
        # hash: input
        meta_dict[m[0].strip()] = m[1] 
        print(m[1])
    
    # turn sess into a dict
    sess_dict = {}
    for s in sess:
        s = s.split(':')
        # calculate missing 
        c = re.sub(r'\[|\]', '', s[1]).split('/') 
        sess_dict[s[0].strip()] = int(c[1]) - int(c[0])

    # Create instances of spy and target elf
    spy = spy_tools.Spy(spy_binary, target_binary, threshold, slot, probe_file, sleep_kill)
    run_bin = spy_tools.TargetElf(target_binary)
    
    for sha_hash, missing in sess_dict.items():

        # Set target bin args 
        run_bin.set_args(meta_dict[sha_hash]) 
        sucsess = 0

        print('{}: {}'.format(meta_dict[sha_hash], missing))
 
        for m in range(0, missing): 

            file_path = common.grab_next(session_dir, sha_hash)

            # start the spy program 
            spy.start_program()
            
            # start the target program
            run_bin.start_program()

            # get the data
            data = spy.get_data()
            spy.clean_up()

            # stop the target prog
            run_bin.stop_program()

            if data:
                common.write_file(data, file_path)
                sucsess += 1
            else: 
                logger.warning('Missed: {}'.format(meta_dict[sha_hash]))
       
        # good to know what's in your data set 
        sess_info = '[{}/{}] : {}\n'.format(sucsess, missing, spy_tools.system_load())
        logger.info(sess_info)


def collect_html(args):
    """
    Collect html data locally, so you don't have to 
    keep hitting the url.
    
    :param args: args for collect html
    :type args: Namespacd
    """
    url_list = args.url_list
    output_dir = args.output_dir

    print(url_list)

    # do some checks
    try: 
        assert os.path.exists(url_list), 'url_list must exist'
        assert os.path.exists(output_dir), 'output_dir must exist'
    except AssertionError as err: 
        logger.error('Failed check: {}'.format(err)) 
        return 

    urls = common.read_file(url_list)
    
    for url in urls: 
        logger.debug(url) 

        html = spy_tools.collect_html(url)
        out = url.split('/')
        output = os.path.join(output_dir, out[-1] + '.html')
        common.write_file(html, output)


def find_addr(args): 
    """
    Find probe addresses 
    
    :param args: args for find_addr
    :type args: Namespace
    """
    target_binary = args.target_binary
    probes = args.probes
    probe_file = args.probe_file
    
    # do some checks
    try: 
        assert os.path.exists(target_binary), 'target_binary must exist'
        assert not (probes is None and probe_file is None), 'Must set --probes or --probe_file'
        assert not (probes is not None and probe_file is not None), 'Must set --probes or --probe_file'
        if probe_file is not None: 
            assert os.path.exists(probe_file), 'probe_file must exist'
    except AssertionError as err:
        logger.error("Failed check: {}".format(err)) 
        return

    if probe_file is not None: 
        probes = bin_tools.load_probes(probe_file)
    else: 
        probes = probes.split(',')

    probe_names = bin_tools.get_probe_address(target_binary, probes)
    
    for name in probe_names: 
        print(name)


def find_probes(args):
    """
    Find potential probes addresses. 
    
    :param args: args for find_addr
    :type args: Namespace
    """
    target_binary = args.target_binary
    input_list = args.input_list 
    probe_file = args.probe_file
    sleep = args.sleep   
    check_num = args.check_num 
    ghidra_data = args.ghidra_data
    max_inputs = args.max_inputs
    take_top_n = args.take_top_n

    # do some checks
    try: 
        assert os.path.exists(target_binary), 'target_binary must exist'
        assert os.path.exists(input_list), 'input_list must exist'
        assert sleep > 0 and sleep < MAX_SLEEP, 'sleep must be greather than 0 and less than: {}'.format(MAX_SLEEP)
        assert check_num > 0 and check_num < MAX_SLEEP, 'check_num must be greather than 0 and less than: {}'.format(MAX_CHECK)
        assert max_inputs > 0, 'max_inputs must be positive'
        if probe_file is not None: 
            pass
            #assert os.path.exists(probe_file), 'probe_file must exist'
    except AssertionError as err:
        logger.error("Failed check: {}".format(err)) 
        return

    p_addr = []

    if ghidra_data and probe_file is not None: 
        p_addr = gdb_tools.load_ghidra_fucns(probe_file)
    elif probe_file is not None:
        p_addr = common.read_file(probe_file) 
    else:
        probes = bin_tools.extract_functions(target_binary) 
        for k,v in probes.items():
            # key = function name
            # value = addr  
            p_addr.append(v) 
    
    # make gdb instance  
    gdb = gdb_tools.GDB(target_binary, p_addr)
    gdb.set_text_section() # get text section bounds

    # If a breakpoint is hit while enabled in this fashion,
    # the count is decremented; when it reaches zero, the breakpoint is disabled.
    # might need to edit this section by hand depending on the target. 
    gdb.set_check_num(check_num)
    gdb.set_breakpoints()
    gdb.set_command_pc() # print $pc ad breakpoint
    gdb.enable_count()  
    gdb.gdb_command('run') 
    gdb.end_script() # write out gdb script

    # target bin inputs
    inputs = common.read_file(input_list) 
    gdb_out = []
    top_probes = {}
    count = 0 
    for count, target_input in enumerate(inputs):
        if count > max_inputs: 
            break
       
        logger.debug(target_input)
        gdb.set_args(target_input)

        gdb.start_gdb() # run gdb script
        # wait for a bit 
        time.sleep(sleep)
        # stop the process
        gdb.stop_gdb()
        gdb_out = gdb.parse_output()

        top = gdb_out[-take_top_n:]
        for t in top: 
            if t[0] in top_probes:
                top_probes[t[0]] += 1
            else: 
                top_probes[t[0]] = 1
        print(top_probes)


def cache_bench(args):
    """
    Plot cache bench. 
    
    :param args: cache bench args 
    :type args: Namespace
    """
    spy_binary = args.spy_binary
   
    # do some checks
    try: 
        if spy_binary is not None: 
            assert os.path.exists(spy_binary), 'spy_binary must exist'
        else: 
            spy_binary = os.path.join(FILE_PATH, 'spy')
            assert os.path.exists(spy_binary), 'spy_binary must exist, please make it.'
    except AssertionError as err:
        logger.error('Failed check: {}'.format(err)) 
        return 

    cb = spy_tools.CacheBench(spy_binary)
    cb.start_program()
    std_out = cb.get_output()

    l1 = re.compile(r"(0:)")  # 0 => L1 cache 
    mem = re.compile(r"(1:)") # 1 => From memory 

    # seperate data and format it 
    l1_timing =  [re.sub('0: ', '', x) for x in std_out if l1.match(x)]
    mem_timing = [re.sub('1: ', '', x) for x in std_out if mem.match(x)]

    logger.debug(max(l1_timing))
    logger.debug(max(mem_timing))
   
    # make in and filter out outliers 
    l1_timing = [int(x) for x in l1_timing if int(x) < 300]
    mem_timing = [int(x) for x in mem_timing if int(x) < 500]
    

    common.plot_bench(l1_timing, mem_timing)


def system_load(args):
    """
    Plot system load.
    
    :param args: system load args
    :type args: Namespace
    """
    session_info = args.session_info

    # do some checks
    try: 
        assert os.path.exists(session_info), 'session_info must exist'
    except AssertionError as err:
        logger.error('Failed check: {}'.format(err)) 
        return 

    sess_info = common.read_file(session_info)

    a = []  # 5 min avg
    b = []  # 10 min avg 
    c = []  # 15 min avg

    for s in sess_info: 
        s = s.split(':')
        s = s[2].split(' ')
        del s[0]
        
        a.append(float(s[0]))
        b.append(float(s[1]))
        c.append(float(s[2]))

    common.plot_sess_info(a, b, c, len(a))


def proc_time(args):
    """
    Process over time.
    
    :param args: processes over time
    :type args: Namespace
    """
    session_info = args.session_info

    # do some checks
    try: 
        assert os.path.exists(session_info), 'session_info must exist'
    except AssertionError as err:
        logger.error('Failed check: {}'.format(err)) 
        return 

    sess_info = common.read_file(session_info)

    a = []  # proc

    for s in sess_info: 
        s = s.split(':')
        s = s[2].split(' ')
        del s[0]
        
        a.append(float(s[0]))

    common.plot_proc_info(a, len(a))


def main(): 
    # make parser
    parser = argparse.ArgumentParser(prog='attack_tools')
    subparsers = parser.add_subparsers()

    # make sub parsers 
    parser_gather_data = subparsers.add_parser('gather-data', help='Clean and parse data.')
    parser_fix_missing = subparsers.add_parser('fix-missing', help='Fix missing data.')
    parser_collect_html = subparsers.add_parser('collect-html', help='Collect html local.')
    parser_find_addr = subparsers.add_parser('find-addr', help='Find probe addresses.')
    parser_find_probes = subparsers.add_parser('find-probes', help='Find the best probes.')
    parser_cache_bench = subparsers.add_parser('bench', help='Get cache benchmark.')
    parser_plot_load = subparsers.add_parser('load', help='Plot system load over time.')
    parser_plot_proc = subparsers.add_parser('proc', help='Processes over time.')

    # gather data arguments 
    parser_gather_data.add_argument('target_binary', type=str, help='Path to the binary to target.')
    parser_gather_data.add_argument('input_list', type=str, help='Path to list of inputs for run_binary.')
    parser_gather_data.add_argument('probe_file', type=str, help='Path to probe file.')
    parser_gather_data.add_argument('samples', type=int, help='Number of sample to capture')
    parser_gather_data.add_argument('train_dir', type=str, help='Directory to save training info in.')
    parser_gather_data.add_argument('--sleep_kill', metavar='', type=int, default=10, 
                                    help='Kill process after N number of seconds (default: 1)')
    parser_gather_data.add_argument('--spy_binary', metavar='', type=str, default=None,
                                    help='Path to binary to spy on (default spy in cwd)')
    parser_gather_data.add_argument('--threshold', metavar='', type=int, default=120, 
                                    help='Threshold time to determine probe hit (default: 120)')
    parser_gather_data.add_argument('--slot', metavar='', type=int, default=2048,
                                    help='You can think of this is how long your sting will be. (default: 2048)')

    # fix missing arguments
    parser_fix_missing.add_argument('target_binary', type=str, help='Path to the binary to target.')
    parser_fix_missing.add_argument('session_dir', type=str, help='Path to session_dir.')
    parser_fix_missing.add_argument('probe_file', type=str, help='Path to probe file.')
    parser_fix_missing.add_argument('meta_data', type=str, help='Path to metadata file')
    parser_fix_missing.add_argument('session_data', type=str, help='Path to session data file')
    parser_fix_missing.add_argument('--sleep_kill', metavar='', type=int, default=1, 
                                    help='Kill process after N number of seconds (default: 1)')
    parser_fix_missing.add_argument('--spy_binary', metavar='', type=str, default=None,
                                    help='Path to binary to spy on (default spy in cwd)')
    parser_fix_missing.add_argument('--threshold', metavar='', type=int, default=120, 
                                    help='Threshold time to determine probe hit (default: 120)')
    parser_fix_missing.add_argument('--slot', metavar='', type=int, default=2048,
                                    help='You can think of this is how long your sting will be. (default: 2048)')

    # collect html arguments 
    parser_collect_html.add_argument('url_list', type=str, help='Path to list of URLs')
    parser_collect_html.add_argument('output_dir', type=str, help='Directory to save html info in.')

    # find address arguments 
    parser_find_addr.add_argument('target_binary', type=str, help='Path to the target bianry')
    parser_find_addr.add_argument('--probes', metavar='', type=str, default=None, 
                                 help='Name of probes to find i.e (get_html,parse_html)') 
    parser_find_addr.add_argument('--probe_file', metavar='', type=str, default=None, 
                                help='Path to probe file.')

    # find probes arguments
    parser_find_probes.add_argument('target_binary', type=str, help='Path to the target bianry')
    parser_find_probes.add_argument('input_list', type=str, help='Path to list of input to train on.')
    parser_find_probes.add_argument('--probe_file', metavar='', type=str, default=None, 
                                    help='Path to probe file.')
    parser_find_probes.add_argument('--sleep', metavar='', type=int, default=10, help='Sleep kill.')
    parser_find_probes.add_argument('--check_num', metavar='', type=int, default=100, 
                                    help='Set num till breakpoint is useless. (Default: 100)')
    parser_find_probes.add_argument('--take_top_n', metavar='', type=int, default=10, 
                                    help='Take top n probes (Default: 10)')
    parser_find_probes.add_argument('--max_inputs', metavar='', type=int, default=10, 
                                    help='Max number of tests. (Default: 10)')
    parser_find_probes.add_argument('--ghidra_data', default=False, action='store_true',
                                    help='Is the probe file ghidra data?')
    
    # cache bench arguments 
    parser_cache_bench.add_argument('--spy_binary', metavar='', type=str, default=None,
                                    help='Path to binary to spy on (default spy in cwd)')

    # plot system load arguments 
    parser_plot_load.add_argument('session_info', type=str, help='Path to session info')

    # plot system load arguments 
    parser_plot_proc.add_argument('session_info', type=str, help='Path to session info')


    # set functions
    parser_gather_data.set_defaults(func=gather_data)
    parser_fix_missing.set_defaults(func=fix_missing)
    parser_collect_html.set_defaults(func=collect_html)
    parser_find_addr.set_defaults(func=find_addr)  
    parser_find_probes.set_defaults(func=find_probes)
    parser_cache_bench.set_defaults(func=cache_bench)
    parser_plot_load.set_defaults(func=system_load)
    parser_plot_proc.set_defaults(func=proc_time) 

    args = parser.parse_args()    

    if len(sys.argv)==1:
        parser.print_help()
        return 

    args.func(args)


if __name__ == "__main__": 
    main()
