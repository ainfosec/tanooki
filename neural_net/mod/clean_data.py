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


import json
import os
import logging
import re
import csv 
import random 

import common

from collections import defaultdict


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


def to_string(list1, length):
    """
    Convert array to string.

    :param list1: the list of characters
    :type list1: list
    :param length: truncation length
    :type length: int
    :return: the return string
    :rtype: str
    """
    str1 = ''.join(str(e) for e in list1)
    # Truncate the data 
    # may also want to have a floor function here 
    str1 = ((str1[:length]) if len(str1) > length else str1) 
    # str1 = str1.replace('',' ').strip()
    return str1


def write_to_csv(data, meta, clean_dir, train_file, length, split=1, eval_file=None, metadata_file=None, spy_data=False):
    """
    Write the data to csv files.
    
    :param data: the probe data
    :type data: dict
    :param meta: the meta data file 
    :type meta: dict
    :param clean_dir: the output directory
    :type clean_dir: str
    :param train_file: name of the train file
    :type train_file: str
    :param length: the len of the string (truncation len)
    :type length: int
    :param split: the percent of the split (data allocated to train), defaults to 1
    :type split: float, optional
    :param eval_file: the name of the eval_file, defaults to None
    :type eval_file: str, optional
    :param metadata_file: name of the metadata file, defaults to None
    :type metadata_file: str, optional
    :param spy_data: new spy data, not eval dat no split, defaults to False
    :type spy_data: bool, optional
    :raises ValueError: spy data was selected, not all optisons were set
    :raises ValueError: spy data selected, too many options were set
    """
    if not spy_data and (eval_file is None or metadata_file is None):
        raise ValueError("please specify all params")
    if spy_data and (metadata_file is not None or eval_file is not None or split != 1):
        raise ValueError("incorect args")

    # delete old tsv's data,  
    common.clean_dir(clean_dir) 

    logger.info("writting new data")
    # logger.debug(data) 
    
    # first row
    if spy_data == False:  
        title_row = ['probe', 'label']
    else: 
        title_row = ['probe']

    csv.register_dialect('myDialect', delimiter = ',', quoting=csv.QUOTE_NONE, skipinitialspace=True) 
    
    train_line = 0
    eval_line = 0
    
    # save metadata
    if spy_data == False:
        with open(metadata_file, 'w') as metadata: 
            json.dump(meta, metadata)

    # write the headers 
    with open(train_file, 'a') as train_csv:
         writer = csv.writer(train_csv, dialect='myDialect')
         writer.writerow(title_row)

    # write the headers
    if spy_data == False:  
        with open(eval_file, 'a') as eval_csv:
            writer = csv.writer(eval_csv, dialect='myDialect')
            writer.writerow(title_row)

    for key in data: 
        probe_strs = data[key]
        # use the rest for eval should be 5 per.INFO1 traing set  
        index = int(len(probe_strs) * split)
        #logger.debug("index: {} len:{}".format(index, len(probe_strs)))
        train_probes_strs = probe_strs[:index]
        eval_probes_strs = probe_strs[index:]
       
        with open(train_file, 'a') as train_tsv:
            writer = csv.writer(train_tsv, dialect='myDialect')
            for probe in train_probes_strs: 
                if(len(probe) < length): 
                    continue
                if spy_data == False:
                    try: 
                        row = [to_string(probe, length), meta[key][1]] 
                    except IndexError as err: 
                        #logger.error("probe:{} \n".format(probe))
                        logger.error(err)
                        return
                else:
                    row = [to_string(probe, length)] 
                writer.writerow(row)
                train_line += 1

        if spy_data == False:
            with open(eval_file, 'a') as eval_tsv: 
                writer = csv.writer(eval_tsv, dialect='myDialect')
                for probe in eval_probes_strs:  
                    if(len(probe) < length): 
                        continue 
                    try: 
                        row = [to_string(probe, length), meta[key][1]] 
                    except IndexError as err: 
                        # logger.error("probe:{} \n len:{} \n meta: {}".format(probe, length, meta))
                        logger.error(err)
                        return
                    writer.writerow(row)
                    eval_line += 1


def clean_data(list_of_files, spy_data=False): 
    """
    Takes the raw data and process cleans it and chops off mistakes.
    This makes Hornby's code compatible with my model.  

    {4} represents a chache miss in hornbys code we simply just delete them.  

    :param list_of_files: list of files to clean
    :type list_of_files: list 
    :param spy_data: this is spy data meta_data will be None, defaults to False
    :type spy_data: bool, optional
    :return: data, metaa
    :rtype: dict, dict
    """
    # we do this a lot so compile it 
    match = re.compile('(\{[0-9]+\})', flags=re.MULTILINE)
    data_dict = defaultdict(list)
    if spy_data == False:
        meta_dict = defaultdict(list)
    else: 
        meta_dict = None

    for my_file in list_of_files:
        start_pos = []
        end_pos = []
        insert_str = []
        content = ""
        adjusted_name = my_file['name'].split('_')[0]

        if spy_data == False:  
            # save the meta data infomation 
            if my_file['name'] == 'METADATA' or my_file['name'] == '01_METADATA':     
                i = 0
                with open(my_file['path'], 'r') as meta_data: 
                    for line in meta_data:  
                        line_split = line.split(': ') 
                        meta_dict[line_split[0]] = (line_split[1].strip(), i)
                        # print(meta_dict)
                        i += 1
                continue

        with open(my_file['path'], 'r') as probe_file: 
            content = probe_file.read()
            # logger.debug("content: {}".format(content))
            # strip the whitespace out of the file
            content = re.sub(r'\s+', '', content)  
            
            # logger.debug("content: {}".format(content))
            # extend adds the actual content of the list not just appends it 
            # so you don't have lists and lists and it can zip
            # the following line finds the all start positions of a given character in a string 
            start_pos.extend([m.start() for m in re.finditer('{', content)])
            end_pos.extend([m.start() for m in re.finditer('}', content)])
        
            if len(start_pos) != len(end_pos): 
                logger.error("invalid string:\n {}".format(content))
                # seems there is a bug in the prob gathering tool
                # chop the bad ends off. 
                content = content[:start_pos[-1]]
                
            if len(start_pos) == 0: 
                # skip nothing to replace 
                content_list = [] 
                content_list.append(content) 
                data_dict[adjusted_name].append(content)
                continue 
            
            # del cahce misses 
            content = match.sub('', content) 

            # start_end_pairs = zip(start_pos, end_pos)
            
            # for pair in start_end_pairs:
                # # grab the number between the brackets 
                # repeat_num = content[pair[0]+1: pair[1]]
                # prev_char = content[pair[0]-1]
                # # make a string of one letter of size repeat_num
                # insert_str.append(prev_char * int(repeat_num))
            # for char_str in insert_str:
                # # match {} with one or more numbers in between 
                # content = re.sub('(\{[0-9]+\})',char_str, content, 1) 

            content_list = [] 
            content_list.append(content) 
            data_dict[adjusted_name].append(content)

            # logging.debug(data_dict)

    return data_dict, meta_dict
