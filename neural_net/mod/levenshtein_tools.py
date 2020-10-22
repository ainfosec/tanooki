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


import Levenshtein as lev 
import sys 
import random 
import common 

from collections import defaultdict


def least_distance(train_probes, test_probe): 
    """
    Get the probe with the least amount of 
    distance. return the key. 
    
    :param train_probes: test of train_probes
    :type train_probes: list of tuples
    :param test_probe: test probe tuple 
    :type test_probe: tuple 
    :return: The number of the label 
    """
    # (distance, label)
    least_dist = (sys.maxsize, -1)

    for train_probe in train_probes:
        #print(train_probe[1])
        #print('+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++')
        #print(test_probe[1])
        distance = lev.distance(train_probe[1], test_probe[1]) 
        if distance < least_dist[0]: 
            least_dist = (distance, train_probe[0])
    
    return least_dist[1], least_dist[0]


def gen_lev_splits(number_of_splits, data, examples=None):
    """
    Generate data splits on given data and labesl.

    :param number_of_splits: number of data splits
    :type number_of_splits: int
    :param data: the trianing data
    :type data: list 
    :param number_of_examples: number of examples per key 
    :type number_of_examples: int
    :return: data and label splits
    :rtype: list of dicts 
    """
    data_splits = []
    prev_number_of_examples = 0 
    number_of_examples = 0
    flag = False

    #shuffel the dictonary 
    keys = list(data.keys())
    #sorted(keys)

    # make the list 
    for i in range(0, number_of_splits):
        data_splits.append(defaultdict(list))

    if examples is not None: 
        for key in data:
            random.shuffle(data[key])
            data[key] = data[key][0:examples]

    # itterate over all lables 
    for key in keys: 
        # must have content 
        if len(data[key]) <= 0: 
            continue
        if flag is True : 
            assert number_of_examples == prev_number_of_examples, "must be the same number of each lablel"
            prev_number_of_examples = number_of_examples
        
        # number examples splits for key 
        number_of_examples = len(data[key]) // number_of_splits
        if flag is False: 
            prev_number_of_examples = number_of_examples

        flag = True 

        start = 0 
        end = number_of_examples  
        
        # actually split the data  
        for i in range(0, number_of_splits):
            data_splits[i][key] = data[key][start:end]
            start = end 
            end += number_of_examples

    return data_splits


def unpack_lev_splits(data_dict): 
    """
    Turn dict into tuple 

    :param data_dict: the dict
    :type data_dict: dict 
    :return: in tuple form 
    """

    data_tuple = [] 

    for key in data_dict: 
        for value in data_dict[key]:
            data_tuple.append((key, value))

    return data_tuple
