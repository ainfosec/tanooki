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


import tensorflow as tf 
import numpy as np 
import csv 
import json
import math 
import common 
import operator 
import random

from functools import reduce
from collections import defaultdict

# set logging level to debug
tf.logging.set_verbosity(tf.logging.DEBUG)


def best_session(lst): 
    index, value = max(enumerate(lst), key=operator.itemgetter(1))
    
    return index+1, value


def average(lst): 
    return reduce(lambda a, b: a + b, lst) / len(lst) 


def get_stats(array_of_acc, hyp):
    n = len(array_of_acc)
    ddof = n -1 
    s = np.std(np.array(array_of_acc), ddof=ddof)
    avg = average(array_of_acc)
    t = (math.sqrt(n) * (avg - hyp))/s

    return t, s, avg


def grab_metadata(json_file): 
    """ 
    target_dict => mapping of origonals labes to url 
    """
    # get the meta data 
    metadata = []
    with open(json_file) as file: 
        metadata = json.load(file)

    targets = list(metadata.values())

    target_dict = dict()

    for target in targets: 
        target_dict[target[1]] = target[0]
    
    return target_dict


def grab_csv(csv_file, truncate): 
    """ 
    Trun csv data into dict 
    """
    # get the meta data 
    data = common.read_file(csv_file)

    csv_dict = defaultdict(list)

    flag = False

    for probe in data: 
        # skip the labels 
        if not flag: 
            flag = True
            continue
            
        probe = probe.split(',')
        # num - probe
        csv_dict[int(probe[1])].append(probe[0][:truncate])
    
    return csv_dict


def gen_splits(number_of_splits, data, labels):
    """
    Generate data splits on given data and labesl.

    :param number_of_splits: number of data splits
    :type number_of_splits: int
    :param data: the trianing data
    :type data: numpy.array
    :param labels: the training labels 
    :type labels: numpy.array
    :return: data and label splits
    """
    data_splits = [] 
    label_splits = []

    number_of_examples = data.shape[0] // number_of_splits
    start = 0 
    end = number_of_examples  
    for i in range(0, number_of_splits):
        data_splits.append(data[start:end])
        label_splits.append(labels[start:end])
        start = end 
        end += number_of_examples

    return data_splits, label_splits


def process_data(csv_file, vocab, truncate=None ,return_original=False):
    """
    Process the data and lables. data will be numpy array, lables will be one hot.
    
    :param csv_file: path to data file 
    :type csv_file: str
    :param truncate: truncate the probe, defaults to None
    :type truncate: int, optional
    :param return_original: return non-one hot, defaults to False
    :type return_original: bool, optional
    :raises ValueError: bad truncation file
    :return: data, lables 
    :rtype: numpy.array, numpy.array
    """
    train_probes = []
    train_labels = []

    flag = False 

    # open the file 
    with open(csv_file) as csv_file: 
        csvReader = csv.reader(csv_file)
        for row in csvReader: 
            # skip first
            if flag == False: 
                flag = True
                continue
            train_probes.append(row[0])
            train_labels.append(row[1])


    #tf.logging.debug(train_probes[1])
    with open(vocab) as vocab_file: 
        vocab_data = vocab_file.readline()
        vocab_data = vocab_data.strip()
        vocab_data = vocab_data.split(',')

    vocab = sorted(set(vocab_data))

    # conversion functions
    char2idx = {u:i for i, u in enumerate(vocab)}

    for i in range(0, len(train_probes)):
        #convert text to char
        new_l =  list([char2idx[c] for c in str(train_probes[i])]) 
        if truncate is None:
            train_probes[i] = new_l
        elif truncate > 0 and truncate < len(new_l):
            train_probes[i] = new_l
            del train_probes[i][truncate:]
        else:
            raise ValueError("If you are going to truncate pick a good number...not: {}".format(truncate))

    # fix data type 
    for i in range(0, len(train_labels)):
        train_labels[i] = int(train_labels[i])

    # convert to numpy array 
    train_labels = np.array(train_labels)
    train_probes = np.array(train_probes)

    # rename data
    train_data = train_probes
    train_labels = train_labels

    # shuffle the data 
    np.random.seed()
    indicies = np.arange(len(train_data))
    np.random.shuffle(indicies)
    train_data = train_data[indicies]
    train_labels = train_labels[indicies]

    # preserve non-one hot test_labes 
    original_test_labels = train_labels

    # need the one hot becuse math 
    train_labels = tf.keras.utils.to_categorical(train_labels) 
    #train_data = tf.keras.utils.to_categorical(train_data) 
    if return_original == True: 
        return train_data, train_labels, original_test_labels
    else: 
        return train_data, train_labels


def process_spy(csv_file, vocab, truncate=None):
    """
    Same as proccess data, but without lables.
    
    :param csv_file: path to raw data file 
    :type csv_file: str
    :param truncate: truncate the len of the probe, defaults to None
    :type truncate: int, optional
    :raises ValueError: bad tuncation value 
    :return: data 
    :rtype: numpy.array
    """
    train_probes = []

    flag = False 

    # open the file 
    with open(csv_file) as csv_file: 
        csvReader = csv.reader(csv_file)
        for row in csvReader: 
            # skip first
            if flag == False: 
                flag = True
                continue
            train_probes.append(row[0])

    #tf.logging.debug(train_probes[1])
    #tf.logging.debug(train_probes[1])
    with open(vocab) as vocab_file: 
        vocab_data = vocab_file.readline()
        vocab_data = vocab_data.strip()
        vocab_data = vocab_data.split(',')

    vocab = sorted(set(vocab_data))

    # conversion functions
    char2idx = {u:i for i, u in enumerate(vocab)}

    for i in range(0, len(train_probes)):
        #convert text to char
        new_l =  list([char2idx[c] for c in str(train_probes[i])]) 
        if truncate is None:
            train_probes[i] = new_l
        elif truncate > 0 and truncate < len(new_l):
            train_probes[i] = new_l
            del train_probes[i][truncate:]
        else:
            raise ValueError("If you are going to truncate pick a good number...not: {}".format(truncate))

    # convert to numpy array 
    train_probes = np.array(train_probes)

    # rename data
    train_data = train_probes

    # shuffle the data 
    np.random.seed()
    indicies = np.arange(len(train_data))
    np.random.shuffle(indicies)
    train_data = train_data[indicies]

    return train_data



        
