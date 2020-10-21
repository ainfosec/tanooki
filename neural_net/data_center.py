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
import logging
import os 
import sys
import numpy as np
import time
import copy

# my modules 
FILE_PATH = os.path.dirname(os.path.abspath(__file__))
MOD_PATH = os.path.join(FILE_PATH, './mod')
sys.path.append(MOD_PATH)
import clean_data
import common 
import process_data
import levenshtein_tools
import character_rnn as rnn

from collections import defaultdict
from common import TermColors

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


def gen_data(args):
    """
    Clean raw data so it can be processed.
    
    :param args: args for gen_data
    :type args: Namespace
    """
    # pull args out 
    length = args.len 
    split = args.split 
    clean_dir = args.output_data
    unclean_dir = args.target_data
    spy_data = args.spy_data

    # do some checks
    try: 
        assert length > 0, "len must be positive"
        assert split <= 1.0 and split > 0, "split must be between 0-1"
        assert os.path.exists(clean_dir), "output_data dir must exist"
        assert os.path.exists(unclean_dir), "target_data dir must exist"
    except AssertionError as err: 
        logger.error("Failed check: {}".format(err)) 
        return 

    # set the directories
    if spy_data == False: 
        metadata_file = clean_dir + "METADATA.json"
        train_file = clean_dir + "Train.csv"
        eval_file = clean_dir + "Eval.csv"
    else: 
        test_file = clean_dir + "Spy.csv"

    # get list of files 
    list_of_files = common.file_list(unclean_dir)

    names = [] 
    for i in list_of_files: 
        names.append(i['name']) 
   
    match = ['02_SESSION_INFO', '03_CPU_INFO']
    # pull out matches 
    meta_files = [s for s in list_of_files if any(m == s['name'] for m in match)]     
    for m in meta_files: 
        list_of_files.remove(m)

    for m in meta_files: 
        if m['name'] == '02_SESSION_INFO':
            session_file = m['path'] 
        elif m['name'] == '03_CPU_INFO':
            cpu_file = m['path']
        else:
            pass

    # process the data
    if spy_data == True: 
        data, metadata = clean_data.clean_data(list_of_files, spy_data=True) 
        logging.debug("DATA: {}".format(data))
        clean_data.write_to_csv(data, metadata, clean_dir, test_file, length, spy_data=True)
    else: 
        data, metadata = clean_data.clean_data(list_of_files) 
        clean_data.write_to_csv(data, metadata, clean_dir, train_file, length, split, eval_file, metadata_file)


def train_data(args):
    """
    Train the model. 

    :param args: args for trin_data
    :type args: Namespace
    """
    # pull args out 
    training_dir = args.training_dir
    train_file = args.train_file 
    eval_file = args.eval_file 
    epochs = args.epochs
    continue_training = args.keep_training
    checkpoint_dir = args.checkpoint_dir
    #truncate = args.truncate
    vocab = args.vocab

    # do some checks
    try:
        if continue_training:
            assert checkpoint_dir is not None, 'to continue training you must give checkpoint_dir'
            assert os.path.exists(checkpoint_dir), 'checkpoint_dir must exist'
        assert epochs > 0, 'epochs must be positive'
        assert os.path.exists(train_file), "train_file must exist"
        assert os.path.exists(training_dir), "training_dir must exist"
        assert os.path.exists(eval_file), "eval_file must exist"
        assert os.path.exists(vocab), "vocab file must exist"
        #assert truncate > 0, 'truncate must be positive'
    except AssertionError as err: 
        logger.error("Failed check: {}".format(err)) 
        return 

    # get train and eval data
    train_data, train_labels = process_data.process_data(train_file, vocab)
    test_data, test_labels = process_data.process_data(eval_file, vocab) 

    # make the checkpoint directory 
    if not continue_training and checkpoint_dir is None: 
        checkpoint_dir = common.grab_next_session(training_dir)

    # train the model 
    history, model_summary = rnn.train_and_validate(train_data, train_labels, test_data, test_labels, epochs, checkpoint_dir, continue_training)

    # plot the data 
    if not continue_training: 
        common.write_file(model_summary,checkpoint_dir + "/MODEL_SUMMARY")
        common.plot_graphs_val(history, 'categorical_accuracy', checkpoint_dir)
        common.plot_graphs_val(history, 'loss', checkpoint_dir)


def eval_data(args):
    """
    Evaluate the model.
    
    :param args: args for eval_data
    :type args: Namespace
    """
    eval_file = args.eval_file 
    metadata_file = args.metadata_file
    hide_results = args.hide_results
    checkpoint_dir = args.checkpoint_dir
    # truncate = args.truncate
    vocab = args.vocab
    
    # do some checks
    try: 
        assert os.path.exists(eval_file), "eval_file must exist"
        assert os.path.exists(metadata_file), "metadata_file must exist"
        assert os.path.exists(checkpoint_dir), "checkpoint_dir must exist"
        assert os.path.exists(vocab), "vocab file must exist"
        # assert truncate > 0, 'truncate must be positive'
    except AssertionError as err: 
        logger.error("Failed check: {}".format(err)) 
        return 

    target_dict = process_data.grab_metadata(metadata_file)
    print("target dict: {}".format(target_dict))
    eval_data, eval_labels, original_test_labels = process_data.process_data(eval_file, vocab, return_original=True)
    
    rnn.eval(eval_data, eval_labels, checkpoint_dir, target_dict, original_test_labels, hide_results)


def predict_data(args):
    """
    Get a prediction from the model. 
    
    :param args: args for predict_data
    :type args: Namespace
    """
    predict_file = args.predict_file 
    metadata_file = args.metadata_file
    checkpoint_dir = args.checkpoint_dir
    vocab = args.vocab
    fun = args.fun

    # do some checks
    try: 
        assert os.path.exists(predict_file), "eval_file must exist"
        assert os.path.exists(metadata_file), "metadata_file must exist"
        assert os.path.exists(checkpoint_dir), "checkpoint_dir must exist"
        assert os.path.exists(vocab), "vocab file must exist"
    except AssertionError as err: 
        logger.error("Failed check: {}".format(err)) 
        return 

    # process spy data 
    spy_data = process_data.process_spy(predict_file, vocab)

    # need the map between hash and url 
    target_dict = process_data.grab_metadata(metadata_file)    
    # get the models best guess
    rnn.predict(spy_data, checkpoint_dir, target_dict, fun)


def gen_stats(args):
    """
    Perfom k-fold validation. 

    :param args: args for gen_stats
    :type args: Namespace
    """
    # pull args out 
    training_dir = args.training_dir
    train_file = args.train_file 
    splits = args.splits
    epochs = args.epochs
    test_file = args.test_file
    hyp = args.hyp
    vocab = args.vocab

    # do some checks
    try:
        assert os.path.exists(training_dir), "training_dir must exist"
        assert os.path.exists(train_file), "eval_file must exist"
        if test_file is not None:  
            assert os.path.exists(test_file), "test_file must exist"
        assert hyp >= 0 and hyp <= 1, "hyp must be between 0 and 1"
        assert epochs > 0, 'epochs must be positive'
        assert os.path.exists(vocab), "vocab file must exist"
        assert splits > 0, "splits must be positive"
    except AssertionError as err: 
        logger.error("Failed check: {}".format(err)) 
        return 

    # get the data together  
    train_data_process, train_labels_process = process_data.process_data(train_file, vocab)
    data_split, data_lables = process_data.gen_splits(splits, train_data_process, train_labels_process)

    if test_file is not None: 
            test_data_process, test_labels_process = process_data.process_data(test_file, vocab)
            test_data_split, test_data_lables = process_data.gen_splits(splits, test_data_process, test_labels_process)

    # delte all the data in this directory 
    common.clean_dir_dir(training_dir)
    
    accuracy_per_session = []

    # run the tests
    for split in range(0, splits):
        # pull out the test data for this session  
        eval_data = data_split[split] 

        start = 0 
        end = len(eval_data)
        # just so we aren't testing and validating on the same data
        test_data = eval_data[int(end/2):end] 
        eval_data = eval_data[start:int(end/2)] 


        # the rest is now trainig
        indicies = list(range(0, splits))
        # remove the test data
        del indicies[split]
        train_data = data_split[indicies[0]]
        train_labels = data_lables[indicies[0]]
        # remove the first one
        del indicies[0]
        for i in indicies:
            train_data = np.append(train_data, data_split[i], axis=0)
            train_labels = np.append(train_labels, data_lables[i], axis=0)

        # logger.debug(train_data)
      
        # make the checkpoint directory
        checkpoint_dir = common.grab_next_session(training_dir)
       
        # train the model 
        logger.debug("TRINING")
        history, model_summary = rnn.train_and_validate(train_data, train_labels, eval_data, eval_labels, epochs, checkpoint_dir)
        
        # get the result
        logger.debug("EVAL")
        metrics = rnn.eval(test_data, test_labels, checkpoint_dir, show_results=False)
        common.write_file(str(model_summary), checkpoint_dir + "/MODEL_SUMMARY")
        accuracy_per_session.append(metrics[1])
        logger.debug("accuracy so far: {}".format(accuracy_per_session))
        common.plot_graphs_val(history, 'categorical_accuracy', checkpoint_dir)
        common.plot_graphs_val(history, 'loss', checkpoint_dir)
    
    t, s, avg = process_data.get_stats(accuracy_per_session, hyp)
    data = "list of accs: {}".format(accuracy_per_session)
    data += "\n t-value:{}, std:{}, avg:{}".format(t, s, avg)
    data += "\n hyp 0: {}".format(hyp)
    common.write_file(data, training_dir + "/SESSION_INFO")


def levenshtein(args): 
    """
    Do levenshtein stuff
    
    :param args: levenshtein args
    :type args: Namespace
    """
    data_set_one = args.data_set_one
    #metadata = args.metadata 
    data_set_two = args.data_set_two
    examples_one = args.examples_one
    examples_two = args.examples_two 
    truncate = args.truncate
    all_flag = args.all

    # do some checks  
    try:
        assert os.path.exists(data_set_one), "data_set_one must exist"
        # assert os.path.exists(metadata), "metadata must exist"
        if data_set_two is not None:  
            assert os.path.exists(data_set_two), "data_set_two must exist"
        if examples_one is not None:
            assert examples_one > 0, 'examples_one must be positive'
        if examples_two is not None: 
            assert examples_two > 0, 'examples_two must be positive'
        assert truncate > 0, 'truncate must be positive'
    except AssertionError as err: 
        logger.error("Failed check: {}".format(err)) 
        return 

    #target_dict = process_data.grab_metadata(metadata)
    data_set_one = process_data.grab_csv(data_set_one, truncate)

    
    # If there is one data set then it came from the same machine 
    # If there are two data sets then we are doing a cross-machine check 
    if data_set_two is None: 
        examples_two += examples_one 
        data_set_two = data_set_one
        start = examples_one
        assert all_flag is False, 'Must specify another directory'
    else: 
        data_set_two = process_data.grab_csv(data_set_two, truncate)
        start = 0

    if examples_one is None: 
        examples_one = len(data_set_one)
    
    if examples_two is None: 
        examples_two
    
    train_probes = []
    test_probes = []
    
    missed_url_train = 0 
    missed_url_test = 0 

    # make training set
    for key, value in data_set_one.items(): 
        for example in range(0, examples_one):
            try:
                train_probes.append((key, value[example]))
            except IndexError as err: 
                print("missed url {}".format(key))
                missed_url_train += 1
                continue

    for key, value in data_set_two.items(): 
        for example in range(start, examples_two):
            try:
                test_probes.append((key, value[example]))
            except IndexError as err: 
                print("missed url {}".format(key))
                missed_url_test += 1
                continue

    correct = 0 
    total = 0 
    incorrect = 0

    for test_probe in test_probes:
        # match test_probe againsts all train probes 
        match, dist = levenshtein_tools.least_distance(train_probes, test_probe)
        time2 = time.time()
        logger.debug('time: {}'.format(time2 - time1))
        if match == test_probe[0]:
            correct += 1 
        else: 
            incorrect += 1
        print('{}:{} dist:{} {}'.format(test_probe[0], match, dist, total))
        total += 1 

    # how many did it get correctly 
    print('\n\nAccuracy: {}\nCorrect: {}\nIncorrect: {}\n missed_train: {} missed_test: {}'.format(correct/total, correct, incorrect, missed_url_train, missed_url_test))


def lev_gen_stats(args): 
    """
    Perfom k-fold validation. 

    :param args: args for lev_gen_stats
    :type args: Namespace
    """
    # pull args out 
    training_dir = args.training_dir
    train_file = args.train_file 
    splits = args.splits
    truncate = args.truncate
    hyp = args.hyp
    number_of_examples = args.number_of_examples

    # do some checks
    try:
        assert os.path.exists(training_dir), "training_dir must exist"
        assert splits > 0, "splits must be positive"
        if number_of_examples is not None:
            assert number_of_examples > 0, "splits must be positive"
    except AssertionError as err: 
        logger.error("Failed check: {}".format(err)) 
        return 

    # grab the data set 
    data_set = process_data.grab_csv(train_file, truncate)
    # gen lev data splits  
    data_split = levenshtein_tools.gen_lev_splits(splits, data_set, number_of_examples)

    
    accuracy_per_session = []

    print(len(data_split)) 
    # run the tests
    for split in range(0, splits):

        # make the checkpoint directory
        checkpoint_dir = common.grab_next_session(training_dir)
        checkpoint_file = checkpoint_dir + "/session.csv"
        
        test_data = []
        train_data =[]

        test_data = levenshtein_tools.unpack_lev_splits(copy.deepcopy(data_split[split]))
        # the rest is now trainig
        indicies = list(range(0, splits))
        # remove the test data
        del indicies[split]
        train_data = levenshtein_tools.unpack_lev_splits(copy.deepcopy(data_split[indicies[0]]))
        # remove the first one
        del indicies[0]
        for i in indicies:
        # logger.debug(train_data)
            train_data += levenshtein_tools.unpack_lev_splits(copy.deepcopy(data_split[i]))

        print(indicies)
    
        # train the model 
        logger.debug("TRINING")

        correct = 0 
        total = 0 
        incorrect = 0
        
        print("test: {}. id:{}".format(len(test_data), id(test_data)))
        print("train: {}. id:{}".format(len(train_data), id(train_data)))
        total_time_one = time.time()
        for test_probe in test_data:
            time1 = time.time()
            match, dist = levenshtein_tools.least_distance(train_data, test_probe)
            time2 = time.time()
            if match == test_probe[0]:
                print("{}: time {}".format(TermColors.GREEN + str(match) + TermColors.ENDC, time2-time1))
                correct += 1 
            else: 
                print("{}: time {}".format(TermColors.RED + str(match) + TermColors.ENDC, time2-time1))
                incorrect += 1
            total += 1 
        total_time_two = time.time()

        # get the result
        logger.debug("EVAL")
        accuracy_per_session.append(correct/total)
        logger.debug("accuracy so far: {}".format(accuracy_per_session))
        logger.debug('Time: {}'.format(total_time_two-total_time_one))
        # write data to file 
        logger.debug("WRITE SESSION DATA")
        csv_data = "probe,label \n"
        for item in train_data: 
            csv_data += "{},{}\n".format(item[1], item[0])
        common.write_file(csv_data, checkpoint_file)

    
    t, s, avg = process_data.get_stats(accuracy_per_session, hyp)
    data = "list of accs: {}".format(accuracy_per_session)
    data += "\n t-value:{}, std:{}, avg:{}".format(t, s, avg)
    data += "\n hyp 0: {}".format(hyp)
    data += "\n time: {}".format(total_time_two-total_time_one)
    common.write_file(data, training_dir + "/SESSION_INFO")


def lev_eval(args): 
    """
    Evaluate the model.
    
    :param args: args for eval_data
    :type args: Namespace
    """
    eval_file = args.eval_file 
    checkpoint_file = args.checkpoint_file
    examples = args.number_of_examples
    hide = args.hide
    banner = args.banner 
    
    # truncate = args.truncate
    
    # do some checks
    try: 
        assert os.path.exists(eval_file), "eval_file must exist"
        assert os.path.exists(checkpoint_file), "checkpoint_dir must exist"
    except AssertionError as err: 
        logger.error("Failed check: {}".format(err)) 
        return 

    eval_set = process_data.grab_csv(eval_file, 450)
    train_set =  process_data.grab_csv(checkpoint_file, 450)
 
    eval_data = levenshtein_tools.gen_lev_splits(1, eval_set, examples)
    train_data = levenshtein_tools.gen_lev_splits(1, train_set)

    eval_data = levenshtein_tools.unpack_lev_splits(copy.deepcopy(eval_data[0]))
    train_data = levenshtein_tools.unpack_lev_splits(copy.deepcopy(train_data[0]))

    correct = 0
    incorrect = 0
    total = 0 

    for test_probe in eval_data:
        time1 = time.time()
        match, dist = levenshtein_tools.least_distance(train_data, test_probe)
        time2 = time.time()
        if match == test_probe[0]:
            if not hide:
                print("{}: time {}".format(TermColors.GREEN + str(match) + TermColors.ENDC, time2-time1))
            correct += 1 
        else: 
            if not hide: 
                print("{}: time {}".format(TermColors.RED + str(match) + TermColors.ENDC, time2-time1))
            incorrect += 1
        total += 1 

    # how many did it get correctly 
    print(banner)
    print('\n\nAccuracy: {}\nCorrect: {}\nIncorrect: {}\n\n'.format(correct/total, correct, incorrect ))


def main():
    # make parser
    parser = argparse.ArgumentParser(prog='data_center')
    subparsers = parser.add_subparsers()

    # make sub parsers 
    parser_gen_data = subparsers.add_parser('gen-data', help='Clean and parse data.')
    parser_train = subparsers.add_parser('train', help='Train the model.')
    parser_eval = subparsers.add_parser('eval', help='Evaluate the model.')
    parser_predict = subparsers.add_parser('predict', help='Get a prediction from the model.')
    parser_gen_stats = subparsers.add_parser('gen-stats', help='Do a student t-test on a k fold cv.')
    parser_levenshtein = subparsers.add_parser('lev', help='Use the levenshtein method. (NOTE:BROKEN)')
    parser_lev_gen_stats = subparsers.add_parser('lev-gen-stats', help='Do a student t-test on a k fold cv. (lev)')
    parser_lev_eval = subparsers.add_parser('lev-eval', help='Eval lev model')

    # gen data arguments
    parser_gen_data.add_argument('target_data', type=str, help='Path to data to be processes.')
    parser_gen_data.add_argument('output_data', type=str, help='Path to output the cleaned data.')
    parser_gen_data.add_argument('--len', metavar='', default=450, type=int, help='Len of the string to truncate too. (Default to 450 characters)')
    parser_gen_data.add_argument('--split', metavar='', default=0.9, type=float, help='When to split to eval. (Default to .90 train .10 eval)')
    parser_gen_data.add_argument('--spy_data', default=False, action='store_true', help='Is this new spy data? (i.e) preparing the data for prediction.')

    # train arguments
    parser_train.add_argument('train_file', type=str, help='Path to train csv.')
    parser_train.add_argument('eval_file', type=str, help='Path to eval csv.')
    parser_train.add_argument('--epochs', default=20, type=int,  help='Number or epochs. (default: 20)')
    parser_train.add_argument('--keep_training', action='store_true', default=False, help='keep training n number of epochs. (pass in exsisting checkpoint_dir)')
    parser_train.add_argument('--training_dir', metavar='', default='./training', type=str, help='Directory to store training sessions. (defualt ./training)')
    parser_train.add_argument('--checkpoint_dir', metavar='', default=None, type=str, help='checkpoint directory.')
    #parser_train.add_argument('--truncate', metavar='', default=450, type=int, help='truncate data. (default: None)') 
    parser_train.add_argument('--vocab', metavar='', default='./vocab.txt', type=str, help="vocab file")
    
    # eval arguments 
    parser_eval.add_argument('metadata_file', type=str, help='Path to metadata.')
    parser_eval.add_argument('eval_file', type=str, help='Path to eval csv.')
    parser_eval.add_argument('checkpoint_dir', type=str, help='Path to checkpoint dir.')
    parser_eval.add_argument('--hide_results', default=True, action='store_false', help='Do not print model guess for each url.')
    #parser_eval.add_argument('--truncate', metavar='', default=450, type=int, help='truncate data. (default: None)')
    parser_eval.add_argument('--vocab', metavar='', default='./vocab.txt', type=str, help="vocab file")

    # predict arguments 
    parser_predict.add_argument('metadata_file', type=str, help='Path to metadata.')
    parser_predict.add_argument('predict_file', type=str, help='Path to probe csv.')
    parser_predict.add_argument('checkpoint_dir', type=str, help='Path to checkpoint dir.')
    #parser_predict.add_argument('--truncate', metavar='', default=450, type=int, help='truncate data.')
    parser_predict.add_argument('--fun', default=False, action="store_true", help='the fun way to dispaly data.')
    parser_predict.add_argument('--vocab', metavar='', default='./vocab.txt', type=str, help="vocab file")

    # gen stats arguments
    parser_gen_stats.add_argument('train_file', type=str, help='Path to train csv.')
    parser_gen_stats.add_argument('--epochs', default=20, type=int,  help='Number or epochs.')
    parser_gen_stats.add_argument('--hyp', default=0.94, type=float,  help='The hypothesis value. (i.e) H0 > 0.94')
    parser_gen_stats.add_argument('--splits', default=10, type=int,  help='Number of train test splits. (default: 10)')
    parser_gen_stats.add_argument('--training_dir', metavar='', default='./cv_training', type=str, help='Directory to store training sessions.')
    parser_gen_stats.add_argument('--test_file', metavar='', default=None, type=str, help='If you need to test against a different data set that it trained on.')
    parser_gen_stats.add_argument('--vocab', metavar='', default='./vocab.txt', type=str, help="vocab file")

    # Levenshtein distance arguments  
    parser_levenshtein.add_argument('data_set_one', type=str, help='first data set.')
    # parser_levenshtein('metadata', type=str, help='metadata file.')
    parser_levenshtein.add_argument('--data_set_two', metavar='', type=str, default=None, help='first data set.')
    parser_levenshtein.add_argument('--examples_one', metavar='', type=int, default=None, help='number of examples. (default all)')
    parser_levenshtein.add_argument('--examples_two', metavar='', type=int, default=None, help='number of examples. (default all)')
    parser_levenshtein.add_argument('--truncate', metavar='', type=int, default=1000, help='Truncate length (default: 1000)')
    parser_levenshtein.add_argument('--all', default=False, action='store_true', help='use all data (please use two different files)')
    #parser_levenshtein.add_argument('--plot', default=False, action="store_true", help='plot misses and hits.')
    
    # Levenshtein gen stats arguments
    parser_lev_gen_stats.add_argument('train_file', type=str, help='Path to train csv.')
    parser_lev_gen_stats.add_argument('--splits', default=10, type=int,  help='Number of train test splits. (default: 10)')
    parser_lev_gen_stats.add_argument('--training_dir', metavar='', default='./cv_training', type=str, help='Directory to store training sessions.')
    parser_lev_gen_stats.add_argument('--truncate', metavar='', default=450, type=int, help='truncate data. (default 450)')
    parser_lev_gen_stats.add_argument('--hyp', default=0.94, type=float,  help='The hypothesis value. (i.e) H0 > 0.94')
    parser_lev_gen_stats.add_argument('--number_of_examples', metavar='', type=int, default=None, help='number of examples. (defaultall)')

    # eval arguments 
    parser_lev_eval.add_argument('eval_file', type=str, help='Path to eval csv.')
    parser_lev_eval.add_argument('checkpoint_file', type=str, help='Path to checkpoint dir.')
    parser_lev_eval.add_argument('--number_of_examples', metavar='', type=int, default=None, help='number of examples. (default all)')
    parser_lev_eval.add_argument('--banner', metavar='', type=str, default=None, help='banner')
    parser_lev_eval.add_argument('--hide', default=False, action='store_true', help='Hide results')

    # set functions
    parser_gen_data.set_defaults(func=gen_data) 
    parser_train.set_defaults(func=train_data) 
    parser_eval.set_defaults(func=eval_data)
    parser_predict.set_defaults(func=predict_data)
    parser_gen_stats.set_defaults(func=gen_stats)
    parser_levenshtein.set_defaults(func=levenshtein) 
    parser_lev_gen_stats.set_defaults(func=lev_gen_stats) 
    parser_lev_eval.set_defaults(func=lev_eval) 

    args = parser.parse_args()    

    if len(sys.argv)==1:
        parser.print_help()
        return 

    args.func(args)


if __name__ ==  "__main__":
    main()
