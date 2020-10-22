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


import os
import shutil
import logging
import matplotlib.pyplot as plt

from operator import itemgetter

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


class TermColors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLO = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def check_empty(directory):
    """
    checks if a directory is empty.

    :param directory: path to directory
    :type directory: str
    :return: True if empty, False if not
    """
    if not os.listdir(directory):
        return True
    else:
        return False


def file_list(directory):
    """
    Get the name and path for all files and file paths.

    :param directory: path to a directory
    :type directory: str
    :return: list of dictionaries that contain dir_name and dir_path
    """
    global list_dirs

    dirs = []

    for dir_name in os.listdir(directory):
        dir_path = os.path.join(directory, dir_name)

        if os.path.isfile(dir_path):
            dir = dict()
            dir['name'] = str(dir_name)
            dir['path'] = str(dir_path)
            dirs.append(dir)

    # sort by dir name
    # logger.debug("{}".format(dirs))
    list_dirs = sorted(dirs, key=itemgetter('name'))

    return list_dirs


def clean_dir(directory):
    """
    Removes all files from a directory.

    :param directory: directory path
    :type directory: str
    """
    for file_name in os.listdir(directory):
        file_path = os.path.join(directory, file_name)
        if os.path.isfile(file_path):
            logger.debug('Removing: {}'.format(file_path))
            os.remove(file_path)


def clean_dir_dir(directory):
    """
    Give a directory name to clean.
    Deletes folders and directorys. 

    :param directory: directory path
    :type directory: str
    """
    for file_name in os.listdir(directory):
        file_path = os.path.join(directory, file_name)
        if os.path.exists(file_path):
            logger.debug('Removing: {}'.format(file_path))
            shutil.rmtree(file_path)


def grab_next_session(session_directory):
    """
    Given an empy directoy create a bunch of folders. 

    session_01 and on. 

    :param session_directory: empty directory you wnat to put these folders in
    :type session_directory: str
    :return: the latest directory path 
    :rtype: str
    """
    dir_list = []

    if not os.listdir(session_directory):
        session = os.path.join(session_directory, 'session_01')
        os.makedirs(session)
    else:
        for file_name in os.listdir(session_directory):
            file_path = os.path.join(session_directory, file_name)

            if os.path.isdir(file_path):
                dir_list.append(int(file_name.split('_')[1]))

        suffix = max(dir_list) + 1
        session_dir = "session_{:02d}".format(suffix)
        session = os.path.join(session_directory, session_dir)
        os.makedirs(session)

    return session


def read_file(file_name):
    """
    read lines from a file and return array
    
    :param file_name: path to file
    :type file_name: str
    """
    with open(file_name, 'r') as file:
        array = []
        for line in file:
            array.append(line.strip())

    return array


def write_file(data, file_name, mode='w'):
    """
    Write data to a file
    
    :param data: the data 
    :type data: str
    :param file_name: the file name/path
    :type file_name: str
    :raises ValueError: if bad file mode
    """
    if mode != 'w' and mode != 'a':
        raise ValueError('Bad mode')

    with open(file_name, mode) as file: 
        file.write(data)


def plot_graphs_val(history, string, dir):
    """
    Graph the results from training.
    
    :param history: history form the fit fucntion
    :type history: tuple 
    :param string: the param you want to plot (accuracy/loss)
    :type string: str
    :param dir: path and file name
    :type dir: str
    """
    plt.cla() # clear the plot 
    plt.plot(history.history[string])
    plt.plot(history.history['val_'+string])
    plt.xlabel("Epochs")
    plt.ylabel(string)
    plt.legend([string, 'val_'+string])
    sav = dir + "/" + string + '.png'
    plt.savefig(sav)


def plot_dist(l1_data, mem_data):
    plt.xlabel('Label (cycles)')
    plt.ylabel('Occurrences')
    plt.title('Distribution of Load Times')
  
    n, bins, patches = plt.hist([l1_data, mem_data], 
                                bins=100,
                                rwidth=0.95, 
                                color=['g','r'],
                                label=['L1 cache', 'Memory'] ,
                                alpha=0.5)
 
    plt.legend()
    plt.show()
