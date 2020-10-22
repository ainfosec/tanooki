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

from __future__ import absolute_import, division, print_function, unicode_literals

import tensorflow as tf
import numpy as np
import os
import io
import time 
import cowsay
 
#from tensorflow.keras.callbacks import TensorBoard
from common import TermColors

# not all of the hyperparameters that were tried, 
# but here are a few leaving for whatever 
# reason. 
#LAYERS = [450, 500, 200, 100, 100]
#LAYERS = [450, 1000, 750, 450, 100]
#LAYERS = [450, 750, 600, 450, 100]
#LAYERS = [450, 300, 300, 300, 100]
#LAYERS = [450, 300, 300, 300, 150, 100]
#LAYERS = [450, 350, 350, 350, 100, 100]


def scheduler(epoch):
    """
    learning rate scheduler.
    
    :param epoch: number of epochs
    :type epoch: int
    """
    if epoch < 10:
        return 0.001
    else:
        return 0.001 - (.00005 * epoch)

# Feel free to change these hyperparameters
def build_model(vocab_len, input_len):
    """
    Build the model.
    
    :param vocab_len: Number of unique characters in the probe
    :type vocab_len: int
    :param input_len: Number of characters in the probe
    :type input_len: int
    :return: the model 
    """
    model = tf.keras.Sequential([
        tf.keras.layers.Embedding(vocab_len, 4, input_length=input_len, embeddings_initializer='glorot_uniform'),
        tf.keras.layers.CuDNNGRU(400, return_sequences=True),
        tf.keras.layers.CuDNNGRU(400, return_sequences=True),
        tf.keras.layers.CuDNNGRU(400),
        tf.keras.layers.Dense(100, activation='relu'),
        tf.keras.layers.Dropout(0.5),
        tf.keras.layers.Dense(100, activation='softmax')
    ])    

    # some hacks to print out the model
    tmp_smry = io.StringIO()
    model.summary(print_fn=lambda x: tmp_smry.write(x + '\n'))
    summary = tmp_smry.getvalue() 
    return model, summary


def compile_model(model, loss='categorical_crossentropy', optimizer='adam', metrics=['categorical_accuracy']):
    """
    Compile the model.
    
    :param model: model form build_model
    :param loss: lost fucntion, defaults to 'categorical_crossentropy'
    :type loss: str, optional
    :param optimizer: optimizer sinstance, defaults to 'adam'
    :type optimizer: str, optional
    :param metrics: metrics to be evaluated by the model, defaults to ['categorical_accuracy']
    :type metrics: list, optional
    :return: compiled model
    """
    model.compile(loss=loss,
              optimizer=optimizer,
              metrics=metrics)
    return model 


def train_and_validate(train_data, train_labels, val_data, val_labels, epochs, checkpoint_dir, continue_training=False):
    """
    Train the model and also pass validataion set.
    
    :param train_data: training data
    :type train_data: numpy.array 
    :param train_labels: training labels 
    :type train_labels: numpy.array
    :param val_data: validataion data 
    :type val_data: numpy.array 
    :param val_labels: validatiaon labels
    :type val_labels: numpy.array
    :param epochs: number of epochs
    :type epochs: int
    :param checkpoint_dir: checkpoint dir
    :type checkpoint_dir: str
    :param continue_training: load weights and continue trining, defaults to False
    :type continue_training: bool, optional
    :return: model histroy and summary
    """
    model, model_summary = build_model(len(set(train_data[0])), train_data.shape[1])
    model = compile_model(model, optimizer=tf.keras.optimizers.Nadam())

    tf.logging.debug(model_summary)
    
    # Name of the checkpoint files
    checkpoint_prefix = os.path.join(checkpoint_dir, "ckpt_{epoch}")
    checkpoint_callback=tf.keras.callbacks.ModelCheckpoint(
        filepath=checkpoint_prefix,
        monitor='val_categorical_accuracy',
        save_best_only=True,
        save_weights_only=True,
        mode='max')

    # for if you want to continue training 
    if continue_training == True:
        model.load_weights(tf.train.latest_checkpoint(checkpoint_dir))

    # Learning rate scheduler tapers off the amout of stuff it can forget towards the end 
    scheduler_callback = tf.keras.callbacks.LearningRateScheduler(scheduler)
    tf.logging.debug("{} {}".format(epochs, type(epochs)) ) 
    # fit the model 
    history = model.fit(train_data, train_labels, epochs=epochs, callbacks=[checkpoint_callback, scheduler_callback], validation_data=(val_data, val_labels), verbose=1)

    return history, model_summary


def eval(test_data, test_labels, checkpoint_dir, target_dict=None, original_test_labels=None, show_results=True): 
    """
    Evaluate the model.
    show_results will print more verbose infomation about how the model performed. 
    
    :param test_data: test data
    :type test_data: numpy.array
    :param test_labels: test labels 
    :type test_labels: numpy.array
    :param checkpoint_dir: checkpoint directory 
    :type checkpoint_dir: str
    :param target_dict: map between int and url, defaults to None
    :type target_dict: dict, optional
    :param original_test_labels: the actual labels as ints, defaults to None
    :type original_test_labels: numpy.array, optional
    :param show_results: show the guesses from the model, defaults to True
    :type show_results: bool, optional
    :raises ValueError: Data dict must be set when dhow results is choosen
    :return: metrics
    """
    if show_results == True and (target_dict is None or original_test_labels is None):
        raise ValueError("In order to show resulst target_dict and original_test_label must be set")
  
    # set up the model load the weights  
    model, model_summary = build_model(len(set(test_data[0])), test_data.shape[1])
    model = compile_model(model)
    model.load_weights(tf.train.latest_checkpoint(checkpoint_dir))

    tf.logging.debug(model_summary)
    
    # evaluate the model
    metrics = model.evaluate(test_data, test_labels, verbose=2)

    # get the predictions 
    if show_results == True:
        time1 = time.time()
        predictions = model.predict(test_data)
        time2 = time.time()
        tf.logging.debug("time: {}".format(time2 - time1))

        total = 0 
        correct = 0 

        result = []
        incorrect = []

        for (prediction, origonal_test_label) in zip(predictions, original_test_labels):
            # get the guess 
            guess = np.argmax(prediction.flatten())
            result.append([(origonal_test_label, target_dict[origonal_test_label]), (guess, target_dict[guess])])
            total += 1
            if origonal_test_label == guess: 
                correct += 1 
            else:
                incorrect.append([(origonal_test_label, target_dict[origonal_test_label]), (guess, target_dict[guess])])
 
        print("RESULTS:")
  
        #for r in sorted(result):
        #    print(r)
   
        print("correct: {}, total: {}, accuracy: {}".format(correct, total, correct/total))
        print("HERE'S WHAT I MISSED:")
    
        for w in sorted(incorrect):
            #print(w)
            pass
    
    return metrics


def predict(test_data, checkpoint_dir, target_dict, fun=False): 
    """
    Prints out a prediction for a given input.
    
    :param test_data: data that you want to make the prediction on 
    :type test_data: numpy 
    :param checkpoint_dir: checkpoint directory 
    :type checkpoint_dir: str
    :param target_dict: map between int and url 
    :type target_dict: dict
    :param fun: wanna have fun?
    :type fun: bool
    """
    model, model_summary = build_model(len(set(test_data[0])), test_data.shape[1])
    model = compile_model(model, optimizer=tf.keras.optimizers.Nadam())
    model.load_weights(tf.train.latest_checkpoint(checkpoint_dir))
    
    tf.logging.debug(model_summary)
    
    time1 = time.time()
    predictions = model.predict(test_data)
    time2 = time.time()
    tf.logging.debug("time: {}".format(time2 - time1))
    result = []

    for prediction in predictions:
        guess = np.argmax(prediction.flatten())
        result.append([(guess, target_dict[guess])])

    if fun == False: 
        for r in result:
            print(TermColors.GREEN + "=======================> " +  str(r) + " <=======================" + TermColors.ENDC)
    else: 
        for r in result:
            print(TermColors.RED)
            cowsay.daemon("Oh no you found out about:\n " + str(r[0][1]))
            print(TermColors.ENDC)
