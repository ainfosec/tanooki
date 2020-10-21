#! /bin/bash

SAMPLES=10
URL_SET='wiki-top-100-of-2013-HTTPS.txt'
#URL_SET='url_data_set.txt'
TRAIN_DIR='data'
BIN='links'
PROBE='links.probes'

MY_PATH=$(pwd)/$line

./flush-reload/myversion/attack_tools.py  gather-data \
    $MY_PATH'experiments/links/binaries/'$BIN \
    $MY_PATH'experiments/links/url_sets/'$URL_SET \
    $MY_PATH'experiments/links/binaries/'$PROBE \
    $SAMPLES \
    $MY_PATH'/'$TRAIN_DIR \
