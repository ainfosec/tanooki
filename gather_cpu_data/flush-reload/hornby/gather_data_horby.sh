#! /bin/bash

SAMPLES=10
SYSTEM_USER=$USER
URL_SET='wiki-top-100-of-2018-HTTPS.txt'
TRAIN_DIR='data-'$SYSTEM_USER'-1-10-2018'
BIN='links'
PROBE='links.probes'

mkdir data 

trap "exit" INT TERM ERR
trap "kill 0" EXIT
echo $(lscpu) > ./data/$USER'-CPU_INFO.txt'
./system_load.sh & 


ruby ./ruby/AttackTrainer.rb \
    --url-list ./experiments/links/url_sets/$URL_SET \
    --train-dir ./data/$TRAIN_DIR \
    --run-binary ./experiments/links/binaries/$BIN \
    --probe-file ./experiments/links/binaries/$PROBE \
    --samples $SAMPLES \
    --sleep-kill 10
