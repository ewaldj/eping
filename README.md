# eping.py 
## eping.py is is a powerful tool that uses fping and python to test the network connectivity of thousands of hosts efficiently and in parallel.

Pings X hosts very quickly (2000 hosts < 4 seconds) thanks to multithreading (-p x) 

Logs every ping (traceability of when a host goes down) in a CSV file

There are several options for what to ping: | Range -r / Network -n / File -f 

It can be used on any machine with Python version > 3.8 and "fping" installed (osx/linux) 

Initial check of which hosts are up, and afterward, only those hosts are pinged. ( -up 3 ) 

Displays the timestamp of the last status change

Displays the number of status changes.


```
» eping.py -h
usage: eping.py [-h] [-f HOSTFILE] [-df] [-n NETWORK_CIDR] [-r [NETWORK_RANGE ...]] [-B BACKOFF] [-t TIMEOUT] [-o LOGFILE] [-dl] [-cl]
                [-up UP_HOSTS_CHECK] [-p NUM_OF_THREADS]

options:
  -h, --help            show this help message and exit
  -f HOSTFILE, --hostfile HOSTFILE
                        hosts filename
  -df, --disable_hostfile
                        disable hostsfile
  -n NETWORK_CIDR, --network NETWORK_CIDR
                        network instead of the hostfile e.g. 172.17.17.0/24 minimum lenght is /18
  -r [NETWORK_RANGE ...], --network_range [NETWORK_RANGE ...]
                        ip range e.g. 172.17.17.1 172.17.17.20 maximum 16384 hosts
  -B BACKOFF, --backoff BACKOFF
                        set exponential backoff factor to N (default: 1.5)
  -t TIMEOUT, --timeout TIMEOUT
                        individual target initial timeout (default: 250ms)
  -o LOGFILE, --logfile LOGFILE
                        logging filename
  -dl, --disable_logging
                        disable logging
  -cl, --clean          delete all files start with 'eping-*''
  -up UP_HOSTS_CHECK, --up UP_HOSTS_CHECK
                        display and check only host the are up x runs
  -p NUM_OF_THREADS, --threads NUM_OF_THREADS
                        default is 3 parallel threads
```
