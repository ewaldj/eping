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
» eping.py --help
usage: eping.py [-h] [-f HOSTFILE] [-df] [-n NETWORK_CIDR] [-n1 NETWORK_CIDR1] [-n2 NETWORK_CIDR2] [-n3 NETWORK_CIDR3] [-n4 NETWORK_CIDR4] [-r [NETWORK_RANGE ...]] [-r1 [NETWORK_RANGE1 ...]] [-r2 [NETWORK_RANGE2 ...]] [-r3 [NETWORK_RANGE3 ...]]
                [-r4 [NETWORK_RANGE4 ...]] [-B BACKOFF] [-t TIMEOUT] [-o LOGFILE] [-dl] [-cl] [-up UP_HOSTS_CHECK] [-p NUM_OF_THREADS] [-tc TIME_ZONE_ADJUST]

options:
  -h, --help            show this help message and exit
  -f HOSTFILE, --hostfile HOSTFILE
                        hosts filename
  -df, --disable_hostfile
                        disable hostsfile
  -n NETWORK_CIDR, --network NETWORK_CIDR
                        network e.g. 172.17.17.0/24 minimum lenght is /19
  -n1 NETWORK_CIDR1, --network1 NETWORK_CIDR1
                        network e.g. 10.0.0.0/30 minimum lenght is /19
  -n2 NETWORK_CIDR2, --network2 NETWORK_CIDR2
                        network e.g. 192.168.100/25 minimum lenght is /19
  -n3 NETWORK_CIDR3, --network3 NETWORK_CIDR3
                        network e.g. 10.10.0.0/22 minimum lenght is /19
  -n4 NETWORK_CIDR4, --network4 NETWORK_CIDR4
                        network e.g. 10.180.0.0/21 minimum lenght is /19
  -r [NETWORK_RANGE ...], --network_range [NETWORK_RANGE ...]
                        ip range e.g. 10.180.0.0 10.180.3.255
  -r1 [NETWORK_RANGE1 ...], --network_range1 [NETWORK_RANGE1 ...]
                        ip range e.g. 172.17.1.1 172.17.1.20
  -r2 [NETWORK_RANGE2 ...], --network_range2 [NETWORK_RANGE2 ...]
                        ip range e.g. 192.168.1.1 192.168.1.60
  -r3 [NETWORK_RANGE3 ...], --network_range3 [NETWORK_RANGE3 ...]
                        ip range e.g. 1.1.1.0 1.1.1.255
  -r4 [NETWORK_RANGE4 ...], --network_range4 [NETWORK_RANGE4 ...]
                        ip range e.g. 8.8.8.8 8.8.8.8
  -B BACKOFF, --backoff BACKOFF
                        set exponential backoff factor to N (default: 1.5)
  -t TIMEOUT, --timeout TIMEOUT
                        individual target initial timeout (default: 250ms)
  -o LOGFILE, --logfile LOGFILE
                        logging filename
  -dl, --disable_logging
                        disable logging
  -cl, --clean          delete all files start with 'eping-l*''
  -up UP_HOSTS_CHECK, --up UP_HOSTS_CHECK
                        display and check only host the are up x runs
  -p NUM_OF_THREADS, --threads NUM_OF_THREADS
                        default is 3 parallel threads maximum 120
  -tc TIME_ZONE_ADJUST, --timezone TIME_ZONE_ADJUST
                        default is 0 range from -24 to 24


```

![grafik](https://github.com/user-attachments/assets/c64e6af1-1db3-4cac-80bd-5d4cfd37dfba)


# epinga.py 
## epinga.py 

```
epinga.py -h
usage: epinga.py [-h] [-f FILENAME]

options:
  -h, --help            show this help message and exit
  -f FILENAME, --logfile FILENAME
                        logfilename
```
![grafik](https://github.com/user-attachments/assets/1e869a9a-bce9-42cf-a23a-d48281195aad)



