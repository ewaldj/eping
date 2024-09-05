#!/usr/bin/env python3

# - - - - - - - - - - - - - - - - - - - - - - - -
# eping.py by ewald@jeitler.cc 2024 
# - - - - - - - - - - - - - - - - - - - - - - - -
# When I wrote this code, only god and 
# I knew how it worked. 
# Now, only god knows it! 
# - - - - - - - - - - - - - - - - - - - - - - - -

# grep sample 
# - - - - - - - - - - - - - - - - - - - - - - - -
# cat logfilename.log | grep www.orf.at 
# cat logfilename.log | grep -E -v "UP,UP" | grep -E -v "DOWN,DOWN"  | grep -E -v "NO-DNS,NO-DNS"
# - - - - - - - - - - - - - - - - - - - - - - - -

import os
import re
import sys
import csv
import glob
import time 
import curses
import signal
import argparse
import ipaddress
import subprocess
import threading
import datetime

version = '0.90'

def error_handler(message):
    screen=curses.initscr()
    screen=curses.endwin()
    print ('\n ' + str(message) + '\n')
    sys.exit(0)

def match_re(word,name_re):
    m = eval(name_re).match(word)
    if m:
        return m.group(0)
        
def get_ipv4_from_range(first_ip, last_ip, max_ip):
    # Return IPs in IPv4 range (check valid ip's and that first_ip is <= last_ip) 
        if match_re(first_ip,'ip_re') and match_re(last_ip,'ip_re'): 
            start_ip_int = int(ipaddress.ip_address(first_ip).packed.hex(), 16)
            end_ip_int = int(ipaddress.ip_address(last_ip).packed.hex(), 16)+1
            if not (end_ip_int-start_ip_int > max_ip):
                if start_ip_int < end_ip_int: 
                    return [ipaddress.ip_address(ip).exploded for ip in range(start_ip_int, end_ip_int)]
                else:
                    raise TypeError('ERROR: The start ip must be less than or equal to the end ip. ')
            else:
                raise TypeError('ERROR: Maximum IP Limit reached < ' + str(max_ip) )

        else:
            raise TypeError('ERROR: One of the values is not an ipv4 address  | ' + first_ip + ' | ' + last_ip + ' |' )

def get_ipv4_from_cidr(cidr, min_mask, max_mask):
    ips=[]
    if match_re(cidr,'cidr_ipv4_re'):
        network, net_bits = cidr.split('/')
        if int(net_bits) >= min_mask and int(net_bits) <= max_mask:
            for ip in ipaddress.IPv4Network(cidr, False):
                ips.append(str(ip)) 
            return (ips)
        else:
           raise TypeError('ERROR: Mask value not in range - minimum mask value: /' + str(min_mask) ) 
    else: 
        raise TypeError('ERROR: Not a vaild CIDR Value e.g. 192.168.66.66/28')

def get_ipv4_from_file(filename):
    ips=[]
    try:
        with open(filename, "r") as f:
            for line in f:
                for word in line.split():
                    word = word.replace(" ", "")
                    word =word.strip('\n')
                    if match_re(word,'ip_re'):
                       ips.append(word)
        f.close()
        return (ips)
    except:
        raise TypeError('ERROR: Unable to open hosts file')

def get_fqdn_and_hostnames_from_file(filename):
    fqdns=[]
    try:
        with open(filename, "r") as f:
            for line in f:
                for word in line.split():
                    word = word.replace(" ", "")
                    word =word.strip('\n')
                    if match_re(word,'ip_re'):
                        pass
                    elif match_re(word,'fqdn_re'):
                        fqdns.append(word)
        f.close()
        return (fqdns)
    except:
        raise TypeError('ERROR: Unable to open hosts file')

def create_file_if_not_exists(filename,data):
    try:
        with open(filename, "r") as f:
            f.close()
    except:
        try:
            print ('\n\nINFO: ' + default_hostfile + ' doese not exists - create sample file\n\n')
            time.sleep(3)
            with open(filename, "w") as f:
                f.writelines(data)
            f.close()
        except:
            raise TypeError('ERROR: Unable to create default hosts file')

def split_seq(seq, num_pieces):
    start = 0
    for i in range(num_pieces):
        stop = start + len(seq[i::num_pieces])
        yield seq[start:stop]
        start = stop

def fping_cmd(summary_hosts_list,lock):
    global fping_cmd_output_raw_total
    global backoff
    global timeout
    fping_cmd_output_raw =[]
    data=[]
    cmd = ['fping', '-4', '-e', '-B', backoff, '-t', timeout]
    cmd.extend(summary_hosts_list)
    try:
        ping = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    except FileNotFoundError:
        error_handler (' ERROR:The command \'fping\' was not found, install it e.g. via \'sudo apt install fping\' or \'brew install fping\'' )

    while ping.stdout.readable() or ping.stderr.readable:
        sline = ping.stdout.readline()
        eline = ping.stderr.readline()
        if not sline and not eline:
            break
        s1 = (str(sline))
        e1 = (str(eline))
        timestamp=get_date_time()
        if (s1): fping_cmd_output_raw.append(timestamp + ' ' + s1)
        if (e1): fping_cmd_output_raw.append(timestamp + ' ' + e1)

    num_of_hosts = 0
    fping_result_data =[]
    for o in fping_cmd_output_raw:
        o = re.sub('\\s{2,}', ' ', o)
        out = o.split(" ")
        data =[]
        no_of_changes = 0 
        add_data = False 
        try: 
            if ('unreachable' in out[4]):
                timestamp= out[0] + ' ' + out[1]
                hostname=out[2]
                rtt = '----'
                state = ' DOWN'
                add_data = True 
            elif(out[4] == 'alive'):
                timestamp= out[0] + ' ' + out[1]
                hostname=out[2]
                rtt = (out[5].replace('(', ''))
                rtt = format(float(rtt), ".2f")
                state = '  UP'
                add_data = True 
            elif((out[3] == 'nodename' and out[4] == 'nor') or (out[3] == 'Name' and out[4] == 'or')):
                timestamp= out[0] + ' ' + out[1]
                hostname = (out[2].replace(':', ''))
                rtt = '----'
                state = 'NO-DNS'
                add_data = True
######### detect multiple reply - not stable !! 
#            elif(out[4]) == 'duplicate':
#                for index, sublist in enumerate(fping_result_data):
#                    if sublist[0] == out[2]:
#                       fping_result_data[index][7] = fping_result_data[index][7] + 1
#                       fping_result_data[index][1] = ' UP-MR'
########## detect multiple reply - not stable !! 
        except:pass

        if add_data:
            data = [hostname,state,timestamp,rtt,'',no_of_changes,'',0]
            fping_result_data.append(data)
            num_of_hosts +=1
    with lock:
        fping_cmd_output_raw_total.extend(fping_result_data)


def get_date_time():
    now = datetime.datetime.now()
    return now.strftime("%d/%m/%Y %H:%M:%S")

def sort_fping_result_data(fping_result_data):
    fping_result_ip=[]
    fping_result_fqdn=[]
    for o in fping_result_data:
        if match_re(o[0],'ip_re'):
            data=([o[0]] + [o[1]] + [o[2]] + [o[3]] + [o[4]] + [o[5]] + [o[6]] + [o[7]])
            fping_result_ip.append(data)
        elif match_re(o[0],'fqdn_re'):
            data=([o[0]] + [o[1]] + [o[2]] + [o[3]] + [o[4]] + [o[5]] + [o[6]] + [o[7]])
            fping_result_fqdn.append(data)
    sorted_fping_result_ip = sorted(fping_result_ip, key=lambda x: int(ipaddress.ip_address(x[0])))
    sorted_fping_result_fqdn = sorted(fping_result_fqdn, key=lambda x: x[0])
    return (sorted_fping_result_ip + sorted_fping_result_fqdn)

def check_python_version(mrv):
    current_version = sys.version_info
    if current_version[0] == mrv[0] and current_version[1] >= mrv[1]:
        return True
    else:
        return False

def delete_files(filestring):
    fileList = glob.glob(filestring, recursive=False)
    for file in fileList:
        try:
            os.remove(file)
            print(file)
        except OSError:
            error_handler('ERROR: unable to delete files' )
    print("Removed all matched files!")
    error_handler('THX for using eping.py ')

def screen_output(line,coll,text,color,attr_val):
    attr = 0
    if attr_val == 1:
        attr ^= curses.A_BOLD
    if attr_val == 2:
        attr ^= curses.A_BOLD + curses.A_BLINK

    attr ^= curses.color_pair(color)
    try:
        screen.addstr(line,coll,text,attr)
    except:
        pass

def screen_print_date_time(color_pair):
    now = datetime.datetime.now()
    dt_string = now.strftime("%d/%m/%Y %H:%M:%S")
    screen_output(0 , 1, dt_string,color_pair,1)
    screen.refresh()

def screen_print_center_top(message,color_pair):
    num_rows, num_cols = screen.getmaxyx()
    free_space = num_cols - int(len(message)) 
    spaces = free_space / 2 
    spacesstring =str()
    spacesstring = spacesstring.rjust(int(spaces), ' ')
    messagetext = spacesstring + message + spacesstring 
    screen_output(0, 0, messagetext,color_pair,1)
    screen.refresh()

def screen_print_horizonta_line (message,color_pair,line):
    num_rows, num_cols = screen.getmaxyx()
    spacesstring =str()
    linestring = spacesstring.rjust(int(num_cols), message)
    if line < num_rows-1: 
        screen_output(line, 0, linestring,color_pair,1 )
        screen.refresh()

def sigint_handler(signal, frame):
    screen=curses.initscr()
    curses.endwin()
    print ('THX for using eping.py ')
    sys.exit(0)

# MAIN MAIN MAIN 
if __name__=='__main__':

    default_hostfile = 'eping-hosts.txt'
    min_required_version = (3,8)
    
    if not check_python_version(min_required_version):
        error_handler('ERROR: Your Python interpreter must be ' + str(min_required_version[0]) + '.' + str(min_required_version[1]) +' or greater' )
    
    now = datetime.datetime.now()
    filename_timextension = (now.strftime("%Y-%m-%d_%H:%M:%S"))
    logfile_file_name = 'eping-log_' + filename_timextension +'.csv'
    
    
    parser = argparse.ArgumentParser()
    
    # adding optional argument
    parser.add_argument('-f', '--hostfile', default=default_hostfile, dest='hostfile', help="hosts filename" )
    parser.add_argument('-df', '--disable_hostfile', action="store_true", help="disable hostsfile")
    parser.add_argument('-n', '--network', default='', dest='network_cidr', help='network instead of the hostfile e.g. 172.17.17.0/24  minimum lenght is /18'  )
    parser.add_argument('-r', '--network_range', default='', nargs = '*' ,dest='network_range', help='ip range  e.g. 172.17.17.1 172.17.17.20  maximum 16384 hosts')
    parser.add_argument('-B', '--backoff', default='1.5', dest='backoff', help="set exponential backoff factor to N (default: 1.5)" )
    parser.add_argument('-t', '--timeout', default='250', dest='timeout', help="individual target initial timeout (default: 250ms)" )
    parser.add_argument('-o', '--logfile', default='', dest='logfile', help="logging filename" )
    parser.add_argument('-dl', '--disable_logging', action="store_false", help="disable logging")
    parser.add_argument('-cl', '--clean', action="store_true", dest='delete_files', help="delete all files start with \'eping-*\'' ")
    parser.add_argument('-up', '--up', default='0', dest='up_hosts_check', help="display and check only host the are up x runs" )
    parser.add_argument('-p', '--threads', default='3', dest='num_of_threads', help="default is 3 parallel threads" )
    
    
    # read arguments from command line
    args = parser.parse_args()
    backoff = args.backoff
    timeout = args.timeout 
    
    # regex IP/FQDN/CIDR .... 
    ip_re = re.compile(r'^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$')
    fqdn_re = re.compile(r'(?=^.{4,253}$)(^((?!-)[a-zA-Z0-9-äöüÄÖÜ]{1,63}(?<!-)([\.]?))+[a-zA-ZäöüÄÖÜ]{0,63}$)')
    cidr_ipv4_re = re.compile (r'^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\/(3[0-2]|[1-2][0-9]|[0-9]))$')
    timestamp_re = re.compile (r'^\[[0-9]{10}.[0-9]{5}\]')
    
    hosts_list_ipv4 =[]
    hosts_list_fqdn= []
    
    if args.delete_files:
        delete_files('eping-l*')
    
    # get ipv4 ips from network range 
    if args.network_range:
        try:
            hosts_list_ipv4.extend(get_ipv4_from_range((args.network_range[0]),(args.network_range[1]),32768))
        except TypeError as error_msg:
            error_handler(error_msg)
    
    # get ipv4 ips from cidr  
    if args.network_cidr:
        try:
            hosts_list_ipv4.extend(get_ipv4_from_cidr((args.network_cidr),15,32))
        except TypeError as error_msg:
            error_handler(error_msg)
        
    # create sample file if not exists and no special file is given 
    if not args.disable_hostfile and (args.hostfile == default_hostfile):
        data = ["127.0.0.1\n", "no-dns.test 1.1.1.1 1.0.0.1 208.67.222.222 \n", "208.67.220.220 \n","www.google.com\n", "localhost 8.8.8.8 8.8.4.4\n", "ö3.at www.orf.at www.jeitler.cc\n" ]
        try:
            create_file_if_not_exists(default_hostfile,data)
        except TypeError as error_msg:
            error_handler(error_msg)
    
    # get ip's hostname's and fqdn's from file
    if not args.disable_hostfile:
        try: 
            hosts_list_fqdn.extend(get_fqdn_and_hostnames_from_file((args.hostfile)))
            hosts_list_ipv4.extend(get_ipv4_from_file((args.hostfile)))
        except TypeError as error_msg:
            error_handler(error_msg)
        
    #remove duplicates from list 
    hosts_list_fqdn = list(set(hosts_list_fqdn))
    hosts_list_ipv4 = list(set(hosts_list_ipv4))
    #combine both lists 
    summary_hosts_list =[]
    summary_hosts_list.extend(hosts_list_ipv4) 
    summary_hosts_list.extend(hosts_list_fqdn)
    
    #if no host with the given option exists - exit  
    if not summary_hosts_list: 
        error_handler('ERROR: There is nothing to do for me ')
    
    run_counter = 1
    
    # stdscr = curses.initscr()
    screen = curses.initscr()
    # disable Curser 
    curses.curs_set(0)
    # enable Color 
    curses.start_color()
    # defing color pairs 
    curses.init_pair(1, curses.COLOR_WHITE, curses.COLOR_BLACK)
    curses.init_pair(2, curses.COLOR_GREEN, curses.COLOR_BLACK)
    curses.init_pair(3, curses.COLOR_RED, curses.COLOR_BLACK)
    
    signal.signal(signal.SIGINT, sigint_handler)

    last_rows, last_cols = screen.getmaxyx()

    # create logfile 
    if args.logfile:
        logfile_file_name = args.logfile

    if args.disable_logging:
        header = ['TIMESTAMP','HOSTNAME','PREVIOUS_STATE','CURRENT_STATE','RTT','NO_OF_CHANGES','CHANGE_TIMESTAMP','TBD']
        try:
            with open(logfile_file_name, 'w', encoding='UTF8') as f:
                writer = csv.writer(f)
                writer.writerow(header)
        except:
            error_handler('ERROR: failed to create logfile: ' + logfile_file_name )

    summary_hosts_list_check = [] 
    fping_result_data_sorted_old = []
    while True:
        # clear screen if terminal size has changed 
        rows, cols = screen.getmaxyx()
        if last_rows != rows or last_cols != cols: 
            screen.clear()
        last_rows, last_cols = screen.getmaxyx()


        # UP check if hosts for x runs are up - cleanup summary_hosts_list 
        if int(args.up_hosts_check) > 0 and run_counter <= int(args.up_hosts_check)+1:
            for i in fping_result_data_sorted_old:
                if 'UP' in i[1]:
                   summary_hosts_list_check.append(i[0])

        if int(args.up_hosts_check) > 0 and run_counter == int(args.up_hosts_check)+1:
            screen.clear()
            summary_hosts_list_check = list(set(summary_hosts_list_check))
            summary_hosts_list = summary_hosts_list_check

        if int(args.up_hosts_check) > 0 and run_counter < int(args.up_hosts_check)+1:
            text = ('   LEARNING PHASE: ' + str(run_counter) + ' of ' +  str(args.up_hosts_check) + '         ').ljust(cols-2)
            screen_output(rows-1,1, text,1,1)
        
        fping_cmd_output_raw_total = list()
        time1 = now = datetime.datetime.now()

        # start fping threads and sort the output 
        threads = []
        if len(summary_hosts_list) < 20:
            num_threads = 1 
        else:
            num_threads =   int(args.num_of_threads)

        summary_hosts_list_split =[]
        # create threads and asign a function for each thread

        for seq in split_seq(summary_hosts_list, num_threads):
            summary_hosts_list_split.append(seq)

        # create a lock
        lock = threading.Lock()
        for i in range(num_threads):
            thread = threading.Thread(target=fping_cmd,args=(summary_hosts_list_split[i],lock))
            threads.append(thread)

        # start all threads
        for thread in threads:
            thread.start()

        for thread in threads:
            thread.join()

        fping_result_data_sorted = sort_fping_result_data(fping_cmd_output_raw_total)

        # copy actual list to compare list   
        if run_counter == 1: 
            fping_result_data_sorted_old = fping_result_data_sorted

        # copy actual list to compare list after hostcheck run   
        if int(args.up_hosts_check) > 0 and run_counter == int(args.up_hosts_check)+1:
            fping_result_data_sorted_old = fping_result_data_sorted

        # compare both lists an generate a new "fping_result_data_sorted_old"
        fping_result_data_sorted_old_new = []
        num_of_hosts = 0
        hosts_count_up = 0
        hosts_count_down = 0
        for x,y in zip(fping_result_data_sorted_old,fping_result_data_sorted):
            if x[1] != y[1]: 
                z1 = y[1]
                z5 = x[5]+1 
                z6 = get_date_time()
                z4 = x[1]
            else: 
                z1 = y[1]
                z5 = x[5]
                z6 = x[6]
                z4 = y[1]

            z0 = y[0]
            z2 = y[2]
            z3 = y[3]
            z7 = y[7]
            num_of_hosts += 1
            data = ([z0] + [z1] + [z2] + [z3] + [z4] + [z5] + [z6] + [z7])
            fping_result_data_sorted_old_new.append(data)
            # count up / down hosts 
            if 'UP' in z1:
                hosts_count_up +=1
            else:
                hosts_count_down +=1 

            # create logfile if not disabled 
            if args.disable_logging:
                logdata =([z2] + [z0]  + [z4.replace(" ", "")] + [z1.replace(" ", "")] + [z3]  + [z5] + [z6] + [z7])
                with open(logfile_file_name, 'a', encoding='UTF8') as f:
                    writer = csv.writer(f)
                    writer.writerow(logdata)

        fping_result_data_sorted_old = fping_result_data_sorted_old_new

        # delay if runtime < 0.5 SEC add delay 
        time2 = datetime.datetime.now()
        time3 = time2 - time1

        if time3.total_seconds() < 0.5:
            sleep_time = (0.5 - time3.total_seconds())
            time.sleep(sleep_time)

        # calculate the runtime 
        time2 = datetime.datetime.now()
        time3 = time2 - time1
        run_time = format(float(time3.total_seconds()), ".2f")

        # output 
        rows, cols = screen.getmaxyx()
        screen_print_center_top('eping.py version ' + version + '  by Ewald Jeitler',1)
        screen_print_date_time(1)
        screen_print_horizonta_line('-',1,1)                                                     
        screen_print_horizonta_line('-',1,3)
        screen_print_horizonta_line('-',1,rows-2)

        # print header based on terminal size 
        colsoffset_header = 0
        maxcols = 0
        while cols-64 >= colsoffset_header: 
            screen_output(2,colsoffset_header, '|      HOSTNAME/IP         |  U/D |   RTT   | CH-TIME  | CH NO ||',1,1 )
            colsoffset_header = colsoffset_header + 64
            maxcols += 1

        linenr = 0
        output_coloffset = 0

        # SET TOP AND BOTTOM OFFSET 
        top_offset = 4
        bottom_offset = 2
        data_in_lists=False

        for o in fping_result_data_sorted_old:
            hostname = (o[0])
            state = (o[1])
            rtt = (o[3])
            changes = (o[5])
            change_timestamp = (o[6])
            try: 
                timehhmm = (change_timestamp).split(' ')
                change_timestamp = timehhmm[1]
            except: pass

            output_linenr = int(linenr)+int(top_offset)
            no_of_hosts = len(fping_result_data_sorted_old)
            # CALCULATE THE OUTPUT POSITION PER HOST
            x = 1
            z = top_offset+bottom_offset
            i = num_of_hosts/rows+z 
            while i > 0:
                if int(linenr)+(z*x)+1 > rows*x:
                    output_coloffset = x*64
                    output_linenr = output_linenr-rows+int(z)
                i -= 1
                x += 1 
            maxrows = rows-z
            maxhosts = maxrows*maxcols 
            output_hostname = ('%.25s' % hostname)
            output_rtt = '{message: >8}'.format(message=rtt)  
            output_changes = '{message: >5}'.format(message=str(changes)) 

            # OUTPUT 
            if int(linenr)<maxhosts:
                screen_output(output_linenr, output_coloffset+0,  '|                                 |         |' ,1,1)
                screen_output(output_linenr, output_coloffset+27, '|' ,1,1)
                screen_output(output_linenr, output_coloffset+55, '|' ,1,1)
                screen_output(output_linenr, output_coloffset+63, '||' ,1,1)
                if 'UP' in state:
                    color_state = 2
                    color_host = 1
                    bold_host = 0
                else: 
                    color_state = 3
                    color_host = 3 
                    bold_host = 1
                screen_output(output_linenr, output_coloffset+2,  output_hostname ,color_host,bold_host)
                screen_output(output_linenr, output_coloffset+28, state,color_state,1)
                screen_output(output_linenr, output_coloffset+35, str(output_rtt),0,0 )
                if int(output_changes) > 0:
                    screen_output(output_linenr, output_coloffset+57, str(output_changes) ,1,1)
                if change_timestamp:
                    screen_output(output_linenr, output_coloffset+46, str(change_timestamp) ,1,0)
                screen_output(rows-1,1, 'HOSTS: ' +str(no_of_hosts) ,1,1)
                screen_output(rows-1,14, 'RUNTIME: ' + str(run_time) +'sec' ,1,1)
                screen_output(rows-1,35, 'RUNS: ' + str(run_counter) ,1,1)
                hosts_up = '{m: <5}'.format(m=hosts_count_up)
                screen_output(rows-1,50, 'HOSTS-UP: ' + str(hosts_up),2,1)
                hosts_down = '{m: <5}'.format(m=hosts_count_down)
                screen_output(rows-1,66, 'HOSTS-DOWN: ' + str(hosts_down),3,1 )
            else: 
                tts_text = '      TERMINAL TOO SMALL '
                tts_msg_len = int(len(tts_text)) 
                tts_col_start = cols - tts_msg_len
                screen_output(rows-1, tts_col_start, tts_text ,3,2)
            linenr  +=1
        run_counter += 1
