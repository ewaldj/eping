#!/usr/bin/env python3

# - - - - - - - - - - - - - - - - - - - - - - - -
# epinga.py by ewald@jeitler.cc 2024 
# - - - - - - - - - - - - - - - - - - - - - - - -
# When I wrote this code, only god and 
# I knew how it worked. 
# Now, only god knows it! 
# - - - - - - - - - - - - - - - - - - - - - - - -

import re
import os 
import csv
import sys
import argparse
import datetime
import ipaddress
import signal
from collections import defaultdict
from datetime import timedelta

version = '0.14'

def error_handler(message):
    print ('\n ' + str(message) + '\n')
    sys.exit(0)

def sigint_handler(signal, frame):
    print ('THX for using epinga.py version ' + version)
    sys.exit(0)


def check_python_version(mrv):
    current_version = sys.version_info
    if current_version[0] == mrv[0] and current_version[1] >= mrv[1]:
        return True
    else:
        return False

def match_re(word,name_re):
    m = eval(name_re).match(word)
    if m:
        return m.group(0)

def sort_fqdn_ip(fping_result_data):
    fping_result_ip=[]
    fping_result_fqdn=[]
    for o in fping_result_data:
        if match_re(o,'ip_re'):
            data=(o)
            fping_result_ip.append(data)
        elif match_re(o,'fqdn_re'):
            data=(o)
            fping_result_fqdn.append(data)
    sorted_fping_result_ip = sorted(fping_result_ip, key=lambda x: int(ipaddress.ip_address(x)))
    sorted_fping_result_fqdn = sorted(fping_result_fqdn, key=lambda x: x[0])
    return (sorted_fping_result_ip + sorted_fping_result_fqdn)

def get_filename(extention):
    result_filelist=[]
    all_files_in_dir = [f.name for f in os.scandir() if f.is_file()]
    for f in all_files_in_dir:
        if f.endswith(extention):
            result_filelist.append(f)
    return(result_filelist)

def check_file(filename):
    print (os.path.isfile(filename))

def open_csv(csv_filename):
    log_data = {}
    try:
        with __builtins__.open(csv_filename, 'r', encoding='UTF8' ) as csvfile:
            reader = csv.DictReader(csvfile)
            log_data = list(reader)
        return (log_data)
    except:
        raise TypeError('ERROR: Unable to open logfile: ' + csv_filename)

def file_menu(extension):
    file_list=get_filename(extension)
    file_list=sorted(file_list, key=lambda x: x)


    print ("--- select csv logfile -----------------------------------")
    print ("|  NO | FILENAME ")
    print ("----------------------------------------------------------")
    x = 1
    for list_x in file_list:
        print ('| ' + str(x).rjust(3) + ' |  ' + list_x)
        x=x+1 
    print ("----------------------------------------------------------")
    fileno=input("enter no of file or \"e\" for exit: ")

    while True:
        if fileno == "e" or fileno =="E":
            sys.exit(0)
        if fileno.isdigit():
            if int(fileno)<x and int(fileno)>=1:
                break
            else:
                print ("Invalid input. Try again. Range is from 1 to " + str(x-1) +" or e for exit")
                fileno=input("select logfile by number: ") 
        else:
            print ("Invalid input. Try again. Range is from 1 to " + str(x-1) +" or e for exit")
            fileno=input("select logfile by number: ")
    return (file_list[int(fileno)-1])

def check_valid_epinglogfile(filename):
    try:
        log_data_list=open_csv(filename)
    except TypeError as error_msg:
        error_handler(error_msg)
    try:
        try: 
            if "HOSTNAME" in log_data_list[0] and "RTT" in log_data_list[0] and "RTT" in log_data_list[0] and "PREVIOUS_STATE" in log_data_list[0]:
                 return (True)
        except:
            error_handler('ERROR: the file ' + filename + ' is not a eping.py logfile')
    except TypeError as error_msg:
        error_handler(error_msg)



# MAIN MAIN MAIN
if __name__=='__main__':
    CRED = '\033[91m'
    CEND = '\033[0m'
    CGREEN = '\033[92m'
    CORANGE = '\033[33m'
    signal.signal(signal.SIGINT, sigint_handler)

    # regex IP/FQDN/CIDR .... 
    ip_re = re.compile(r'^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$')
    fqdn_re = re.compile(r'(?=^.{4,253}$)(^((?!-)[a-zA-Z0-9-äöüÄÖÜ]{1,63}(?<!-)([\.]?))+[a-zA-ZäöüÄÖÜ]{0,63}$)')
    cidr_ipv4_re = re.compile (r'^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\/(3[0-2]|[1-2][0-9]|[0-9]))$')
    timestamp_re = re.compile (r'^\[[0-9]{10}.[0-9]{5}\]')

    min_required_version = (3,8)
    if not check_python_version(min_required_version):
        error_handler('ERROR: Your Python interpreter must be ' + str(min_required_version[0]) + '.' + str(min_required_version[1]) +' or greater' )


    parser = argparse.ArgumentParser()
    # adding optional argument
    parser.add_argument('-f', '--logfile', default='', dest='filename', help="logfilename" )
    args = parser.parse_args()

    # start file menu if no args given 
    if not args.filename:
        filename=file_menu("csv")
    else:
        filename=args.filename
    
    # check valid epinglogfile 
    check_status=(check_valid_epinglogfile(filename))
    if not check_status: 
        error_handler('ERROR: the file ' + filename + ' is not a eping.py logfile')

    # open csv file 
    log_data_list=open_csv(filename)

    # ------------------------ ANALYSE START --------------------------
    hostlist =[]
    hosts_with_changes =[]

    # hostlist / hosts_with_changes / hosts_without_changes 
    for row in log_data_list:
        if (row['HOSTNAME']) not in hostlist:
            hostlist.append(row['HOSTNAME'])
                            
        if (row['PREVIOUS_STATE'] != row['CURRENT_STATE'] and (row['HOSTNAME'] not in hosts_with_changes)): 
            hosts_with_changes.append(row['HOSTNAME'])

    hosts_without_changes = set(hostlist) - set(hosts_with_changes)

    hosts_allways_up=[]
    hosts_allways_down=[]
    hosts_allways_no_dns=[]

    # 
    for row in hosts_without_changes:
        for row_log_data_list in log_data_list:
            if (row_log_data_list['HOSTNAME']) == row:
                if (row_log_data_list['CURRENT_STATE']) == 'UP':
                    hosts_allways_up.append((row))
                    break
                elif (row_log_data_list['CURRENT_STATE']) == 'DOWN':
                    hosts_allways_down.append((row))
                    break
                elif (row_log_data_list['CURRENT_STATE']) == 'NO-DNS':
                    hosts_allways_no_dns.append((row))
                    break


    hostlist=sort_fqdn_ip(hostlist)
    hosts_allways_up=sort_fqdn_ip(hosts_allways_up)
    hosts_allways_down=sort_fqdn_ip(hosts_allways_down)
    hosts_allways_no_dns=sort_fqdn_ip(hosts_allways_no_dns)
    
    host_up_or_flapping = set(hostlist) - set(hosts_allways_down) - set(hosts_allways_no_dns)
    host_up_or_flapping =sort_fqdn_ip(host_up_or_flapping)

    # frist and last seen data start 
    first_seen_list_data =[] 
    last_seen_list_data=[]
    last_seen_list=[]
    allready_seen_hosts = []
    changes_data =[]
    rtt_data_2 = []


    for row in log_data_list: 
        data = row
        # generate first seen data 
        if row['HOSTNAME'] in host_up_or_flapping and not row['HOSTNAME'] in allready_seen_hosts:
            first_seen_list_data.append(data)
            allready_seen_hosts.append((row['HOSTNAME']))

        # generate last seen data 
        if row['HOSTNAME'] in host_up_or_flapping and row['HOSTNAME'] in last_seen_list: 
            last_seen_list.remove((row['HOSTNAME']))  
            # delete delete old entry's in last_seen_list 
            last_seen_list_data = [entry for entry in last_seen_list_data if entry['HOSTNAME'] != row['HOSTNAME']]
        if row['HOSTNAME'] in host_up_or_flapping and row['HOSTNAME'] not in last_seen_list: 
            last_seen_list.append((row['HOSTNAME']))  
            last_seen_list_data.append(row)

        # generate state changes list 
        if row['CURRENT_STATE'] != row['PREVIOUS_STATE']:
            changes_data.append(row)

        ## generate rtt list 
        if row['HOSTNAME'] in host_up_or_flapping and row['RTT'] != '----':
            data = row['HOSTNAME'],row['RTT']
            rtt_data_2.append(data)


    ## RTT CACULATION 
    rtt_data = defaultdict(list)

    for host, rtt in rtt_data_2:
        rtt_data[host].append(float(rtt))

    rtt_stats = {}
    for host, rtts in rtt_data.items():
        min_rtt = min(rtts)
        max_rtt = max(rtts)
        avg_rtt = sum(rtts) / len(rtts)
        rtt_stats[host] = {'min': min_rtt, 'max': max_rtt, 'avg': avg_rtt}

    
    print ('')
    print ('-'.ljust(96,'-'))
    header = " epinga.py version " + version + " by Ewald Jeitler " 
    print (header.center(96,"-"))
    print ('-'.ljust(96,'-'))
    
    up_down_data =[]

    for row in first_seen_list_data:
        print ('')
        out= ('- '+ row['HOSTNAME'] +' -') 
        print (out.center(96,"-"))

        hostname_out = (row['HOSTNAME']).ljust(30)
        current_state_output = (row['CURRENT_STATE'].center(8," "))
        timestamp_output = row['TIMESTAMP']

        if  'UP' in current_state_output:
            print (timestamp_output + ' | ' + hostname_out + ' | change state to  '   + CGREEN + current_state_output + CEND +'   |')
        if 'DOWN' in current_state_output or 'NO-DNS' in current_state_output:
            print (timestamp_output + ' | ' + hostname_out + ' | change state to  '   + CRED + current_state_output + CEND + '   |')
       
        time1 = datetime.datetime.strptime((row['TIMESTAMP']), "%d/%m/%Y %H:%M:%S")
        time_delta = time1 - time1 
        data_updown = (row['HOSTNAME'],row['CURRENT_STATE'],time_delta)
        up_down_data.append (data_updown)


        for row3 in changes_data:
            if row3['HOSTNAME'] == row['HOSTNAME']:
                time2 = datetime.datetime.strptime((row3['TIMESTAMP']), "%d/%m/%Y %H:%M:%S")
                time_delta = time2  - time1
                hostname_out = (row3['HOSTNAME']).ljust(30)
                current_state_output = (row3['CURRENT_STATE'].center(8," "))
                timestamp_output = row3['TIMESTAMP']

                if  'UP' in current_state_output:
                    print (timestamp_output + ' | ' + hostname_out + ' | change state to  '   + CGREEN + current_state_output + CEND + '   | ∆t '  + str(time_delta) )

                if 'DOWN' in current_state_output or 'NO-DNS' in current_state_output:
                    print (timestamp_output + ' | ' + hostname_out + ' | change state to  '   + CRED + current_state_output + CEND + '   | ∆t '  + str(time_delta) )

                data_updown = (row3['HOSTNAME'],row3['CURRENT_STATE'],time_delta)
                up_down_data.append (data_updown)

                time1 = time2 

        
        for row2 in last_seen_list_data:
            if row2['HOSTNAME'] == row['HOSTNAME']:
                time2 = datetime.datetime.strptime((row2['TIMESTAMP']), "%d/%m/%Y %H:%M:%S")
                time_delta = time2  - time1
                timestamp_output = row2['TIMESTAMP']
                hostname_out = (row2['HOSTNAME']).ljust(30)
                current_state_output = (row2['CURRENT_STATE'].center(8," "))
                no_of_changes_output = (row2['NO_OF_CHANGES'])

                if  'UP' in current_state_output:
                    print (timestamp_output + ' | ' + hostname_out + ' | change state to  '   + CGREEN + current_state_output + CEND + '   | ∆t '  + str(time_delta)  )
                if 'DOWN' in current_state_output or 'NO-DNS' in current_state_output:
                    print (timestamp_output + ' | ' + hostname_out + ' | change state to  '   + CRED + current_state_output + CEND + '   | ∆t '  + str(time_delta)  )

                data_updown = (row2['HOSTNAME'],row2['CURRENT_STATE'],time_delta)
                up_down_data.append (data_updown)

                last_state =''
                for host, stats in rtt_stats.items():
                    if row2['HOSTNAME'] in {host}:
                        x=0
                        up_time = time2  - time2
                        down_time = time2  - time2

                        # uptime / downtime calculation 
                        for row4 in up_down_data:
                            if row4[0] == row2['HOSTNAME']:
                                #NO CHANGES LAST LINE IF STABLE  
                                if last_state == 'DOWN' and (row4[1] == 'DOWN' and x == 1):
                                    x= 1; last_state = row4[1]
                                    down_time = down_time+row4[2]  

                                if last_state == 'UP' and (row4[1] == 'UP' and x == 1):
                                    x= 1; last_state = row4[1]
                                    up_time = up_time+row4[2] 
                                #CHANGES 
                                if last_state == 'DOWN' and (row4[1] != last_state and x == 1):
                                    x= 1; last_state = row4[1]
                                    down_time = down_time+row4[2]  
                                if last_state == 'UP' and (row4[1] != last_state and x == 1):
                                    x= 1; last_state = row4[1]
                                    up_time = up_time+row4[2] 
                                #FIRST LINE 
                                if row4[1] == 'UP' and x == 0:
                                    x= 1; last_state = row4[1]
                                if row4[1] == 'DOWN' and x == 0:
                                    x= 1; last_state = row4[1]
                                if row4[1] == 'NO-DNS' and x == 0:
                                    x= 1; last_state = row4[1]

                        print ("-----------------------------------------------------------------------------------------------")
                        print(f"RTT Min: {stats['min']:.2f} | Max: {stats['max']:.2f} | Avg: {stats['avg']:.2f}  | Uptime: {up_time} Downtime: {down_time} | StateChanges: {no_of_changes_output}" )
                        print ("-----------------------------------------------------------------------------------------------")
                        time1 = time2

    print ("\n\n")
    print ("--- ALL HOSTS ------------------------------------------------------------------------| " + str(len(hostlist)).rjust(5) + ' |' )
    print (*hostlist,sep=' | ')
    print ("-----------------------------------------------------------------------------------------------")
    print ("")
    print (CGREEN + "--- STABLE HOSTS - ALLWAYS UP --------------------------------------------------------" + CEND + '| ' + str(len(hosts_allways_up)).rjust(5) + ' |'  )
    print (*hosts_allways_up, sep=" | ")
    print ("-----------------------------------------------------------------------------------------------")
    print ("")
    print (CORANGE +"--- FLAPPING HOSTS --------------------------------------------------------------------" + CEND + '| ' + str(len(hosts_with_changes)).rjust(5) + ' |')
    print (*hosts_with_changes, sep =" | ")
    print ("-----------------------------------------------------------------------------------------------")
    print ("")
    print (CRED + "--- STABLE HOSTS - ALLWAYS DOWN -------------------------------------------------------" + CEND + '| ' + str(len(hosts_allways_down)).rjust(5) + ' |' )
    print (*hosts_allways_down, sep=" | ")
    print ("-----------------------------------------------------------------------------------------------")
    print ("")
    print (CRED +"--- STABLE HOSTS - NO-DNS ------------------------------------------------------------" + CEND + '| ' + str(len(hosts_allways_no_dns)).rjust(5) + ' |')
    print (*hosts_allways_no_dns, sep=" | ")
    print ("-----------------------------------------------------------------------------------------------")
    print ("")

    print ("THX for using epinga.py version " + version )
    print ("")
