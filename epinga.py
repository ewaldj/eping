#!/usr/bin/env python3

# - - - - - - - - - - - - - - - - - - - - - - - -
# epinga.py by ewald@jeitler.cc 2024 https://www.jeitler.guru 
# - - - - - - - - - - - - - - - - - - - - - - - -
# When I wrote this code, only god and 
# I knew how it worked. 
# Now, only god knows it! 
# - - - - - - - - - - - - - - - - - - - - - - - -
version = '1.13'

import re
import os 
import csv
import sys
import argparse
import datetime
import ipaddress
import signal
import collections 

#checkversion online 
try:
    import urllib.request
    import socket
except:
    urllib = None
    socket = None

def check_version_online (url: str, tool_name: str, timeout: float = 2.0):
    if not urllib or not socket:
        return None
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            content = response.read().decode('utf-8')
            for line in content.splitlines():
                if line.startswith(tool_name + " "):
                    return line.split()[1]
        return None
    except (urllib.error.URLError, socket.timeout) as e:
        return None

def error_handler(message):
    print ('\n ' + str(message) + '\n')
    sys.exit(0)

def sigint_handler(signal, frame):
    print ('THX for using epinga.py version ' + version + '  - www.jeitler.guru - \n')
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

def sort_fqdn_ip(data_to_sort):
    ip_data=[]
    fqdn_data=[]
    for o in data_to_sort:
        if match_re(o,'ip_re'):
            data=(o)
            ip_data.append(data)
        elif match_re(o,'fqdn_re'):
            data=(o)
            fqdn_data.append(data)
    sorted_ip_data = sorted(ip_data, key=lambda x: int(ipaddress.ip_address(x)))
    sorted_fqdn_data = sorted(fqdn_data, key=lambda x: x[0])
    return (sorted_ip_data + sorted_fqdn_data)

def get_filename(file_extension):
    result_filelist=[]
    all_files_in_dir = [f.name for f in os.scandir() if f.is_file()]
    for f in all_files_in_dir:
        if f.endswith(file_extension):
            result_filelist.append(f)
    return(result_filelist)

def file_menu(file_extension):
    file_list=get_filename(file_extension)
    # sort filelist 
    file_list=sorted(file_list, key=lambda x: x)
    # print menue 
    print ("--- select csv logfile -----------------------------------")
    print ("|  NO | FILENAME ")
    print ("----------------------------------------------------------")
    x = 1
    for list_x in file_list:
        print ('| ' + str(x).rjust(3) + ' |  ' + list_x)
        x=x+1 
    print ("----------------------------------------------------------")
    # get file_number via terminal 
    file_number=input("enter no of file or \"e\" for exit: ")
    while True:
        # exit the menue 
        if file_number == "e" or file_number =="E":
            sys.exit(0)
        # check valid input 
        if file_number.isdigit():
            if int(file_number)<x and int(file_number)>=1:
                break
            else:
                print ("Invalid input. Try again. Range is from 1 to " + str(x-1) +" or e for exit")
                file_number=input("select logfile by number: ") 
        else:
            print ("Invalid input. Try again. Range is from 1 to " + str(x-1) +" or e for exit")
            file_number=input("select logfile by number: ")
    # return selected filename 
    return (file_list[int(file_number)-1])

def open_csv(csv_filename):
    log_data = {}
    try:
        with open(csv_filename, 'r', encoding='UTF8' ) as csvfile:
            reader = csv.DictReader(csvfile)
            log_data = list(reader)
        return (log_data)
    except:
        raise TypeError('ERROR: Unable to open logfile: ' + csv_filename)

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

def rtt_caclulation(rtt_data_raw):
    rtt_data = collections.defaultdict(list)

    for host, rtt in rtt_data_raw:
        rtt_data[host].append(float(rtt))

    rtt_data_per_host = {}
    for host, rtts in rtt_data.items():
        min_rtt = min(rtts)
        max_rtt = max(rtts)
        avg_rtt = sum(rtts) / len(rtts)
        # limit to dow decimals places
        min_rtt = round(float(min_rtt),2)
        max_rtt = round(float(max_rtt),2)        
        avg_rtt = round(float(avg_rtt),2)

        rtt_data_per_host[host] = {'min': min_rtt, 'max': max_rtt, 'avg': avg_rtt}
    return(rtt_data_per_host)

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
    # ------------------------ ANALYSE START --------------------------

    hosts_all =[]
    hosts_with_changes  =[]
    rtt_data_raw =[]
    host_values_per_host = collections.defaultdict(list)


    #split log_data_list to per host |  host_values_per_host['1.0.0.1'][0] -> first row  | host_values_per_host['www.jeitler.guru'][-1]['TIMESTAMP'] | last row TIMESPAMP ONLY 

    for row in log_data_list:
        host_values_per_host[row['HOSTNAME']].append(row)

        # generate host_all 
        if (row['HOSTNAME']) not in hosts_all:
            hosts_all.append(row['HOSTNAME'])
        # generate hostlist with changes 
        if (row['PREVIOUS_STATE'] != row['CURRENT_STATE'] and (row['HOSTNAME'] not in hosts_with_changes)): 
            hosts_with_changes.append(row['HOSTNAME'])
        # generate list for the rtt calculation 
        if  row['RTT'] != '----':
            data = row['HOSTNAME'],row['RTT']
            rtt_data_raw.append(data)

    # hosts without changes - stable 
    hosts_no_changes = set(hosts_all) - set(hosts_with_changes)

    # generate lists for stable hosts - alway down / up / no-dns 
    hosts_allways_up=[]
    hosts_allways_down=[]
    hosts_allways_no_dns=[]

    for row in hosts_no_changes:
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

    # generate list for up of flapping hosts 
    host_up_or_flapping = set(hosts_all) - set(hosts_allways_down) - set(hosts_allways_no_dns)
    host_up_or_flapping =sort_fqdn_ip(host_up_or_flapping)

    # rtt calculation 
    rtt_data_per_host=rtt_caclulation(rtt_data_raw)

   # output start with header 
    print ('')
    print ('-'.ljust(96,'-'))
    header = " epinga.py version " + version + " by Ewald Jeitler - www.jeitler.guru " 
    print (header.center(96,"-"))
    print ('-'.ljust(96,'-'))


    # ------------------------------------------------------------------------------------------------------
    # loop per host start 
    # ------------------------------------------------------------------------------------------------------
    for x_host in hosts_all:
        y2 = 0 

        # get rtt data for x_host 
        rtt_data_x_host = rtt_data_per_host.get(x_host, None)

        # print hostname top of each host  
        x_host_print = ' ' + x_host + ' '
        print (x_host_print.center(96,"-"))
    
        host_output_values=[]
        y = 0
        y_current_state =' '
        time_host_down = datetime.timedelta(0)
        time_host_up = datetime.timedelta(0)

        for y_host in host_values_per_host[x_host]:
            y_length = (len(host_values_per_host[x_host]))
            # first seen values for host
            if y == 0:
                # generate results an store it in host_output_values 
                y_timestamp_last_seen_value = y_host ['TIMESTAMP']
                y_current_state_last_seen_value = y_host['CURRENT_STATE']
                host_data_for_output = (y_host['TIMESTAMP'],y_host['HOSTNAME'],y_host['CURRENT_STATE'],'---','-')
                host_output_values.append (host_data_for_output)
                host_data_previous_values  = (y_host['TIMESTAMP'],y_host['HOSTNAME'],y_host['CURRENT_STATE'],'---','-')

            # values between the first and the last row 
            elif y2 <= y_length-2:   
                y_timestamp = y_host ['TIMESTAMP']
                y_current_state = y_host['CURRENT_STATE']

                if y_current_state_last_seen_value != y_current_state:
                    # calculation of sum up down 
                    time_1 = datetime.datetime.strptime((host_data_previous_values[0]), "%Y-%m-%d %H:%M:%S")
                    time_2 = datetime.datetime.strptime(y_host['TIMESTAMP'], "%Y-%m-%d %H:%M:%S")
                    time_delta = time_2 - time_1 
                    if y_current_state_last_seen_value == "UP": 
                        time_host_up = time_host_up + time_delta
                    if y_current_state_last_seen_value == "DOWN" or y_current_state_last_seen_value == "NO-DNS": 
                        time_host_down = time_host_down + time_delta
                    # generate results an store it in host_output_values 
                    host_data_for_output = (y_host['TIMESTAMP'],y_host['HOSTNAME'],y_host['CURRENT_STATE'],str(time_delta))
                    host_output_values.append (host_data_for_output)
                    host_data_previous_values  = (y_host['TIMESTAMP'],y_host['HOSTNAME'],y_host['CURRENT_STATE'])

                y_timestamp_last_seen_value = y_host ['TIMESTAMP']
                y_current_state_last_seen_value = y_host['CURRENT_STATE']


            # last values for host 
            elif y2 == y_length-1:
                y_timestamp = y_host ['TIMESTAMP']
                y_current_state = y_host['CURRENT_STATE']

                # calculation of sum up down 
                time_1 = datetime.datetime.strptime((host_data_previous_values[0]), "%Y-%m-%d %H:%M:%S")
                time_2 = datetime.datetime.strptime(y_host['TIMESTAMP'], "%Y-%m-%d %H:%M:%S")
                time_delta = time_2 - time_1 
                if y_current_state_last_seen_value == "UP": 
                    time_host_up = time_host_up + time_delta
                if y_current_state_last_seen_value == "DOWN" or y_current_state_last_seen_value == "NO-DNS": 
                    time_host_down = time_host_down + time_delta

                # generate results an store it in host_output_values 
                host_data_for_output = (y_host['TIMESTAMP'],y_host['HOSTNAME'],y_host['CURRENT_STATE'],str(time_delta))
                host_output_values.append (host_data_for_output)

                # set state_changes_of_host 
                state_changes_of_host =y_host['NO_OF_CHANGES']
                break
            y = y+1      
            y2 = y2+1 

        # print results per host up down timedelta
        for z_host in host_output_values:
            if  'UP' in z_host[2]:
                print (z_host[0] + ' | ' + z_host[1].ljust(30) + ' | change state to  '   + CGREEN + z_host[2].center(8," ") + CEND + '   | ∆t '  + str(z_host[3])  )
            if 'DOWN' in z_host[2] or 'NO-DNS' in z_host[2]:
                print (z_host[0] + ' | ' + z_host[1].ljust(30) + ' | change state to  '   + CRED + z_host[2].center(8," ") + CEND + '   | ∆t '  + str(z_host[3])  )

        # print results rtt and up down sum  
        print ("------------------------------------------------------------------------------------------------")
        try:
            print ('RTT Min: ' +  str(rtt_data_x_host['min']) + ' | Max: ' + str(rtt_data_x_host['max']) + ' |  Avg:' + str(rtt_data_x_host['avg']) + ' | Uptime: ' + str(time_host_up) + ' | Downtime: ' + str(time_host_down) + ' | StateChanges: ' + state_changes_of_host) 
        except: pass 
        print ("------------------------------------------------------------------------------------------------")

        print (" ")

    # statistic section output 
    print ("--- ALL HOSTS -------------------------------------------------------------------------| " + str(len(hosts_all)).rjust(5) + ' |' )
    print (*hosts_all,sep=' | ')
    print ("------------------------------------------------------------------------------------------------\n")
    print (CGREEN + "--- STABLE HOSTS - ALLWAYS UP ---------------------------------------------------------" + CEND + '| ' + str(len(hosts_allways_up)).rjust(5) + ' |'  )
    print (*hosts_allways_up, sep=" | ")
    print ("------------------------------------------------------------------------------------------------\n")
    print (CORANGE +"--- FLAPPING HOSTS --------------------------------------------------------------------" + CEND + '| ' + str(len(hosts_with_changes)).rjust(5) + ' |')
    print (*hosts_with_changes, sep =" | ")
    print ("------------------------------------------------------------------------------------------------\n")
    print (CRED + "--- STABLE HOSTS - ALLWAYS DOWN -------------------------------------------------------" + CEND + '| ' + str(len(hosts_allways_down)).rjust(5) + ' |' )
    print (*hosts_allways_down, sep=" | ")
    print ("------------------------------------------------------------------------------------------------\n")
    print (CRED +"--- STABLE HOSTS - NO-DNS -------------------------------------------------------------" + CEND + '| ' + str(len(hosts_allways_no_dns)).rjust(5) + ' |')
    print (*hosts_allways_no_dns, sep=" | ")
    print ("------------------------------------------------------------------------------------------------\n")
    print ("---- FILENAME ----------------------------------------------------------------------------------")
    print (filename)
    print ("------------------------------------------------------------------------------------------------\n")

    # check version online - info 
    url = "https://raw.githubusercontent.com/ewaldj/eping/refs/heads/main/eversions"
    toolname = "epinga.py"
    remote_version = check_version_online(url, toolname)
    if remote_version: 
        if remote_version <= version:
            print ("THX for using epinga.py version " + version + '  - www.jeitler.guru - \n' )
        else:
            print (CRED +'!! Update available – please visit https://www.jeitler.guru !! \n' )
    else:
        print ("THX for using epinga.py version " + version + '  - www.jeitler.guru - \n' )
# THX – Wanna patch my brain? Drop your tweaks here: https://github.com/ewaldj/eping — you know how 😉
