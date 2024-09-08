#!/usr/bin/env python3
import re
import os 
import csv
import sys
import argparse
import datetime
import ipaddress
import signal
import time 
version = '0.06'

def error_handler(message):
    print ('\n ' + str(message) + '\n')
    sys.exit(0)

def sigint_handler(signal, frame):
    print ('THX for using epinganalysis.py version ' + version)
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
        csvfile.close()
        return (log_data)
    except:
        raise TypeError('ERROR: Unable to open logfile: ' + csv_filename)


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

    if not args.filename:
        print ("--- select csv logfile -----------------------------------")
        print ("|  NO | FILENAME ")
        print ("----------------------------------------------------------")
  
        x = 1
        all_filenames=get_filename("csv")
  
        for list_x in all_filenames:
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
  
        csv_filename = (all_filenames[int(fileno)-1])

    else:
        csv_filename = args.filename

    try:
        log_data_list=open_csv(csv_filename)

    except TypeError as error_msg:
        error_handler(error_msg)

    try:
        try: 
            if "HOSTNAME" in log_data_list[0] and "RTT" in log_data_list[0] and "RTT" in log_data_list[0] and "PREVIOUS_STATE" in log_data_list[0]:
                pass
        except:
            error_handler('ERROR: the file ' + csv_filename + ' is not a eping.py logfile') 
    except TypeError as error_msg:
        error_handler(error_msg)

    hostlist =[]
    hosts_with_changes =[]

    for row_hosts_with_changes in log_data_list:
        timestamp = (row_hosts_with_changes['TIMESTAMP'])
        hostname = (row_hosts_with_changes['HOSTNAME'])
        previous_state = (row_hosts_with_changes['PREVIOUS_STATE'])
        current_state = (row_hosts_with_changes['CURRENT_STATE'])
        rtt = (row_hosts_with_changes['RTT'])
        no_of_changes =(row_hosts_with_changes['NO_OF_CHANGES'])
        change_timestamp =(row_hosts_with_changes['CHANGE_TIMESTAMP'])

        if hostname not in hostlist:
            hostlist.append(hostname)

        if previous_state != current_state:
            if hostname not in hosts_with_changes:
                hosts_with_changes.append(hostname)

    hosts_without_changes = set(hostlist) - set(hosts_with_changes)

    hosts_allways_up=[]
    hosts_allways_down=[]
    hosts_allways_no_dns=[]

    for row_hosts_with_changes in hosts_without_changes:
        for row_log_data_list in log_data_list:
            if (row_log_data_list['HOSTNAME']) == row_hosts_with_changes:
                if (row_log_data_list['CURRENT_STATE']) == 'UP':
                    hosts_allways_up.append((row_hosts_with_changes))
                    break
                elif (row_log_data_list['CURRENT_STATE']) == 'DOWN':
                    hosts_allways_down.append((row_hosts_with_changes))
                    break
                elif (row_log_data_list['CURRENT_STATE']) == 'NO-DNS':
                    hosts_allways_no_dns.append((row_hosts_with_changes))
                    break
    hostlist=sort_fqdn_ip(hostlist)
    hosts_allways_up=sort_fqdn_ip(hosts_allways_up)
    hosts_allways_down=sort_fqdn_ip(hosts_allways_down)
    hosts_allways_no_dns=sort_fqdn_ip(hosts_allways_no_dns)

    print ('')
    print ('--------------------------------------------------------------------------------------')
    print ('--------------- epinganalysis.py version ' + version + ' by Ewald Jeitler -----------------------')
    print ('--------------------------------------------------------------------------------------')
    print ('')

    hosts_with_changes=sort_fqdn_ip(hosts_with_changes)

    for row_hosts_with_changes in hosts_with_changes:
        i=0
        x=0
        print ('')
        print ('-------- HOST: ' + row_hosts_with_changes + '  --------')
        for row_log_data_list in log_data_list:
            hostname_out = (row_hosts_with_changes).ljust(30)
            # FIRST STATE OF HOST 
            if (row_log_data_list['HOSTNAME']) == row_hosts_with_changes:
                if x==0:
                    temp_state=(row_log_data_list['CURRENT_STATE'])
                    if (row_log_data_list['CURRENT_STATE']) == 'UP':
                        print ((row_log_data_list['TIMESTAMP']) + ' | ' + hostname_out + ' | change state to   '   + CGREEN + (row_log_data_list['CURRENT_STATE']) + CEND)
                        timestamp_1 = (row_log_data_list['TIMESTAMP'])
                        x=1
                    elif (row_log_data_list['CURRENT_STATE']) == 'DOWN':
                        print ((row_log_data_list['TIMESTAMP']) + ' | ' + hostname_out + ' | change state to  '   + CRED + (row_log_data_list['CURRENT_STATE']) + CEND)
                        timestamp_1 = (row_log_data_list['TIMESTAMP'])
                        x=1
                    elif (row_log_data_list['CURRENT_STATE']) == 'NO-DNS':
                        print ((row_log_data_list['TIMESTAMP']) + ' | ' + hostname_out + ' | change state to  '   + CRED + (row_log_data_list['CURRENT_STATE']) + CEND) 
                        timestamp_1 = (row_log_data_list['TIMESTAMP'])
                        x=1

                if temp_state != (row_log_data_list['CURRENT_STATE']):
                    time1 = datetime.datetime.strptime((row_log_data_list['TIMESTAMP']), "%d/%m/%Y %H:%M:%S")
                    time2 = datetime.datetime.strptime(timestamp_1, "%d/%m/%Y %H:%M:%S")
                    time_delta = time1  - time2

                    temp_state=(row_log_data_list['CURRENT_STATE'])
                    timestamp_1 = (row_log_data_list['TIMESTAMP'])

                    if (row_log_data_list['CURRENT_STATE']) == 'UP':
                        print ((row_log_data_list['TIMESTAMP']) + ' | ' + hostname_out + ' | change state to   '   + CGREEN + (row_log_data_list['CURRENT_STATE']) + CEND + '    | ∆t ' + str(time_delta) )
                        i=0
                    elif (row_log_data_list['CURRENT_STATE']) == 'DOWN':
                        print ((row_log_data_list['TIMESTAMP']) + ' | ' + hostname_out + ' | change state to  '   + CRED + (row_log_data_list['CURRENT_STATE']) + CEND + '   | ∆t '  + str(time_delta) )
                        i=0
                    elif (row_log_data_list['CURRENT_STATE']) == 'NO-DNS':
                        print ((row_log_data_list['TIMESTAMP']) + ' | ' + hostname_out + ' | change state to  '   + CRED + (row_log_data_list['CURRENT_STATE']) + CEND + ' | ∆t ' + str(time_delta) )
                        i=0

    print ("\n\n")
    print ("--- ALL HOSTS---------------------------------------------")
    print (*hostlist,sep=' | ')
    print ("----------------------------------------------------------")
    print ("")
    print (CGREEN + "--- STABLE HOSTS - ALLWAYS UP   --------------------------" + CEND)
    print (*hosts_allways_up, sep=" | ")
    print ("----------------------------------------------------------")
    print ("")
    print (CRED +"--- STABLE HOSTS - ALLWAYS DOWN --------------------------"+ CEND)
    print (*hosts_allways_down, sep=" | ")
    print ("----------------------------------------------------------")
    print ("")
    print (CRED +"--- STABLE HOSTS - NO-DNS --------------------------------"+ CEND)
    print (*hosts_allways_no_dns, sep=" | ")
    print ("----------------------------------------------------------")
    print ("")
    print (CORANGE +"--- FLAPPING HOSTS ---------------------------------------"+ CEND)
    print (*hosts_with_changes, sep =" | ")
    print ("----------------------------------------------------------")
    print ("")
    print ("THX for using epinganalysis.py version " + version )


