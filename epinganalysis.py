#!/usr/bin/env python3

import csv
import sys
import argparse
import datetime

version = '0.02'

def error_handler(message):
#    screen=curses.initscr()
#   screen=curses.endwin()
    print ('\n ' + str(message) + '\n')
    sys.exit(0)

def sigint_handler(signal, frame):
#    screen=curses.initscr()
#    curses.endwin()
    print ('THX for using eping.py ')
    sys.exit(0)


def check_python_version(mrv):
    current_version = sys.version_info
    if current_version[0] == mrv[0] and current_version[1] >= mrv[1]:
        return True
    else:
        return False


def open_csv(filename):
    log_data = {}
    try:
        with open(filename, 'r', encoding='UTF8' ) as csvfile:
            reader = csv.DictReader(csvfile)
            log_data = list(reader)
        csvfile.close()
        return (log_data)
    except:
        raise TypeError('ERROR: Unable to open logfile: ' + filename)


# MAIN MAIN MAIN
if __name__=='__main__':
    CRED = '\033[91m'
    CEND = '\033[0m'
    CGREEN = '\033[92m'
    CORANGE = '\033[33m'

    min_required_version = (3,8)
    if not check_python_version(min_required_version):
        error_handler('ERROR: Your Python interpreter must be ' + str(min_required_version[0]) + '.' + str(min_required_version[1]) +' or greater' )

    parser = argparse.ArgumentParser()
    # adding optional argument
    parser.add_argument('-f', '--logfile', default='', dest='filename', help="logfilename" )
    args = parser.parse_args()

    if not args.filename:
        error_handler('Please specify log file -f <filename>')

    try:
        log_data_list=open_csv(args.filename)
    except TypeError as error_msg:
        error_handler(error_msg)


    hostlist =[]
    hosts_with_changes =[]
    for row in log_data_list:
        timestamp = (row['TIMESTAMP'])
        hostname = (row['HOSTNAME'])
        previous_state = (row['PREVIOUS_STATE'])
        current_state = (row['CURRENT_STATE'])
        rtt = (row['RTT'])
        no_of_changes =(row['NO_OF_CHANGES'])
        change_timestamp =(row['CHANGE_TIMESTAMP'])

        if hostname not in hostlist:
            hostlist.append(hostname)

        if previous_state != current_state:
            if hostname not in hosts_with_changes:
                hosts_with_changes.append(hostname)

    hosts_without_changes = set(hostlist) - set(hosts_with_changes)

    hosts_allways_up=[]
    hosts_allways_down=[]
    hosts_allways_no_dns=[]

    for row in hosts_without_changes:
        for row2 in log_data_list:
            if (row2['HOSTNAME']) == row:
                if (row2['CURRENT_STATE']) == 'UP':
                    hosts_allways_up.append((row))
                    break
                elif (row2['CURRENT_STATE']) == 'DOWN':
                    hosts_allways_down.append((row))
                    break
                elif (row2['CURRENT_STATE']) == 'NO-DNS':
                    hosts_allways_no_dns.append((row))
                    break


    for row in hosts_with_changes:
        i=0
        print (' ')
        print ('-------- HOST: ' + row + '  --------')
        for row2 in log_data_list:
            if (row2['HOSTNAME']) == row:
                if (row2['CURRENT_STATE'])  ==  (row2['PREVIOUS_STATE']) and i!=1 :
                     timestamp_1 = (row2['TIMESTAMP'])
                     i=1
                elif (row2['CURRENT_STATE'])  !=  (row2['PREVIOUS_STATE']):
                    time1 = datetime.datetime.strptime((row2['TIMESTAMP']), "%d/%m/%Y %H:%M:%S")
                    time2 = datetime.datetime.strptime(timestamp_1, "%d/%m/%Y %H:%M:%S")
                    time_delta = time1  - time2


                    if (row2['CURRENT_STATE']) == 'UP':
                        print ((row2['TIMESTAMP']) + ' | ' + (row) + ' | change state to '   + CGREEN + (row2['CURRENT_STATE']) + CEND + '     | ' + str(time_delta) )
                        i=0
                    elif (row2['CURRENT_STATE']) == 'DOWN':
                        print ((row2['TIMESTAMP']) + ' | ' + (row) + ' | change state to '   + CRED + (row2['CURRENT_STATE']) + CEND + '   | ' + str(time_delta) )
                        i=0
                    elif (row2['CURRENT_STATE']) == 'NO-DNS':
                        print ((row2['TIMESTAMP']) + ' | ' + (row) + ' | change state to '   + CRED + (row2['CURRENT_STATE']) + CEND + ' | ' + str(time_delta) )
                        i=0




    print ("")
    print ("--ALL HOSTS---------------------------------------------")
    print (hostlist)
    print ("--------------------------------------------------------")
    print ("")
    print (CGREEN + "--STABLE HOSTS - ALLWAYS UP   --------------------------" + CEND)
    print (hosts_allways_up)
    print ("--------------------------------------------------------")
    print ("")
    print (CRED +"--STABLE HOSTS - ALLWAYS DOWN --------------------------"+ CEND)
    print (hosts_allways_down)
    print ("--------------------------------------------------------")
    print ("")
    print (CRED +"--STABLE HOSTS - NO-DNS --------------------------------"+ CEND)
    print (hosts_allways_no_dns)
    print ("--------------------------------------------------------")
    print ("")
#    print ("--STABLE HOSTS - NO CHANGES  ---------------------------")
#    print (hosts_without_changes)
    print (CORANGE +"--FLAPPING HOSTS - STATE CHANGES -----------------------"+ CEND)
    print (hosts_with_changes)
    print ("--------------------------------------------------------")
    print ("")
