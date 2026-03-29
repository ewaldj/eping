#!/usr/bin/env python3

# - - - - - - - - - - - - - - - - - - - - - - - -
# eping.py by ewald@jeitler.cc 2024 https://www.jeitler.guru 
# - - - - - - - - - - - - - - - - - - - - - - - -
# When I wrote this code, only god and 
# I knew how it worked. 
# Now, only god knows it! 
# - - - - - - - - - - - - - - - - - - - - - - - -
version = '1.32'

import os
import re
import sys
import csv
import glob
import math
import time
import signal
import shutil
import argparse
import ipaddress
import subprocess
import threading
import datetime
import resource

# terminal fix for serial console (e.g. vt220 has no color support)
if os.environ.get('TERM') in ('vt220', 'vt100', 'vt102', None):
    os.environ['TERM'] = 'xterm-256color'

import curses

#checkversion online
try:
    import urllib.request
    import socket
except Exception:
    urllib = None
    socket = None


def curses_supports_curs_set():
    def _inner(stdscr):
        try:
            curses.curs_set(0)
            return True
        except curses.error:
            return False
    return curses.wrapper(_inner)

def set_half_of_hard_limit():
    try:
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        half = max(1, hard // 2)
        # set soft limit to the half of the systm
        resource.setrlimit(resource.RLIMIT_NOFILE, (half, hard))
    except Exception as e:
        raise TypeError('ERROR: Unable to set RLIMIT_NOFILE. The requested file descriptor limit exceeds the permitted range.')

   
def check_version_online(url: str, tool_name: str, timeout: float = 2.0):
    if not urllib or not socket:
        return None
    import ssl
    ctx = ssl._create_unverified_context()
    try:
        with urllib.request.urlopen(url, timeout=timeout, context=ctx) as response:
            content = response.read().decode('utf-8')
            for line in content.splitlines():
                if line.startswith(tool_name + " "):
                    return line.split()[1]
        return None
    except (urllib.error.URLError, socket.timeout):
        return None


def is_program_installed(program_name: str) -> bool:
    return shutil.which(program_name) is not None

def error_handler(message):
    print ('\n ' + str(message) + '\n')
    sys.exit(0)

def match_re(word,name_re):
    m = name_re.match(word)
    if m:
        return m.group(0)
        
def get_ipv4_from_range(first_ip, last_ip, max_ip):
    # Return IPs in IPv4 range (check valid ip's and that first_ip is <= last_ip) 
        if match_re(first_ip, ip_re) and match_re(last_ip, ip_re): 
            start_ip_int = int(ipaddress.ip_address(first_ip).packed.hex(), 16)
            end_ip_int = int(ipaddress.ip_address(last_ip).packed.hex(), 16)+1
            if not (end_ip_int-start_ip_int > max_ip):
                if start_ip_int < end_ip_int: 
                    return [ipaddress.ip_address(ip).exploded for ip in range(start_ip_int, end_ip_int)]
                else:
                    raise TypeError('ERROR: The start IP must be less than or equal to the end IP. ')
            else:
                raise TypeError('ERROR: Maximum IP Limit reached < ' + str(max_ip) )
        else:
            raise TypeError('ERROR: One of the values is not a valid IPv4 address: ' + first_ip + ', ' + last_ip)

def get_ipv4_from_cidr(cidr, min_mask, max_mask):
    ips=[]
    if match_re(cidr, cidr_ipv4_re):
        network, net_bits = cidr.split('/')
        if int(net_bits) >= min_mask and int(net_bits) <= max_mask:
            for ip in ipaddress.IPv4Network(cidr, False):
                ips.append(str(ip)) 
            return (ips)
        else:
           raise TypeError('ERROR: Mask value not in range - minimum mask value: /' + str(min_mask) ) 
    else: 
        raise TypeError('ERROR: Not a valid CIDR value (e.g., 192.168.66.66/28)')

def get_ipv4_from_file(filename):
    ips=[]
    try:
        with open(filename, "r") as f:
            for line in f:
                for word in line.split():
                    word = word.replace(" ", "")
                    word =word.strip('\n')
                    if match_re(word, ip_re):
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
                    if match_re(word, ip_re):
                        pass
                    elif match_re(word, fqdn_re):
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
            print ('\n\nINFO: File ' + default_hostfile + ' does not exist — creating sample file.\n\n')
            time.sleep(2)
            with open(filename, "w") as f:
                f.writelines(data)
            f.close()
        except:
            raise TypeError('ERROR: Unable to create file: ' + default_hostfile )

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
    global retries
    global interval
    fping_cmd_output_raw =[]
    data=[]
    cmd = ['fping', '-4', '-e', '-B', backoff, '-t', timeout, '-r', retries]
    if interval:
        cmd.extend(['-i', interval])
    cmd.extend(summary_hosts_list)
    try:
        ping = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL, universal_newlines=True)
    except FileNotFoundError:
        error_handler ("ERROR: The command 'fping' was not found. \n Install it via 'sudo apt install fping' (Debian/Ubuntu), 'brew install fping' (macOS), or however it works on your system.")

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
        if match_re(o[0], ip_re):
            data=([o[0]] + [o[1]] + [o[2]] + [o[3]] + [o[4]] + [o[5]] + [o[6]] + [o[7]])
            fping_result_ip.append(data)
        elif match_re(o[0], fqdn_re):
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

    try:
        attr ^= curses.color_pair(color)
    except curses.error:
        pass  # no color support – use default attribute
    try:
        screen.addstr(line,coll,text,attr)
    except:
        pass

def screen_print_date_time(color_pair):
    now = datetime.datetime.now() + datetime.timedelta(hours=int(args.time_zone_adjust))
    dt_string = now.strftime("%d/%m/%Y %H:%M:%S")
    screen_output(0, 1, dt_string, color_pair, 1)

def screen_print_center_top(message,color_pair):
    num_rows, num_cols = screen.getmaxyx()
    free_space = num_cols - int(len(message)) 
    spaces = free_space / 2 
    spacesstring =str()
    spacesstring = spacesstring.rjust(int(spaces), ' ')
    messagetext = spacesstring + message + spacesstring 
    screen_output(0, 0, messagetext,color_pair,1)

def screen_print_horizonta_line (message,color_pair,line):
    num_rows, num_cols = screen.getmaxyx()
    spacesstring =str()
    linestring = spacesstring.rjust(int(num_cols), message)
    if line < num_rows-1: 
        screen_output(line, 0, linestring,color_pair,1 )

def sigint_handler(signal, frame):
    screen=curses.initscr()
    curses.endwin()
    print ('THX for using eping.py ')
    sys.exit(0)

# MAIN MAIN MAIN 
if __name__=='__main__':

    if not is_program_installed("fping"):
        error_handler ("ERROR: The command 'fping' was not found. \n Install it via 'sudo apt install fping' (Debian/Ubuntu), 'brew install fping' (macOS), or however it works on your system.")

    if curses_supports_curs_set():
        curses.curs_set(0)
    else:
        pass  # fallback: vt220/serial terminals may not support curs_set – continue anyway


    default_hostfile = 'eping-hosts.txt'
    min_required_version = (3,6)
    # SET HALF OF ULIMIT OF THE SYSTEM 
    set_half_of_hard_limit()

    if not check_python_version(min_required_version):
        error_handler('ERROR: Your Python interpreter must be ' + str(min_required_version[0]) + '.' + str(min_required_version[1]) +' or greater' )
    
    now = datetime.datetime.now()
    parser = argparse.ArgumentParser()
    
    # adding optional argument
    parser.add_argument('-f', '--hostfile', default=default_hostfile, dest='hostfile', help="hosts filename" )
    parser.add_argument('-df', '--disable_hostfile', action="store_true", help="disable hostsfile")
    parser.add_argument('-n', '--network', default='', dest='network_cidr', help='network e.g. 172.17.17.0/24  minimum lenght is /19'  )
    parser.add_argument('-n1', '--network1', default='', dest='network_cidr1', help='network e.g. 10.0.0.0/30  minimum lenght is /19'  )
    parser.add_argument('-n2', '--network2', default='', dest='network_cidr2', help='network e.g. 192.168.100/25  minimum lenght is /19'  )
    parser.add_argument('-n3', '--network3', default='', dest='network_cidr3', help='network e.g. 10.10.0.0/22  minimum lenght is /19'  )
    parser.add_argument('-n4', '--network4', default='', dest='network_cidr4', help='network e.g. 10.180.0.0/21  minimum lenght is /19'  )
    parser.add_argument('-r', '--network_range', default='', nargs = '*' ,dest='network_range', help='ip range e.g. 10.180.0.0 10.180.3.255')
    parser.add_argument('-r1', '--network_range1', default='', nargs = '*' ,dest='network_range1', help='ip range e.g. 172.17.1.1 172.17.1.20')
    parser.add_argument('-r2', '--network_range2', default='', nargs = '*' ,dest='network_range2', help='ip range e.g. 192.168.1.1 192.168.1.60')
    parser.add_argument('-r3', '--network_range3', default='', nargs = '*' ,dest='network_range3', help='ip range e.g. 1.1.1.0 1.1.1.255')
    parser.add_argument('-r4', '--network_range4', default='', nargs = '*' ,dest='network_range4', help='ip range e.g. 8.8.8.8 8.8.8.8')
    parser.add_argument('-B', '--backoff', default='1.5', dest='backoff', help="set exponential backoff factor to N (default: 1.5)" )
    parser.add_argument('-t', '--timeout', default='250', dest='timeout', help="individual target initial timeout (default: 250ms)") 
    parser.add_argument('-re', '--retries', default='3', dest='retries', help="number of retries per host (default: 3)")
    parser.add_argument('-i', '--interval', default='', dest='interval', help="interval between sending pings in ms (default: fping default 10ms, LAN: 2, WAN: 5)")
    parser.add_argument('-o', '--logfile', default='', dest='logfile', help="logging filename" )
    parser.add_argument('-dl', '--disable_logging', action="store_false", help="disable logging")
    parser.add_argument('-cl', '--clean', action="store_true", dest='delete_files', help="delete all files start with \'eping-l*\'' ")
    parser.add_argument('-up', '--up', default='0', dest='up_hosts_check', help="display and check only host the are up x runs" )
    parser.add_argument('-p', '--threads', default='auto', dest='num_of_threads', help="parallel threads (default: auto-scaled max 50, manual max 120)" )
    parser.add_argument('-tz', '--timezone', default='0', dest='time_zone_adjust', help="default is 0 range from -24 to 24" )
    parser.add_argument('-w', '--wait', default ='0.5', dest='waittime', help="wait time" )   
    parser.add_argument('-du', '--disable_versioncheck', action="store_true", help="disable online versioncheck")

    # read arguments from command line
    args = parser.parse_args()
    backoff = args.backoff
    timeout = args.timeout 
    retries = args.retries
    interval = args.interval

    # check online current version
    if not args.disable_versioncheck: 
           url = "https://raw.githubusercontent.com/ewaldj/eping/refs/heads/main/eversions"
           toolname = "eping.py"
           remote_version = check_version_online(url, toolname)
    else: 
        remote_version = version

    # regex IP/FQDN/CIDR .... 
    ip_re = re.compile(r'^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$')
    fqdn_re = re.compile(r'(?=^.{4,253}$)(^((?!-)[a-zA-Z0-9-äöüÄÖÜ]{1,63}(?<!-)([\.]?))+[a-zA-ZäöüÄÖÜ]{0,63}$)')
    cidr_ipv4_re = re.compile (r'^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\/(3[0-2]|[1-2][0-9]|[0-9]))$')
    timestamp_re = re.compile (r'^\[[0-9]{10}.[0-9]{5}\]')
    
    hosts_list_ipv4 =[]
    hosts_list_fqdn= []
    
    # delete files eping-*.......
    if args.delete_files:
        delete_files('eping-*')

    # --- network range -r and r1 to r4  
    range_args = [
        args.network_range,
        args.network_range1,
        args.network_range2,
        args.network_range3,
        args.network_range4
    ]
    for network_range in range_args:
        if network_range:
            try:
                hosts_list_ipv4.extend(get_ipv4_from_range(network_range[0], network_range[1], 32768))
            except Exception as e:
                error_handler(f"Range error: {e}")
    
    # --- cidr  -n  and n1 to n4 
    cidr_args = [
        args.network_cidr,
        args.network_cidr1,
        args.network_cidr2,
        args.network_cidr3,
        args.network_cidr4
    ]
    for cidr in cidr_args:
        if cidr:
            try:
                hosts_list_ipv4.extend(get_ipv4_from_cidr(cidr, 19, 32))
            except Exception as e:
                error_handler(f"CIDR error: {e}")

    # time_zone_range -24 to +24 check 
    try:
        tz = int(args.time_zone_adjust)
        if tz < -24 or tz > 24:
            error_handler("ERROR: -tz: must be between -24 and 24")
    except ValueError:
            error_handler("ERROR: -tz: must be between -24 and 24")

    # threads 1 to 120 check / auto-scaling (auto max 50)
    if args.num_of_threads == 'auto':
        _threads_auto = True
    else:
        _threads_auto = False
        try:
            threads = int(args.num_of_threads)
            if threads < 1 or threads > 120:
                error_handler("ERROR: -p: must be between 1 and 120" )
        except ValueError:
                error_handler("ERROR: -p: must be between 1 and 120" )
    # waittime 
    try:
        wait_time = float(args.waittime)
        if wait_time < 0 or wait_time > 3600:
            error_handler("ERROR: -w must be between 0 and 3600 e.g 0.2 ")
    except ValueError:
        error_handler("ERROR: -w must be between 0 and 3600 e.g 0.2 ")

    # retries 0 to 5 check
    try:
        r = int(args.retries)
        if r < 0 or r > 5:
            error_handler("ERROR: -re: must be between 0 and 5")
    except ValueError:
        error_handler("ERROR: -re: must be between 0 and 5")

    # interval check (ms) - if set, must be 1-100
    if args.interval:
        try:
            iv = int(args.interval)
            if iv < 1 or iv > 100:
                error_handler("ERROR: -i: must be between 1 and 100 (ms)")
        except ValueError:
            error_handler("ERROR: -i: must be between 1 and 100 (ms)")

    # create sample file if not exists and no special file is given 
    if not args.disable_hostfile and (args.hostfile == default_hostfile):
        data = ["127.0.0.1\n", "no-dns.test 1.1.1.1 1.0.0.1 208.67.222.222 \n", "208.67.220.220 \n","www.google.com\n", "localhost 8.8.8.8 8.8.4.4\n", "ö3.at www.orf.at www.jeitler.guru\n" ]
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

    # auto-scale thread count based on number of hosts (linear: 1 thread per 100 hosts)
    if _threads_auto:
        num_hosts = len(summary_hosts_list)
        auto_threads = max(3, min(50, int(math.ceil(num_hosts / 100.0))))
        args.num_of_threads = str(auto_threads)
    
    run_counter = 1
    
    # stdscr = curses.initscr()
    screen = curses.initscr()
    # disable Cursor
    try:
        curses.curs_set(0)
    except curses.error:
        pass  # terminal does not support curs_set
    # enable Color
    try:
        curses.start_color()
        if curses.has_colors() and curses.COLORS > 1:
            curses.init_pair(1, curses.COLOR_WHITE, curses.COLOR_BLACK)
            curses.init_pair(2, curses.COLOR_GREEN, curses.COLOR_BLACK)
            curses.init_pair(3, curses.COLOR_RED, curses.COLOR_BLACK)
    except curses.error:
        pass  # terminal has no color support – running without colors
    
    signal.signal(signal.SIGINT, sigint_handler)

    last_rows, last_cols = screen.getmaxyx()

    # create logfile_file_name 
    now_logfile = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
    now_logfile_tmp = datetime.datetime.strptime(now_logfile, "%Y-%m-%d %H:%M:%S.%f")
    now_logfile = now_logfile_tmp + datetime.timedelta(hours=int(args.time_zone_adjust))
    filename_timextension = (now_logfile.strftime("%Y-%m-%d_%H:%M:%S"))
    logfile_file_name = 'eping-log_' + filename_timextension +'.csv'

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

    # --- state dict: hostname -> [hostname, state, timestamp, rtt, prev_state, changes, change_ts, tbd]
    host_state = {}

    original_hosts_list = list(summary_hosts_list)
    active_hosts_list   = list(summary_hosts_list)

    # -up learning phase
    up_check_runs       = int(args.up_hosts_check)
    learning_done       = (up_check_runs == 0)
    up_seen             = set()

    def add_hosts_dialog():
        """Show an input dialog, parse IP/hostname/CIDR and return list of new hosts."""
        rows, cols = screen.getmaxyx()
        dialog_w    = min(70, cols - 4)
        dialog_h    = 7
        dialog_y    = rows // 2 - dialog_h // 2
        dialog_x    = cols // 2 - dialog_w // 2

        # draw dialog box
        curses.curs_set(1)
        screen.nodelay(False)
        for dy in range(dialog_h):
            screen_output(dialog_y + dy, dialog_x, ' ' * dialog_w, 1, 0)
        screen_output(dialog_y,     dialog_x, '┌' + '─' * (dialog_w - 2) + '┐', 1, 1)
        screen_output(dialog_y + 1, dialog_x, '│' + ' ADD HOSTS '.center(dialog_w - 2) + '│', 1, 1)
        screen_output(dialog_y + 2, dialog_x, '│' + '─' * (dialog_w - 2) + '│', 1, 0)
        screen_output(dialog_y + 3, dialog_x, '│' + ' Enter IP, hostname or CIDR:'.ljust(dialog_w - 2) + '│', 1, 0)
        screen_output(dialog_y + 4, dialog_x, '│' + ' > '.ljust(dialog_w - 2) + '│', 1, 0)
        screen_output(dialog_y + 5, dialog_x, '│' + ' [ENTER]=confirm'.ljust(dialog_w - 2) + '│', 1, 0)
        screen_output(dialog_y + 6, dialog_x, '└' + '─' * (dialog_w - 2) + '┘', 1, 1)
        screen.refresh()

        # input loop
        input_x   = dialog_x + 4
        input_y   = dialog_y + 4
        input_str = ''
        max_input = dialog_w - 6
        screen.move(input_y, input_x)

        while True:
            screen.move(input_y, input_x)
            screen_output(input_y, input_x, (input_str + ' ' * max_input)[:max_input], 1, 1)
            screen.move(input_y, input_x + len(input_str))
            screen.refresh()
            ch = screen.getch()
            if ch in (10, 13):                     # ENTER = confirm
                break
            elif ch in (curses.KEY_BACKSPACE, 127, 8):
                input_str = input_str[:-1]
            elif 32 <= ch <= 126 and len(input_str) < max_input:
                input_str += chr(ch)

        curses.curs_set(0)
        screen.nodelay(True)
        screen.clear()

        value = input_str.strip()
        if not value:
            return []

        new_hosts = []
        # CIDR?
        if match_re(value, cidr_ipv4_re):
            try:
                new_hosts = get_ipv4_from_cidr(value, 19, 32)
            except: pass
        # IP range  e.g. "10.0.0.1-10.0.0.20"
        elif '-' in value and value.count('-') == 1:
            parts = value.split('-')
            try:
                new_hosts = get_ipv4_from_range(parts[0].strip(), parts[1].strip(), 32768)
            except: pass
        # single IP
        elif match_re(value, ip_re):
            new_hosts = [value]
        # hostname/fqdn
        elif match_re(value, fqdn_re):
            new_hosts = [value]

        return new_hosts

    # non-blocking keyboard input - main thread only, no separate thread
    screen.nodelay(True)

    run_counter = 1
    while True:

        # --- keyboard: drain all buffered keys ---
        cmd = None
        while True:
            k = screen.getch()
            if k == -1:
                break
            if k in (ord('u'), ord('U')):
                cmd = 'UP_ONLY'
            elif k in (ord('a'), ord('A')):
                cmd = 'ADD'
            elif k in (ord('r'), ord('R')):
                cmd = 'SCREENREFRESH'
            elif k in (ord('e'), ord('E')):
                cmd = 'EXIT'
        if cmd == 'UP_ONLY':
            if active_hosts_list == original_hosts_list or set(active_hosts_list) == set(original_hosts_list):
                up_now = [h for h in original_hosts_list if h in host_state and 'UP' in host_state[h][1]]
                if up_now:
                    active_hosts_list = up_now
                    screen.clear()
            else:
                active_hosts_list = list(original_hosts_list)
                screen.clear()
        elif cmd == 'ADD':
            new_hosts = add_hosts_dialog()
            for h in new_hosts:
                if h not in active_hosts_list:
                    active_hosts_list.append(h)
                if h not in original_hosts_list:
                    original_hosts_list.append(h)
        elif cmd == 'SCREENREFRESH':
            screen.refresh()
        elif cmd == 'EXIT':
            curses.endwin()
            print('THX for using eping.py ')
            sys.exit(0)

        # --- clear screen on resize ---
        rows, cols = screen.getmaxyx()
        if last_rows != rows or last_cols != cols:
            screen.clear()
        last_rows, last_cols = screen.getmaxyx()

        # --- learning phase: switch to UP-only after up_check_runs ---
        if not learning_done:
            if run_counter <= up_check_runs:
                learning_phase = False
            else:
                learning_done = True
                active_hosts_list = sorted(up_seen, key=lambda h: (
                    int(ipaddress.ip_address(h)) if match_re(h, ip_re) else float('inf')
                ))
                screen.clear()
                learning_phase = True
        else:
            learning_phase = True

        # --- run fping ---
        fping_cmd_output_raw_total = list()
        time1 = datetime.datetime.now()

        threads = []
        num_threads = min(len(active_hosts_list), int(args.num_of_threads))
        summary_hosts_list_split = list(split_seq(active_hosts_list, num_threads))
        lock = threading.Lock()
        for i in range(num_threads):
            t = threading.Thread(target=fping_cmd, args=(summary_hosts_list_split[i], lock))
            threads.append(t)
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        fping_result_data_sorted = sort_fping_result_data(fping_cmd_output_raw_total)

        # --- update state dict ---
        now_str = get_date_time()
        hosts_count_up   = 0
        hosts_count_down = 0
        for entry in fping_result_data_sorted:
            hostname  = entry[0]
            new_state = entry[1]
            timestamp = entry[2]
            rtt       = entry[3]
            tbd       = entry[7]

            if hostname in host_state:
                old        = host_state[hostname]
                old_state  = old[1]
                changes    = old[5]
                change_ts  = old[6]
                if old_state != new_state:
                    changes  += 1
                    change_ts = now_str
            else:
                old_state = new_state
                changes   = 0
                change_ts = ''

            # timezone adjust
            try:
                ts_tmp = datetime.datetime.strptime(timestamp, "%d/%m/%Y %H:%M:%S")
                timestamp = ts_tmp + datetime.timedelta(hours=int(args.time_zone_adjust))
            except: pass
            try:
                ct_tmp = datetime.datetime.strptime(change_ts, "%d/%m/%Y %H:%M:%S")
                change_ts = ct_tmp + datetime.timedelta(hours=int(args.time_zone_adjust))
            except: pass

            host_state[hostname] = [hostname, new_state, timestamp, rtt, old_state, changes, change_ts, tbd]

            # learning phase tracking
            if not learning_done and 'UP' in new_state:
                up_seen.add(hostname)

            # logging
            if args.disable_logging and learning_phase:
                logdata = ([timestamp] + [hostname] + [old_state.replace(" ", "")] + [new_state.replace(" ", "")] + [rtt] + [changes] + [change_ts] + [tbd])
                with open(logfile_file_name, 'a', encoding='UTF8') as f:
                    writer = csv.writer(f)
                    writer.writerow(logdata)

        # --- build display list (only active hosts, sorted) ---
        display_list = [host_state[h] for h in active_hosts_list if h in host_state]
        display_list = sort_fping_result_data(display_list)

        for entry in display_list:
            if 'UP' in entry[1]:
                hosts_count_up += 1
            else:
                hosts_count_down += 1

        # --- wait + key polling (keys are processed at the top of the main loop) ---
        if run_counter >= 2:
            time2 = datetime.datetime.now()
            time3 = time2 - time1
            remaining = float(args.waittime) - time3.total_seconds()
            deadline  = time.time() + remaining
            while time.time() < deadline:
                time.sleep(0.1)
                k = screen.getch()
                if k != -1:
                    curses.ungetch(k)
                    break

        time2    = datetime.datetime.now()
        run_time = format(float((time2 - time1).total_seconds()), ".2f")

        # --- screen output ---
        rows, cols = screen.getmaxyx()
        if remote_version:
            if remote_version <= version:
                screen_print_center_top('eping.py version ' + version + ' by Ewald Jeitler', 1)
            else:
                screen_print_center_top('Update available – please visit https://www.jeitler.guru', 3)
        else:
            screen_print_center_top('eping.py version ' + version + ' by Ewald Jeitler', 1)

        screen_print_date_time(1)
        screen_print_horizonta_line('-', 1, 1)
        screen_print_horizonta_line('-', 1, 3)
        screen_print_horizonta_line('-', 1, rows - 2)

        colsoffset_header = 0
        maxcols = 0
        while cols - 64 >= colsoffset_header:
            screen_output(2, colsoffset_header, '|      HOSTNAME/IP         |  U/D |   RTT   | CH-TIME  | CH NO ||', 1, 1)
            colsoffset_header += 64
            maxcols += 1

        linenr          = 0
        output_coloffset = 0
        top_offset      = 4
        bottom_offset   = 2
        num_of_hosts    = len(display_list)

        if num_of_hosts == 0:
            screen_output(rows - 1, 1, 'NO HOSTS TO PING!', 3, 2)

        for o in display_list:
            hostname         = o[0]
            state            = o[1]
            rtt              = o[3]
            changes          = o[5]
            change_timestamp = o[6]
            try:
                timehhmm         = (str(change_timestamp)).split(' ')
                change_timestamp = timehhmm[1]
            except: pass

            output_linenr    = int(linenr) + int(top_offset)
            x = 1
            z = top_offset + bottom_offset
            i = num_of_hosts / rows + z
            while i > 0:
                if int(linenr) + (z * x) + 1 > rows * x:
                    output_coloffset = x * 64
                    output_linenr    = output_linenr - rows + int(z)
                i -= 1
                x += 1
            maxrows  = rows - z
            maxhosts = maxrows * maxcols

            output_hostname = ('%.25s' % hostname)
            output_rtt      = '{message: >8}'.format(message=rtt)
            output_changes  = '{message: >5}'.format(message=str(changes))

            if int(linenr) < maxhosts:
                screen_output(output_linenr, output_coloffset + 0,  '|                                 |         |', 1, 1)
                screen_output(output_linenr, output_coloffset + 27, '|', 1, 1)
                screen_output(output_linenr, output_coloffset + 55, '|', 1, 1)
                screen_output(output_linenr, output_coloffset + 63, '||', 1, 1)
                if 'UP' in state:
                    color_state = 2; color_host = 1; bold_host = 0
                else:
                    color_state = 3; color_host = 3; bold_host = 1
                screen_output(output_linenr, output_coloffset + 2,  output_hostname, color_host, bold_host)
                screen_output(output_linenr, output_coloffset + 28, state, color_state, 1)
                screen_output(output_linenr, output_coloffset + 35, str(output_rtt), 0, 0)
                if int(output_changes) > 0:
                    screen_output(output_linenr, output_coloffset + 57, str(output_changes), 1, 1)
                if change_timestamp:
                    screen_output(output_linenr, output_coloffset + 46, str(change_timestamp), 1, 0)
            else:
                pass  # TERMINAL TOO SMALL shown in status bar below

            linenr += 1

        # --- status bar and key bar always drawn after host loop ---
        hosts_up   = '{m: <5}'.format(m=hosts_count_up)
        hosts_down = '{m: <5}'.format(m=hosts_count_down)
        screen_output(rows - 1, 1,  'HOSTS: '   + str(num_of_hosts), 1, 1)
        screen_output(rows - 1, 14, 'RUNTIME: ' + str(run_time) + 'sec', 1, 1)
        screen_output(rows - 1, 35, 'RUNS: '    + str(run_counter), 1, 1)
        screen_output(rows - 1, 50, 'HOSTS-UP: '   + str(hosts_up),   2, 1)
        screen_output(rows - 1, 66, 'HOSTS-DOWN: ' + str(hosts_down), 3, 1)
        if args.disable_logging:
            screen_output(rows - 1, 87, 'LOGGING-ON: ' + logfile_file_name, 1, 1)
        else:
            screen_output(rows - 1, 87, 'LOGGING-OFF', 1, 1)
        # TERMINAL TOO SMALL - bottom right, drawn last so always visible
        if num_of_hosts > 0 and maxhosts < num_of_hosts:
            tts_text = ' | TERMINAL TOO SMALL '
            screen_output(rows - 1, cols - len(tts_text), tts_text, 3, 2)

        if len(active_hosts_list) < len(original_hosts_list):
            screen_output(rows - 2, 2,  ' [U]=UP-ONLY ', 2, 1)
        else:
            screen_output(rows - 2, 2,  ' [U]=UP-ONLY ', 1, 0)
        screen_output(rows - 2, 15, ' [A]=ADD HOST  ', 1, 0)
        screen_output(rows - 2, 48, ' [E]=EXIT ', 1, 0)
        screen_output(rows - 2, 29, ' [R]=SCREEN REFRESH', 1, 0)

        # learning phase: centered green box overlay
        if not learning_phase:
            lp_line1 = '        PLEASE WAIT        '
            lp_line2 = ' Scanning hosts for UP status '
            lp_line3 = '   LEARNING PHASE ' + str(run_counter) + ' of ' + str(up_check_runs) + '   '
            box_w    = max(len(lp_line1), len(lp_line2), len(lp_line3)) + 4
            lp_col   = max(0, (cols - box_w) // 2)
            lp_row   = rows // 2 - 2
            def bp(r, text, bold=0):
                screen_output(lp_row + r, lp_col, text.center(box_w), 2, bold)
            bp(0, '+' + '-' * (box_w - 2) + '+', 1)
            bp(1, '|' + lp_line1.center(box_w - 2) + '|', 1)
            bp(2, '|' + lp_line2.center(box_w - 2) + '|', 0)
            bp(3, '|' + lp_line3.center(box_w - 2) + '|', 1)
            bp(4, '+' + '-' * (box_w - 2) + '+', 1)

        screen.refresh()
        run_counter += 1
# THX – Wanna patch my brain? Drop your tweaks here: https://github.com/ewaldj/eping — you know how 😉