#!/usr/bin/env python3

# - - - - - - - - - - - - - - - - - - - - - - - -
# eping.py by ewald@jeitler.cc 2024 https://www.jeitler.guru 
# - - - - - - - - - - - - - - - - - - - - - - - -
# When I wrote this code, only god and 
# I knew how it worked. 
# Now, only god knows it! 
# - - - - - - - - - - - - - - - - - - - - - - - -
VERSION = '1.51'
version = VERSION  # legacy alias (kept for existing references)

# --- scaling limits ---
MAX_TOTAL_HOSTS    = 512000   # hard cap on combined host list
MAX_IPS_PER_RANGE  = 524288   # -r/-r1..4 range size cap
CIDR_MIN_MASK      = 13       # /13 ~= 524288 addresses
CIDR_MAX_MASK      = 32
THREADS_MANUAL_MAX = 32       # -p upper bound; more than 1 costs accuracy, see PROCS_PER_GROUP
FD_TARGET          = 65536    # desired soft RLIMIT_NOFILE
FPING_STDIN_THRESH = 5000     # feed targets via stdin above this count (avoids ARG_MAX)

# --- scan tuning ---
# fping serialises sending: one packet every -i ms PER PROCESS. A scan round therefore
# takes hosts/rate seconds, no matter how the hosts are spread over the processes.
# So the packet rate is the knob, and -i is derived from it and the process count.
DEFAULT_RATE_PPS   = 1000     # aggregate ICMP packets per second over all fping processes
MIN_RATE_PPS       = 10
MAX_RATE_PPS       = 100000
# One fping process per retry group - and no more. Every raw ICMP socket receives a
# copy of every incoming ICMP packet and has to filter by id, so N concurrent fping
# processes give each of them N times the receive load. Measured on a /20 with 4109
# hosts: 9 processes reported 244 hosts UP, a single process reported 866 - roughly
# 70% of the reachable hosts were lost as false DOWN. Extra processes buy nothing
# either, because a scan round takes hosts/rate seconds no matter how it is split.
PROCS_PER_GROUP    = 1        # fping processes per retry group (accuracy over speed)
INTERVAL_MAX_MS    = 100      # upper bound for -i (fping accepts more, we stay sane)
DNS_CACHE_TTL      = 300      # seconds a resolved hostname stays valid (0 = no caching)
DNS_FAIL_TTL       = 30       # negative cache: retry unresolvable names sooner
DNS_RESOLVERS      = 16       # parallel name lookups

# --- retry classes ---
# Retries exist so that an UP host is not wrongly reported DOWN. A host that is already
# DOWN cannot be wrongly reported DOWN, and a single reply is proof that it is UP again -
# so confirmed DOWN hosts do not need the full retry budget. Hosts we have never probed
# keep the full budget, otherwise a lost first packet would be a false alarm.
# Do NOT lower this to 0. On paper one probe looks safe (a reply is proof of UP, and a
# host that is already DOWN cannot be wrongly reported DOWN) - but tested against a real
# /20 it produced flapping hosts that are stable with 1. Two probes stay the default.
DOWN_RETRIES_DEF   = 1        # -r for hosts already known to be DOWN
FULL_SWEEP_DEF     = 10       # every Nth run probes everything with full retries (0 = off)
CONFIRM_DEF        = 2        # consecutive DOWN observations before UP -> DOWN is accepted

# The DOWN group dominates the cycle: measured on a /20, 867 UP hosts needed 1.9s while
# 3240 DOWN hosts needed 12.4s. Probing only 1/N of the DOWN hosts per round shortens
# the cycle a lot, so the UP hosts - the interesting ones - refresh much more often.
# It is a trade, not a free win: measured with 16 UP / 112 DOWN, -ds 4 cut the cycle
# from 2.9s to 1.2s, but a single DOWN host is then rechecked every 4.9s instead of
# every 2.9s. Accuracy is untouched - a host that is probed always gets the full
# treatment, it is only probed less often. -ds 1 restores the old behaviour.
DOWN_SLICES_DEF    = 4        # DOWN hosts are spread over this many rounds (1 = off)

# --- flapping, view filter and sort order ---
# A host counts as flapping while its last state change lies inside this window. Only
# the timestamp of the LAST change is kept per host, which is enough for 'recently
# unstable' - it deliberately does not try to measure a change rate.
FLAP_WINDOW_DEF    = 10       # minutes

# [U] cycles through these views. Like before, the filter also shrinks what is pinged,
# which is what makes UP-ONLY shorten the cycle. Hosts filtered away are not probed and
# therefore cannot come back until the view is switched to ALL again.
FILTER_MODES = [
    ('ALL HOSTS',   'ALL',   'ALL'),
    ('UP-ONLY',     'UP',    'UP'),
    ('UP+FLAPPING', 'UP+FL', 'U+F'),
]

# [O] cycles through these orders. A flapping host is also UP or DOWN right now, so the
# FLAP group takes precedence over its current state; NO-DNS counts as DOWN. Inside the
# UP and DOWN group the usual order applies (IPv4 numerically, hostnames after that);
# inside FLAP the state comes first in the direction of the mode, then the change count.
SORT_MODES = [
    ('ADDRESS',       'ADDR',  None),
    ('UP/FLAP/DOWN',  'U/F/D', ('up', 'flap', 'down')),
    ('DOWN/FLAP/UP',  'D/F/U', ('down', 'flap', 'up')),
    ('FLAP/UP/DOWN',  'F/U/D', ('flap', 'up', 'down')),
    ('FLAP/DOWN/UP',  'F/D/U', ('flap', 'down', 'up')),
]

# --- web gui defaults ---
WEB_DEFAULT_PORT   = 8080
WEB_DEFAULT_BIND   = '0.0.0.0'
WEB_MAX_UPLOAD     = 16 * 1024 * 1024   # max size of an uploaded host file

import os
import re
import sys
import csv
import glob
import math
import time 
import curses
import signal
import shutil
import argparse
import ipaddress
import subprocess
import json
import threading
import datetime
import resource
import http.server
import socketserver
import socket
import concurrent.futures
#checkversion online
try:
    import urllib.request
except Exception:
    urllib = None

import resource

import curses

def curses_supports_curs_set():
    def _inner(stdscr):
        try:
            curses.curs_set(0)
            return True
        except curses.error:
            return False
    return curses.wrapper(_inner)

def raise_fd_limit(target=FD_TARGET):
    # Raise soft RLIMIT_NOFILE up to min(target, hard). Hard stays untouched.
    try:
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        new_soft = min(target, hard) if hard != resource.RLIM_INFINITY else target
        if new_soft > soft:
            resource.setrlimit(resource.RLIMIT_NOFILE, (new_soft, hard))
    except Exception:
        # non-fatal: keep running with current soft limit
        pass

   
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
    # Expand an IPv4 range [first_ip, last_ip] inclusive. Returns list of strings.
    if not (match_re(first_ip, ip_re) and match_re(last_ip, ip_re)):
        raise TypeError('ERROR: One of the values is not a valid IPv4 address: ' + first_ip + ', ' + last_ip)
    start = int(ipaddress.IPv4Address(first_ip))
    end   = int(ipaddress.IPv4Address(last_ip))
    if start > end:
        raise TypeError('ERROR: The start IP must be less than or equal to the end IP. ')
    count = end - start + 1
    if count > max_ip:
        raise TypeError('ERROR: Maximum IP Limit reached < ' + str(max_ip))
    # str(IPv4Address(int)) is fast and avoids per-element regex
    return [str(ipaddress.IPv4Address(i)) for i in range(start, end + 1)]

def get_ipv4_from_cidr(cidr, min_mask, max_mask):
    # Expand CIDR to list of all addresses (incl. network/broadcast, matches original behavior).
    if not match_re(cidr, cidr_ipv4_re):
        raise TypeError('ERROR: Not a valid CIDR value (e.g., 192.168.66.66/28)')
    net_bits = int(cidr.split('/')[1])
    if net_bits < min_mask or net_bits > max_mask:
        raise TypeError('ERROR: Mask value not in range - allowed: /' + str(min_mask) + '../' + str(max_mask))
    net   = ipaddress.IPv4Network(cidr, strict=False)
    start = int(net.network_address)
    size  = net.num_addresses
    return [str(ipaddress.IPv4Address(start + i)) for i in range(size)]

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

use_check_source = True   # set from --no_check_source in main
web_readonly     = False  # True with --web_view: the CLI drives, the browser only looks

_fping_caps = None
def fping_capabilities():
    """Probe 'fping -h' once and remember which optional flags this build supports."""
    global _fping_caps
    if _fping_caps is None:
        caps = set()
        try:
            p = subprocess.run(['fping', '-h'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               universal_newlines=True, timeout=5)
            text = p.stdout or ''
            for flag in ('--check-source', '--seqmap-timeout'):
                if flag in text:
                    caps.add(flag)
        except Exception:
            pass
        _fping_caps = caps
    return _fping_caps


def tune_group(group_hosts, total_hosts, rate_pps, threads_arg, interval_arg):
    """Derive (processes, interval_ms) for one retry group.

    Each group gets the share of the packet rate budget that matches its size, so a
    small UP group does not finish early and leave the rate unused while the large
    DOWN group runs on alone. fping sends one packet every 'interval' ms per process,
    hence interval = 1000 * processes / group_rate. Explicit -p / -i always win.

    Note the hard floor: -i cannot go below 1ms, so one process tops out at 1000
    packets/s nominally - measured against a real /20 fping only reached about 1.8ms,
    so the practical ceiling is near 550 packets/s per process. A --rate above that
    has no effect at all. More processes would lift it but cost accuracy (see
    PROCS_PER_GROUP); -i 0 lifts it without that cost, at the price of no pacing.
    """
    if group_hosts < 1:
        group_hosts = 1
    if threads_arg == 'auto':
        procs = PROCS_PER_GROUP
    else:
        procs = max(1, int(threads_arg))
    procs = max(1, min(procs, group_hosts))

    if interval_arg:
        interval = int(interval_arg)
    else:
        share      = group_hosts / float(max(1, total_hosts))
        group_rate = max(1.0, rate_pps * share)
        interval   = int(round(1000.0 * procs / group_rate))
        interval   = max(1, min(INTERVAL_MAX_MS, interval))
    return procs, interval


# --- DNS cache: resolve hostnames once and ping the address, instead of letting every
#     fping run resolve them again (fping resolves ALL targets before it starts pinging,
#     so one hanging lookup stalls the whole batch).
_dns_cache = {}          # name -> (ip or None, expires_at)
_dns_lock  = threading.Lock()

def resolve_name(name, ttl):
    now = time.time()
    with _dns_lock:
        entry = _dns_cache.get(name)
        if entry and entry[1] > now:
            return entry[0]
    ip = None
    try:
        infos = socket.getaddrinfo(name, None, socket.AF_INET, socket.SOCK_DGRAM)
        if infos:
            ip = infos[0][4][0]
    except Exception:
        ip = None
    with _dns_lock:
        _dns_cache[name] = (ip, time.time() + (ttl if ip else min(ttl, DNS_FAIL_TTL)))
    return ip

def forget_names(names):
    with _dns_lock:
        for n in names:
            _dns_cache.pop(n, None)

def prepare_targets(hosts, ttl):
    """Map the host list to what is actually handed to fping.

    Returns (targets, target -> [display names], unresolved names).
    With ttl <= 0 nothing is cached and fping does the resolving itself (old behaviour).
    """
    if ttl <= 0:
        return list(hosts), dict((h, [h]) for h in hosts), []

    pending = []
    now     = time.time()
    with _dns_lock:
        for h in hosts:
            if match_re(h, ip_re):
                continue
            entry = _dns_cache.get(h)
            if not entry or entry[1] <= now:
                pending.append(h)
    if pending:
        workers = max(1, min(DNS_RESOLVERS, len(pending)))
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
                list(pool.map(lambda n: resolve_name(n, ttl), pending))
        except Exception:
            for n in pending:
                resolve_name(n, ttl)

    targets     = []
    name_map    = {}
    unresolved  = []
    for h in hosts:
        if match_re(h, ip_re):
            target = h
        else:
            target = resolve_name(h, ttl)
            if not target:
                unresolved.append(h)
                continue
        if target not in name_map:
            name_map[target] = []
            targets.append(target)
        name_map[target].append(h)
    return targets, name_map, unresolved


def build_fping_cmd(interval_ms, retries_override=None):
    """Assemble the fping command line shared by all worker processes of one group."""
    use_retries = str(retries if retries_override is None else retries_override)
    cmd = ['fping', '-4', '-e', '-B', backoff, '-t', timeout, '-r', use_retries]
    # careful: 0 is a valid interval (no pacing at all) but falsy, so test explicitly
    try:
        iv = int(interval_ms)
    except (TypeError, ValueError):
        iv = None
    if iv is not None and iv >= 0:
        cmd.extend(['-i', str(iv)])
    if use_check_source and '--check-source' in fping_capabilities():
        # drop echo replies coming from a foreign address - two concurrent fping
        # processes can share the lower 16 bits of their PID and steal each other's
        # replies, which would show a dead host as UP
        cmd.append('--check-source')
    return cmd


def split_seq(seq, num_pieces):
    # Split seq into num_pieces contiguous chunks. O(n) total.
    n = len(seq)
    if num_pieces <= 0:
        num_pieces = 1
    base, rem = divmod(n, num_pieces)
    start = 0
    for i in range(num_pieces):
        stop = start + base + (1 if i < rem else 0)
        yield seq[start:stop]
        start = stop

# A scan round can take many seconds. To stay responsive the main thread watches the
# worker threads instead of blocking in join(), and can terminate the running fping
# processes when the user presses a key. Cutting a round short is safe: a host that
# produced no output simply keeps its previous state, it is never reported DOWN.
_running_procs = []
_procs_lock    = threading.Lock()
_abort_scan    = False

def scan_reset_abort():
    global _abort_scan
    with _procs_lock:
        _abort_scan = False
        del _running_procs[:]

def scan_abort():
    global _abort_scan
    with _procs_lock:
        _abort_scan = True
        procs = list(_running_procs)
    for pr in procs:
        try:
            pr.terminate()
        except Exception:
            pass


def timed_fping(hosts, lock, cmd_base, stats, slot):
    """Run fping_cmd and record (start, end) so a group's wall time can be derived."""
    t0 = time.time()
    try:
        fping_cmd(hosts, lock, cmd_base)
    finally:
        with lock:
            stats[slot].append((t0, time.time()))


def fping_cmd(summary_hosts_list, lock, cmd_base=None):
    # Run fping on a subset of hosts and append parsed results to the global list.
    global fping_cmd_output_raw_total

    if not summary_hosts_list:
        return

    cmd = list(cmd_base) if cmd_base else build_fping_cmd(interval)

    use_stdin = len(summary_hosts_list) > FPING_STDIN_THRESH
    if not use_stdin:
        cmd.extend(summary_hosts_list)

    with _procs_lock:
        if _abort_scan:
            return

    try:
        ping = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,          # merge: simpler + avoids deadlock
            stdin=(subprocess.PIPE if use_stdin else subprocess.DEVNULL),
            universal_newlines=True,
            bufsize=1,
        )
    except FileNotFoundError:
        error_handler("ERROR: The command 'fping' was not found. \n Install it via 'sudo apt install fping' (Debian/Ubuntu), 'brew install fping' (macOS), or however it works on your system.")

    with _procs_lock:
        _running_procs.append(ping)

    # Feed targets via stdin for large batches (avoids ARG_MAX). Close stdin so fping starts pinging.
    if use_stdin:
        try:
            ping.stdin.write('\n'.join(summary_hosts_list) + '\n')
            ping.stdin.close()
        except BrokenPipeError:
            pass

    fping_cmd_output_raw = []
    for line in ping.stdout:
        if not line:
            continue
        fping_cmd_output_raw.append(get_date_time() + ' ' + line)
    ping.wait()
    with _procs_lock:
        try:
            _running_procs.remove(ping)
        except ValueError:
            pass

    fping_result_data = []
    for o in fping_cmd_output_raw:
        o = re.sub(r'\s{2,}', ' ', o)
        out = o.split(' ')
        add_data = False
        no_of_changes = 0
        try:
            if 'unreachable' in out[4]:
                timestamp = out[0] + ' ' + out[1]
                hostname  = out[2]
                rtt       = '----'
                state     = ' DOWN'
                add_data  = True
            elif out[4] == 'alive':
                timestamp = out[0] + ' ' + out[1]
                hostname  = out[2]
                rtt       = out[5].replace('(', '')
                rtt       = format(float(rtt), ".2f")
                state     = '  UP'
                add_data  = True
            elif (out[3] == 'nodename' and out[4] == 'nor') or (out[3] == 'Name' and out[4] == 'or'):
                timestamp = out[0] + ' ' + out[1]
                hostname  = out[2].replace(':', '')
                rtt       = '----'
                state     = 'NO-DNS'
                add_data  = True
        except IndexError:
            pass

        if add_data:
            fping_result_data.append([hostname, state, timestamp, rtt, '', no_of_changes, '', 0])

    with lock:
        fping_cmd_output_raw_total.extend(fping_result_data)


def get_date_time():
    now = datetime.datetime.now()
    return now.strftime("%d/%m/%Y %H:%M:%S")

_ip_int_cache = {}
def _ip_sort_key(h):
    # Memoized IPv4 -> int for sort keys. Non-IP hostnames cached as None.
    v = _ip_int_cache.get(h)
    if v is None and h not in _ip_int_cache:
        try:
            v = int(ipaddress.IPv4Address(h))
        except (ipaddress.AddressValueError, ValueError):
            v = None
        _ip_int_cache[h] = v
    return v

def sort_fping_result_data(fping_result_data):
    # Partition into IPv4 vs FQDN in one pass, then sort each bucket.
    ip_rows   = []
    fqdn_rows = []
    for row in fping_result_data:
        if _ip_sort_key(row[0]) is not None:
            ip_rows.append(row)
        else:
            fqdn_rows.append(row)
    ip_rows.sort(key=lambda r: _ip_sort_key(r[0]))
    fqdn_rows.sort(key=lambda r: r[0])
    return ip_rows + fqdn_rows

def now_local(tz_offset):
    return datetime.datetime.now() + datetime.timedelta(hours=tz_offset)

def host_is_flapping(entry, now_ref, window_minutes):
    """True while the last state change of this host is inside the flap window."""
    if not entry[5]:
        return False
    ts = entry[6]
    if not isinstance(ts, datetime.datetime):
        return False
    return (now_ref - ts).total_seconds() <= window_minutes * 60

def host_group(entry, now_ref, window_minutes):
    if host_is_flapping(entry, now_ref, window_minutes):
        return 'flap'
    return 'up' if 'UP' in entry[1] else 'down'

def build_display(active_hosts_list, host_state, sort_mode=0, tz_offset=0,
                  flap_window=FLAP_WINDOW_DEF):
    """Rows to show, ordered by the selected sort mode."""
    rows   = [host_state[h] for h in active_hosts_list if h in host_state]
    groups = SORT_MODES[sort_mode % len(SORT_MODES)][2]
    if not groups:
        return sort_fping_result_data(rows)
    now_ref = now_local(tz_offset)
    buckets = {'up': [], 'flap': [], 'down': []}
    for row in rows:
        buckets[host_group(row, now_ref, flap_window)].append(row)
    # inside FLAP the state comes first, in the same direction as the mode, so the
    # DOWN rows form one block instead of sitting between the UP ones. After that the
    # change count decides (worst first), and sorted() being stable keeps the address
    # order for hosts that match in both.
    up_first = groups.index('up') < groups.index('down')
    out = []
    for g in groups:
        rows_g = sort_fping_result_data(buckets[g])
        if g == 'flap':
            rows_g = sorted(rows_g, key=lambda r: (
                0 if (('UP' in r[1]) == up_first) else 1, -int(r[5] or 0)))
        out.extend(rows_g)
    return out

def filter_hosts(mode, original_hosts_list, host_state, tz_offset,
                 flap_window=FLAP_WINDOW_DEF):
    """Host list for the given view mode - a snapshot, taken when the view switches."""
    if mode <= 0:
        return list(original_hosts_list)
    now_ref = now_local(tz_offset)
    out = []
    for h in original_hosts_list:
        entry = host_state.get(h)
        if not entry:
            continue
        if 'UP' in entry[1]:
            out.append(h)
        elif mode == 2 and host_is_flapping(entry, now_ref, flap_window):
            out.append(h)
    return out

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

def parse_hosts_from_text(text, stats=None):
    """Extract hosts from arbitrary text (host file, upload, ADD FILE).

    Understands IPv4 addresses, CIDR networks (expanded to every address in the
    range, network and broadcast included, same as -n) and hostnames/FQDNs.
    Everything after a '#' is a comment, comma and semicolon separate like blanks.
    Pass a dict as 'stats' to learn how many networks were expanded and which ones
    were rejected because their mask is outside /CIDR_MIN_MASK../CIDR_MAX_MASK.
    """
    ips      = []
    fqdns    = []
    networks = 0
    skipped  = []
    for line in (text or '').splitlines():
        line = line.split('#')[0]          # ignore comments
        for word in line.replace(',', ' ').replace(';', ' ').split():
            word = word.strip()
            if not word:
                continue
            if match_re(word, ip_re):
                ips.append(word)
            elif match_re(word, cidr_ipv4_re):
                try:
                    ips.extend(get_ipv4_from_cidr(word, CIDR_MIN_MASK, CIDR_MAX_MASK))
                    networks += 1
                except Exception:
                    skipped.append(word)
            elif match_re(word, fqdn_re):
                fqdns.append(word)
    seen = set()
    out  = []
    for h in ips + fqdns:
        if h not in seen:
            seen.add(h)
            out.append(h)
    if stats is not None:
        stats['networks'] = networks
        stats['skipped']  = skipped
    return out

def load_hosts_file(path):
    """Read a host file from disk. Returns (hosts, error_message)."""
    path = os.path.expanduser((path or '').strip())
    if not path:
        return [], 'no filename given'
    try:
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            text = f.read(WEB_MAX_UPLOAD + 1)
    except IsADirectoryError:
        return [], 'not a file: ' + path
    except FileNotFoundError:
        return [], 'file not found: ' + path
    except PermissionError:
        return [], 'permission denied: ' + path
    except Exception:
        return [], 'unable to read: ' + path
    if len(text) > WEB_MAX_UPLOAD:
        return [], 'file too large: ' + path
    stats = {}
    hosts = parse_hosts_from_text(text, stats)
    if stats.get('skipped'):
        return [], ('mask out of range (/%d../%d): %s'
                    % (CIDR_MIN_MASK, CIDR_MAX_MASK, stats['skipped'][0]))
    if not hosts:
        return [], 'no valid host found in: ' + path
    return hosts, ''

def add_hosts_to(new_hosts, active_list, original_list, max_total=MAX_TOTAL_HOSTS):
    """Append hosts to the active/reference list, skipping duplicates. Returns (added, error)."""
    active_set   = set(active_list)
    original_set = set(original_list)
    fresh = [h for h in new_hosts if h not in active_set]
    if len(active_list) + len(fresh) > max_total:
        return 0, 'rejected: more than ' + str(max_total) + ' hosts'
    added = 0
    for h in new_hosts:
        if h not in active_set:
            active_list.append(h); active_set.add(h); added += 1
        if h not in original_set:
            original_list.append(h); original_set.add(h)
    return added, ''

def remove_hosts_from(targets, active_list, original_list, host_state):
    """Remove hosts from the active list, the reference list and the state dict."""
    tset    = set(targets)
    removed = sum(1 for h in active_list if h in tset)
    active_list[:]   = [h for h in active_list   if h not in tset]
    original_list[:] = [h for h in original_list if h not in tset]
    for h in tset:
        host_state.pop(h, None)
    return removed

def parse_host_input(value):
    """Parse a user supplied string (IP, FQDN, CIDR or 'ip1-ip2') into a host list."""
    value = (value or '').strip()
    if not value:
        return []
    new_hosts = []
    # CIDR?
    if match_re(value, cidr_ipv4_re):
        try:
            new_hosts = get_ipv4_from_cidr(value, 19, 32)
        except Exception:
            pass
    # IP range  e.g. "10.0.0.1-10.0.0.20"
    elif '-' in value and value.count('-') == 1:
        parts = value.split('-')
        try:
            new_hosts = get_ipv4_from_range(parts[0].strip(), parts[1].strip(), 32768)
        except Exception:
            pass
    # single IP
    elif match_re(value, ip_re):
        new_hosts = [value]
    # hostname/fqdn
    elif match_re(value, fqdn_re):
        new_hosts = [value]
    return new_hosts

def update_host_state(host_state, fping_result_data_sorted, tz_offset,
                      learning_done, learning_phase, up_seen,
                      logging_enabled, logfile_file_name,
                      confirm=1, down_streak=None):
    """Merge one fping run into the persistent host_state dict (+ optional CSV logging).

    With confirm > 1 a host only leaves the UP state after that many consecutive
    non-UP observations. A single lost reply then no longer produces a DOWN report.
    The other direction is never damped: one reply is proof that a host is up.
    The TBD column carries the number of currently suppressed observations.
    """
    now_str = get_date_time()
    if down_streak is None:
        down_streak = {}
    for entry in fping_result_data_sorted:
        hostname  = entry[0]
        new_state = entry[1]
        timestamp = entry[2]
        rtt       = entry[3]
        tbd       = entry[7]

        # --- flap damping (UP -> not UP only) ---
        if confirm > 1 and hostname in host_state:
            previous = host_state[hostname]
            if 'UP' in previous[1] and 'UP' not in new_state:
                streak = down_streak.get(hostname, 0) + 1
                if streak < confirm:
                    down_streak[hostname] = streak
                    new_state = previous[1]      # keep UP for now
                    rtt       = previous[3]      # no fresh measurement to show
                    tbd       = streak
                else:
                    down_streak[hostname] = 0
            else:
                down_streak.pop(hostname, None)

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

        # timestamp must become a datetime object so CSV serializes as YYYY-MM-DD HH:MM:SS
        try:
            ts_tmp = datetime.datetime.strptime(timestamp, "%d/%m/%Y %H:%M:%S")
            timestamp = ts_tmp + datetime.timedelta(hours=tz_offset) if tz_offset else ts_tmp
        except: pass
        if change_ts:
            try:
                ct_tmp = datetime.datetime.strptime(change_ts, "%d/%m/%Y %H:%M:%S")
                change_ts = ct_tmp + datetime.timedelta(hours=tz_offset) if tz_offset else ct_tmp
            except: pass

        host_state[hostname] = [hostname, new_state, timestamp, rtt, old_state, changes, change_ts, tbd]

        # learning phase tracking
        if not learning_done and 'UP' in new_state:
            up_seen.add(hostname)

        # logging
        if logging_enabled and learning_phase:
            logdata = ([timestamp] + [hostname] + [old_state.replace(" ", "")] + [new_state.replace(" ", "")] + [rtt] + [changes] + [change_ts] + [tbd])
            with open(logfile_file_name, 'a', encoding='UTF8') as f:
                writer = csv.writer(f)
                writer.writerow(logdata)

def run_ping_round(active_hosts_list, threads_arg, rate_pps=DEFAULT_RATE_PPS,
                   interval_arg='', dns_ttl=DNS_CACHE_TTL,
                   down_hosts=None, down_retries=None, progress_cb=None,
                   slice_idx=0, slice_count=1):
    """Run one fping round.

    Hosts listed in down_hosts are probed with 'down_retries' instead of the full -r
    budget (see the retry class comment at the top). Pass down_hosts=None for a full
    sweep in which every target gets the full treatment.

    Returns (sorted rows, scan description, (full_count, reduced_count), timings).
    """
    global fping_cmd_output_raw_total
    fping_cmd_output_raw_total = list()
    timings = {'dns': 0.0, 'ping': 0.0, 'groups': []}

    if not active_hosts_list:
        return [], '', (0, 0), timings

    # resolve hostnames from the cache and ping addresses instead of names
    _t = time.time()
    targets, name_map, unresolved = prepare_targets(active_hosts_list, dns_ttl)
    timings['dns'] = time.time() - _t

    # --- split into retry classes ---
    # a target counts as 'confirmed down' only if every hostname pointing at it is down
    reduced_targets = []
    full_targets    = targets
    down_total      = 0
    if down_hosts and down_retries is not None:
        reduced_targets = [t for t in targets
                           if all(nm in down_hosts for nm in name_map.get(t, [t]))]
        reduced_set  = set(reduced_targets)
        full_targets = [t for t in targets if t not in reduced_set]
        down_total   = len(reduced_targets)
        # only one slice of the DOWN hosts per round - strided, so every slice covers
        # the whole address range instead of one contiguous block
        if slice_count > 1 and reduced_targets:
            reduced_targets = reduced_targets[slice_idx % slice_count::slice_count]

    # each group runs its own fping with its own share of the rate budget
    groups = []
    if full_targets:
        groups.append((full_targets, None, 'full'))
    if reduced_targets:
        groups.append((reduced_targets, down_retries, 'reduced'))

    lock        = threading.Lock()
    thread_list = []
    parts       = []
    total_pps   = 0.0
    stats       = [[] for _ in groups]
    meta        = []
    # the rate budget is shared between what is actually probed this round, not
    # between all known hosts - otherwise slicing would not speed anything up
    probed_total = sum(len(g[0]) for g in groups)
    for slot, (grp_targets, grp_retries, grp_name) in enumerate(groups):
        procs, interval_ms = tune_group(len(grp_targets), probed_total,
                                        rate_pps, threads_arg, interval_arg)
        cmd_base = build_fping_cmd(interval_ms, grp_retries)
        for chunk in split_seq(grp_targets, procs):
            thread_list.append(threading.Thread(target=timed_fping,
                                                args=(chunk, lock, cmd_base, stats, slot)))
        if interval_ms > 0:
            total_pps += procs * 1000.0 / interval_ms
        else:
            total_pps = -1.0          # -i 0: unpaced, no meaningful rate
        label = grp_name
        if grp_name == 'reduced' and slice_count > 1:
            label = 'reduced slice %d/%d of %d' % (slice_idx % slice_count + 1,
                                                   slice_count, down_total)
        parts.append('%d %s (-r %s, %d x fping, -i %dms)'
                     % (len(grp_targets), label,
                        retries if grp_retries is None else grp_retries,
                        procs, interval_ms))
        meta.append((grp_name, len(grp_targets),
                     retries if grp_retries is None else grp_retries, procs, interval_ms))
    _t = time.time()
    scan_reset_abort()
    for t in thread_list:
        t.start()
    if progress_cb is None:
        for t in thread_list:
            t.join()
    else:
        # stay responsive: poll instead of blocking, and let the caller cut it short
        while any(t.is_alive() for t in thread_list):
            if progress_cb(time.time() - _t):
                scan_abort()
                break
            time.sleep(0.15)
        for t in thread_list:
            t.join(timeout=10)
    timings['ping'] = time.time() - _t
    if total_pps < 0:
        scan_desc = ' + '.join(parts) + ', unpaced (-i 0)'
    else:
        scan_desc = ' + '.join(parts) + (', ~%d pps' % int(round(total_pps)))
        # be honest when the requested rate cannot be delivered: once -i sits at its
        # 1ms floor, a higher --rate changes nothing at all
        if not interval_arg and total_pps < rate_pps * 0.95:
            scan_desc += (' (--rate %d not reachable, -i floor 1ms)' % rate_pps)
    if use_check_source and '--check-source' in fping_capabilities():
        scan_desc += ', check-source'

    # per group: how long did fping itself actually run?
    for slot, (name, cnt, rr, procs, iv) in enumerate(meta):
        wall = 0.0
        if stats[slot]:
            wall = max(e for _, e in stats[slot]) - min(b for b, _ in stats[slot])
        timings['groups'].append((name, cnt, rr, iv, wall))

    # map the pinged address back to the hostname(s) the user entered
    rows = []
    for row in fping_cmd_output_raw_total:
        for display_name in name_map.get(row[0], [row[0]]):
            new_row    = list(row)
            new_row[0] = display_name
            rows.append(new_row)

    # names that do not resolve never reach fping - report them like fping would
    if unresolved:
        now_str = get_date_time()
        for name in unresolved:
            rows.append([name, 'NO-DNS', now_str, '----', '', 0, '', 0])

    return (sort_fping_result_data(rows), scan_desc,
            (len(full_targets), len(reduced_targets)), timings)


# =====================================================================
# WEB GUI  (optional - the CLI/curses mode stays the default)
# =====================================================================

web_lock         = threading.Lock()
web_commands     = []
web_state = {
    'version'          : VERSION,
    'update_available' : False,
    'datetime'         : '',
    'rows'             : [],
    'hosts'            : 0,
    'hosts_up'         : 0,
    'hosts_down'       : 0,
    'run_counter'      : 0,
    'run_time'         : '0.00',
    'logging'          : False,
    'logfile'          : '',
    'filter_mode'      : 0,
    'filter_label'     : FILTER_MODES[0][0],
    'sort_mode'        : 0,
    'readonly'         : False,
    'learning_phase'   : True,
    'learning_run'     : 0,
    'learning_total'   : 0,
    'wait_time'        : 0.5,
    'stopped'          : False,
    'message'          : '',
    'scan_info'        : '',
    'phase_info'       : '',
    'scanning'         : 0.0,
}

WEB_INDEX_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>eping.py</title>
<style>
  :root{
    --bg:#0b0f0b; --fg:#c8d6c8; --dim:#5d6b5d; --line:#1e2a1e;
    --up:#3ddc60; --down:#ff4b4b; --acc:#7fd1ff; --panel:#101610;
    --fs:14px; --hostw:26ch;
  }
  *{box-sizing:border-box}
  html,body{height:100%}
  body{margin:0;background:var(--bg);color:var(--fg);overflow:hidden;
       font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,"DejaVu Sans Mono",monospace;
       font-size:13px}
  header{padding:6px 12px;border-bottom:1px solid var(--line);
         display:flex;flex-wrap:wrap;gap:12px;align-items:center;justify-content:space-between}
  .title{font-weight:700;letter-spacing:.5px}
  .title small{color:var(--dim);font-weight:400}
  .clock{color:var(--dim)}
  .bar{display:flex;flex-wrap:wrap;gap:6px;padding:6px 12px;border-bottom:1px solid var(--line);align-items:center}
  button{background:var(--panel);color:var(--fg);border:1px solid var(--line);
         padding:4px 10px;cursor:pointer;font:inherit;border-radius:3px}
  button:hover{border-color:var(--acc);color:var(--acc)}
  button.on{border-color:var(--up);color:var(--up)}
  button.danger:hover{border-color:var(--down);color:var(--down)}
  .fsbox{display:flex;align-items:center;gap:4px;margin-left:auto;color:var(--dim)}
  .fsbox button{padding:4px 9px}
  .fsbox #fsVal{min-width:5ch;text-align:right;color:var(--fg)}
  input[type=text]{background:var(--panel);color:var(--fg);border:1px solid var(--line);
                   padding:4px 8px;font:inherit;border-radius:3px;min-width:200px}
  select{background:var(--panel);color:var(--fg);border:1px solid var(--line);
         padding:4px 8px;font:inherit;border-radius:3px}
  select:hover{border-color:var(--acc)}
  select.on{border-color:var(--up);color:var(--up)}
  input[type=text]:focus{outline:none;border-color:var(--acc)}
  input[type=text].delmode{border-color:var(--down);color:var(--down)}
  input[type=range]{width:110px;accent-color:var(--acc)}
  .stats{display:flex;flex-wrap:wrap;gap:16px;padding:5px 12px;border-bottom:1px solid var(--line);color:var(--dim)}
  .stats b{color:var(--fg);font-weight:600}
  .stats .u b{color:var(--up)} .stats .d b{color:var(--down)}
  .banner{padding:6px 12px;background:#2a1414;color:var(--down);border-bottom:1px solid var(--line)}

  /* ---- CLI style column grid ---- */
  #ctrls{display:inline-flex;flex-wrap:wrap;gap:6px;align-items:center}
  #ro{color:var(--acc)}
  #grid{display:flex;align-items:flex-start;gap:0;
        overflow-x:auto;overflow-y:hidden;padding:4px 0 0 8px;
        font-size:var(--fs);line-height:1.35}
  table.hosts{border-collapse:collapse;table-layout:fixed;flex:0 0 auto;
              border-left:1px solid var(--line);border-right:1px solid var(--line)}
  table.hosts th,table.hosts td{padding:0 .6ch;white-space:nowrap;overflow:hidden;
                                text-overflow:ellipsis;border-bottom:1px solid #131b13}
  table.hosts th{color:var(--dim);font-weight:600;text-align:left;cursor:pointer;
                 user-select:none;border-bottom:1px solid var(--line)}
  table.hosts th:hover{color:var(--acc)}
  table.hosts th.sorted{color:var(--acc)}
  td.rtt,td.chno,th.rtt,th.chno{text-align:right}
  td.state{font-weight:700;text-align:center}
  td.state.up{color:var(--up)} td.state.down{color:var(--down)}
  tr.down td.host{color:var(--down);font-weight:700}
  #probe{position:absolute;visibility:hidden;pointer-events:none;top:0;left:-9999px;
         font-size:var(--fs);line-height:1.35}
  .empty{padding:14px;color:var(--down);font-weight:700}
  .empty .hint{color:var(--dim);font-weight:400;margin-top:6px}
  .learn{padding:12px;margin:10px 12px;border:1px solid var(--up);color:var(--up);text-align:center}
  .msg{color:var(--acc)}
  .msg.pending{color:var(--up)}
  .off{opacity:.45}
  footer{border-top:1px solid var(--line);padding:4px 12px;color:var(--dim);font-size:12px;
         white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
  .layout{display:flex;flex-direction:column;height:100%}
  .body{flex:1 1 auto;min-height:0;display:flex;flex-direction:column}
</style>
</head>
<body>
<div class="layout">
  <div id="banner" class="banner" style="display:none"></div>
  <header>
    <div class="title">eping.py <small id="ver"></small> <small>by Ewald Jeitler</small>
      <small id="ro"></small></div>
    <div class="clock" id="clock"></div>
  </header>

  <div class="bar">
   <span id="ctrls">
    <button id="btnUp" title="cycle: ALL HOSTS / UP-ONLY / UP+FLAPPING">ALL HOSTS</button>
    <select id="sortSel" title="sort order - a flapping host is grouped as FLAP regardless of its current state">
      <option value="0">sort: ADDRESS</option>
      <option value="1">sort: UP/FLAP/DOWN</option>
      <option value="2">sort: DOWN/FLAP/UP</option>
      <option value="3">sort: FLAP/UP/DOWN</option>
      <option value="4">sort: FLAP/DOWN/UP</option>
    </select>
    <input type="text" id="addInput" placeholder="IP / host / CIDR / ip1-ip2">
    <button id="btnAdd">ADD HOST</button>
    <button id="btnDel" title="remove the given host(s) - same input as ADD HOST">DEL HOST</button>
    <button id="btnUpload">UPLOAD FILE</button>
    <input type="file" id="fileInput" accept=".txt,.csv,.list,text/plain" style="display:none">
    <button id="btnSetRef" title="use the hosts currently shown as the new reference list">SET REFERENCE</button>
    <button id="btnZero" title="reset CH-TIME and CH NO for all hosts">ZERO CHANGES</button>
    <button id="btnClear" class="danger">CLEAR ALL</button>
    <button id="btnExit" class="danger">EXIT</button>
   </span>
    <span class="fsbox">
      FONT
      <button id="fsMinus" title="smaller (-)">A&minus;</button>
      <input type="range" id="fsRange" min="6" max="28" step="1">
      <button id="fsPlus" title="bigger (+)">A+</button>
      <span id="fsVal"></span>
    </span>
  </div>

  <div class="stats">
    <span>HOSTS: <b id="sHosts">0</b></span>
    <span>RUNTIME: <b id="sRuntime">0.00</b>sec</span>
    <span>RUNS: <b id="sRuns">0</b></span>
    <span class="u">HOSTS-UP: <b id="sUp">0</b></span>
    <span class="d">HOSTS-DOWN: <b id="sDown">0</b></span>
    <span id="sLog"></span>
    <span class="msg" id="msg"></span>
  </div>

  <div class="body">
    <div id="learn" class="learn" style="display:none"></div>
    <div id="grid"></div>
  </div>

  <footer id="foot">connecting ...</footer>
</div>
<div id="probe"></div>

<script>
var sortKey = null, sortDir = 1, lastRows = [], stopped = false;
var FS_MIN = 6, FS_MAX = 28, fontSize = 13;

var COLS = [
  {k:'host',  t:'HOSTNAME/IP', c:'host'},
  {k:'state', t:'U/D',         c:'state'},
  {k:'rtt',   t:'RTT',         c:'rtt'},
  {k:'chts',  t:'CH-TIME',     c:'chts'},
  {k:'chno',  t:'CH',          c:'chno'}
];
var WIDTH = {state:'8ch', rtt:'9ch', chts:'11ch', chno:'6ch'};
var hasData = false, firstRunDone = false;

function esc(s){ return String(s==null?'':s).replace(/[&<>"']/g, function(c){
  return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]; }); }

function store(k,v){ try{ localStorage.setItem(k,v); }catch(e){} }
function load(k){ try{ return localStorage.getItem(k); }catch(e){ return null; } }

/* ---------------- font size ---------------- */
function setFont(px, save){
  fontSize = Math.max(FS_MIN, Math.min(FS_MAX, px|0));
  document.documentElement.style.setProperty('--fs', fontSize + 'px');
  document.getElementById('fsVal').textContent   = fontSize + 'px';
  document.getElementById('fsRange').value       = fontSize;
  if(save !== false) store('eping_fs', fontSize);
  render(lastRows);
}
document.getElementById('fsMinus').onclick = function(){ setFont(fontSize - 1); };
document.getElementById('fsPlus').onclick  = function(){ setFont(fontSize + 1); };
document.getElementById('fsRange').oninput = function(){ setFont(parseInt(this.value,10)); };

/* ---------------- commands ---------------- */
var PENDING = {up_only:'switching view ...', sort:'sorting ...', add:'adding host(s) ...',
               del:'removing host(s) ...', set_ref:'setting reference ...',
               clear:'clearing all hosts ...', zero:'resetting change counters ...',
               exit:'stopping eping ...'};
var pending = false, lastServerMsg = null;

function note(text, isPending){
  var m = document.getElementById('msg');
  m.textContent = text || '';
  m.className   = isPending ? 'msg pending' : 'msg';
  pending       = !!isPending;
}
function post(cmd, value){
  note(PENDING[cmd] || 'working ...', true);   // instant feedback, no waiting
  return fetch('api/command', {method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({cmd:cmd, value:value||''})}).then(function(r){return r.json();});
}
document.getElementById('btnUp').onclick   = function(){ post('up_only'); };
document.getElementById('sortSel').onchange = function(){
  sortKey = null;                       // server order wins again after a mode change
  post('sort', this.value);
};
document.getElementById('btnExit').onclick = function(){
  if(confirm('Stop eping.py?')){ post('exit'); } };
function send(cmd){
  var el = document.getElementById('addInput');
  var v = el.value.trim();
  if(!v){ el.focus(); return; }
  post(cmd, v).then(function(){ el.value=''; });
}
document.getElementById('btnAdd').onclick = function(){ setMode('add'); send('add'); };
document.getElementById('btnDel').onclick = function(){ setMode('del'); send('del'); };

/* the text field feeds both ADD and DEL - 'a' / 'd' preselect the mode for [ENTER] */
function setMode(m){
  var el = document.getElementById('addInput');
  el.dataset.mode = m;
  el.classList.toggle('delmode', m === 'del');
  el.placeholder = (m === 'del' ? 'DELETE: ' : '') + 'IP / host / CIDR / ip1-ip2';
}
document.getElementById('addInput').addEventListener('keydown', function(e){
  if(e.key === 'Enter'){ send(this.dataset.mode === 'del' ? 'del' : 'add'); }
  else if(e.key === 'Escape'){ this.value = ''; setMode('add'); this.blur(); }
});

document.getElementById('btnSetRef').onclick = function(){ post('set_ref'); };
document.getElementById('btnZero').onclick   = function(){ post('zero'); };
document.getElementById('btnClear').onclick  = function(){
  if(confirm('Remove ALL hosts and reset their state?')){ post('clear'); } };

/* ---- host file upload ---- */
var fileInput = document.getElementById('fileInput');
document.getElementById('btnUpload').onclick = function(){ fileInput.click(); };
fileInput.addEventListener('change', function(){
  var f = fileInput.files && fileInput.files[0];
  if(!f) return;
  var rd = new FileReader();
  rd.onload = function(){
    note('uploading ' + f.name + ' ...', true);
    fetch('api/upload', {method:'POST', headers:{'Content-Type':'text/plain; charset=utf-8'},
      body: rd.result}).then(function(r){ return r.json(); }).then(function(j){
        if(!j.ok){ note('upload failed: ' + (j.error||''), false); }
      }).catch(function(){ note('upload failed', false); });
    fileInput.value = '';
  };
  rd.readAsText(f);
});
/* drag & drop a host file anywhere on the page */
document.addEventListener('dragover', function(e){ e.preventDefault(); });
document.addEventListener('drop', function(e){
  e.preventDefault();
  var f = e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0];
  if(!f) return;
  var rd = new FileReader();
  rd.onload = function(){
    fetch('api/upload', {method:'POST', headers:{'Content-Type':'text/plain; charset=utf-8'},
      body: rd.result});
  };
  rd.readAsText(f);
});

/* Only the font size keys are bound. Everything else stays free for the browser -
   a letter shortcut would swallow Ctrl+C, text selection and normal typing. */
document.addEventListener('keydown', function(e){
  if(e.ctrlKey || e.metaKey || e.altKey || e.shiftKey) return;
  if(document.activeElement && document.activeElement.tagName === 'INPUT') return;
  if(e.key === '+' || e.key === '=')      setFont(fontSize + 1);
  else if(e.key === '-' || e.key === '_') setFont(fontSize - 1);
});

/* ---------------- sorting ---------------- */
function ipKey(h){
  var m = /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(h);
  if(!m) return null;
  return ((+m[1])*16777216)+((+m[2])*65536)+((+m[3])*256)+(+m[4]);
}
function sortRows(r){
  if(!sortKey) return r;
  return r.sort(function(a,b){
    var x=a[sortKey], y=b[sortKey];
    if(sortKey==='host'){
      var ax=ipKey(x), by=ipKey(y);
      if(ax!==null&&by!==null) return (ax-by)*sortDir;
      if(ax!==null) return -1*sortDir;
      if(by!==null) return  1*sortDir;
      return String(x).localeCompare(String(y))*sortDir;
    }
    if(sortKey==='rtt'||sortKey==='chno'){
      var fa=parseFloat(x), fb=parseFloat(y);
      if(isNaN(fa)) fa=Number.MAX_VALUE;
      if(isNaN(fb)) fb=Number.MAX_VALUE;
      return (fa-fb)*sortDir;
    }
    return String(x).localeCompare(String(y))*sortDir;
  });
}
function onHeadClick(k){
  if(sortKey === k){ sortDir = -sortDir; } else { sortKey = k; sortDir = 1; }
  render(lastRows);
}

/* ---------------- layout ---------------- */
function colgroupHTML(){
  var s = '<colgroup>';
  for(var i=0;i<COLS.length;i++){
    var w = COLS[i].k === 'host' ? 'var(--hostw)' : WIDTH[COLS[i].k];
    s += '<col style="width:'+w+'">';
  }
  return s + '</colgroup>';
}
function headHTML(){
  var s = '<thead><tr>';
  for(var i=0;i<COLS.length;i++){
    var c = COLS[i];
    var arrow = (sortKey === c.k) ? (sortDir > 0 ? ' ▲' : ' ▼') : '';
    s += '<th class="'+c.c+(sortKey===c.k?' sorted':'')+'" data-k="'+c.k+'">'+c.t+arrow+'</th>';
  }
  return s + '</tr></thead>';
}
function rowHTML(o){
  var isUp = o.state.indexOf('UP') !== -1;
  return '<tr class="'+(isUp?'up':'down')+'">'
    +'<td class="host" title="'+esc(o.host)+'">'+esc(o.host)+'</td>'
    +'<td class="state '+(isUp?'up':'down')+'">'+esc(String(o.state).trim())+'</td>'
    +'<td class="rtt">'+esc(o.rtt)+'</td>'
    +'<td class="chts">'+esc(o.chts)+'</td>'
    +'<td class="chno">'+(o.chno>0?esc(o.chno):'')+'</td></tr>';
}
function measure(){
  var p = document.getElementById('probe');
  p.innerHTML = '<table class="hosts">'+colgroupHTML()+headHTML()+'<tbody>'
    + rowHTML({host:'888.888.888.888',state:'UP',rtt:'99.99',chts:'00:00:00',chno:1})
    + '</tbody></table>';
  var th = p.querySelector('thead tr');
  var tr = p.querySelector('tbody tr');
  var tb = p.querySelector('table');
  return {head: th.getBoundingClientRect().height,
          row : tr.getBoundingClientRect().height || 1,
          w   : tb.getBoundingClientRect().width  || 1};
}
function hostWidthCh(rows){
  var max = 11;
  for(var i=0;i<rows.length;i++){
    var l = String(rows[i].host).length;
    if(l > max) max = l;
  }
  if(max > 38) max = 38;
  return (max + 2) + 'ch';
}

function render(rows){
  lastRows = rows || [];
  var grid = document.getElementById('grid');
  if(!lastRows.length){
    // firstRunDone only becomes true once a scan round has actually published results
    grid.innerHTML = firstRunDone
      ? '<div class="empty">NO HOSTS TO PING!<div class="hint">'
        + 'add a host above, upload a host file or drop one onto this page</div></div>'
      : '<div class="empty" style="color:var(--up)">PLEASE WAIT'
        + '<div class="hint">scanning ...</div></div>';
    document.getElementById('foot').textContent = firstRunDone
      ? 'live 1s | no hosts - add a host above, upload a file or drop one onto this page'
      : 'scanning - please wait ...';
    return;
  }
  document.documentElement.style.setProperty('--hostw', hostWidthCh(lastRows));

  var r = sortRows(lastRows.slice());
  var m = measure();

  var avail = window.innerHeight - grid.getBoundingClientRect().top
              - document.getElementById('foot').getBoundingClientRect().height - 6;
  var perCol = Math.max(1, Math.floor((avail - m.head) / m.row));
  var nCols  = Math.ceil(r.length / perCol);
  if(nCols < 1) nCols = 1;
  /* balance: do not leave a nearly empty last column */
  perCol = Math.ceil(r.length / nCols);

  grid.style.height = Math.max(0, avail) + 'px';

  var out = [], i, j;
  for(i = 0; i < nCols; i++){
    out.push('<table class="hosts">' + colgroupHTML() + headHTML() + '<tbody>');
    for(j = i*perCol; j < Math.min((i+1)*perCol, r.length); j++){
      out.push(rowHTML(r[j]));
    }
    out.push('</tbody></table>');
  }
  var keepScroll = grid.scrollLeft;
  grid.innerHTML = out.join('');
  grid.scrollLeft = keepScroll;

  var ths = grid.querySelectorAll('th[data-k]');
  for(i=0;i<ths.length;i++){
    ths[i].onclick = (function(k){ return function(){ onHeadClick(k); }; })(ths[i].getAttribute('data-k'));
  }

  var fits = grid.scrollWidth <= grid.clientWidth + 2;
  document.getElementById('foot').textContent =
    'live 1s | ' + nCols + ' column(s) x ' + perCol + ' rows | font ' + fontSize + 'px'
    + (fits ? '' : ' | SCROLL RIGHT FOR MORE - reduce font size to fit')
    + ' | +/- font size';
}

var rz;
window.addEventListener('resize', function(){
  clearTimeout(rz); rz = setTimeout(function(){ render(lastRows); }, 80); });

/* ---------------- polling ---------------- */
function poll(){
  if(stopped) return;
  fetch('api/status').then(function(r){return r.json();}).then(function(s){
    document.getElementById('ver').textContent   = 'version '+s.version;
    if(s.readonly){
      document.getElementById('ctrls').style.display = 'none';
      document.getElementById('ro').textContent = '- read only, controlled from the terminal';
    }
    document.getElementById('clock').textContent = s.datetime;
    document.getElementById('sHosts').textContent   = s.hosts;
    document.getElementById('sRuntime').textContent = s.run_time;
    document.getElementById('sRuns').textContent    = s.run_counter;
    document.getElementById('sUp').textContent      = s.hosts_up;
    document.getElementById('sDown').textContent    = s.hosts_down;
    document.getElementById('sLog').innerHTML = s.logging
      ? 'LOGGING-ON: <b>'+esc(s.logfile)+'</b>' : 'LOGGING-OFF';
    var bu = document.getElementById('btnUp');
    bu.textContent = s.filter_label || 'ALL HOSTS';
    bu.className   = s.filter_mode ? 'on' : '';
    var ss = document.getElementById('sortSel');
    if(document.activeElement !== ss) ss.value = String(s.sort_mode || 0);
    ss.className = s.sort_mode ? 'on' : '';
    // keep the local 'working ...' note until the server actually answers something new
    if(s.message !== lastServerMsg){ lastServerMsg = s.message; note(s.message || '', false); }
    else if(!pending){ note(s.message || '', false); }

    var b = document.getElementById('banner');
    if(s.update_available){ b.style.display='block';
      b.innerHTML = 'Update available &ndash; please visit '
        +'<a style="color:inherit" href="https://www.jeitler.guru" target="_blank" rel="noopener">https://www.jeitler.guru</a>'; }
    else { b.style.display='none'; }

    var lz = document.getElementById('learn');
    if(!s.learning_phase){ lz.style.display='block';
      lz.textContent = 'PLEASE WAIT - scanning hosts for UP status - LEARNING PHASE '
        + s.learning_run + ' of ' + s.learning_total; }
    else { lz.style.display='none'; }

    hasData = true;
    if(s.run_counter > 0) firstRunDone = true;
    render(s.rows);

    if(s.stopped){ stopped = true;
      document.getElementById('foot').textContent = 'eping.py stopped - THX for using eping.py';
      document.body.classList.add('off');
    }
  }).catch(function(){
    document.getElementById('foot').textContent = 'no connection to eping.py ...';
  });
}

setFont(parseInt(load('eping_fs') || '13', 10), false);
poll();
setInterval(poll, 1000);
</script>
</body>
</html>
"""


class EpingWebHandler(http.server.BaseHTTPRequestHandler):
    server_version  = 'eping/' + VERSION
    protocol_version = 'HTTP/1.1'

    def log_message(self, *a):
        pass  # keep the console quiet

    def _respond(self, code, ctype, body):
        if isinstance(body, str):
            body = body.encode('utf-8')
        try:
            self.send_response(code)
            self.send_header('Content-Type', ctype)
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_GET(self):
        path = self.path.split('?')[0]
        if path in ('/', '/index.html'):
            self._respond(200, 'text/html; charset=utf-8', WEB_INDEX_HTML)
        elif path in ('/api/status', 'api/status'):
            with web_lock:
                body = json.dumps(web_state)
            self._respond(200, 'application/json; charset=utf-8', body)
        else:
            self._respond(404, 'text/plain; charset=utf-8', 'not found')

    def _read_body(self, max_bytes):
        try:
            length = int(self.headers.get('Content-Length') or 0)
        except ValueError:
            length = 0
        if length <= 0:
            return b''
        if length > max_bytes:
            return None
        return self.rfile.read(length)

    def do_POST(self):
        path = self.path.split('?')[0]

        if web_readonly:
            self._respond(403, 'application/json; charset=utf-8',
                          json.dumps({'ok': False, 'error': 'read only view'}))
            return

        # --- host file upload (plain text body) ---
        if path in ('/api/upload', 'api/upload'):
            raw = self._read_body(WEB_MAX_UPLOAD)
            if raw is None:
                self._respond(413, 'application/json; charset=utf-8',
                              json.dumps({'ok': False, 'error': 'file too large'}))
                return
            try:
                text = raw.decode('utf-8', 'replace')
            except Exception:
                text = ''
            with web_lock:
                web_commands.append(('upload', text))
            self._respond(200, 'application/json; charset=utf-8', json.dumps({'ok': True}))
            return

        if path not in ('/api/command', 'api/command'):
            self._respond(404, 'text/plain; charset=utf-8', 'not found')
            return
        raw = self._read_body(65536) or b'{}'
        try:
            payload = json.loads(raw.decode('utf-8') or '{}')
        except Exception:
            payload = {}
        cmd   = str(payload.get('cmd', ''))
        value = str(payload.get('value', ''))[:256]
        if cmd not in ('up_only', 'add', 'del', 'set_ref', 'clear', 'zero', 'sort', 'exit'):
            self._respond(400, 'application/json; charset=utf-8', json.dumps({'ok': False}))
            return
        with web_lock:
            web_commands.append((cmd, value))
        self._respond(200, 'application/json; charset=utf-8', json.dumps({'ok': True}))


class EpingWebServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def handle_error(self, request, client_address):
        # a traceback on stderr would destroy the curses screen in --web_view mode
        pass


def start_web_server(bind_addr, port):
    try:
        httpd = EpingWebServer((bind_addr, port), EpingWebHandler)
    except OSError as e:
        error_handler('ERROR: unable to bind web gui to ' + str(bind_addr) + ':' + str(port) + ' - ' + str(e))
    def serve():
        try:
            httpd.serve_forever()
        except Exception:
            pass          # never print - the terminal may be running curses
    t = threading.Thread(target=serve, daemon=True)
    t.start()
    return httpd


def web_rows(display_list):
    """Turn state rows into what the browser table needs."""
    rows = []
    for o in display_list:
        chts = o[6]
        try:
            chts = str(chts).split(' ')[1]
        except Exception:
            chts = ''
        rows.append({'host': o[0], 'state': o[1].strip(), 'rtt': o[3],
                     'chts': chts, 'chno': o[5]})
    return rows


def web_publish(display_list, run_counter, run_time, hosts_up, hosts_down,
                filter_mode, learning_phase, learning_run, learning_total,
                logging_enabled, logfile_file_name, update_available, tz_offset, message='',
                scan_info='', sort_mode=0):
    now  = now_local(tz_offset)
    rows = web_rows(display_list)
    with web_lock:
        web_state.update({
            'datetime'        : now.strftime("%d/%m/%Y %H:%M:%S"),
            'rows'            : rows,
            'hosts'           : len(rows),
            'hosts_up'        : hosts_up,
            'hosts_down'      : hosts_down,
            'run_counter'     : run_counter,
            'run_time'        : run_time,
            'logging'         : bool(logging_enabled),
            'logfile'         : logfile_file_name if logging_enabled else '',
            'filter_mode'     : filter_mode,
            'filter_label'    : FILTER_MODES[filter_mode][0],
            'sort_mode'       : sort_mode,
            'learning_phase'  : learning_phase,
            'learning_run'    : learning_run,
            'learning_total'  : learning_total,
            'update_available': update_available,
            'message'         : message,
            'scan_info'       : scan_info,
        })


def run_web_mode(original_hosts_list, host_state, args, logfile_file_name,
                 update_available, up_check_runs, down_retries=None, full_sweep=0,
                 confirm=1, down_slices=1, flap_window=FLAP_WINDOW_DEF):
    """Headless main loop - same logic as the CLI loop, output goes to the web gui."""
    bind_addr = args.web_bind
    port      = int(args.web_port)
    start_web_server(bind_addr, port)

    shown = '127.0.0.1' if bind_addr in ('0.0.0.0', '') else bind_addr
    print('\n eping.py ' + VERSION + ' - web gui mode')
    print(' listening on http://' + str(bind_addr) + ':' + str(port))
    print(' open  http://' + shown + ':' + str(port) + '  in your browser')
    if args.disable_logging:
        print(' logging to ' + logfile_file_name)
    if not original_hosts_list:
        print(' no hosts yet - use ADD HOST or UPLOAD FILE in the web gui')
    print(' press CTRL-C to stop\n')

    with web_lock:
        web_state['wait_time'] = float(args.waittime)

    tz_offset         = int(args.time_zone_adjust)
    active_hosts_list = list(original_hosts_list)
    filter_mode       = 0
    sort_mode         = 0
    down_streak       = {}
    learning_done     = (up_check_runs == 0)
    up_seen           = set()
    run_counter       = 1
    message           = ''

    while True:
        # --- commands coming from the browser ---
        with web_lock:
            cmds = list(web_commands)
            del web_commands[:]
        for cmd, value in cmds:
            if cmd == 'up_only':
                next_mode = (filter_mode + 1) % len(FILTER_MODES)
                next_list = filter_hosts(next_mode, original_hosts_list, host_state,
                                         tz_offset, flap_window)
                if next_list or next_mode == 0:
                    filter_mode       = next_mode
                    active_hosts_list = next_list
                    message = 'view: ' + FILTER_MODES[filter_mode][0]
                else:
                    message = 'no hosts match ' + FILTER_MODES[next_mode][0]
            elif cmd == 'sort':
                try:
                    sort_mode = int(value) % len(SORT_MODES)
                except ValueError:
                    sort_mode = 0
                message = 'sort: ' + SORT_MODES[sort_mode][0]
            elif cmd == 'add':
                new_hosts = parse_host_input(value)
                if not new_hosts:
                    message = 'invalid host: ' + value
                else:
                    added, err = add_hosts_to(new_hosts, active_hosts_list, original_hosts_list)
                    message = err if err else 'added ' + str(added) + ' host(s)'
            elif cmd == 'del':
                del_hosts = parse_host_input(value)
                if not del_hosts:
                    message = 'invalid host: ' + value
                else:
                    removed = remove_hosts_from(del_hosts, active_hosts_list,
                                                original_hosts_list, host_state)
                    up_seen.difference_update(del_hosts)
                    for _h in del_hosts:
                        down_streak.pop(_h, None)
                    forget_names(del_hosts)
                    message = 'removed ' + str(removed) + ' host(s)'
            elif cmd == 'upload':
                up_stats  = {}
                new_hosts = parse_hosts_from_text(value, up_stats)
                if not new_hosts and up_stats.get('skipped'):
                    message = ('upload: mask must be /%d../%d: %s'
                               % (CIDR_MIN_MASK, CIDR_MAX_MASK, up_stats['skipped'][0]))
                elif not new_hosts:
                    message = 'upload: no valid host found in file'
                else:
                    added, err = add_hosts_to(new_hosts, active_hosts_list, original_hosts_list)
                    if err:
                        message = 'upload ' + err
                    else:
                        message = ('uploaded file: ' + str(added) + ' new host(s) of '
                                   + str(len(new_hosts)) + ' found')
                        if up_stats.get('networks'):
                            message += (', %d network(s) expanded' % up_stats['networks'])
                        if up_stats.get('skipped'):
                            message += (', %d ignored (mask)' % len(up_stats['skipped']))
            elif cmd == 'set_ref':
                # what is displayed right now becomes the new reference list
                original_hosts_list[:] = list(active_hosts_list)
                filter_mode = 0
                message = 'reference set to the ' + str(len(active_hosts_list)) + ' host(s) shown'
            elif cmd == 'zero':
                for _entry in host_state.values():
                    _entry[5] = 0
                    _entry[6] = ''
                message = 'change counters reset'
            elif cmd == 'clear':
                active_hosts_list   = []
                original_hosts_list[:] = []
                host_state.clear()
                up_seen.clear()
                down_streak.clear()
                _dns_cache.clear()
                filter_mode = 0
                message = 'all hosts cleared'
            elif cmd == 'exit':
                with web_lock:
                    web_state['stopped'] = True
                    web_state['message'] = 'stopped'
                time.sleep(1.5)   # let the browser pick up the final status
                print('THX for using eping.py ')
                sys.exit(0)

        if cmds:
            # view and order are pure display changes - show them at once instead of
            # letting the browser wait for the running round, same as the CLI does
            quick    = build_display(active_hosts_list, host_state, sort_mode,
                                     tz_offset, flap_window)
            quick_up = sum(1 for e in quick if 'UP' in e[1])
            with web_lock:
                web_state['message']      = message
                web_state['rows']         = web_rows(quick)
                web_state['hosts']        = len(quick)
                web_state['hosts_up']     = quick_up
                web_state['hosts_down']   = len(quick) - quick_up
                web_state['filter_mode']  = filter_mode
                web_state['filter_label'] = FILTER_MODES[filter_mode][0]
                web_state['sort_mode']    = sort_mode

        # --- learning phase ---
        if not learning_done:
            if run_counter <= up_check_runs:
                learning_phase = False
            else:
                learning_done = True
                active_hosts_list = sorted(up_seen, key=lambda h: (
                    int(ipaddress.ip_address(h)) if match_re(h, ip_re) else float('inf')))
                learning_phase = True
        else:
            learning_phase = True

        # --- ping round ---
        time1 = datetime.datetime.now()
        # --fs 0 means 'never sweep', not 'always sweep' - only down_retries = None
        # (i.e. --down_retries -1) disables the retry classes altogether
        sweep_now = (down_retries is None
                     or (full_sweep > 0 and (run_counter - 1) % full_sweep == 0))
        down_now  = None if sweep_now else set(
            h for h, e in host_state.items() if 'UP' not in e[1])

        def web_progress(elapsed):
            with web_lock:
                web_state['scanning'] = elapsed
                pending = bool(web_commands)
            return pending          # a click in the browser cuts the round short

        fping_result_data_sorted, used_scan, used_split, phase = run_ping_round(
            active_hosts_list, args.num_of_threads, int(args.rate_pps),
            args.interval, int(args.dns_ttl), down_now, down_retries, web_progress,
            run_counter - 1, down_slices)
        with web_lock:
            web_state['scanning'] = 0.0
        _t = time.time()
        update_host_state(host_state, fping_result_data_sorted, tz_offset,
                          learning_done, learning_phase, up_seen,
                          args.disable_logging, logfile_file_name,
                          confirm, down_streak)
        phase['state'] = time.time() - _t

        _t = time.time()
        display_list = build_display(active_hosts_list, host_state, sort_mode,
                                     tz_offset, flap_window)
        hosts_count_up   = sum(1 for e in display_list if 'UP' in e[1])
        hosts_count_down = len(display_list) - hosts_count_up
        phase['build'] = time.time() - _t

        # --- wait ---
        _t = time.time()
        if run_counter >= 2:
            remaining = float(args.waittime) - (datetime.datetime.now() - time1).total_seconds()
            if remaining > 0:
                time.sleep(remaining)
        phase['wait'] = time.time() - _t

        run_time = format(float((datetime.datetime.now() - time1).total_seconds()), ".2f")

        grp_txt = '  '.join('%s %d(-r %s,-i %dms) %.2fs' % g for g in phase.get('groups', []))
        with web_lock:
            web_state['phase_info'] = ('fping %.2f [%s] | dns %.2f | state %.2f | build %.2f | wait %.2f'
                                       % (phase.get('ping', 0), grp_txt, phase.get('dns', 0),
                                          phase.get('state', 0), phase.get('build', 0),
                                          phase.get('wait', 0)))
        with web_lock:
            web_state['sort_mode'] = sort_mode
        scan_info = used_scan
        if scan_info and sweep_now and down_retries is not None:
            scan_info += ' | full sweep'
        if scan_info and confirm > 1:
            damped = sum(1 for v in down_streak.values() if v)
            scan_info += ' | confirm %d%s' % (confirm, (', %d pending' % damped) if damped else '')

        web_publish(display_list, run_counter, run_time, hosts_count_up, hosts_count_down,
                    filter_mode,
                    learning_phase, run_counter, up_check_runs,
                    args.disable_logging, logfile_file_name, update_available,
                    tz_offset, message, scan_info, sort_mode)

        run_counter += 1


# MAIN MAIN MAIN
if __name__=='__main__':

    if not is_program_installed("fping"):
        error_handler ("ERROR: The command 'fping' was not found. \n Install it via 'sudo apt install fping' (Debian/Ubuntu), 'brew install fping' (macOS), or however it works on your system.")

    default_hostfile = 'eping-hosts.txt'
    min_required_version = (3,6)
    # raise soft FD limit for large host counts
    raise_fd_limit()

    if not check_python_version(min_required_version):
        error_handler('ERROR: Your Python interpreter must be ' + str(min_required_version[0]) + '.' + str(min_required_version[1]) +' or greater' )
    
    now = datetime.datetime.now()
    parser = argparse.ArgumentParser()
    
    # adding optional argument
    parser.add_argument('-f', '--hostfile', default=default_hostfile, dest='hostfile', help="hosts filename" )
    parser.add_argument('-df', '--disable_hostfile', action="store_true", help="disable hostsfile")
    parser.add_argument('-n', '--network', default='', dest='network_cidr', help='network e.g. 172.17.17.0/24  minimum mask: /' + str(CIDR_MIN_MASK) )
    parser.add_argument('-n1', '--network1', default='', dest='network_cidr1', help='network e.g. 10.0.0.0/30  minimum mask: /' + str(CIDR_MIN_MASK) )
    parser.add_argument('-n2', '--network2', default='', dest='network_cidr2', help='network e.g. 192.168.100/25  minimum mask: /' + str(CIDR_MIN_MASK) )
    parser.add_argument('-n3', '--network3', default='', dest='network_cidr3', help='network e.g. 10.10.0.0/22  minimum mask: /' + str(CIDR_MIN_MASK) )
    parser.add_argument('-n4', '--network4', default='', dest='network_cidr4', help='network e.g. 10.180.0.0/21  minimum mask: /' + str(CIDR_MIN_MASK) )
    parser.add_argument('-r', '--network_range', default='', nargs = '*' ,dest='network_range', help='ip range e.g. 10.180.0.0 10.180.3.255')
    parser.add_argument('-r1', '--network_range1', default='', nargs = '*' ,dest='network_range1', help='ip range e.g. 172.17.1.1 172.17.1.20')
    parser.add_argument('-r2', '--network_range2', default='', nargs = '*' ,dest='network_range2', help='ip range e.g. 192.168.1.1 192.168.1.60')
    parser.add_argument('-r3', '--network_range3', default='', nargs = '*' ,dest='network_range3', help='ip range e.g. 1.1.1.0 1.1.1.255')
    parser.add_argument('-r4', '--network_range4', default='', nargs = '*' ,dest='network_range4', help='ip range e.g. 8.8.8.8 8.8.8.8')
    parser.add_argument('-B', '--backoff', default='1.5', dest='backoff', help="set exponential backoff factor to N (default: 1.5)" )
    parser.add_argument('-t', '--timeout', default='250', dest='timeout', help="individual target initial timeout (default: 250ms)") 
    parser.add_argument('-re', '--retries', default='3', dest='retries', help="number of retries per host (default: 3)")
    parser.add_argument('-i', '--interval', default='', dest='interval', help="interval between sending pings in ms; overrides --rate. 0 = no pacing at all (fastest, needs the privileges fping was installed with, sends one hard burst)")
    parser.add_argument('-o', '--logfile', default='', dest='logfile', help="logging filename" )
    parser.add_argument('-dl', '--disable_logging', action="store_false", help="disable logging")
    parser.add_argument('-cl', '--clean', action="store_true", dest='delete_files', help="delete all files start with \'eping-l*\'' ")
    parser.add_argument('-up', '--up', default='0', dest='up_hosts_check', help="display and check only host the are up x runs" )
    parser.add_argument('-p', '--threads', default='auto', dest='num_of_threads', help="fping processes per retry group (default: auto = " + str(PROCS_PER_GROUP) + "; higher values cost accuracy)" )
    parser.add_argument('-tz', '--timezone', default='0', dest='time_zone_adjust', help="default is 0 range from -24 to 24" )
    parser.add_argument('-w', '--wait', default ='0.5', dest='waittime', help="wait time" )   
    parser.add_argument('-du', '--disable_versioncheck', action="store_true", help="disable online versioncheck")
    parser.add_argument('-ra', '--rate', default=str(DEFAULT_RATE_PPS), dest='rate_pps', help="ICMP packets per second (default: " + str(DEFAULT_RATE_PPS) + "; -i cannot go below 1ms, so one process per group tops out near 1000 - higher values have no effect. Use -i 0 to remove the limit entirely)")
    parser.add_argument('-dns', '--dns_ttl', default=str(DNS_CACHE_TTL), dest='dns_ttl', help="seconds a resolved hostname is cached (default: " + str(DNS_CACHE_TTL) + ", 0 = let fping resolve every run)")
    parser.add_argument('-dr', '--down_retries', default=str(DOWN_RETRIES_DEF), dest='down_retries', help="retries for hosts already known to be DOWN (default: " + str(DOWN_RETRIES_DEF) + ", -1 = treat them like every other host)")
    parser.add_argument('-dg', '--diag', action="store_true", dest='diag', help="show where the cycle time goes: fping wall time per retry group plus dns/state/build/wait/draw")
    parser.add_argument('-fw', '--flap_window', default=str(FLAP_WINDOW_DEF), dest='flap_window', help="minutes since the last state change for a host to count as flapping (default: " + str(FLAP_WINDOW_DEF) + ")")
    parser.add_argument('-cf', '--confirm', default=str(CONFIRM_DEF), dest='confirm', help="consecutive DOWN observations before a host leaves UP (default: " + str(CONFIRM_DEF) + ", 1 = report every single observation)")
    parser.add_argument('-ds', '--down_slices', default=str(DOWN_SLICES_DEF), dest='down_slices', help="spread the known DOWN hosts over N rounds (default: " + str(DOWN_SLICES_DEF) + ", 1 = probe all of them every round)")
    parser.add_argument('-fs', '--full_sweep', default=str(FULL_SWEEP_DEF), dest='full_sweep', help="every Nth run probes every host with full retries (default: " + str(FULL_SWEEP_DEF) + ", 0 = never)")
    parser.add_argument('-ncs', '--no_check_source', action="store_true", dest='no_check_source', help="do not pass --check-source to fping (only needed for hosts replying from a different address)")
    parser.add_argument('-web', '--web', action="store_true", dest='web', help="start the web gui instead of the terminal (CLI) output")
    parser.add_argument('-wv', '--web_view', action="store_true", dest='web_view', help="CLI mode plus a read-only web view on --port (browser shows the same data, no controls)")
    parser.add_argument('-port', '--port', default=str(WEB_DEFAULT_PORT), dest='web_port', help="http port for --web and --web_view (default: " + str(WEB_DEFAULT_PORT) + ")")
    parser.add_argument('-bind', '--bind', default=WEB_DEFAULT_BIND, dest='web_bind', help="bind address for --web and --web_view (default: " + WEB_DEFAULT_BIND + " = all interfaces)")

    # read arguments from command line
    args = parser.parse_args()
    backoff = args.backoff
    timeout = args.timeout
    retries = args.retries
    interval = args.interval
    use_check_source = not args.no_check_source

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
                hosts_list_ipv4.extend(get_ipv4_from_range(network_range[0], network_range[1], MAX_IPS_PER_RANGE))
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
                hosts_list_ipv4.extend(get_ipv4_from_cidr(cidr, CIDR_MIN_MASK, CIDR_MAX_MASK))
            except Exception as e:
                error_handler(f"CIDR error: {e}")

    # time_zone_range -24 to +24 check 
    try:
        tz = int(args.time_zone_adjust)
        if tz < -24 or tz > 24:
            error_handler("ERROR: -tz: must be between -24 and 24")
    except ValueError:
            error_handler("ERROR: -tz: must be between -24 and 24")

    # -p: fping processes per retry group, 'auto' = PROCS_PER_GROUP
    if args.num_of_threads == 'auto':
        _threads_auto = True
    else:
        _threads_auto = False
        try:
            threads = int(args.num_of_threads)
            if threads < 1 or threads > THREADS_MANUAL_MAX:
                error_handler("ERROR: -p: must be between 1 and " + str(THREADS_MANUAL_MAX))
        except ValueError:
                error_handler("ERROR: -p: must be between 1 and " + str(THREADS_MANUAL_MAX))
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

    # interval check (ms) - if set, must be 0-100 (0 = no pacing, needs privileges)
    if args.interval:
        try:
            iv = int(args.interval)
            if iv < 0 or iv > 100:
                error_handler("ERROR: -i: must be between 0 and 100 (ms)")
        except ValueError:
            error_handler("ERROR: -i: must be between 0 and 100 (ms)")

    # packet rate budget
    try:
        rate_pps = int(args.rate_pps)
        if rate_pps < MIN_RATE_PPS or rate_pps > MAX_RATE_PPS:
            error_handler("ERROR: --rate: must be between " + str(MIN_RATE_PPS) + " and " + str(MAX_RATE_PPS))
    except ValueError:
        error_handler("ERROR: --rate: must be between " + str(MIN_RATE_PPS) + " and " + str(MAX_RATE_PPS))

    # retries for hosts already known to be down (-1 disables the retry classes)
    try:
        down_retries = int(args.down_retries)
        if down_retries < -1 or down_retries > 5:
            error_handler("ERROR: --down_retries: must be between -1 and 5")
        if down_retries > int(args.retries):
            error_handler("ERROR: --down_retries must not be larger than --retries")
    except ValueError:
        error_handler("ERROR: --down_retries: must be between -1 and 5")
    if down_retries < 0:
        down_retries = None          # disabled - every host gets the full budget

    # flap window
    try:
        flap_window = int(args.flap_window)
        if flap_window < 1 or flap_window > 1440:
            error_handler("ERROR: --flap_window: must be between 1 and 1440 (minutes)")
    except ValueError:
        error_handler("ERROR: --flap_window: must be between 1 and 1440 (minutes)")

    # flap damping
    try:
        confirm = int(args.confirm)
        if confirm < 1 or confirm > 10:
            error_handler("ERROR: --confirm: must be between 1 and 10")
    except ValueError:
        error_handler("ERROR: --confirm: must be between 1 and 10")

    # down slices
    try:
        down_slices = int(args.down_slices)
        if down_slices < 1 or down_slices > 100:
            error_handler("ERROR: --down_slices: must be between 1 and 100")
    except ValueError:
        error_handler("ERROR: --down_slices: must be between 1 and 100")

    # full sweep interval
    try:
        full_sweep = int(args.full_sweep)
        if full_sweep < 0 or full_sweep > 100000:
            error_handler("ERROR: --full_sweep: must be between 0 and 100000")
    except ValueError:
        error_handler("ERROR: --full_sweep: must be between 0 and 100000")

    # dns cache ttl
    try:
        dns_ttl = int(args.dns_ttl)
        if dns_ttl < 0 or dns_ttl > 86400:
            error_handler("ERROR: --dns_ttl: must be between 0 and 86400")
    except ValueError:
        error_handler("ERROR: --dns_ttl: must be between 0 and 86400")

    # web gui port check (relevant with --web and --web_view)
    if args.web or args.web_view:
        try:
            web_port = int(args.web_port)
            if web_port < 1 or web_port > 65535:
                error_handler("ERROR: --port: must be between 1 and 65535")
        except ValueError:
            error_handler("ERROR: --port: must be between 1 and 65535")

    # create sample file if not exists and no special file is given
    if not args.disable_hostfile and (args.hostfile == default_hostfile):
        data = ["# eping hosts - IPs, hostnames and CIDR networks, '#' starts a comment\n",
                "# a network is expanded to every address in it, e.g.: 192.168.99.0/29\n",
                "127.0.0.1\n", "no-dns.test 1.1.1.1 1.0.0.1 208.67.222.222 \n", "208.67.220.220 \n","www.google.com\n", "localhost 8.8.8.8 8.8.4.4\n", "ö3.at www.orf.at www.jeitler.guru\n" ]
        try:
            create_file_if_not_exists(default_hostfile,data)
        except TypeError as error_msg:
            error_handler(error_msg)
    
    # get ip's, networks, hostname's and fqdn's from file - same parser as the web
    # upload and [F]=ADD FILE, so all three understand CIDR networks and comments
    if not args.disable_hostfile:
        try:
            with open(args.hostfile, 'r', encoding='utf-8', errors='replace') as f:
                hostfile_text = f.read()
        except Exception:
            error_handler('ERROR: Unable to open hosts file: ' + str(args.hostfile))
        hostfile_stats = {}
        for entry in parse_hosts_from_text(hostfile_text, hostfile_stats):
            if match_re(entry, ip_re):
                hosts_list_ipv4.append(entry)
            else:
                hosts_list_fqdn.append(entry)
        if hostfile_stats.get('skipped'):
            print('\n WARNING: ' + args.hostfile + ' - network(s) ignored, mask must be /'
                  + str(CIDR_MIN_MASK) + ' .. /' + str(CIDR_MAX_MASK) + ': '
                  + ', '.join(hostfile_stats['skipped'][:5]) + '\n')
            time.sleep(2)
        
    #remove duplicates from list 
    hosts_list_fqdn = list(set(hosts_list_fqdn))
    hosts_list_ipv4 = list(set(hosts_list_ipv4))
    #combine both lists 
    summary_hosts_list =[]
    summary_hosts_list.extend(hosts_list_ipv4) 
    summary_hosts_list.extend(hosts_list_fqdn)

    # hard cap on total host count
    if len(summary_hosts_list) > MAX_TOTAL_HOSTS:
        error_handler('ERROR: Host count ' + str(len(summary_hosts_list)) +
                      ' exceeds maximum of ' + str(MAX_TOTAL_HOSTS))

    # no hosts at all is fine - eping starts empty and hosts can be added later
    # (CLI: [A]=ADD HOST, web gui: ADD HOST / UPLOAD FILE)

    # processes and -i are derived per round and per retry group (tune_group),
    # so args.num_of_threads keeps its value ('auto' or the number the user asked for)

    run_counter = 1

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

    # =================================================================
    # WEB GUI MODE - no curses at all, everything runs headless
    # =================================================================
    if args.web:
        _update_available = bool(remote_version) and (remote_version > version)
        with web_lock:
            web_state['version'] = version
        def _web_sigint(sig, frame):
            print('\nTHX for using eping.py ')
            sys.exit(0)
        signal.signal(signal.SIGINT, _web_sigint)
        run_web_mode(list(summary_hosts_list), host_state, args, logfile_file_name,
                     _update_available, int(args.up_hosts_check), down_retries, full_sweep,
                     confirm, down_slices, flap_window)
        sys.exit(0)

    # =================================================================
    # CLI MODE (default) - unchanged behaviour
    # =================================================================
    if curses_supports_curs_set():
        curses.curs_set(0)
    else:
        # fallback: do nothing or log
        error_handler('ERROR: curs_set() is not supported by this terminal. Some terminal types (e.g. vt100) do not allow changing cursor visibility' )

    if args.web_view:
        shown_bind = '127.0.0.1' if args.web_bind in ('0.0.0.0', '') else args.web_bind
        print('\n read-only web view on http://' + shown_bind + ':' + str(args.web_port) + '\n')
        time.sleep(1.5)

    # stdscr = curses.initscr()
    screen = curses.initscr()
    # single key input without echo (needed for the [A]/[F]/[D] dialogs)
    try:
        curses.noecho()
        curses.cbreak()
    except curses.error:
        pass
    try:
        curses.set_escdelay(25)      # python 3.9+: make [ESC] react instantly
    except Exception:
        pass
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

    original_hosts_list = list(summary_hosts_list)
    active_hosts_list   = list(summary_hosts_list)

    # -up learning phase
    up_check_runs       = int(args.up_hosts_check)
    learning_done       = (up_check_runs == 0)
    up_seen             = set()

    def input_dialog(title, prompt):
        """Show a single line input dialog and return the entered string (may be empty)."""
        rows, cols = screen.getmaxyx()
        dialog_w    = min(70, max(20, cols - 4))
        dialog_h    = 7
        dialog_y    = max(0, rows // 2 - dialog_h // 2)
        dialog_x    = max(0, cols // 2 - dialog_w // 2)

        # draw dialog box
        curses.curs_set(1)
        screen.nodelay(False)
        for dy in range(dialog_h):
            screen_output(dialog_y + dy, dialog_x, ' ' * dialog_w, 1, 0)
        screen_output(dialog_y,     dialog_x, '┌' + '─' * (dialog_w - 2) + '┐', 1, 1)
        screen_output(dialog_y + 1, dialog_x, '│' + title.center(dialog_w - 2) + '│', 1, 1)
        screen_output(dialog_y + 2, dialog_x, '│' + '─' * (dialog_w - 2) + '│', 1, 0)
        screen_output(dialog_y + 3, dialog_x, '│' + prompt[:dialog_w - 2].ljust(dialog_w - 2) + '│', 1, 0)
        screen_output(dialog_y + 4, dialog_x, '│' + ' > '.ljust(dialog_w - 2) + '│', 1, 0)
        screen_output(dialog_y + 5, dialog_x, '│' + ' [ENTER]=confirm  [ESC]=cancel'.ljust(dialog_w - 2) + '│', 1, 0)
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
            view = input_str[-max_input:] if len(input_str) > max_input else input_str
            screen_output(input_y, input_x, (view + ' ' * max_input)[:max_input], 1, 1)
            screen.move(input_y, input_x + len(view))
            screen.refresh()
            ch = screen.getch()
            if ch in (10, 13):                     # ENTER = confirm
                break
            elif ch == 27:                         # ESC = cancel
                input_str = ''
                break
            elif ch in (curses.KEY_BACKSPACE, 127, 8):
                input_str = input_str[:-1]
            elif 32 <= ch <= 126 and len(input_str) < 255:
                input_str += chr(ch)

        curses.curs_set(0)
        screen.nodelay(True)
        screen.clear()
        return input_str.strip()

    def notice(text, color=3, seconds=1.4):
        """Show a short message box in the middle of the screen."""
        rows, cols = screen.getmaxyx()
        text  = ' ' + text + ' '
        box_w = min(len(text), max(10, cols - 4))
        box_x = max(0, (cols - box_w) // 2)
        box_y = max(0, rows // 2)
        screen_output(box_y - 1, box_x, '+' + '-' * (box_w - 2) + '+', color, 1)
        screen_output(box_y,     box_x, text[:box_w], color, 1)
        screen_output(box_y + 1, box_x, '+' + '-' * (box_w - 2) + '+', color, 1)
        screen.refresh()
        time.sleep(seconds)
        screen.clear()

    # non-blocking keyboard input - main thread only, no separate thread
    screen.nodelay(True)

    # precompute values used in hot loop
    tz_offset = int(args.time_zone_adjust)

    down_streak = {}
    last_draw_time = 0.0
    # False until the first round has produced something to look at; until then the
    # progress callback shows a 'please wait' box instead of an empty screen
    have_data      = False
    filter_mode    = 0
    sort_mode      = 0
    display_list   = []
    hosts_count_up = 0
    hosts_count_down = 0
    run_time       = '0.00'
    phase          = {}
    used_scan      = ''
    learning_phase = True
    update_available_cli = bool(remote_version) and (remote_version > version)

    # --web_view: read only browser view next to the terminal. The curses loop stays the
    # only driver - one process, one scan, two ways to look at it. Two separate eping
    # processes would mean two fping groups stealing each other's replies.
    if args.web_view:
        web_readonly = True
        with web_lock:
            web_state['version']  = version
            web_state['readonly'] = True
        start_web_server(args.web_bind, int(args.web_port))

    def web_sync(msg=''):
        if not args.web_view:
            return
        web_publish(display_list, run_counter, run_time, hosts_count_up, hosts_count_down,
                    filter_mode, learning_phase, run_counter, up_check_runs,
                    args.disable_logging, logfile_file_name, update_available_cli,
                    tz_offset, msg, used_scan, sort_mode)


    def rebuild_display():
        """Recompute the visible list straight from host_state - no ping needed.

        UP-ONLY, SET REFERENCE, DEL HOST and ZERO CHANGES are pure display operations,
        so they can take effect at once instead of after the next scan round.
        """
        global display_list, hosts_count_up, hosts_count_down
        display_list = build_display(active_hosts_list, host_state, sort_mode,
                                     tz_offset, flap_window)
        hosts_count_up   = sum(1 for e in display_list if 'UP' in e[1])
        hosts_count_down = len(display_list) - hosts_count_up

    def draw_screen():
        """Paint the whole screen from the data of the last completed round.

        Decoupled from the scan on purpose: it can be called any time, also while
        fping is still running, so a resize or a filter change shows immediately.
        """
        rows, cols = screen.getmaxyx()
        if remote_version and remote_version > version:
            screen_print_center_top('Update available - please visit https://www.jeitler.guru', 3)
        else:
            screen_print_center_top('eping.py version ' + version + ' by Ewald Jeitler', 1)

        screen_print_date_time(1)
        screen_print_horizonta_line('-', 1, 1)
        screen_print_horizonta_line('-', 1, 3)
        screen_print_horizonta_line('-', 1, rows - 2)

        # how many 64 column blocks fit on this terminal
        maxcols = 0
        colsoffset_header = 0
        while cols - 64 >= colsoffset_header:
            colsoffset_header += 64
            maxcols += 1

        top_offset    = 4
        bottom_offset = 3 if args.diag else 2   # --diag needs one extra line
        maxrows       = max(1, rows - (top_offset + bottom_offset))
        maxhosts      = maxrows * maxcols
        num_of_hosts  = len(display_list)

        # a header only belongs above a column that actually holds hosts - otherwise
        # switching to UP-ONLY would leave the headers of the emptied columns behind
        shown_hosts = min(num_of_hosts, maxhosts)
        used_cols   = max(1, min(maxcols, (shown_hosts + maxrows - 1) // maxrows))
        for ci in range(maxcols):
            if ci < used_cols:
                screen_output(2, ci * 64, '|      HOSTNAME/IP         |  U/D |   RTT   | CH-TIME  | CH NO ||', 1, 1)
            else:
                # the header is 65 chars wide: its closing '|' sits on the first
                # position of the next block, so blanking starts one to the right
                screen_output(2, ci * 64 + 1, ' ' * 64, 1, 0)

        if num_of_hosts == 0:
            nh_msg = ' NO HOSTS TO PING - PRESS [A] TO ADD A HOST '
            screen_output(max(4, rows // 2 - 1), max(0, (cols - len(nh_msg)) // 2), nh_msg, 3, 1)

        # column major layout. This used to be an iterative search costing
        # num_of_hosts/rows steps per host (731k iterations at 4109 hosts); it is
        # plain integer division, and rows beyond maxhosts were never drawn anyway.
        for linenr, o in enumerate(display_list):
            if linenr >= maxhosts:
                break
            output_linenr    = top_offset + linenr % maxrows
            output_coloffset = (linenr // maxrows) * 64

            hostname         = o[0]
            state            = o[1]
            rtt              = o[3]
            changes          = o[5]
            change_timestamp = o[6]
            try:
                change_timestamp = (str(change_timestamp)).split(' ')[1]
            except: pass

            output_hostname = ('%.25s' % hostname)
            output_rtt      = '{message: >8}'.format(message=rtt)
            output_changes  = '{message: >5}'.format(message=str(changes))

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

        # --- status bar and key bar ---
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
        if num_of_hosts > 0 and maxhosts < num_of_hosts:
            tts_text = ' | TERMINAL TOO SMALL '
            screen_output(rows - 1, cols - len(tts_text), tts_text, 3, 2)

        # key bar - four label sets so it still fits on narrow terminals. [U] and [O]
        # show the view and the order that are active right now.
        fm = FILTER_MODES[filter_mode]
        sm = SORT_MODES[sort_mode]
        keys_full  = [' [U]=' + fm[0] + ' ', ' [A]=ADD HOST ', ' [F]=ADD FILE ', ' [D]=DEL HOST ',
                      ' [S]=SET REFERENCE ', ' [O]=SORT ' + sm[0] + ' ', ' [Z]=ZERO CHANGES ',
                      ' [C]=CLEAR ALL ', ' [R]=SCREEN REFRESH ', ' [E]=EXIT ']
        keys_short = [' [U]=' + fm[1] + ' ', ' [A]=ADD ', ' [F]=FILE ', ' [D]=DEL ',
                      ' [S]=SET REF ', ' [O]=' + sm[1] + ' ', ' [Z]=ZERO ',
                      ' [C]=CLEAR ', ' [R]=REFRESH ', ' [E]=EXIT ']
        keys_tiny  = [' [U]' + fm[2] + ' ', ' [A]ADD ', ' [F]FILE ', ' [D]DEL ',
                      ' [S]REF ', ' [O]' + sm[1] + ' ', ' [Z]ZERO ',
                      ' [C]CLR ', ' [R]RFR ', ' [E]EXIT ']
        keys_micro = [' U ', ' A ', ' F ', ' D ', ' S ', ' O ', ' Z ', ' C ', ' R ', ' E ']
        for keys in (keys_full, keys_short, keys_tiny, keys_micro):
            if sum(len(k) for k in keys) + 2 <= cols:
                break
        key_col = 2
        for idx, label in enumerate(keys):
            highlight = (idx == 0 and filter_mode != 0) or (idx == 5 and sort_mode != 0)
            screen_output(rows - 2, key_col, label, 2 if highlight else 1, 1 if highlight else 0)
            key_col += len(label)

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

        if args.diag:
            grp = '  '.join('%s %d(-r %s,-i %dms) %.2fs' % g for g in phase.get('groups', []))
            diag = ('FPING %.2f [%s] || DNS %.2f STATE %.2f BUILD %.2f WAIT %.2f DRAW %.2f'
                    % (phase.get('ping', 0), grp, phase.get('dns', 0), phase.get('state', 0),
                       phase.get('build', 0), phase.get('wait', 0), last_draw_time))
            screen_output(rows - 3, 1, diag[:max(0, cols - 2)], 2, 1)

    def scan_box(elapsed, host_count):
        """Full screen 'please wait' box - shown whenever the screen was cleared."""
        rows, cols = screen.getmaxyx()
        lines = ['PLEASE WAIT',
                 'scanning ' + str(host_count) + ' hosts',
                 '%.1f sec' % elapsed]
        box_w = min(max(len(l) for l in lines) + 8, max(12, cols - 2))
        box_x = max(0, (cols - box_w) // 2)
        box_y = max(1, rows // 2 - len(lines) // 2 - 1)
        screen_output(box_y, box_x, '+' + '-' * (box_w - 2) + '+', 2, 1)
        for idx, text in enumerate(lines):
            screen_output(box_y + 1 + idx, box_x,
                          '|' + text.center(box_w - 2) + '|', 2, 1 if idx == 0 else 0)
        screen_output(box_y + 1 + len(lines), box_x, '+' + '-' * (box_w - 2) + '+', 2, 1)

    def scan_progress(elapsed):
        """Called while fping runs. Redraws, so the UI stays alive during a scan.

        Returns True to cut the round short - only for keys that change the host
        list. A resize or [R] just repaints, the measurement keeps running.
        """
        global last_rows, last_cols
        rows, cols = screen.getmaxyx()
        if (rows, cols) != (last_rows, last_cols):
            screen.clear()
            last_rows, last_cols = rows, cols
        if have_data:
            draw_screen()
        else:
            scan_box(elapsed, len(active_hosts_list))
        screen.refresh()
        k = screen.getch()
        if k == -1:
            return False
        # a terminal resize arrives through getch as KEY_RESIZE - repainting is
        # enough for it, no reason to discard a running measurement
        if k in (ord('r'), ord('R'), curses.KEY_RESIZE):
            screen.clear()
            return False
        curses.ungetch(k)          # handled at the top of the main loop
        return True

    # show something immediately instead of a black window
    screen_print_center_top('eping.py version ' + version + ' by Ewald Jeitler', 1)
    screen_print_horizonta_line('-', 1, 1)
    scan_box(0.0, len(active_hosts_list))
    screen.refresh()

    run_counter = 1
    while True:

        # --- keyboard: drain all buffered keys ---
        cmd = None
        while True:
            k = screen.getch()
            if k == -1:
                break
            if k == curses.KEY_RESIZE:
                screen.clear()          # geometry handled below, not a command
            elif k in (ord('u'), ord('U')):
                cmd = 'UP_ONLY'
            elif k in (ord('a'), ord('A')):
                cmd = 'ADD'
            elif k in (ord('f'), ord('F')):
                cmd = 'ADD_FILE'
            elif k in (ord('d'), ord('D')):
                cmd = 'DEL'
            elif k in (ord('s'), ord('S')):
                cmd = 'SET_REFERENCE'
            elif k in (ord('z'), ord('Z')):
                cmd = 'ZERO'
            elif k in (ord('o'), ord('O')):
                cmd = 'ORDER'
            elif k in (ord('c'), ord('C')):
                cmd = 'CLEAR'
            elif k in (ord('r'), ord('R')):
                cmd = 'SCREENREFRESH'
            elif k in (ord('e'), ord('E')):
                cmd = 'EXIT'
        if cmd == 'SET_REFERENCE':
            # the currently displayed host list becomes the new reference list
            original_hosts_list = list(active_hosts_list)
            filter_mode = 0            # active == reference, so no filter is active
            screen.clear()
        elif cmd == 'CLEAR':
            active_hosts_list   = []
            original_hosts_list = []
            host_state.clear()
            up_seen.clear()
            down_streak.clear()
            _dns_cache.clear()
            filter_mode = 0
            screen.clear()
        elif cmd == 'UP_ONLY':
            next_mode = (filter_mode + 1) % len(FILTER_MODES)
            next_list = filter_hosts(next_mode, original_hosts_list, host_state,
                                     tz_offset, flap_window)
            if next_list or next_mode == 0:
                filter_mode       = next_mode
                active_hosts_list = next_list
                screen.clear()
            else:
                notice('NO HOSTS MATCH ' + FILTER_MODES[next_mode][0], 3)
        elif cmd == 'ORDER':
            sort_mode = (sort_mode + 1) % len(SORT_MODES)
            screen.clear()
        elif cmd == 'ADD':
            value     = input_dialog(' ADD HOSTS ', ' Enter IP, hostname, CIDR or ip1-ip2:')
            if value:
                new_hosts = parse_host_input(value)
                if not new_hosts:
                    notice('INVALID HOST: ' + value, 3)
                else:
                    added, err = add_hosts_to(new_hosts, active_hosts_list, original_hosts_list)
                    if err:
                        notice(err.upper(), 3)
        elif cmd == 'ADD_FILE':
            value = input_dialog(' ADD HOSTS FROM FILE ', ' Enter path of the host file:')
            if value:
                new_hosts, err = load_hosts_file(value)
                if err:
                    notice(err.upper(), 3)
                else:
                    added, err = add_hosts_to(new_hosts, active_hosts_list, original_hosts_list)
                    if err:
                        notice(err.upper(), 3)
                    else:
                        notice('ADDED ' + str(added) + ' NEW HOST(S) OF ' + str(len(new_hosts)) + ' FOUND', 2)
        elif cmd == 'DEL':
            value = input_dialog(' DELETE HOSTS ', ' Enter IP, hostname, CIDR or ip1-ip2:')
            if value:
                del_hosts = parse_host_input(value)
                if not del_hosts:
                    notice('INVALID HOST: ' + value, 3)
                else:
                    removed = remove_hosts_from(del_hosts, active_hosts_list,
                                                original_hosts_list, host_state)
                    up_seen.difference_update(del_hosts)
                    for _h in del_hosts:
                        down_streak.pop(_h, None)
                    forget_names(del_hosts)
                    notice('REMOVED ' + str(removed) + ' HOST(S)', 2 if removed else 3)
        elif cmd == 'ZERO':
            # forget the change history, keep the current UP/DOWN state
            for _entry in host_state.values():
                _entry[5] = 0
                _entry[6] = ''
            notice('CHANGE COUNTERS RESET', 2)
        elif cmd == 'SCREENREFRESH':
            screen.clear()
        elif cmd == 'EXIT':
            curses.endwin()
            print('THX for using eping.py ')
            sys.exit(0)

        # a command only changes what is shown - repaint at once instead of making
        # the user wait for the next scan round to finish
        if cmd and have_data:
            rebuild_display()
            draw_screen()
            screen.refresh()
            web_sync()

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
                filter_mode = 1        # the learning phase leaves an UP-only view
                learning_phase = True
                # same as after a command: the list changed, repaint at once
                if have_data:
                    rebuild_display()
                    draw_screen()
                    screen.refresh()
        else:
            learning_phase = True

        # --- run fping ---
        time1 = datetime.datetime.now()
        # confirmed DOWN hosts get the reduced retry budget, unknown hosts do not.
        # every full_sweep-th run probes everything fully, so a slow host cannot get
        # stuck in DOWN just because its reply never fits into the shorter window.
        # --fs 0 means 'never sweep', not 'always sweep' - only down_retries = None
        # (i.e. --down_retries -1) disables the retry classes altogether
        sweep_now = (down_retries is None
                     or (full_sweep > 0 and (run_counter - 1) % full_sweep == 0))
        down_now  = None if sweep_now else set(
            h for h, e in host_state.items() if 'UP' not in e[1])

        fping_result_data_sorted, used_scan, used_split, phase = run_ping_round(
            active_hosts_list, args.num_of_threads, int(args.rate_pps),
            args.interval, int(args.dns_ttl), down_now, down_retries, scan_progress,
            run_counter - 1, down_slices)
        if not have_data:
            screen.clear()         # remove the 'please wait' box
            have_data = True

        # --- update state dict ---
        _t = time.time()
        update_host_state(host_state, fping_result_data_sorted, tz_offset,
                          learning_done, learning_phase, up_seen,
                          args.disable_logging, logfile_file_name,
                          confirm, down_streak)
        phase['state'] = time.time() - _t
        _t = time.time()

        # --- build display list (only active hosts, sorted) ---
        rebuild_display()
        phase['build'] = time.time() - _t

        # --- wait + key polling (keys are processed at the top of the main loop) ---
        _t = time.time()
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
        phase['wait'] = time.time() - _t

        time2    = datetime.datetime.now()
        run_time = format(float((time2 - time1).total_seconds()), ".2f")
        t_draw   = time.time()

        draw_screen()
        screen.refresh()
        last_draw_time = time.time() - t_draw
        web_sync()
        run_counter += 1
# THX – Wanna patch my brain? Drop your tweaks here: https://github.com/ewaldj/eping — you know how 😉