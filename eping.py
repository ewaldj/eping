#!/usr/bin/env python3

# - - - - - - - - - - - - - - - - - - - - - - - -
# eping.py by ewald@jeitler.cc 2024 https://www.jeitler.cc
# - - - - - - - - - - - - - - - - - - - - - - - -
# When I wrote this code, only god and
# I knew how it worked.
# Now, only god knows it!
# - - - - - - - - - - - - - - - - - - - - - - - -
VERSION = '4.11'
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
MAX_RATE_PPS       = 25000
# One fping process per retry group - and no more. Every raw ICMP socket receives a
# copy of every incoming ICMP packet and has to filter by id, so N concurrent fping
# processes give each of them N times the receive load. Measured on a /20 with 4109
# hosts: 9 processes reported 244 hosts UP, a single process reported 866 - roughly
# 70% of the reachable hosts were lost as false DOWN. Extra processes buy nothing
# either, because a scan round takes hosts/rate seconds no matter how it is split.
PROCS_PER_GROUP    = 1        # fping processes per retry group (accuracy over speed)
INTERVAL_MAX_MS    = 100      # upper bound for the auto-computed pacing interval (not -i itself, see -i validation)

# --- -B/-t/-re/-i/-w hard bounds (CLI validation and ADV OPTIONS, both use these) ---
BACKOFF_MIN        = 1.0      # fping -B exponential backoff factor; <1 would make retries faster, not slower
BACKOFF_MAX        = 2.0
TIMEOUT_MIN_MS     = 10       # fping -t initial per-target timeout
TIMEOUT_MAX_MS     = 5000
RETRIES_MAX        = 5        # fping -re retries per host
INTERVAL_ARG_MAX   = 250      # -i upper bound; -1 = auto (unset, use --rate), 0 = no pacing
WAITTIME_MAX       = 600      # -w upper bound (seconds)
DOWN_SLICES_MAX    = 20
FULL_SWEEP_MAX     = 50       # 0 = disabled (never sweep)
DNS_TTL_MAX        = 3600
DOWNLOAD_FILE_EXTS = ('.csv', '.txt', '.html')  # CHOOSE FILE picker - listed types
VIEW_FILE_EXTS     = ('.csv', '.txt')           # VIEW FILE FROM SERVER - listed types
VIEW_FILE_MAX_BYTES = 200 * 1024 * 1024  # rendered inline in one response - must fit in memory
RUNTIME_UNAVAILABLE = 'n/a'  # shown instead of a stale/misleading RUNTIME value - see
                             # run_background_pings(): background rounds during a dialog
                             # advance RUNS but never update RUNTIME, so the figure would
                             # otherwise look frozen/wrong right after the dialog closes
LOG_MAX_SIZE_MIN   = 10       # MB - lower bound once log rotation by size is enabled
LOG_MAX_SIZE_MAX   = 2500     # MB - upper bound; 0 = no limit (rotation disabled)
LOG_MAX_FILES_MAX  = 500      # 0 = unlimited kept eping-log_*.csv files
DNS_CACHE_TTL      = 300      # seconds a resolved hostname stays valid (0 = no caching)
DNS_FAIL_TTL       = 30       # negative cache: retry unresolvable names sooner
DNS_TTL_JITTER_LO  = 0.5      # effective TTL is randomized to lo..1.0 x the configured
                               # TTL (see resolve_name) - a big batch of hostnames
                               # resolved together (e.g. at startup) would otherwise all
                               # expire in the same round later, forcing a giant
                               # re-resolve burst through DNS_RESOLVERS threads at once
DNS_RESOLVERS      = 32       # parallel name lookups
DNS_PTR_TIMEOUT    = 3.0      # seconds per reverse-DNS lookup for [G] GET NAMES

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
# unstable' - it deliberately does not try to measure a change rate. Default is the
# allowed maximum (see -fw validation below) - flapping is opt-in via a shorter -fw,
# not something that kicks in unasked.
FLAP_WINDOW_MAX    = 72000     # minutes = 50 days - see -fw validation
FLAP_WINDOW_DEF    = FLAP_WINDOW_MAX

# [U] cycles through these views. A view is a pure display filter, evaluated live on
# every refresh (see view_hosts()): all hosts keep being pinged. Only SET REFERENCE
# drops the hosts that are not shown from the host list.
FILTER_MODES = [
    ('ALL HOSTS',   'ALL',   'ALL'),
    ('UP',          'UP',    'UP'),
    ('UP+FLAPPING', 'UP+FL', 'U+F'),
]

# web gui only: the view dropdown offers every combination filter_hosts() supports,
# not just the 3 the CLI's [U] key cycles through - see WEB_VIEW_MODES below.
# indices 0-2 (ALL HOSTS/UP/UP+FLAPPING) match FILTER_MODES exactly - required so
# the CLI's [U] key and its web keyboard-shortcut equivalent keep working when they
# land on one of these three via the shared filter_mode int. Indices 3-8 are the
# web-only views, reachable only through the dropdown (set_filter).
WEB_VIEW_MODES = FILTER_MODES + [
    ('ALWAYS-UP',      'A-UP',  'AUP'),
    ('FLAPPING-ONLY',  'FLAP',  'FLP'),
    ('ALWAYS-DOWN',    'A-DWN', 'ADN'),
    ('DOWN',           'DOWN',  'DWN'),
    ('DOWN+FLAPPING',  'DN+FL', 'D+F'),
    ('NO-DNS',         'NODNS', 'NDN'),
]
# EVER-UP (former mode 9) was removed - redundant with UP+FLAPPING (mode 2), see
# epinga.py's same removal for the identical reasoning.

# [U] view picker (curses) shows WEB_VIEW_MODES in the same order as the web
# gui's <select id="selFilter"> dropdown - NOT WEB_VIEW_MODES' own index order.
# Each entry is a WEB_VIEW_MODES index; see filter_hosts() for what each mode does.
VIEW_PICKER_ORDER = [0, 1, 3, 2, 4, 5, 6, 7, 8]

# web gui only: unifies the previously independent PREFER HOSTNAME / IP ONLY
# toggles into one mutually-exclusive dropdown (see the 'addr_mode' web command).
# 0/1/2 are non-destructive display filters (recomputed from original_hosts_list
# each time); 3 renames hosts to their address in place (apply_ip_only_on/off).
ADDR_MODE_LABELS = ['hostname & ip', 'prefer hostname', 'prefer ip address', 'ip only']

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
import array
import collections
import sys
import html
import csv
import io
import glob
import math
import random
import time
try:
    import curses
except ImportError:         # Windows: no curses - web modes only
    curses = None
import signal
import shutil
import argparse
import ipaddress
import subprocess
import json
import threading
import datetime
try:
    import resource
except ImportError:         # Windows: no RLIMIT_NOFILE
    resource = None
import http.server
import socketserver
import heapq
import contextlib
import urllib.parse
import zipfile
import gzip
import socket
import shlex
import getpass
import tempfile
import atexit
import concurrent.futures
import urllib.request
import urllib.error
import tempfile

# --- host/network regexes (IPv4 only - IPv6 is handled via ipaddress, see is_ip_host) ---
_OCTET = r'(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])'
ip_re        = re.compile(r'^(?:' + _OCTET + r'\.){3}' + _OCTET + r'$')
cidr_ipv4_re = re.compile(r'^(?:' + _OCTET + r'\.){3}' + _OCTET + r'(?:\/(?:3[0-2]|[1-2][0-9]|[0-9]))$')
# hostname/FQDN: 1..253 chars, labels 1..63 of [A-Za-z0-9-] (umlauts tolerated), no
# leading/trailing '-'. An all-numeric dotted string (e.g. 999.1.1.1, a malformed
# IPv4) is rejected so it cannot slip through as a "hostname".
_LABEL  = r'(?!-)[a-zA-Z0-9\-äöüÄÖÜ]{1,63}(?<!-)'
fqdn_re = re.compile(r'(?=^.{1,253}$)(?!^[0-9.]+$)^' + _LABEL + r'(?:\.' + _LABEL + r')*\.?$')

# --- fping tuning values (module-level so build_fping_cmd() works when imported;
#     overwritten from the CLI args in main and by apply_adv_option()) ---
backoff  = '1.5'
timeout  = '250'
retries  = '3'
interval = ''

def version_tuple(v):
    """'3.36' -> (3, 36) for a correct numeric version comparison ('2.9' > '2.26'
    as strings is True, as tuples it is False). Non-numeric parts count as 0."""
    out = []
    for part in str(v or '').split('.'):
        try:
            out.append(int(part))
        except ValueError:
            out.append(0)
    return tuple(out)

def is_newer_version(remote, local):
    return bool(remote) and version_tuple(remote) > version_tuple(local)

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
    if resource is None:
        return
    try:
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        new_soft = min(target, hard) if hard != resource.RLIM_INFINITY else target
        if new_soft > soft:
            resource.setrlimit(resource.RLIMIT_NOFILE, (new_soft, hard))
    except Exception:
        # non-fatal: keep running with current soft limit
        pass


def check_version_online(url: str, tool_name: str, timeout: float = 2.0):
    """Return the version string listed for tool_name at url, or None on any error
    (network, proxy, decode, malformed line) - the check must never crash startup."""
    import ssl
    ctx = ssl._create_unverified_context()
    try:
        with urllib.request.urlopen(url, timeout=timeout, context=ctx) as response:
            content = response.read().decode('utf-8', 'replace')
            for line in content.splitlines():
                parts = line.split()
                if len(parts) >= 2 and parts[0] == tool_name:
                    return parts[1]
        return None
    except Exception:
        return None


def is_program_installed(program_name: str) -> bool:
    return shutil.which(program_name) is not None

_remote_version = None   # set by the top-level script code after the online version
                          # check - lets sigint_handler() (defined earlier in the file)
                          # show the same update notice as the normal [E] EXIT path
_logfile_file_name = None   # ditto, for maybe_run_epinga() - the actual logfile path
_logging_enabled = False    # ditto - args.disable_logging (True unless -dl was given)

def print_update_notice(remote_ver):
    """Printed once on CLI exit when a newer eping.py is available online."""
    print()
    print(f'  A new version of eping.py is available! (installed: v{VERSION}, latest: v{remote_ver})')
    print()
    print('  Install it with:')
    print('    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/ewaldj/eping/refs/heads/main/e-install.sh)"')
    print()
    print('  Or visit:')
    print('    https://www.jeitler.cc')
    print('    https://github.com/ewaldj/eping')
    print()

_epinga_prompt_active = False

def find_epinga_path():
    """Resolve epinga.py: prefer the copy next to eping.py, fall back to PATH.

    Returns the path, or None if not found either way.
    """
    local_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'epinga.py')
    if os.path.exists(local_path):
        return local_path
    return shutil.which('epinga.py')

def maybe_run_epinga(logfile_file_name, logging_enabled):
    """Offer to analyse the just-written logfile with epinga.py, on exit.

    Only offered if logging was on and the logfile actually exists and has
    content - running epinga.py on a missing/empty file would just fail.
    Enter (or anything but 'y') skips it, same as an empty input elsewhere.

    Reentrancy guard: a Ctrl+C while the input() prompt below is blocked
    triggers the installed SIGINT handler, which calls this function again
    to print the THX message and exit. Without the guard that nested call
    would hit input() a second time while the first call's readline state
    is still unwound, raising 'RuntimeError: can't re-enter readline'. The
    guard makes the nested call a no-op so the handler can exit cleanly.
    """
    global _epinga_prompt_active
    if _epinga_prompt_active:
        return
    if not logging_enabled or not logfile_file_name:
        return
    try:
        if not os.path.exists(logfile_file_name) or os.path.getsize(logfile_file_name) == 0:
            return
    except OSError:
        return
    _epinga_prompt_active = True
    try:
        answer = input('\n  Run an analysis of this logfile with epinga.py now? [y/N]: ').strip().lower()
    except (EOFError, KeyboardInterrupt):
        return
    finally:
        _epinga_prompt_active = False
    if answer != 'y':
        return
    epinga_path = find_epinga_path()
    if not epinga_path:
        print('  epinga.py not found next to eping.py or in PATH - skipping.')
        return
    try:
        subprocess.call([sys.executable, epinga_path, '-f', logfile_file_name])
    except Exception as e:
        print(f'  Failed to run epinga.py: {e}')

def error_handler(message, exit_code=1):
    """Print message and exit. Errors exit 1 (scriptable); pass exit_code=0 for a
    normal, informational exit."""
    print('\n ' + str(message) + '\n')
    sys.exit(exit_code)

def match_re(word,name_re):
    m = name_re.match(word)
    if m:
        return m.group(0)

def is_ip_host(word):
    """True if word is a literal IPv4 or IPv6 address (any family) - unlike ip_re,
    which is IPv4-only and stays that way since it also backs CIDR/-r range parsing."""
    try:
        ipaddress.ip_address(word)
        return True
    except ValueError:
        return False

def normalize_ip(word):
    """Canonical/shortest text form of a literal IP - a no-op for IPv4, but an
    IPv6 address written in full (2001:4860:4860:0000:...:8888) is compressed
    (2001:4860:4860::8888) so the host list, CSV log, display and DNS cache all use
    one consistent, short spelling regardless of how it was entered (ADD HOST, host
    file, upload). Not an IP literal - returned unchanged."""
    try:
        return str(ipaddress.ip_address(word))
    except ValueError:
        return word

def ip_version_str(word):
    """'4' or '6' for a literal IP string, else None. Only meaningful on already
    resolved targets (see prepare_targets) - fping needs to know which binary flag
    (-4/-6) to use since it cannot mix families in one invocation."""
    try:
        return str(ipaddress.ip_address(word).version)
    except ValueError:
        return None

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

def expand_range_end(start_ip, end_fragment):
    """Fill in a shortened -r range end using the start address's leading octets.

    A full address (4 octets) is returned unchanged. 1-3 octets borrow that many
    leading octets from start_ip instead, e.g. start '172.19.0.0' + end '1.13' ->
    '172.19.1.13'; start '172.20.2.0' + end '15' -> '172.20.2.15'.
    """
    end_parts = end_fragment.split('.')
    if len(end_parts) == 4:
        return end_fragment
    if not (1 <= len(end_parts) <= 3):
        raise TypeError("ERROR: Not a valid range end: '" + end_fragment
                        + "' (expected a full IPv4 address, or its last 1-3 octets)")
    start_parts = start_ip.split('.')
    if len(start_parts) != 4:
        raise TypeError('ERROR: Not a valid start IPv4 address: ' + start_ip)
    return '.'.join(start_parts[:4 - len(end_parts)] + end_parts)


def parse_ranges_arg(value, max_ip_per_range):
    """Parse a -r value: one or more comma-separated 'start-end' ranges.

    'end' may be abbreviated to its last 1-3 octets, borrowed from 'start' - see
    expand_range_end(). Blanks around commas/dashes are tolerated. Returns the
    combined list of expanded IPv4 address strings.
    """
    hosts = []
    for chunk in (value or '').split(','):
        chunk = chunk.strip()
        if not chunk:
            continue
        if '-' not in chunk:
            raise TypeError("ERROR: Range '" + chunk
                            + "' must be start-end, e.g. 10.0.0.1-10.0.0.10")
        start_str, end_str = chunk.split('-', 1)
        start_str = start_str.strip()
        end_str   = end_str.strip()
        if not match_re(start_str, ip_re):
            raise TypeError('ERROR: Not a valid start IPv4 address: ' + start_str)
        end_full = expand_range_end(start_str, end_str)
        hosts.extend(get_ipv4_from_range(start_str, end_full, max_ip_per_range))
    return hosts


def parse_cidrs_arg(value, min_mask, max_mask):
    """Parse a -n value: one or more comma-separated CIDR networks."""
    hosts = []
    for chunk in (value or '').split(','):
        chunk = chunk.strip()
        if chunk:
            hosts.extend(get_ipv4_from_cidr(chunk, min_mask, max_mask))
    return hosts

def split_hostfile_list(value):
    """Split a -f value into individual file paths - comma and/or whitespace
    separated (e.g. 'a.txt,b.txt', 'a.txt b.txt' or a mix), empty parts dropped."""
    return [p for p in re.split(r'[,\s]+', (value or '').strip()) if p]

SAMPLE_CSV_INFO = ('INFO: File eping-hosts-sample.csv created - a template for an inventory .csv\n'
                   '      (same hosts, invented Model/Location/sysLocation/Type/Comment values).\n'
                   '      Use it with: -f eping-hosts-sample.csv - it is NOT loaded now.')
INFO_DELAY = 6   # seconds the start-up INFO stays readable

def create_file_if_not_exists(filename, data, extra=''):
    """Create a sample file; extra = more INFO text shown with the same message."""
    if os.path.exists(filename):
        return
    print('\n\nINFO: File ' + filename + ' does not exist - creating sample file.'
          + ('\n' + extra if extra else '') + '\n\n')
    time.sleep(INFO_DELAY)
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            f.writelines(data)
    except OSError as e:
        raise TypeError('ERROR: Unable to create file: ' + filename + ' (' + str(e) + ')')

SAMPLE_CSV_NAME = 'eping-hosts-sample.csv'

def create_sample_csv(filename=SAMPLE_CSV_NAME):
    """Write an inventory sample .csv (same hosts as the default eping-hosts.txt, invented
    values) unless it exists. Never loaded by eping - only a template for ADV FILTER.
    Returns True if it was created."""
    if os.path.exists(filename):
        return False
    rows = [
        # hostname, ip, serial, model, location, sysLocation, type, comment
        ('', '127.0.0.1', 'SN0001', 'Loopback', 'Vienna DC', 'Rack A1', 'Server', ''),
        ('no-dns.test', '1.1.1.1', 'SN0002', 'C9300-48P', 'Vienna DC', 'Rack A2', 'Switch', 'no DNS entry'),
        ('', '1.0.0.1', 'SN0003', 'C9300-24T', 'Graz HQ', 'Rack B1', 'Switch', ''),
        ('', '208.67.222.222', 'SN0004', 'FPR-2130', 'Graz HQ', 'Rack B2', 'Firewall', ''),
        ('', '208.67.220.220', 'SN0005', 'FPR-2130', 'Graz HQ', 'Rack B2', 'Firewall', 'standby'),
        ('www.heise.de', '193.99.144.85', 'SN0006', 'ASR1001-X', 'Munich DC', 'Room 3', 'Router', ''),
        ('www.google.com', '', 'SN0007', 'F5-i5800', 'Munich DC', 'Room 3', 'Load Balancer', ''),
        ('localhost', '8.8.8.8', 'SN0008', 'C9120AXI-E', 'Linz Office', 'Floor 2', 'Access Point', 'under maintenance'),
        ('', '8.8.4.4', 'SN0009', 'C9120AXI-E', 'Linz Office', 'Floor 3', 'Access Point', ''),
        ('ö3.at', '', 'SN0010', 'PowerEdge R650', 'Vienna DC', 'Rack A3', 'Server', ''),
        ('www.orf.at', '', 'SN0011', 'PowerEdge R650', 'Vienna DC', 'Rack A3', 'Server', ''),
        ('', '::1', 'SN0012', 'Loopback', 'Vienna DC', 'Rack A1', 'Server', ''),
        ('ipv4.jeitler.cc', '', 'SN0013', 'C9500-24Y4C', 'Salzburg Office', 'Lobby', 'Switch', ''),
        ('ipv6.jeitler.cc', '', 'SN0014', 'C9500-24Y4C', 'Salzburg Office', 'Lobby', 'Switch', ''),
        ('www.jeitler.cc', '', 'SN0015', 'N9K-C93180YC-FX', 'Innsbruck Branch', 'Rack C1', 'Switch', ''),
        ('', '2603:c020:8016:1313::10', 'SN0016', 'ISR4331', 'Innsbruck Branch', 'Rack C1', 'Router', ''),
    ]
    try:
        with open(filename, 'w', encoding='utf-8', newline='') as f:
            w = csv.writer(f, delimiter=';')
            w.writerow(INVENTORY_CSV_HEADER)
            w.writerows(rows)
        return True
    except OSError:
        return False        # a read-only directory must not stop eping

use_check_source = True   # set from --no_check_source in main
csv_ip_fallback  = True   # set from --no_csv_fallback in main: a CSV hostname that does not resolve is pinged by its CSV IP
_csv_fb_names    = frozenset()  # hostnames pinged by their CSV IP in the last round (host popup)
web_readonly     = False  # True with --web_view: the CLI drives, the browser only looks

# ---- SSH source: fping runs on a jump host, results come back over ssh ----
# Set with -ssh at startup or at runtime with the JUMPHOST window (web gui / [J]).
# System ssh only. The secret (password / key passphrase) lives in memory and reaches
# ssh through SSH_ASKPASS; with ControlMaster (not on Windows) one connection carries
# all fping runs. Local DNS is not used: the jump host resolves the names. A source
# switch is queued and applied at the start of the next round (ssh_apply_pending).
SSH_MAX_PROCS   = 4       # parallel fping runs per round (sshd MaxSessions is 10 per connection)
SSH_MAX_PROCS_NT = 2      # Windows OpenSSH has no ControlMaster: every run is its own connection
SSH_REMOTE_PATH = '/usr/sbin:/sbin:/usr/local/bin:/usr/local/sbin'   # fping often lives in sbin
SSH_TEST_TIMEOUT = 40
SSH_HOSTKEY_MODES = ('accept-new', 'ask', 'off')   # unknown host key: confirm / trust new hosts / no check at all
ssh_cfg    = None         # active SshCfg; None = local fping
ssh_target = None         # ssh_cfg.target, None = local (quick test used all over)
SOURCE_LABEL = 'local'    # log column SOURCE
_remote_help = ''         # 'fping -h' of the jump host (capability probe)
_source_fail_reason = ''  # set by a failed ssh run during the current round
_source_down  = False
_source_alert = ''         # visible error text while the ssh source is down
_source_events = []       # pending comment texts (JUMPHOST OFFLINE / ONLINE, SOURCE SWITCH), written by update_host_state()
_ssh_pending  = None      # None = no change, False = switch to local, SshCfg = switch to it
_ssh_lock     = threading.Lock()
_ssh_cfgs     = []        # every SshCfg that owns a temp dir (cleaned at exit)
_jump_last    = {'host': '', 'port': '', 'user': '', 'key': '', 'hostkey': 'accept-new', 'resolve': True}   # form values of the last try (never the secret)
_jump_hostkeys = {}       # (host, port) -> hashed known_hosts lines offered by TRUST KEY

# Name resolution on the jump host: with a working resolver tool there (getent, dig,
# nslookup or host - found and probed by ssh_check) the DNS lookups that eping does
# itself (GET NAMES, PREFER HOSTNAME / IP ADDRESS, IP ONLY) run there, over the same ssh
# connection, instead of on this computer. Results are cached per source.
JR_TOOLS = ('getent', 'dig', 'nslookup', 'host')   # in order of preference
JR_CHUNK = 400                                      # names per ssh call
_jr_fwd = {}                  # name -> (ips, expires_at)
_jr_rev = {}                  # ip -> (name or None, expires_at)
_jr_cache_lock = threading.Lock()
_jr_run_lock   = threading.Lock()      # one remote lookup batch at a time

class SshCfg(object):
    """One jump host: where, how to log in, and its private temp dir (ControlPath + askpass)."""
    def __init__(self, host, user=None, port=None, key=None, secret='', hostkey='accept-new', resolve=True):
        self.host, self.user, self.port = host, (user or None), (port or None)
        self.resolve = bool(resolve)     # wish: resolve names on the jump host
        self.resolver = ''               # tool that works there ('' = none / not checked)
        self.hostkey = hostkey if hostkey in SSH_HOSTKEY_MODES else 'accept-new'
        self.key = os.path.expanduser(key) if key else None
        self.secret = secret or ''
        self.target = (self.user + '@' if self.user else '') + host
        self.label = self.target + (':' + str(self.port) if self.port else '')
        self.dir = None
        self.help = ''
        self.version = ''

    def prepare(self):
        if self.dir:
            return
        self.dir = tempfile.mkdtemp(prefix='eping-ssh-', dir=('/tmp' if os.name != 'nt' else None))
        _ssh_cfgs.append(self)
        if self.secret:
            if os.name == 'nt':
                name, body = 'askpass.cmd', '@echo off\r\necho %EPING_SSHPW%\r\n'
            else:
                name, body = 'askpass.sh', ('#!/bin/sh\ncase "$1" in *yes/no*|*ingerprint*) exit 1;; esac\n'
                                            'printf \'%s\\n\' "$EPING_SSHPW"\n')
            hp = os.path.join(self.dir, name)
            with open(hp, 'w') as f:
                f.write(body)
            os.chmod(hp, 0o700)

    def close(self):
        d, self.dir = self.dir, None
        if self in _ssh_cfgs:
            _ssh_cfgs.remove(self)
        if not d:
            return
        try:
            if os.name != 'nt':
                subprocess.run(['ssh', '-o', 'ControlPath=' + os.path.join(d, 'c-%C'), '-O', 'exit']
                               + (['-p', str(self.port)] if self.port else []) + [self.target],
                               stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, timeout=5)
        except Exception:
            pass
        shutil.rmtree(d, ignore_errors=True)

def ssh_shutdown():
    """Close every connection and remove all temp dirs (exit paths)."""
    for c in list(_ssh_cfgs):
        c.close()

def ssh_parse_target(value):
    """'user@host[:port]' / 'host' / 'user@[v6addr]:port' -> (user, host, port) or None."""
    m = re.match(r'^(?:([A-Za-z0-9._][A-Za-z0-9._-]*)@)?(\[[0-9a-fA-F:.]+\]|[A-Za-z0-9._][A-Za-z0-9._-]*)'
                 r'(?::(\d{1,5}))?$', (value or '').strip())
    if not m:
        return None
    user, host, port = m.groups()
    port = int(port) if port else None
    if port is not None and not (1 <= port <= 65535):
        return None
    return user, host.strip('[]'), port

def ssh_prereq():
    """Is an OpenSSH client available? {'ok', 'version', 'keyscan', 'hint'}"""
    if not shutil.which('ssh'):
        if sys.platform.startswith('win'):
            hint = "OpenSSH client not found. Windows: Settings > Apps > Optional features > add 'OpenSSH Client'."
        elif sys.platform == 'darwin':
            hint = "OpenSSH client not found (/usr/bin/ssh ships with macOS - check PATH)."
        else:
            hint = "OpenSSH client not found. Install it, e.g. 'sudo apt install openssh-client'."
        return {'ok': False, 'version': '', 'keyscan': False, 'hint': hint}
    ver = ''
    try:
        p = subprocess.run(['ssh', '-V'], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, encoding='utf-8', errors='replace', timeout=5)
        ver = (p.stdout or '').strip().splitlines()[0] if (p.stdout or '').strip() else ''
    except Exception:
        pass
    return {'ok': True, 'version': ver, 'keyscan': bool(shutil.which('ssh-keyscan')), 'hint': ''}

def ssh_base(c):
    """ssh command prefix (options only, no destination) for jump host c."""
    cmd = ['ssh', '-T', '-o', 'ConnectTimeout=10', '-o', 'ServerAliveInterval=10',
           '-o', 'ServerAliveCountMax=3', '-o', 'LogLevel=ERROR']
    if c.hostkey == 'off':           # no host key check, nothing stored (insecure)
        cmd += ['-o', 'StrictHostKeyChecking=no', '-o', 'UserKnownHostsFile=' + ('NUL' if os.name == 'nt' else '/dev/null')]
    elif c.hostkey == 'accept-new':  # trust hosts seen for the first time, still refuse a changed key
        cmd += ['-o', 'StrictHostKeyChecking=accept-new']
    else:
        cmd += ['-o', 'StrictHostKeyChecking=yes']
    if c.secret:
        cmd += ['-o', 'NumberOfPasswordPrompts=1']
    else:
        cmd += ['-o', 'BatchMode=yes']
    if c.key:
        cmd += ['-i', c.key, '-o', 'IdentitiesOnly=yes']
    if c.port:
        cmd += ['-p', str(c.port)]
    if os.name != 'nt' and c.dir:
        cmd += ['-o', 'ControlMaster=auto', '-o', 'ControlPath=' + os.path.join(c.dir, 'c-%C'),
                '-o', 'ControlPersist=30']
    return cmd

def ssh_env(c):
    env = os.environ.copy()
    if c is not None and c.secret and c.dir:
        env['SSH_ASKPASS'] = os.path.join(c.dir, 'askpass.cmd' if os.name == 'nt' else 'askpass.sh')
        env['SSH_ASKPASS_REQUIRE'] = 'force'
        env.setdefault('DISPLAY', 'eping:0')       # OpenSSH < 8.4 only uses askpass with DISPLAY set
        env['EPING_SSHPW'] = c.secret
    return env

def ssh_wrap(argv, c=None):
    """Full local command that runs argv on the jump host (targets via stdin)."""
    c = c or ssh_cfg
    inner = 'PATH="$PATH:%s"; export PATH; exec %s' % (
        SSH_REMOTE_PATH, ' '.join(shlex.quote(a) for a in argv))
    return ssh_base(c) + [c.target, 'sh -c ' + shlex.quote(inner)]

def ssh_exec(c, script, timeout=SSH_TEST_TIMEOUT, stdin_text=None):
    """Run a /bin/sh script on jump host c (optionally feeding stdin_text). Returns (returncode, output)."""
    inner = 'PATH="$PATH:%s"; export PATH\n%s' % (SSH_REMOTE_PATH, script)
    kw = {'input': stdin_text} if stdin_text is not None else {'stdin': subprocess.DEVNULL}
    try:
        p = subprocess.run(ssh_base(c) + [c.target, 'sh -c ' + shlex.quote(inner)],
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           encoding='utf-8', errors='replace', timeout=timeout, env=ssh_env(c), **kw)
        return p.returncode, p.stdout or ''
    except FileNotFoundError:
        return 255, 'ssh command not found'
    except subprocess.TimeoutExpired:
        return 255, 'ssh timeout'

_SSH_CHECK = r'''RES=""; for t in getent dig nslookup host; do command -v $t >/dev/null 2>&1 && { RES=$t; break; }; done
echo "EPING_RESOLVER=$RES"
command -v fping >/dev/null 2>&1 || { echo EPING_NOFPING; exit 0; }
echo "EPING_VERSION=$(fping -v 2>&1 | head -1)"
out=$(fping -4 -c1 -t500 127.0.0.1 2>&1); echo "EPING_RC=$?"; echo "EPING_OUT=$out"
echo EPING_HELP_BEGIN; fping -h 2>&1; echo EPING_HELP_END'''

# One lookup per input line, up to 16 in parallel (xargs -P). The body must not contain
# single quotes: it is wrapped into sh -c '...'. Result line: "<input> <answers...>".
_JR_FWD = {
    'getent':   r'r=$(getent ahosts "$0" 2>/dev/null | awk "{print \$1}" | sort -u | tr "\n" " ")',
    'dig':      r'r=$( (dig +short +time=3 +tries=1 A "$0"; dig +short +time=3 +tries=1 AAAA "$0") 2>/dev/null | grep -E "^[0-9a-fA-F:.]+\$" | sort -u | tr "\n" " ")',
    'nslookup': r'r=$(nslookup -timeout=3 "$0" 2>/dev/null | awk "/^Name:/{f=1} f&&/^Address/{print \$NF}" | sort -u | tr "\n" " ")',
    'host':     r'r=$(host -W 3 "$0" 2>/dev/null | awk "/has address|has IPv6 address/{print \$NF}" | sort -u | tr "\n" " ")',
}
_JR_REV = {
    'getent':   r'r=$(getent hosts "$0" 2>/dev/null | awk "NR==1{print \$2}")',
    'dig':      r'r=$(dig +short +time=3 +tries=1 -x "$0" 2>/dev/null | head -1)',
    'nslookup': r'r=$(nslookup -timeout=3 "$0" 2>/dev/null | awk "/name = /{print \$NF; exit}")',
    'host':     r'r=$(host -W 3 "$0" 2>/dev/null | awk "/domain name pointer/{print \$NF; exit}")',
}

def _jr_run(mode, items, c):
    """Look up items ('fwd': names -> addresses, 'rev': addresses -> name) on jump host c
    with its resolver tool. Returns {item: [answer tokens]}; items of a failed batch are
    missing. Input is validated (no shell metacharacters) and goes in via stdin."""
    body = (_JR_FWD if mode == 'fwd' else _JR_REV)[c.resolver]
    script = ('XP=-P16; echo x | xargs -P16 -n1 true >/dev/null 2>&1 || XP=""\n'
              "xargs -n1 $XP sh -c '" + body + '; echo "$0 $r"' + "'")
    out = {}
    items = [i for i in items if re.match(r'^[A-Za-z0-9._:-]{1,253}$', i)]
    for k in range(0, len(items), JR_CHUNK):
        chunk = items[k:k + JR_CHUNK]
        rc, text = ssh_exec(c, script, timeout=30 + len(chunk) // 5, stdin_text='\n'.join(chunk) + '\n')
        if rc != 0:
            continue
        for line in text.splitlines():
            parts = line.split()
            if parts and parts[0] in chunk:
                out[parts[0]] = parts[1:]
    return out

def jr_active():
    """True if lookups go to the jump host (ssh source, enabled, working resolver)."""
    c = ssh_cfg
    return bool(c is not None and c.resolve and c.resolver)

def _jr_ttl():
    try:
        return max(30.0, float(getattr(globals().get('args'), 'dns_ttl', 300)))
    except Exception:
        return 300.0

def jr_forward(names):
    """{name: [addresses]} resolved on the jump host (cached, one ssh call for all
    uncached names). A name whose batch failed is missing in the result."""
    c = ssh_cfg
    if not jr_active():
        return {}
    now = time.time()
    res, todo = {}, []
    with _jr_cache_lock:
        for n in set(names):
            e = _jr_fwd.get(n)
            if e and e[1] > now:
                res[n] = e[0]
            else:
                todo.append(n)
    if todo:
        with _jr_run_lock:
            got = _jr_run('fwd', todo, c)
        now, ttl = time.time(), _jr_ttl()
        with _jr_cache_lock:
            for n in todo:
                if n not in got:
                    res[n] = []
                    _jr_fwd[n] = ([], now + DNS_FAIL_TTL)    # failed batch / bad name: retry later
                    continue
                ips = []
                for a in got[n]:
                    try:
                        ipaddress.ip_address(a)
                        ips.append(a)
                    except ValueError:
                        pass
                _jr_fwd[n] = (ips, now + (ttl if ips else min(ttl, DNS_FAIL_TTL)))
                res[n] = ips
    return res

def jr_reverse(ips):
    """{ip: hostname or None} (PTR) looked up on the jump host, cached."""
    c = ssh_cfg
    if not jr_active():
        return {}
    now = time.time()
    res, todo = {}, []
    with _jr_cache_lock:
        for i in set(ips):
            e = _jr_rev.get(i)
            if e and e[1] > now:
                res[i] = e[0]
            else:
                todo.append(i)
    if todo:
        with _jr_run_lock:
            got = _jr_run('rev', todo, c)
        now, ttl = time.time(), _jr_ttl()
        with _jr_cache_lock:
            for i in todo:
                if i in got:
                    nm = got[i][0].rstrip('.') if got[i] else None
                    _jr_rev[i] = (nm or None, now + (ttl if nm else min(ttl, DNS_FAIL_TTL)))
                    res[i] = nm or None
                else:
                    res[i] = None
                    _jr_rev[i] = (None, now + DNS_FAIL_TTL)
    return res

_ssh_fam6 = set()     # hostnames tried with fping -6 on the jump host (no resolver there, see below)

def ssh_name_family(name):
    """Address family ('4'/'6') used for the fping run of a hostname on the jump host.
    With a resolver there the names are looked up first (A preferred, AAAA if there is
    no A record - same rule as locally), so an IPv6-only name is pinged with -6.
    Without one, -4 is used and a name that fping reports as NO-DNS is tried with -6
    in the next round (and back to -4 if that fails too), see run_ping_round()."""
    if dns_family in ('4', '6'):
        return dns_family
    if jr_active():
        ips = resolve_all_ips(name)
        if ips:
            return ip_version_str(ips[0]) or '4'
        return '4'
    return '6' if name in _ssh_fam6 else '4'

def jr_prefetch(hosts):
    """Resolve all hostnames of 'hosts' on the jump host in one go (fills the cache, so
    the per-name lookups of the callers below do not each need an ssh call)."""
    if jr_active():
        jr_forward([h for h in hosts if not is_ip_host(h)])

def ssh_scan_hostkeys(c):
    """Fetch the jump host's keys (hashed known_hosts lines) and their fingerprints."""
    lines, fps = [], []
    try:
        p = subprocess.run(['ssh-keyscan', '-H', '-T', '5'] + (['-p', str(c.port)] if c.port else []) + [c.host],
                           stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                           encoding='utf-8', errors='replace', timeout=15)
        lines = [l for l in (p.stdout or '').splitlines() if l.strip() and not l.startswith('#')]
        for l in lines:
            q = subprocess.run(['ssh-keygen', '-lf', '-'], input=l + '\n', stdout=subprocess.PIPE,
                               stderr=subprocess.DEVNULL, encoding='utf-8', errors='replace', timeout=5)
            m = re.search(r'(SHA256:\S+).*\((\w+)\)', q.stdout or '')
            if m:
                fps.append('%s %s' % (m.group(2), m.group(1)))
    except Exception:
        pass
    _jump_hostkeys[(c.host, c.port)] = lines
    return fps

def ssh_trust_hostkeys(host, port):
    """Append the keys that were shown to the user to ~/.ssh/known_hosts. Returns an error or ''."""
    lines = _jump_hostkeys.get((host, port)) or []
    if not lines:
        return 'no host key to trust - run TEST first'
    try:
        d = os.path.join(os.path.expanduser('~'), '.ssh')
        os.makedirs(d, mode=0o700, exist_ok=True)
        with open(os.path.join(d, 'known_hosts'), 'a') as f:
            f.write('\n'.join(lines) + '\n')
    except OSError as e:
        return 'cannot write known_hosts: ' + str(e)
    return ''

def ssh_check(c):
    """Verify jump host c: login, fping present and allowed to ping. Never raises/exits.
    Returns dict: ok, code (ok|nossh|hostkey|hostkey_changed|auth|conn|nofping|perm),
    error, version, help, fingerprints."""
    r = {'ok': False, 'code': '', 'error': '', 'version': '', 'help': '', 'fingerprints': []}
    pre = ssh_prereq()
    if not pre['ok']:
        r.update(code='nossh', error=pre['hint'])
        return r
    c.prepare()
    rc, out = ssh_exec(c, _SSH_CHECK)
    if rc == 255 and 'Host key verification failed' in out:
        if 'IDENTIFICATION HAS CHANGED' in out:
            r.update(code='hostkey_changed', error='The host key of %s CHANGED (possible attack). '
                     'Fix ~/.ssh/known_hosts only if you know why.' % c.host)
        else:
            r.update(code='hostkey', fingerprints=ssh_scan_hostkeys(c),
                     error='Host key of %s is not known yet - check the fingerprint and TRUST KEY.' % c.host)
        return r
    if 'EPING_NOFPING' in out:
        r.update(code='nofping', error='fping was not found on %s (searched PATH + %s). '
                 "Install it there, e.g. 'sudo apt install fping'." % (c.target, SSH_REMOTE_PATH))
        return r
    if 'EPING_RC=' not in out:
        why = out.strip().splitlines()[-1] if out.strip() else 'rc=' + str(rc)
        r.update(code=('auth' if 'Permission denied' in out else 'conn'),
                 error='connection to %s failed: %s' % (c.target, why))
        return r
    r['version'] = (re.search(r'EPING_VERSION=(.*)', out) or [None, '?'])[1].strip()
    code = (re.search(r'EPING_RC=(\d+)', out) or [None, '-1'])[1]
    if code != '0':
        detail = (re.search(r'EPING_OUT=(.*)', out) or [None, ''])[1].strip()
        r.update(code='perm', error='fping on %s does not work (%s; exit %s): %s - usually missing ICMP '
                 'permission: needs root, setuid/cap_net_raw, or net.ipv4.ping_group_range covering the user.'
                 % (c.target, r['version'], code, detail))
        return r
    m = re.search(r'EPING_HELP_BEGIN\n(.*)EPING_HELP_END', out, re.S)
    r.update(ok=True, code='ok', help=(m.group(1) if m else ''))
    c.help, c.version = r['help'], r['version']
    # resolver on the jump host: tool found by the check script, then a real lookup
    c.resolver = ''
    tool = (re.search(r'EPING_RESOLVER=(\w*)', out) or [None, ''])[1]
    if tool in JR_TOOLS:
        c.resolver = tool
        got = _jr_run('fwd', ['localhost'], c)
        if not any(a in ('127.0.0.1', '::1') for a in got.get('localhost', [])):
            c.resolver = ''
    r['resolver'] = c.resolver
    return r

def ssh_activate(c):
    """Make c the active source (c=None: local). Only called between rounds."""
    global ssh_cfg, ssh_target, SOURCE_LABEL, _remote_help, _fping_caps, _source_down, _source_alert
    old = ssh_cfg
    ssh_cfg, ssh_target = c, (c.target if c else None)
    SOURCE_LABEL = c.label if c else 'local'
    _remote_help = c.help if c else ''
    _fping_caps = None
    _source_down = False
    _source_alert = ''
    with _jr_cache_lock:
        _jr_fwd.clear()
        _jr_rev.clear()
    _ssh_fam6.clear()
    with _dns_lock:                      # lookups made for the old source do not apply
        _dns_cache.clear()
        _addr_redundancy_cache.clear()
    if old is not None and old is not c:
        old.close()

def ssh_request(c):
    """Queue a source switch (c = SshCfg, or False for local); applied at the next round."""
    global _ssh_pending
    with _ssh_lock:
        if isinstance(_ssh_pending, SshCfg) and _ssh_pending is not c:
            _ssh_pending.close()
        _ssh_pending = c

def ssh_apply_pending():
    """Start of every round: switch the source if one was requested."""
    global _ssh_pending
    with _ssh_lock:
        p, _ssh_pending = _ssh_pending, None
    if p is None:
        return
    old = SOURCE_LABEL
    ssh_activate(p if p is not False else None)
    _source_events.append((get_date_time(), 'SOURCE SWITCH %s -> %s' % (old, SOURCE_LABEL)))

def ssh_init(target, key, hostkey='accept-new', resolve=True):
    """-ssh at startup: ask for the secret, trust the host key (ssh's own prompt), verify
    that fping works on the jump host. Exits with a clear message on any problem."""
    parsed = ssh_parse_target(target)
    if not parsed:
        error_handler("ERROR: -ssh: expected [user@]host[:port] (IPv6: user@[addr]:port): " + str(target))
    pre = ssh_prereq()
    if not pre['ok']:
        error_handler("ERROR: -ssh: " + pre['hint'])
    user, host, port = parsed
    if key and not os.path.isfile(os.path.expanduser(key)):
        error_handler("ERROR: -sshkey: file not found: " + os.path.expanduser(key))
    secret = ''
    if sys.stdin.isatty():
        try:
            secret = getpass.getpass('SSH password / key passphrase for %s (ENTER = none, key or agent only): '
                                     % ((user + '@' if user else '') + host))
        except (EOFError, KeyboardInterrupt):
            error_handler("ERROR: -ssh: aborted")
    c = SshCfg(host, user, port, key, secret, hostkey, resolve)
    print('SSH source %s: connecting ...' % c.label)
    sys.stdout.flush()
    r = ssh_check(c)
    if r['code'] == 'hostkey':
        if not sys.stdin.isatty():
            error_handler("ERROR: -ssh: host key of %s is not known (run ssh %s once to trust it)" % (host, c.target))
        print('Host key of %s is not known yet - ssh asks for confirmation:' % host)
        sys.stdout.flush()
        env = os.environ.copy()
        env.pop('SSH_ASKPASS', None)
        subprocess.call(['ssh', '-o', 'StrictHostKeyChecking=ask', '-o', 'PreferredAuthentications=none',
                         '-o', 'ConnectTimeout=10'] + (['-p', str(port)] if port else [])
                        + [c.target, 'true'], env=env)
        r = ssh_check(c)
    if not r['ok']:
        c.close()
        error_handler("ERROR: -ssh: " + r['error'])
    ssh_activate(c)
    print('SSH source %s: OK (%s)' % (c.label, r['version']))
    print('Name resolution: ' + (('on the jump host (%s)' % c.resolver) if (c.resolve and c.resolver)
          else ('local (disabled by -sshnr)' if not c.resolve
                else 'local (no working getent/dig/nslookup/host on the jump host)')))
    sys.stdout.flush()

def jump_cfg_from(req):
    """JUMPHOST window fields (dict) -> (SshCfg, error)."""
    host = str(req.get('host', '')).strip()
    user = str(req.get('user', '')).strip()
    port = str(req.get('port', '')).strip()
    key  = str(req.get('key', '')).strip()
    secret = str(req.get('secret', ''))
    if not re.match(r'^[A-Za-z0-9._][A-Za-z0-9._:%-]*$', host):
        return None, 'host: enter a hostname or IP address'
    if user and not re.match(r'^[A-Za-z0-9._][A-Za-z0-9._-]*$', user):
        return None, 'user: invalid characters'
    if port and not (port.isdigit() and 1 <= int(port) <= 65535):
        return None, 'port: 1-65535'
    if key and not os.path.isfile(os.path.expanduser(key)):
        return None, 'key file not found: ' + key
    hk = str(req.get('hostkey', 'accept-new'))
    if hk not in SSH_HOSTKEY_MODES:
        hk = 'accept-new'
    resolve = str(req.get('resolve', True)).strip().lower() not in ('0', 'false', 'off', 'no')
    _jump_last.update(host=host, user=user, port=port, key=key, hostkey=hk, resolve=resolve)
    return SshCfg(host, user, int(port) if port else None, key, secret, hk, resolve), ''

def jump_info():
    return {'ssh': ssh_prereq(), 'active': SOURCE_LABEL if ssh_cfg else '', 'last': dict(_jump_last),
            'resolver': (ssh_cfg.resolver if (ssh_cfg and ssh_cfg.resolve) else ''),
            'pending': ('local' if _ssh_pending is False else (_ssh_pending.label if _ssh_pending else ''))}

def jump_handle(req):
    """JUMPHOST window actions (web gui). info | test | trust | connect | local."""
    act = str(req.get('action', 'info'))
    if act == 'info':
        return dict(ok=True, **jump_info())
    if act == 'local':
        ssh_request(False)
        return dict(ok=True, message='switching to local fping at the next round', **jump_info())
    c, err = jump_cfg_from(req)
    if c is None:
        return dict(ok=False, code='input', error=err)
    if act == 'trust':
        e = ssh_trust_hostkeys(c.host, c.port)
        return dict(ok=not e, code='trust', error=e, message='' if e else 'host key trusted - press TEST')
    r = ssh_check(c)
    note = ''
    if r['ok']:
        note = ('; names are resolved on the jump host (%s)' % c.resolver if (c.resolve and c.resolver)
                else ('; names are resolved locally (option off)' if not c.resolve
                      else '; names are resolved locally (no working getent/dig/nslookup/host there)'))
    if act == 'test' or not r['ok']:
        c.close()
        if r['ok']:
            r['message'] = 'OK - ' + (r['version'] or 'fping works') + note
        return r
    ssh_request(c)                               # connect
    r['message'] = 'connected to %s - switching at the next round%s' % (c.label, note)
    return r

def source_set(down, reason=''):
    """Track the SSH source state; a change queues one #INFO# log line."""
    global _source_down, _source_alert
    _source_alert = ('JUMPHOST %s OFFLINE - %s - reconnecting' % (SOURCE_LABEL, reason)) if down else ''
    if down != _source_down:
        _source_down = down
        # logged as a comment row (shown in epinga.py's comment timeline)
        _source_events.append((get_date_time(), ('JUMPHOST %s OFFLINE: %s' % (SOURCE_LABEL, reason)) if down
                              else ('JUMPHOST %s ONLINE again' % SOURCE_LABEL)))

_fping_caps = None
def fping_capabilities():
    """Probe 'fping -h' once and remember which optional flags this build supports."""
    global _fping_caps
    if _fping_caps is None:
        caps = set()
        try:
            if ssh_target:
                text = _remote_help
            else:
                p = subprocess.run(['fping', '-h'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                   encoding='utf-8', errors='replace', timeout=5)
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

dns_family = 'auto'   # '4'=force A only, '6'=force AAAA only, 'auto'=A first, AAAA fallback

def resolve_name(name, ttl):
    now = time.time()
    with _dns_lock:
        entry = _dns_cache.get(name)
        if entry and entry[1] > now:
            return entry[0]
    ip = None
    try:
        ips = resolve_all_ips(name)
        if ips:
            ip = ips[0]     # deterministic (lowest) pick when a name has several records
    except Exception:
        ip = None
    base_ttl = ttl if ip else min(ttl, DNS_FAIL_TTL)
    # jitter the effective TTL (DNS_TTL_JITTER_LO..1.0 x base_ttl) so a large batch
    # of names resolved together (e.g. thousands at startup) doesn't all expire in
    # the same later round - that would force prepare_targets() to re-resolve all
    # of them at once through the small DNS_RESOLVERS pool, stalling that round.
    # Spreading the expiries out keeps re-resolution work small and steady instead.
    expires_at = now + (random.uniform(DNS_TTL_JITTER_LO, 1.0) * base_ttl if base_ttl > 0 else 0)
    with _dns_lock:
        _dns_cache[name] = (ip, expires_at)
    return ip

def resolve_all_ips(name, family=None):
    """Every A/AAAA record for name, sorted numerically for a stable order.

    family: '4' or '6' sets which record type is preferred; None/omitted uses the
    global dns_family setting ('4', '6' or 'auto' - A first, AAAA only if no A
    record). -4/-6 pick a preference, not an exclusive restriction: if the preferred
    family has no record, the other family is used instead of failing outright - a
    name reachable only over the non-forced family still resolves and gets pinged.
    Uncached and used only where all addresses matter (prefer-hostname redundancy
    check) or once per name resolution - not hot enough to need caching here."""
    fam = family if family is not None else dns_family
    if jr_active():                       # the jump host's view of DNS
        ips = jr_forward([name]).get(name) or []
        v4, v6 = [], []
        for a in ips:
            ip = ipaddress.ip_address(a)
            if ip.version == 4:
                v4.append(a)
            elif not ip.ipv4_mapped:
                v6.append(a)
        key = lambda a: int(ipaddress.ip_address(a))
        for grp in ((v6, v4) if fam == '6' else (v4, v6)):
            if grp:
                return sorted(grp, key=key)
        return []
    af_list = {'4': [socket.AF_INET, socket.AF_INET6],
              '6': [socket.AF_INET6, socket.AF_INET]}.get(
        fam, [socket.AF_INET, socket.AF_INET6])
    for af in af_list:
        try:
            infos = socket.getaddrinfo(name, None, af, socket.SOCK_DGRAM)
            ips = set(i[4][0] for i in infos)
            if af == socket.AF_INET6:
                # some resolvers (macOS mDNSResponder, DNS64/NAT64 synthesis) return
                # an IPv4-mapped IPv6 address (::ffff:a.b.c.d) for an AAAA query
                # against a v4-only name instead of failing - that is not a real
                # AAAA record and is not a pingable native IPv6 destination (fping -6
                # on it just reports the host down), so treat it as no AAAA record
                # and let the loop fall through to plain IPv4 instead
                ips = set(ip for ip in ips if not ipaddress.ip_address(ip).ipv4_mapped)
            ips = sorted(ips, key=lambda a: int(ipaddress.ip_address(a)))
            if ips:
                return ips
        except Exception:
            continue
    return []

def forget_names(names):
    with _dns_lock:
        for n in names:
            _dns_cache.pop(n, None)

def _reverse_lookup_one(ip):
    try:
        name = socket.gethostbyaddr(ip)[0].rstrip('.')
        return name or None
    except Exception:
        return None

def get_names_for_ips(ip_list, timeout=DNS_PTR_TIMEOUT, workers=DNS_RESOLVERS):
    """Reverse-DNS a batch of IPs in parallel. Returns {ip: hostname_or_None}.

    socket.gethostbyaddr() has no per-call timeout, so the process-wide default is
    set for the duration of this batch and restored afterwards. The CLI/web loop is
    single-threaded around this call (called from cmd handling, before the next ping
    round starts), so there is no other thread relying on a different timeout while
    this runs."""
    if not ip_list:
        return {}
    if jr_active():                       # PTR lookups on the jump host
        got = jr_reverse(list(ip_list))
        return dict((ip, got.get(ip)) for ip in ip_list)
    old_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    results = {}
    try:
        with concurrent.futures.ThreadPoolExecutor(
                max_workers=max(1, min(workers, len(ip_list)))) as pool:
            futs = {pool.submit(_reverse_lookup_one, ip): ip for ip in ip_list}
            for fut in concurrent.futures.as_completed(futs):
                results[futs[fut]] = fut.result()
    finally:
        socket.setdefaulttimeout(old_timeout)
    return results

def _rename_host_in_place(old, new, original_hosts_list, active_hosts_list,
                          host_state, up_seen, down_streak):
    """Rename one host list entry everywhere it is tracked - both host lists,
    host_state, up_seen, down_streak - preserving history/uptime. A rename, not a
    delete+re-add. Shared by GET NAMES (IP -> hostname) and IP ONLY (hostname -> IP).

    If 'new' already has a host_state entry - e.g. an orphaned identity left behind
    by SET REFERENCE dropping this host earlier, with the host then reappearing
    under 'old' via a fresh scan before GET NAMES caught up - the two are merged:
    live ping fields come from 'old' (the more recent observation), but the change
    counter/timestamp (the actual monitoring history) is kept from whichever side
    has more of it, instead of being silently reset to 0."""
    for lst in (original_hosts_list, active_hosts_list):
        for i, h in enumerate(lst):
            if h == old:
                lst[i] = new
    if old in host_state:
        entry    = host_state.pop(old)
        entry[0] = new
        existing = host_state.get(new)
        if existing and existing[5] >= entry[5]:
            entry[5] = existing[5]   # changes
            entry[6] = existing[6]   # change_ts
        host_state[new] = entry
    if old in host_hist:
        host_hist[new] = host_hist.pop(old)
    if old in up_seen:
        up_seen.discard(old)
        up_seen.add(new)
    if old in down_streak:
        down_streak[new] = down_streak.pop(old)
    if old in host_meta and new not in host_meta:
        host_meta[new] = host_meta[old]          # inventory values follow the host
    if is_ip_host(old):
        host_csv_ip.setdefault(new, host_csv_ip.get(old, old))
    elif old in host_csv_ip:
        host_csv_ip.setdefault(new, host_csv_ip[old])
    forget_names([new])   # force a fresh forward lookup for the new identity

def merge_csv_ips_into_lists(hosts, original_hosts_list, active_hosts_list,
                             host_state, up_seen, down_streak):
    """ADD LIST with an inventory CSV: a CSV host whose IP is already in the lists as a
    plain IP entry (e.g. from a .txt file) updates that entry - it is renamed to the
    CSV hostname in place (history kept) instead of being added a second time.
    Returns the number of renamed entries. host_csv_ip holds the IP of each CSV host."""
    cur = set(original_hosts_list) | set(active_hosts_list)
    renamed = 0
    for h in hosts:
        if h in cur:
            continue
        ip = host_csv_ip.get(h)
        if ip and ip != h and ip in cur:
            _rename_host_in_place(ip, h, original_hosts_list, active_hosts_list,
                                  host_state, up_seen, down_streak)
            cur.discard(ip)
            cur.add(h)
            renamed += 1
    return renamed

def _forward_confirms(name, ip):
    """True if 'name' has a forward record (A for an IPv4 ip, AAAA for an IPv6 ip)
    that resolves back to exactly this ip. Guards GET NAMES: a PTR record with no
    matching forward record must not be used to rename a host, or pinging it
    afterwards by name would fail (NO-DNS) or silently hit a different address."""
    if jr_active():
        return ip in (jr_forward([name]).get(name) or [])
    try:
        af = socket.AF_INET6 if ip_version_str(ip) == '6' else socket.AF_INET
        infos = socket.getaddrinfo(name, None, af, socket.SOCK_DGRAM)
        ips = set(i[4][0] for i in infos)
        if af == socket.AF_INET6:
            ips = set(a for a in ips if not ipaddress.ip_address(a).ipv4_mapped)
        return ip in ips
    except Exception:
        return False

def _get_names_lookup(candidates):
    """Reverse-DNS 'candidates' via get_names_for_ips(), then for every IP whose PTR
    name passes the fqdn format check, confirm it forward-resolves back to that same
    IP (in parallel, same worker budget as the PTR batch). Returns (ptr, fwd_ok): ptr
    is get_names_for_ips()'s {ip: name_or_None}; fwd_ok is {ip: True/False} for every
    ip that had a plausible PTR name."""
    ptr = get_names_for_ips(candidates)
    checkable = [ip for ip in candidates if ptr.get(ip) and match_re(ptr[ip], fqdn_re)]
    fwd_ok = {}
    if checkable and jr_active():
        jr_forward([ptr[ip] for ip in checkable])      # one ssh call for all forward checks
    if checkable:
        with concurrent.futures.ThreadPoolExecutor(
                max_workers=max(1, min(DNS_RESOLVERS, len(checkable)))) as pool:
            futs = {pool.submit(_forward_confirms, ptr[ip], ip): ip for ip in checkable}
            for fut in concurrent.futures.as_completed(futs):
                fwd_ok[futs[fut]] = fut.result()
    return ptr, fwd_ok

def _get_names_apply(candidates, ptr, fwd_ok, original_hosts_list, active_hosts_list,
                     host_state, up_seen, down_streak):
    """Apply reverse-DNS results already looked up for 'candidates' (ptr/fwd_ok, from
    _get_names_lookup()): rename each confirmed IP in place. Pure in-memory work, no
    I/O - safe to call from the main thread once the lookup has completed.

    Skipped: IPs with no (usable) PTR record, PTR names with no matching forward
    A/AAAA record back to the same IP, and PTR names that collide with a host
    already in the list or with another PTR result from this same batch."""
    # A PTR name claimed by more than one candidate IP (e.g. anycast siblings that
    # share one reverse record, like 1.1.1.1 / 1.0.0.1 -> one.one.one.one) is
    # ambiguous: renaming only one of them would make PREFER HOSTNAMES treat the
    # other as a redundant duplicate and silently drop it from monitoring. Keep both
    # as plain IPs instead of renaming either. Names that failed the forward check
    # do not count here either - they will never be renamed, so they must not make
    # some other, forward-confirmed candidate look ambiguous.
    name_counts = {}
    for ip in candidates:
        name = ptr.get(ip)
        if name and match_re(name, fqdn_re) and fwd_ok.get(ip):
            name_counts[name.lower()] = name_counts.get(name.lower(), 0) + 1

    existing   = set(h.lower() for h in original_hosts_list)
    used_names = set()
    renamed_n, unresolved, no_fwd, collisions, shared_ptr = 0, 0, 0, 0, 0
    for ip in candidates:
        name = ptr.get(ip)
        if not name or not match_re(name, fqdn_re):
            unresolved += 1
            continue
        if not fwd_ok.get(ip):
            no_fwd += 1
            continue
        key = name.lower()
        if name_counts.get(key, 0) > 1:
            shared_ptr += 1
            continue
        if key in existing or key in used_names:
            collisions += 1
            continue
        used_names.add(key)
        _rename_host_in_place(ip, name, original_hosts_list, active_hosts_list,
                              host_state, up_seen, down_streak)
        renamed_n += 1

    parts = [str(renamed_n) + ' renamed']
    if unresolved:
        parts.append(str(unresolved) + ' no PTR')
    if no_fwd:
        parts.append(str(no_fwd) + ' no matching A/AAAA (kept as IP)')
    if collisions:
        parts.append(str(collisions) + ' name collision')
    if shared_ptr:
        parts.append(str(shared_ptr) + ' shared PTR (kept as IP)')
    return 'get names: ' + ', '.join(parts)

def apply_get_names(original_hosts_list, active_hosts_list, host_state, up_seen,
                    down_streak, dns_ttl):
    """[G] GET NAMES, synchronous: reverse-DNS every raw-IP host that has no
    hostname counterpart yet, and rename it in place (host_state, both host lists,
    up_seen, down_streak) so history/uptime survive - a rename, not a delete+re-add.
    Returns a status message. Blocks until every PTR lookup is done or times out -
    only used at startup (-gn), before the CLI/web loop exists to stay responsive
    for. The interactive [G] key/cmd runs this in the background instead, see
    get_names_start()/get_names_finish()."""
    jr_prefetch(original_hosts_list)
    covered_ips = set()
    for h in original_hosts_list:
        if not is_ip_host(h):
            ip = resolve_name(h, dns_ttl)
            if ip:
                covered_ips.add(ip)

    candidates = [h for h in original_hosts_list
                 if is_ip_host(h) and h not in covered_ips]
    if not candidates:
        return 'get names: no eligible IP host(s)'

    ptr, fwd_ok = _get_names_lookup(candidates)
    return _get_names_apply(candidates, ptr, fwd_ok, original_hosts_list, active_hosts_list,
                            host_state, up_seen, down_streak)

def get_names_start(original_hosts_list, dns_ttl):
    """[G] GET NAMES, background: compute the candidate IPs (fast, in-memory) and
    kick off the slow part - the PTR lookups plus the forward A/AAAA confirmation -
    on a daemon thread, so the caller's main loop is never blocked waiting on DNS.
    Returns (thread, result_holder, candidates); thread is None (nothing started)
    when there is nothing to look up. Poll thread.is_alive() and, once False, call
    get_names_finish() with result_holder."""
    if ssh_target and not jr_active():      # reverse DNS here would not match the jump host's view
        return None, None, []
    jr_prefetch(original_hosts_list)
    covered_ips = set()
    for h in original_hosts_list:
        if not is_ip_host(h):
            ip = resolve_name(h, dns_ttl)
            if ip:
                covered_ips.add(ip)

    candidates = [h for h in original_hosts_list
                 if is_ip_host(h) and h not in covered_ips]
    if not candidates:
        return None, None, candidates

    result_holder = {}
    def _worker():
        ptr, fwd_ok = _get_names_lookup(candidates)
        result_holder['ptr']    = ptr
        result_holder['fwd_ok'] = fwd_ok
    thread = threading.Thread(target=_worker, daemon=True)
    thread.start()
    return thread, result_holder, candidates

def get_names_finish(candidates, result_holder, original_hosts_list, active_hosts_list,
                     host_state, up_seen, down_streak):
    """[G] GET NAMES, background: apply the PTR/forward-check results a
    get_names_start() thread has finished computing. Call only after
    thread.is_alive() is False."""
    ptr    = result_holder.get('ptr', {})    if result_holder else {}
    fwd_ok = result_holder.get('fwd_ok', {}) if result_holder else {}
    return _get_names_apply(candidates, ptr, fwd_ok, original_hosts_list, active_hosts_list,
                            host_state, up_seen, down_streak)

def prepare_targets(hosts, ttl, progress_cb=None):
    """Map the host list to what is actually handed to fping.

    Returns (targets, target -> [display names], unresolved names).
    With ttl <= 0 nothing is cached and fping does the resolving itself (old behaviour).
    progress_cb(elapsed) -> True cuts the name lookups short (a keypress/browser
    command is waiting): nothing is returned for this round ([], {}, []), the lookups
    already running still fill the cache, so the next round only resolves the rest.
    """
    if ttl <= 0 or ssh_target:      # ssh: the jump host resolves the names
        return list(hosts), dict((h, [h]) for h in hosts), []

    pending = []
    now     = time.time()
    with _dns_lock:
        for h in hosts:
            if is_ip_host(h):
                continue
            entry = _dns_cache.get(h)
            if not entry or entry[1] <= now:
                pending.append(h)
    if pending and progress_cb is not None:
        pool = concurrent.futures.ThreadPoolExecutor(max_workers=max(1, min(DNS_RESOLVERS, len(pending))))
        futs = [pool.submit(resolve_name, n, ttl) for n in pending]
        t0   = time.time()
        try:
            while not all(f.done() for f in futs):
                if progress_cb(time.time() - t0):
                    for f in futs:
                        f.cancel()                 # not started yet: dropped
                    return [], {}, []
                time.sleep(0.1)
        finally:
            pool.shutdown(wait=False)
    elif pending:
        workers = max(1, min(DNS_RESOLVERS, len(pending)))
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
                list(pool.map(lambda n: resolve_name(n, ttl), pending))
        except Exception:
            for n in pending:
                resolve_name(n, ttl)

    global _csv_fb_names
    targets     = []
    name_map    = {}
    unresolved  = []
    fallback    = set()
    for h in hosts:
        if is_ip_host(h):
            target = h
        else:
            target = resolve_name(h, ttl)
            if not target and csv_ip_fallback:
                # no DNS record, but the inventory CSV has an address for this host: ping that
                target = host_csv_ip.get(h) or ''
                if target and is_ip_host(target):
                    fallback.add(h)
                else:
                    target = ''
            if not target:
                unresolved.append(h)
                continue
        if target not in name_map:
            name_map[target] = []
            targets.append(target)
        name_map[target].append(h)
    _csv_fb_names = frozenset(fallback)
    return targets, name_map, unresolved


def build_fping_cmd(interval_ms, retries_override=None, family='4'):
    """Assemble the fping command line shared by all worker processes of one group.
    family selects -4/-6 - fping cannot ping v4 and v6 targets in the same invocation,
    so a round with both families in play runs two separate fping command lines."""
    use_retries = str(retries if retries_override is None else retries_override)
    cmd = ['fping', '-' + str(family), '-e', '-B', backoff, '-t', timeout, '-r', use_retries]
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
_scan_error    = ''   # last fatal error from a worker (e.g. fping vanished) - shown in scan_desc


def parse_fping_line(line, timestamp):
    """Parse one line of 'fping -e' output into a result row, or None if the line
    is not a per-host result. Row layout (see host_state): [hostname, state, timestamp,
    rtt, pinged_ip, no_of_changes, change_ts, tbd] - slot 4 carries the pinged
    address and is replaced by the display name in run_ping_round()."""
    out = line.split()
    if len(out) < 3:
        return None
    try:
        if out[1] == 'is' and out[2].startswith('unreachable'):
            return [out[0], ' DOWN', timestamp, '----', out[0], 0, '', 0]
        if out[2] == 'alive':
            rtt = format(float(out[3].lstrip('(')), '.2f')
            return [out[0], '  UP', timestamp, rtt, out[0], 0, '', 0]
        if (out[1] == 'nodename' and out[2] == 'nor') or (out[1] == 'Name' and out[2] == 'or'):
            host = out[0].rstrip(':')
            return [host, 'NO-DNS', timestamp, '----', host, 0, '', 0]
    except (IndexError, ValueError):
        pass
    return None

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
    global fping_cmd_output_raw_total, _source_fail_reason

    if not summary_hosts_list:
        return

    cmd = list(cmd_base) if cmd_base else build_fping_cmd(interval)

    use_stdin = len(summary_hosts_list) > FPING_STDIN_THRESH or bool(ssh_target)
    if not use_stdin:
        cmd.extend(summary_hosts_list)
    popen_env = None
    if ssh_target:
        cmd = ssh_wrap(cmd)
        popen_env = ssh_env(ssh_cfg)

    with _procs_lock:
        if _abort_scan:
            return

    try:
        ping = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,          # merge: simpler + avoids deadlock
            stdin=(subprocess.PIPE if use_stdin else subprocess.DEVNULL),
            encoding='utf-8', errors='replace',
            bufsize=1,
            env=popen_env,
        )
    except FileNotFoundError:
        # never sys.exit() inside a worker thread - it would only kill this thread
        # and leave the main loop running with an empty result. Report via scan_desc.
        global _scan_error
        if ssh_target:
            _source_fail_reason = 'ssh command not found'
        else:
            _scan_error = "fping not found - install it via 'sudo apt install fping' or 'brew install fping'"
        return

    with _procs_lock:
        _running_procs.append(ping)

    # Feed targets via stdin for large batches (avoids ARG_MAX). Close stdin so fping starts pinging.
    if use_stdin:
        try:
            ping.stdin.write('\n'.join(summary_hosts_list) + '\n')
            ping.stdin.close()
        except BrokenPipeError:
            pass

    # parse while streaming - no second pass over a buffered copy of the output
    fping_result_data = []
    stray = collections.deque(maxlen=3)        # non-result lines (ssh errors), for the SOURCE DOWN reason
    for line in ping.stdout:
        row = parse_fping_line(line, get_date_time())
        if row is not None:
            fping_result_data.append(row)
        elif ssh_target and line.strip():
            stray.append(line.strip())
    ping.wait()
    # a scan cut short by a command (scan_abort) ends the ssh client with exit 255 ("Killed
    # by signal 15"): that is not a lost jump host
    if ssh_target and not _abort_scan and (ping.returncode == 255 or (
            not fping_result_data and ping.returncode not in (0, 1, 2))):
        _source_fail_reason = (' / '.join(stray) or ('ssh/fping exit ' + str(ping.returncode)))[:200]
    with _procs_lock:
        try:
            _running_procs.remove(ping)
        except ValueError:
            pass

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
    fqdn_rows.sort(key=lambda r: (r[0].lower(), r[0]))      # case-insensitive, exact name as tie-break
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

def match_host(pattern, name, ip=''):
    """True if pattern (compiled regex) matches the host name, its IP or any
    inventory CSV field (hostname, serial, model, location, sysLocation, type, comment)."""
    if pattern.search(name) or (ip and pattern.search(ip)):
        return True
    meta = host_meta.get(name) or (host_meta.get(ip) if ip else None)
    return bool(meta) and any(v and pattern.search(v) for v in meta)

# ---- ADV FILTER: display-only filter on the inventory fields (see host_meta) ----
# Excel-style: per field a set of values with mode 'in' (show only these) or 'out'
# (hide these). OR within a field, AND across fields, applied on top of the view and
# the [M] regex.
ADV_FIELDS = (('model', 'Model', 2), ('location', 'Location', 3),
              ('sysloc', 'sysLocation', 4), ('type', 'Type', 5), ('comment', 'Comment', 6))
ADV_NONE   = '\x01none'   # member of a value set: hosts without a value in that field
# field key -> (mode, frozenset(values)); mode 'in' | 'out'; empty dict = filter off
adv_filter = {}

def _adv_ok(meta, sel, skip=None):
    """True if the inventory values 'meta' (or None) fit every field selection in
    'sel' ({key: (mode, values)}); the field 'skip' is not checked."""
    for key, _label, idx in ADV_FIELDS:
        want = sel.get(key)
        if want is None or key == skip:
            continue
        mode, values = want
        have = meta[idx] if meta else ''
        hit = (ADV_NONE if have == '' else have) in values
        if hit != (mode == 'in'):
            return False
    return True

def _wrap_footer(text, width):
    """Wrap a key-help line into lines of at most 'width' chars (split at spaces)."""
    lines, cur = [], ''
    for w in text.split(' '):
        if cur and len(cur) + 1 + len(w) > width:
            lines.append(cur)
            cur = w
        else:
            cur = (cur + ' ' + w) if cur else w
    return lines + [cur] if cur else lines

def adv_match(name, ip=''):
    """True if the host passes the ADV FILTER (always True while it is off)."""
    if not adv_filter:
        return True
    return _adv_ok(host_meta.get(name) or (host_meta.get(ip) if ip else None), adv_filter)

def host_visible(pattern, name, ip=''):
    """[M] regex (pattern, may be None) AND ADV FILTER."""
    return (pattern is None or match_host(pattern, name, ip)) and adv_match(name, ip)

def adv_parse(d):
    """Normalise a selection {field: {"mode": in|out, "values": [..]}} (or the old
    {field: "value"}) into {key: (mode, frozenset)}; unknown/empty entries are dropped."""
    known = {k for k, _l, _i in ADV_FIELDS}
    out = {}
    if not isinstance(d, dict):
        return out
    for k, v in d.items():
        if k not in known:
            continue
        if isinstance(v, str):
            mode, vals = 'in', [v]
        elif isinstance(v, dict):
            mode, vals = v.get('mode', 'in'), v.get('values')
        else:
            continue
        if mode not in ('in', 'out') or not isinstance(vals, list):
            continue
        vals = frozenset(x for x in vals if isinstance(x, str) and x != '')
        if vals:
            out[k] = (mode, vals)
    return out

def adv_export(sel=None):
    """JSON-serialisable form of a selection (default: the active filter)."""
    sel = adv_filter if sel is None else sel
    return {k: {'mode': m, 'values': sorted(v)} for k, (m, v) in sel.items()}

def adv_values(hosts, selection=None):
    """Selectable values per ADV FILTER field over the given host entries:
    {key: {'values': [[value, host_count], ...] sorted, 'empty': hosts_without}}.
    With a selection ({key: (mode, values)}) each field only offers what is still
    possible given the OTHER fields' selection (its own selection does not narrow its
    list). Fields without any value in any host are left out."""
    sel   = selection or {}
    metas = [host_meta.get(h) for h in hosts]
    out = {}
    for k, _l, idx in ADV_FIELDS:
        if not any(m and m[idx] for m in metas):
            continue
        counts, empty = {}, 0
        for m in metas:
            if not _adv_ok(m, sel, k):
                continue
            v = m[idx] if m else ''
            if v:
                counts[v] = counts.get(v, 0) + 1
            else:
                empty += 1
        out[k] = {'values': [[v, counts[v]] for v in
                             sorted(counts, key=lambda x: (x.lower(), x))],
                  'empty': empty}
    return out

def adv_text():
    """Short description of the active ADV FILTER, e.g. 'Model in (A, B), Type not in (AP)'."""
    parts = []
    for k, label, _i in ADV_FIELDS:
        if k in adv_filter:
            mode, vals = adv_filter[k]
            names = sorted(('(empty)' if v == ADV_NONE else v) for v in vals)
            shown = ', '.join(names[:3]) + (', +%d' % (len(names) - 3) if len(names) > 3 else '')
            parts.append('%s %s (%s)' % (label, 'in' if mode == 'in' else 'not in', shown))
    return ', '.join(parts)

def adv_filter_set(text):
    """Replace the ADV FILTER from a JSON object ('{}' = off), see adv_parse().
    Returns an error text, or '' on success."""
    try:
        d = json.loads(text) if text.strip() else {}
    except ValueError:
        return 'invalid filter'
    if not isinstance(d, dict):
        return 'invalid filter'
    new = adv_parse(d)
    adv_filter.clear()
    adv_filter.update(new)
    return ''

def apply_match_filter(rows, pattern):
    """Pure display filter: keep only rows whose display name (rows[i][0]),
    resolved/pinged IP (rows[i][8], when present) or inventory CSV field (see
    match_host) matches 'pattern' (an already-
    compiled regex). This is applied after build_display(), on the rows about to be
    shown - it never touches active_hosts_list, so every host keeps being pinged on
    every round regardless of what the filter currently hides. Pass pattern=None for
    no-op (filter off). The ADV FILTER (adv_filter) is ANDed in."""
    if pattern is None and not adv_filter:
        return rows
    return [r for r in rows
            if host_visible(pattern, r[0], r[8] if len(r) > 8 and r[8] else '')]

def view_hosts(mode, hosts, host_state, tz_offset, flap_window=FLAP_WINDOW_DEF):
    """Hosts of 'hosts' shown by the view 'mode' (live; mode 0 = all, list unchanged)."""
    if mode <= 0:
        return hosts
    return filter_hosts(mode, hosts, host_state, tz_offset, flap_window)

def view_rows(rows, mode, host_state, tz_offset, flap_window=FLAP_WINDOW_DEF):
    """Rows (from build_display) of the hosts shown by the view 'mode' (live)."""
    if mode <= 0:
        return rows
    keep = set(filter_hosts(mode, [r[0] for r in rows], host_state, tz_offset, flap_window))
    return [r for r in rows if r[0] in keep]

def filter_hosts(mode, original_hosts_list, host_state, tz_offset,
                 flap_window=FLAP_WINDOW_DEF, up_seen=None):
    """Host list for the given view mode - a snapshot, taken when the view switches.
    Modes 0-2 (ALL/UP/UP+FLAPPING) are also used by the CLI's [U] key and its web
    gui keyboard-shortcut equivalent; modes 3-8 are reachable only through the web
    gui's view dropdown (set_filter) - see WEB_VIEW_MODES.
    'changes' (entry[5], the CH NO column) is 0 while a host has never left the state
    it was first observed in this run - that is what ALWAYS-UP/ALWAYS-DOWN mean here;
    it is a live-session fact, not the full-log uptime% epinga.py's report computes.
    up_seen is accepted for signature compatibility with its other callers (used
    elsewhere for renaming/pruning bookkeeping) - no current mode reads it here;
    EVER-UP (former mode 9, the only mode that did) was removed as redundant with
    UP+FLAPPING (mode 2)."""
    if mode <= 0:
        return list(original_hosts_list)
    now_ref = now_local(tz_offset)
    out = []
    for h in original_hosts_list:
        entry = host_state.get(h)
        if not entry:
            continue
        is_up   = 'UP' in entry[1]
        is_flap = host_is_flapping(entry, now_ref, flap_window)
        changes = entry[5]
        if mode == 1 and is_up:
            out.append(h)
        elif mode == 2 and (is_up or is_flap):
            out.append(h)
        elif mode == 3 and is_up and not changes:
            out.append(h)
        elif mode == 4 and is_flap:
            out.append(h)
        elif mode == 5 and not is_up and not changes:
            out.append(h)
        elif mode == 6 and not is_up:
            out.append(h)
        elif mode == 7 and (not is_up or is_flap):
            out.append(h)
        elif mode == 8 and 'NO-DNS' in entry[1]:
            out.append(h)
    return out

_addr_redundancy_cache = {}   # name -> (ips list, expires_at) - see _cached_all_ips()

def _cached_all_ips(name, ttl):
    """resolve_all_ips(), cached for ttl seconds (own cache, independent of
    resolve_name()'s _dns_cache so GET NAMES / forget_names invalidation is not
    affected). apply_prefer_hostname()/apply_prefer_ip() call this once per hostname
    on every single address-mode switch (PREFER HOSTNAME <-> PREFER IP ADDRESS
    switches back and forth without ever going through IP ONLY, so this runs on
    every one of them); resolving live and uncached every time made the redundancy
    check both slow (blocks the ping loop for the whole switch on a large host
    list) and, on any transient DNS hiccup, inconsistent between switches - a
    hostname that failed to resolve just that once was treated as having no
    address at all, silently skipping the redundancy check that switch. ttl <= 0
    disables caching (matches prepare_targets()'s convention elsewhere)."""
    if ttl <= 0:
        return resolve_all_ips(name)
    now = time.time()
    with _dns_lock:
        entry = _addr_redundancy_cache.get(name)
        if entry and entry[1] > now:
            return entry[0]
    ips = resolve_all_ips(name)
    with _dns_lock:
        _addr_redundancy_cache[name] = (ips, now + (ttl if ips else min(ttl, DNS_FAIL_TTL)))
    return ips

def draw_wait_box(lines):
    """Centered green 'PLEASE WAIT' box on the curses screen (same look as the
    scanning box): first line bold, the rest plain."""
    rows, cols = screen.getmaxyx()
    box_w = min(max(len(l) for l in lines) + 8, max(12, cols - 2))
    box_x = max(0, (cols - box_w) // 2)
    box_y = max(1, rows // 2 - len(lines) // 2 - 1)
    screen_output(box_y, box_x, '+' + '-' * (box_w - 2) + '+', 2, 1)
    for idx, text in enumerate(lines):
        screen_output(box_y + 1 + idx, box_x,
                      '|' + text[:box_w - 2].center(box_w - 2) + '|', 2, 1 if idx == 0 else 0)
    screen_output(box_y + 1 + len(lines), box_x, '+' + '-' * (box_w - 2) + '+', 2, 1)

def run_with_wait_box(lines, work):
    """Run work() and return its result. With a curses screen a PLEASE WAIT box with
    an elapsed counter is shown meanwhile (and removed afterwards, nothing is left
    behind); without one (web gui) a plain line goes to stdout."""
    scr = globals().get('screen')
    if scr is None:
        print(' - '.join(lines), flush=True)
        return work()
    box = {}
    def _run():
        try:
            box['v'] = work()
        except BaseException as e:      # re-raised in the caller below
            box['e'] = e
    th = threading.Thread(target=_run, daemon=True)
    t0 = time.time()
    th.start()
    while th.is_alive():
        try:
            scr.erase()
            draw_wait_box(list(lines) + ['%.1f sec' % (time.time() - t0)])
            scr.refresh()
        except curses.error:
            pass
        th.join(0.2)
    try:
        scr.clear()
        scr.refresh()
    except curses.error:
        pass
    if 'e' in box:
        raise box['e']
    return box.get('v')

def apply_prefer_hostname(hosts_list, dns_ttl):
    """[P] toggle: drop raw-IP entries whose address is also covered by a hostname
    entry in the same list. The hostname gets pinged anyway, so pinging the bare IP a
    second time is redundant - a raw IP with no hostname counterpart is kept as-is.
    A hostname with several A-records (e.g. anycast siblings) covers all of them, not
    just the one resolve_name() currently has cached. dns_ttl controls how long a
    hostname's resolved addresses are cached for this check - see _cached_all_ips()."""
    hostname_ips = set()
    names = [h for h in hosts_list if not is_ip_host(h)]
    jr_prefetch(names)
    if len(names) > 1:     # resolve in parallel - serial lookups of unresolvable names are slow
        with concurrent.futures.ThreadPoolExecutor(max_workers=32) as ex:
            for ips in ex.map(lambda n: _cached_all_ips(n, dns_ttl), names):
                hostname_ips.update(ips)
    else:
        for h in names:
            hostname_ips.update(_cached_all_ips(h, dns_ttl))
    return [h for h in hosts_list
            if not (is_ip_host(h) and h in hostname_ips)]

def apply_prefer_ip(hosts_list, dns_ttl):
    """[K] toggle / web addr_mode=2 mirror of apply_prefer_hostname: drop a hostname
    entry when its resolved address is already covered by a raw-IP entry in the same
    list (the opposite redundancy check - IP wins, hostname is dropped). dns_ttl
    controls how long a hostname's resolved addresses are cached for this check - see
    _cached_all_ips()."""
    raw_ips = set(h for h in hosts_list if is_ip_host(h))
    if not raw_ips:
        return list(hosts_list)
    jr_prefetch(hosts_list)
    return [h for h in hosts_list
            if is_ip_host(h) or not raw_ips.intersection(_cached_all_ips(h, dns_ttl))]

def apply_ip_only_on(original_hosts_list, active_hosts_list, host_state, up_seen,
                     down_streak, dns_ttl):
    """[I] IP ONLY (turning on): resolve every hostname entry to its address -
    whichever family resolve_name() returns (A preferred by default, or whichever
    family -4/-6 forces - no per-host choice, v4/v6 are not distinguished here) - and
    rename it to that address in place, so pinging happens by IP, not name. History
    and uptime carry over (see _rename_host_in_place). A hostname that does not
    resolve is left untouched. A hostname whose resolved address collides with a host
    already in the list (raw IP or another hostname resolving to the same address) is
    dropped entirely - the address is already tracked under the other entry, so
    keeping both would be a redundant duplicate. Dropped hosts are not restored when
    IP ONLY is switched off. Returns (ip_map, message); ip_map is {ip: original_
    hostname}, kept so IP ONLY can be turned back off later and restore the renamed
    entries."""
    existing = set(h.lower() for h in original_hosts_list)
    ip_map, unresolved, dropped = {}, 0, 0
    jr_prefetch(original_hosts_list)
    for h in list(original_hosts_list):
        if is_ip_host(h):
            continue
        ip = resolve_name(h, dns_ttl)
        if not ip:
            unresolved += 1
            continue
        if ip in ip_map or ip.lower() in existing:
            for lst in (original_hosts_list, active_hosts_list):
                if h in lst:
                    lst.remove(h)
            host_state.pop(h, None)
            up_seen.discard(h)
            down_streak.pop(h, None)
            dropped += 1
            continue
        _rename_host_in_place(h, ip, original_hosts_list, active_hosts_list,
                              host_state, up_seen, down_streak)
        ip_map[ip] = h
        existing.add(ip.lower())

    parts = [str(len(ip_map)) + ' resolved']
    if unresolved:
        parts.append(str(unresolved) + ' unresolved')
    if dropped:
        parts.append(str(dropped) + ' dropped (duplicate address)')
    return ip_map, 'ip only: on, ' + ', '.join(parts)

def apply_ip_only_off(ip_map, original_hosts_list, active_hosts_list, host_state,
                      up_seen, down_streak):
    """[I] IP ONLY (turning off): restore the original hostname for every entry
    that apply_ip_only_on renamed to its IP. A host removed or renamed again (e.g. by
    GET NAMES) meanwhile is left as-is."""
    restored = 0
    for ip, name in list(ip_map.items()):
        if ip in original_hosts_list:
            _rename_host_in_place(ip, name, original_hosts_list, active_hosts_list,
                                  host_state, up_seen, down_streak)
            restored += 1
    return 'ip only: off, ' + str(restored) + ' restored'

def apply_ip_only_on_web(original_hosts_list, active_hosts_list, host_state,
                         up_seen, down_streak, dns_ttl):
    """Web-gui-only variant of apply_ip_only_on: never permanently drops a host.
    A hostname whose resolved address collides with another entry already in the
    list (a raw IP, or another hostname already claimed earlier in this same call)
    is left untouched instead of removed - exactly like an unresolved (NO-DNS)
    hostname, it simply stays out of what is shown/pinged while IP ONLY is active
    (see the is_ip_host() filter after this call in run_web_mode), and reappears
    under its original name as soon as a different address mode is selected, since
    original_hosts_list/host_state are never touched for it. The CLI's [I] key still
    uses apply_ip_only_on above and keeps the old drop-on-collision behaviour."""
    existing = set(h.lower() for h in original_hosts_list)
    ip_map, unresolved, skipped = {}, 0, 0
    jr_prefetch(original_hosts_list)
    for h in list(original_hosts_list):
        if is_ip_host(h):
            continue
        ip = resolve_name(h, dns_ttl)
        if not ip:
            unresolved += 1
            continue
        if ip in ip_map or ip.lower() in existing:
            skipped += 1
            continue
        _rename_host_in_place(h, ip, original_hosts_list, active_hosts_list,
                              host_state, up_seen, down_streak)
        ip_map[ip] = h
        existing.add(ip.lower())

    parts = [str(len(ip_map)) + ' resolved']
    if unresolved:
        parts.append(str(unresolved) + ' unresolved')
    if skipped:
        parts.append(str(skipped) + ' skipped (duplicate address)')
    return ip_map, 'ip only: on, ' + ', '.join(parts)

def check_python_version(mrv):
    return tuple(sys.version_info[:2]) >= tuple(mrv[:2])

def delete_files(filestring):
    file_list = glob.glob(filestring, recursive=False)
    for file in file_list:
        try:
            os.remove(file)
            print(file)
        except OSError:
            error_handler('ERROR: unable to delete files' )
    print("Removed all matched files!")
    error_handler(f'THX for using eping.py v{VERSION} - www.jeitler.cc', exit_code=0)

_ASCII_FALLBACK = str.maketrans({'\u250c': '+', '\u2510': '+', '\u2514': '+', '\u2518': '+', '\u2500': '-', '\u2502': '|'})

def screen_output(line,coll,text,color,attr_val):
    attr = 0
    if attr_val == 1:
        attr |= curses.A_BOLD
    if attr_val == 2:
        attr |= curses.A_BOLD | curses.A_BLINK

    attr |= curses.color_pair(color)
    try:
        screen.addstr(line, coll, text, attr)
    except curses.error:
        pass   # writing past the last cell raises - harmless
    except UnicodeEncodeError:
        # non-UTF-8 locale (e.g. ASCII on Python 3.6): draw an ASCII fallback
        try:
            screen.addstr(line, coll, text.translate(_ASCII_FALLBACK).encode('ascii', 'replace').decode('ascii'), attr)
        except curses.error:
            pass

def screen_print_date_time(color_pair, tz_offset=None):
    offset = int(args.time_zone_adjust) if tz_offset is None else tz_offset
    now = datetime.datetime.now() + datetime.timedelta(hours=offset)
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

def screen_print_horizontal_line(message, color_pair, line):
    num_rows, num_cols = screen.getmaxyx()
    spacesstring =str()
    linestring = spacesstring.rjust(int(num_cols), message)
    if line < num_rows-1:
        screen_output(line, 0, linestring,color_pair,1 )

def sigint_handler(signal, frame):
    # tell a --web_view browser mirror right away, BEFORE maybe_run_epinga() below
    # can block on its "[y/N]" input() prompt for as long as the user takes to
    # answer it - same notice the web GUI's own EXIT button already gives.
    with web_lock:
        web_state['stopped'] = True
        web_state['message'] = 'stopped'
    time.sleep(1.5)   # guarantee the browser's next poll sees it even if
                       # maybe_run_epinga() below has nothing to prompt for
    try:
        curses.endwin()
    except curses.error:
        pass
    print(f'THX for using eping.py v{VERSION} - www.jeitler.cc')
    if is_newer_version(_remote_version, VERSION):
        print_update_notice(_remote_version)
    maybe_run_epinga(_logfile_file_name, _logging_enabled)
    sys.stdout.flush()
    # os._exit(), not sys.exit(): a running [G] GET NAMES background lookup uses a
    # ThreadPoolExecutor whose worker threads are not daemons, so sys.exit() would
    # block here until every in-flight PTR lookup finishes (or times out) instead of
    # stopping right away.
    ssh_shutdown()
    os._exit(0)

# ---- inventory CSV import: hosts + per-device columns carried into the log ----
LOG_HEADER = ['TIMESTAMP','HOSTNAME','PREVIOUS_STATE','CURRENT_STATE','RTT',
              'NO_OF_CHANGES','CHANGE_TIMESTAMP','TBD','IP',
              'INV_HOSTNAME','SERIAL_NUMBER','MODEL','LOCATION','SYSLOCATION','TYPE','INV_COMMENT','SOURCE']
_CSV_META_COLS = ('hostname', 'serial number', 'model', 'location', 'syslocation', 'type', 'comment')
_EMPTY_META    = ('',) * len(_CSV_META_COLS)
host_meta      = {}   # host entry or IP -> tuple of _CSV_META_COLS values (log columns 10..16)
host_csv_ip    = {}   # host entry -> its 'IP Address' from the inventory CSV (SAVE HOSTS FILE)
host_state     = {}   # host entry -> state row (rebound by the main block at startup)

# ---- change history per host (mouse-over popup) ----
# One uint32 per state change: bits 31..4 seconds since HIST_T0, bits 3..2 old state,
# bits 1..0 new state (0 UP, 1 DOWN, 2 NO-DNS, 3 other). The array of a host is created
# on its first change and keeps the last HIST_MAX changes (~4 bytes per change).
HIST_MAX   = 50
HIST_T0    = datetime.datetime.now().replace(microsecond=0)
HIST_NAMES = ('UP', 'DOWN', 'NO-DNS', '?')
host_hist  = {}        # host entry -> array('I')
comment_hist = collections.deque(maxlen=HIST_MAX)   # (naive local datetime, text) of the log comments

def comment_add(when, text):
    """Remember a log comment (COMMENT / [T]) for the history in the host popup."""
    comment_hist.append((when, str(text)[:256]))

def _state_code(s):
    s = str(s)
    return 0 if 'UP' in s else (2 if 'NO-DNS' in s else (1 if 'DOWN' in s else 3))

def hist_add(name, when, old_state, new_state):
    """Record one state change of host 'name' ('when' = naive local datetime)."""
    secs = int((when - HIST_T0).total_seconds())
    if secs < 0:
        secs = 0
    a = host_hist.get(name)
    if a is None:
        a = host_hist[name] = array.array('I')
    a.append(((secs & 0xFFFFFFF) << 4) | (_state_code(old_state) << 2) | _state_code(new_state))
    if len(a) > HIST_MAX:
        del a[0]

def hist_list(name, tz_offset=0):
    """History of host 'name', newest first: [[time string, old, new], ...] for state
    changes and [time string, '#', text] for log comments (the global comments from
    the first retained change on, all of them if the host never changed)."""
    ev = []
    for v in reversed(host_hist.get(name) or ()):
        ev.append((v >> 4, [HIST_NAMES[(v >> 2) & 3], HIST_NAMES[v & 3]]))
    first = ev[-1][0] if ev else None               # oldest retained change
    for when, text in reversed(comment_hist):
        secs = int((when - HIST_T0).total_seconds())
        if first is None or secs >= first:
            ev.append((secs, ['#', text]))
    ev.sort(key=lambda e: e[0], reverse=True)       # stable: same second keeps change before comment
    return [[(HIST_T0 + datetime.timedelta(seconds=s, hours=tz_offset)).strftime('%Y-%m-%d %H:%M:%S')] + x
            for s, x in ev]

def _inventory_header(line):
    """(delimiter, lower-cased column names) if line is an inventory CSV header
    (needs 'IP Address' and 'Hostname'), else (None, None)."""
    delim = max((';', ',', '\t'), key=line.count)
    if not line.count(delim):
        return None, None
    try:
        cols = [c.strip().lower() for c in next(csv.reader([line], delimiter=delim))]
    except (csv.Error, StopIteration):
        return None, None
    if 'ip address' in cols and 'hostname' in cols:
        return delim, cols
    return None, None

def _csv_lead_line(line):
    """True for a line before the CSV header that is not the header: blank,
    '#' comment or 'opt:'/'OPT:' options line (see opt_lines_text)."""
    t = line.strip()
    return not t or t.startswith('#') or t.startswith('opt:') or t.startswith('OPT:')

def _csv_header_index(lines):
    """Index of the first line that can be the CSV header, or None."""
    return next((i for i, l in enumerate(lines) if not _csv_lead_line(l)), None)

def parse_inventory_csv_header(text):
    """True-ish if text starts with an inventory CSV header line, else None."""
    lines = (text or '').lstrip('\ufeff').splitlines()
    hi = _csv_header_index(lines)
    return _inventory_header(lines[hi])[0] if hi is not None else None

def parse_inventory_csv(text, use_names, stats=None):
    """Parse an inventory CSV (header with 'IP Address' and 'Hostname'; other columns
    are ignored except Serial Number, Model, Location, sysLocation, Type, Comment). One host
    per row. The host entry is the Hostname column (also for rows without an IP) when
    use_names is set - the callers' default for a CSV, only the IP modes (IP ONLY,
    PREFER IP ADDRESS) turn it off - else the IP (rows without a valid IP are skipped).
    The IP is the fallback when the name is not a valid hostname.
    The row's values are stored in host_meta for the log. Returns the host list, or
    None if text is not an inventory CSV."""
    lines = (text or '').lstrip('\ufeff').splitlines()
    hi = _csv_header_index(lines)
    if hi is None:
        return None
    delim, cols = _inventory_header(lines[hi])
    if delim is None:
        return None
    idx = {c: i for i, c in enumerate(cols)}
    def cell(row, col):
        i = idx.get(col)
        return row[i].strip() if i is not None and i < len(row) else ''
    hosts, seen, seen_ips, ignored, dups = [], set(), set(), 0, 0
    try:
        for row in csv.reader(io.StringIO('\n'.join(lines[hi + 1:]), newline=''), delimiter=delim):
            if not row:
                continue
            ip    = cell(row, 'ip address')
            name  = cell(row, 'hostname')
            ip_ok = is_ip_host(ip)
            if use_names and match_re(name, fqdn_re) and not is_ip_host(name):
                key = name                 # hostname entry: also rows without an IP
            elif ip_ok:
                key = ip
            else:
                ignored += 1
                continue
            if ip_ok:
                ip = normalize_ip(ip)
            if key in seen:
                dups += 1
                continue
            seen.add(key)
            hosts.append(key)
            meta = tuple(neutralize_csv_formula(cell(row, c)) for c in _CSV_META_COLS)
            host_meta[key] = meta
            if ip_ok:
                host_csv_ip[key] = ip      # kept for SAVE HOSTS FILE (.csv)
            if ip_ok and ip not in seen_ips:
                seen_ips.add(ip)
                host_meta[ip] = meta     # lookup by pinged address when the key was renamed
    except csv.Error:
        pass                              # broken quoting - keep what was read so far
    if stats is not None:
        stats['csv'] = True
        stats['csv_ignored'] = ignored
        stats['csv_dups'] = dups
    return hosts

def parse_hosts_from_text(text, stats=None, use_names=False, name=None):
    """Hosts from host-file text. An inventory CSV (see parse_inventory_csv) is
    recognised by its header; anything else - and every file named *.txt - is parsed
    as a plain host list (_parse_plain_hosts). A NUL byte separates concatenated files."""
    csv_ok = not (name and str(name).lower().endswith('.txt'))
    out, seen, networks, skipped, ignored = [], set(), 0, [], []
    csv_stats = {}
    for seg in (text or '').split('\x00'):
        sub = {}
        got = parse_inventory_csv(seg, use_names, sub) if csv_ok else None
        if got is None:
            got = _parse_plain_hosts(seg, sub)
        else:
            for k in ('csv_ignored', 'csv_dups'):
                csv_stats[k] = csv_stats.get(k, 0) + sub.get(k, 0)
            csv_stats['csv'] = True
        networks += sub.get('networks', 0)
        skipped.extend(sub.get('skipped', []))
        ignored.extend(sub.get('ignored', []))
        for h in got:
            if h not in seen:
                seen.add(h)
                out.append(h)
    if stats is not None:
        stats['networks'] = networks
        stats['skipped']  = skipped
        stats['ignored']  = ignored
        stats.update(csv_stats)
    return out

def _parse_plain_hosts(text, stats=None):
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
    ignored  = []
    for line in (text or '').splitlines():
        line = line.split('#')[0]          # ignore comments
        for word in line.replace(',', ' ').replace(';', ' ').split():
            word = word.strip()
            if not word:
                continue
            if is_ip_host(word):
                ips.append(normalize_ip(word))   # IPv6 stored in its shortest/compressed form
            elif match_re(word, cidr_ipv4_re):
                try:
                    ips.extend(get_ipv4_from_cidr(word, CIDR_MIN_MASK, CIDR_MAX_MASK))
                    networks += 1
                except Exception:
                    skipped.append(word)
            elif (word.count('/') == 1 and word.rsplit('/', 1)[1] == '128'
                  and ip_version_str(word.rsplit('/', 1)[0]) == '6'):
                ips.append(normalize_ip(word.rsplit('/', 1)[0]))   # single-host IPv6 CIDR, no expansion
            elif match_re(word, fqdn_re):
                fqdns.append(word)
            else:
                ignored.append(word)
    seen = set()
    out  = []
    for h in ips + fqdns:
        if h not in seen:
            seen.add(h)
            out.append(h)
    if stats is not None:
        stats['networks'] = networks
        stats['skipped']  = skipped
        stats['ignored']  = ignored
    return out

def extract_opt_lines(text):
    """Pull CLI options out of a host file's 'opt:'/'OPT:' lines.

    A line counts only if it starts with exactly 'opt:' or 'OPT:' (leading blanks
    are fine); anything else ('Opt:', 'options:', ...) is left alone as a plain
    host line. Several opt: lines are allowed and are concatenated in file order.
    '#' works exactly like it does for host lines: it comments out the rest of the
    line (or, at the very start, the whole line), so a commented-out opt: line
    contributes nothing. Values with spaces can be quoted, e.g. opt: -f "my hosts.txt".
    Returns a list of tokens (possibly empty).
    """
    tokens = []
    for raw in (text or '').splitlines():
        line = raw.split('#', 1)[0].strip()      # '#' comments out the rest (or all) of the line
        if line.startswith('opt:') or line.startswith('OPT:'):
            rest = line[4:].strip()
            if rest:
                try:
                    tokens.extend(shlex.split(rest))
                except ValueError:
                    pass   # unbalanced quotes - ignore this one line rather than crash
    return tokens


def load_hosts_file(path, use_names=False):
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
    hosts = parse_hosts_from_text(text, stats, use_names, path)
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

def prune_dropped_hosts(dropped, host_state, up_seen, down_streak):
    """Purge host_state/up_seen/down_streak for hosts no longer in the reference
    list. Used by SET REFERENCE, which narrows original_hosts_list/active_hosts_list
    but - unlike CLEAR or DEL HOST - used to leave this state behind: a dropped host
    then reappearing later (e.g. a rescan of the same IP-only source) got tracked
    under a fresh identity while its real history sat orphaned in these dicts, which
    is how logging ended up showing it as a brand-new host with no history."""
    for h in dropped:
        host_state.pop(h, None)
        up_seen.discard(h)
        down_streak.pop(h, None)

def parse_host_input(value, stats=None):
    """Parse a user supplied string (IP, FQDN, CIDR or 'ip1-ip2') into a host list.

    Uses the same limits as -n and the host file (CIDR_MIN_MASK..CIDR_MAX_MASK,
    MAX_IPS_PER_RANGE). Pass a dict as 'stats' to get the reason for an empty result
    in stats['error'] instead of guessing that the input was malformed.
    """
    value = (value or '').strip()
    if stats is not None:
        stats['error'] = ''
    if not value:
        return []
    new_hosts = []
    # CIDR?
    if match_re(value, cidr_ipv4_re):
        try:
            new_hosts = get_ipv4_from_cidr(value, CIDR_MIN_MASK, CIDR_MAX_MASK)
        except Exception:
            if stats is not None:
                stats['error'] = ('mask must be /%d../%d: %s'
                                  % (CIDR_MIN_MASK, CIDR_MAX_MASK, value))
    # IP range  e.g. "10.0.0.1-10.0.0.20" - both sides must already look like
    # full IPv4 addresses, or a hyphenated hostname (e.g. "01-markus.jeitler.cc")
    # would be misread as a broken range instead of falling through to the
    # hostname/fqdn check below
    elif ('-' in value and value.count('-') == 1
          and all(match_re(p.strip(), ip_re) for p in value.split('-'))):
        parts = value.split('-')
        try:
            new_hosts = get_ipv4_from_range(parts[0].strip(), parts[1].strip(),
                                            MAX_IPS_PER_RANGE)
        except Exception:
            if stats is not None:
                stats['error'] = ('bad range, or more than %d addresses: %s'
                                  % (MAX_IPS_PER_RANGE, value))
    # single-host IPv6 written as CIDR (/128) - no IPv6 network expansion, just the
    # one address, same as typing the bare address
    elif (value.count('/') == 1 and value.rsplit('/', 1)[1] == '128'
          and ip_version_str(value.rsplit('/', 1)[0]) == '6'):
        new_hosts = [normalize_ip(value.rsplit('/', 1)[0])]
    # any other IPv6/mask combination - no IPv6 network expansion, say so clearly
    elif value.count('/') == 1 and ip_version_str(value.rsplit('/', 1)[0]) == '6':
        if stats is not None:
            stats['error'] = 'IPv6 networks are not expanded - only a single host (/128) is supported: ' + value
    # single IP (v4 or v6) - IPv6 stored in its shortest/compressed form
    elif is_ip_host(value):
        new_hosts = [normalize_ip(value)]
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
    while _source_events:
        _ev = _source_events.pop(0)
        write_log_comment(logging_enabled, logfile_file_name, _ev[1], tz_offset, now_str=_ev[0])   # time of the event, not of the write   # shown in the report's comment timeline
    if down_streak is None:
        down_streak = {}
    # process in real chronological order (not the IP/hostname sort order the caller
    # uses for display) - a round's subgroups (full/reduced retry class, v4/v6) run
    # concurrently and finish at different real times, so their result rows are not
    # naturally time-ordered; processing them out of order would let a stale result
    # overwrite a fresher host_state entry and would write the CSV log out of order
    # (negative deltas -> negative downtime / >100% uptime in epinga.py's report).
    def _row_ts_key(e):
        try:
            return datetime.datetime.strptime(e[2], "%d/%m/%Y %H:%M:%S")
        except (ValueError, TypeError):
            return datetime.datetime.min
    log_fh = writer = None
    if logging_enabled and learning_phase and fping_result_data_sorted:
        try:
            log_fh = open(logfile_file_name, 'a', encoding='UTF8', newline='')
            writer = csv.writer(log_fh)
        except OSError:
            log_fh = writer = None   # unwritable log must not stop monitoring
    for entry in sorted(fping_result_data_sorted, key=_row_ts_key):
        hostname  = entry[0]
        new_state = entry[1]
        timestamp = entry[2]
        rtt       = entry[3]
        resolved_ip = entry[4]
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
                try:
                    _when = datetime.datetime.strptime(timestamp, "%d/%m/%Y %H:%M:%S")
                except (ValueError, TypeError):
                    _when = datetime.datetime.now()
                hist_add(hostname, _when, old_state, new_state)
        else:
            old_state = new_state
            changes   = 0
            change_ts = ''

        # timestamp must become a datetime object so CSV serializes as YYYY-MM-DD HH:MM:SS
        try:
            ts_tmp = datetime.datetime.strptime(timestamp, "%d/%m/%Y %H:%M:%S")
            timestamp = ts_tmp + datetime.timedelta(hours=tz_offset) if tz_offset else ts_tmp
        except (ValueError, TypeError):
            pass
        if change_ts:
            try:
                ct_tmp = datetime.datetime.strptime(change_ts, "%d/%m/%Y %H:%M:%S")
                change_ts = ct_tmp + datetime.timedelta(hours=tz_offset) if tz_offset else ct_tmp
            except (ValueError, TypeError):
                pass

        host_state[hostname] = [hostname, new_state, timestamp, rtt, old_state, changes, change_ts, tbd, resolved_ip]

        # up_seen tracks "seen UP at least once" for the whole run - fed here so
        # the one-time learning-phase seeding read (active_hosts_list =
        # sorted(up_seen, ...) below) has data to read once up_check_runs reaches
        # 0. Not gated on learning_done (with the default -up 0, learning_done is
        # True from run 1, which would leave up_seen permanently empty otherwise).
        if 'UP' in new_state:
            up_seen.add(hostname)

        # logging - the file is opened once per round (see log_fh below), not per row
        if writer is not None:
            writer.writerow([timestamp, hostname, old_state.replace(' ', ''),
                             new_state.replace(' ', ''), rtt, changes, change_ts, tbd,
                             resolved_ip]
                            + list(host_meta.get(hostname) or host_meta.get(resolved_ip)
                                   or _EMPTY_META) + [SOURCE_LABEL])
    if log_fh is not None:
        log_fh.close()
    if host_hist:                                   # drop the history of deleted hosts
        for _h in [h for h in host_hist if h not in host_state]:
            del host_hist[_h]

def neutralize_csv_formula(text):
    """Prefix a leading = + @ (and tab/CR) with a quote so a spreadsheet does not
    execute a free-text comment as a formula (CSV injection). '-' is deliberately
    not touched: '#INFO#' rows legitimately start with CLI flags like '-B 1.5'."""
    if text and text[0] in ('=', '+', '@', '\t', '\r'):
        return "'" + text
    return text

def write_log_comment(logging_enabled, logfile_file_name, comment_text, tz_offset=0, now_str=None):
    """Append a free-text, timestamped comment row to the CSV log (if logging is on).

    Uses the sentinel HOSTNAME '#COMMENT#' so epinga.py can split these rows out
    of the normal host data; the comment text itself goes in the IP column (last
    field) - csv.writer already quotes it safely for Excel/Numbers re-import.
    Timestamp format/tz handling matches update_host_state() so epinga.py's
    TS_FMT ('%Y-%m-%d %H:%M:%S') parser accepts it.
    Returns True if the row was written, False if logging is currently off.
    """
    if not logging_enabled or not comment_text:
        return False
    now_str = now_str or get_date_time()
    ts = datetime.datetime.strptime(now_str, "%d/%m/%Y %H:%M:%S")
    if tz_offset:
        ts = ts + datetime.timedelta(hours=tz_offset)
    logdata = [ts, '#COMMENT#', '', '', '', '', '', '', neutralize_csv_formula(comment_text)]
    try:
        with open(logfile_file_name, 'a', encoding='UTF8', newline='') as f:
            csv.writer(f).writerow(logdata)
    except OSError:
        return False
    comment_add(ts - datetime.timedelta(hours=tz_offset or 0), comment_text)
    return True

def write_log_info(logging_enabled, logfile_file_name, info_text, tz_offset=0):
    """Append a timestamped settings-snapshot row to the CSV log (if logging is on).

    Same mechanics as write_log_comment(), but with the '#INFO#' sentinel so
    epinga.py can tell a settings snapshot/change apart from a free-text
    comment. info_text is a CLI-flag-style string (e.g. '-B 1.5 -t 250 ...' for
    a full snapshot, or '-B 2.0' for a single ADV OPTIONS change) - see
    build_cli_snapshot()/format_option_cli().
    Returns True if the row was written, False if logging is currently off.
    """
    if not logging_enabled or not info_text:
        return False
    now_str = get_date_time()
    ts = datetime.datetime.strptime(now_str, "%d/%m/%Y %H:%M:%S")
    if tz_offset:
        ts = ts + datetime.timedelta(hours=tz_offset)
    logdata = [ts, '#INFO#', '', '', '', '', '', '', info_text]
    try:
        with open(logfile_file_name, 'a', encoding='UTF8', newline='') as f:
            csv.writer(f).writerow(logdata)
    except OSError:
        return False
    return True

def reset_logfile(logfile_file_name):
    """(Re)write the CSV log with just its header row - used by RESET LOGGING / L,
    both for clearing the current file and for creating a fresh one.

    Same header as the initial file creation at startup. Returns True on success,
    False if the file could not be (re)written (e.g. permission denied).
    """
    header = LOG_HEADER
    try:
        with open(logfile_file_name, 'w', encoding='UTF8') as f:
            writer = csv.writer(f)
            writer.writerow(header)
        return True
    except OSError:
        return False

# time separator in log file names - ':' is not allowed in Windows file names
LOG_TS_FMT = '%Y-%m-%d_%H-%M-%S' if os.name == 'nt' else '%Y-%m-%d_%H:%M:%S'

def new_logfile_name(tz_offset=0):
    """Fresh 'eping-log_<timestamp>.csv' name, same format used at startup."""
    now = datetime.datetime.now() + datetime.timedelta(hours=tz_offset)
    return 'eping-log_' + now.strftime(LOG_TS_FMT) + '.csv'

_rotate_std_re = re.compile(
    r'^eping-log_(\d{4}-\d{2}-\d{2}_\d{2}[:-]\d{2}[:-]\d{2})(?:-(\d+))?\.csv$')
_rotate_seq_re = re.compile(r'^(.*)-(\d+)$')

def rotated_logfile_name(current_name, tz_offset=0):
    """Next filename in a size-rotation chain (see rotate_log_if_needed()).

    Reuses the chain's ORIGINAL timestamp - the first file's, taken from
    current_name - with an incrementing '-N' suffix (N = which rotation this
    is: 1, 2, 3, ...). This is deliberately different from new_logfile_name(),
    which RESET LOGGING's 'start a fresh file' action keeps using with the
    current time - only size-based rotation renames within its own chain.
    Falls back to appending/incrementing a numeric suffix on a custom
    (--logfile) filename that doesn't match the eping-log_<timestamp> pattern.
    """
    base = os.path.basename(current_name)
    m = _rotate_std_re.match(base)
    if m:
        ts, seq = m.group(1), m.group(2)
        next_seq = int(seq) + 1 if seq else 1
        return 'eping-log_' + ts + '-' + str(next_seq) + '.csv'
    stem, ext = os.path.splitext(base)
    m2 = _rotate_seq_re.match(stem)
    if m2 and m2.group(2).isdigit():
        stem, next_seq = m2.group(1), int(m2.group(2)) + 1
    else:
        next_seq = 1
    dirpart = os.path.dirname(current_name)
    new_base = stem + '-' + str(next_seq) + ext
    return os.path.join(dirpart, new_base) if dirpart else new_base

def validate_custom_logfile_name(name):
    """Turn a user-supplied 'new logfile' name into a safe filename, or None
    if it's unusable - used by RESET LOGGING's optional custom name (CLI [L]
    and the web reset_log 'start'/'new' actions; new_logfile_name()/
    rotated_logfile_name() remain the default when no name is given).
    Appends .csv if missing; rejects blank input, path separators/traversal
    (via safe_cwd_filename()) and any name that already exists - reset_logfile()
    would silently overwrite an unrelated file otherwise.
    """
    name = (name or '').strip()
    if not name:
        return None
    if not name.lower().endswith('.csv'):
        name += '.csv'
    if not safe_cwd_filename(name, ('.csv',)):
        return None
    if os.path.exists(name):
        return None
    return name

def prune_old_logfiles(max_files):
    """Delete the oldest eping-log_*.csv files (by mtime) beyond max_files.

    max_files <= 0 means unlimited kept files (no-op). Used after a size-based
    rollover (see rotate_log_if_needed()) to enforce MAX LOG FILES.
    """
    if max_files <= 0:
        return
    try:
        files = [f for f in os.listdir('.') if f.startswith('eping-log_') and f.endswith('.csv')]
        files.sort(key=lambda f: os.path.getmtime(f))
        for old in files[:-max_files] if len(files) > max_files else []:
            try:
                os.remove(old)
            except OSError:
                pass
    except OSError:
        pass

def rotate_log_if_needed(logfile_file_name, max_size_mb, max_files, tz_offset=0):
    """Start a fresh CSV log file once the current one reaches max_size_mb.

    max_size_mb <= 0 disables rotation (default: no limit). On rollover, also
    enforces max_files via prune_old_logfiles(). Returns the active logfile
    path - unchanged unless a rollover actually happened.
    """
    if max_size_mb <= 0:
        return logfile_file_name
    try:
        size = os.path.getsize(logfile_file_name)
    except OSError:
        return logfile_file_name
    if size < max_size_mb * 1024 * 1024:
        return logfile_file_name
    new_name = rotated_logfile_name(logfile_file_name, tz_offset)
    if not reset_logfile(new_name):
        return logfile_file_name
    prune_old_logfiles(max_files)
    return new_name

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
    ssh_apply_pending()                     # JUMPHOST switch requested since the last round
    fping_cmd_output_raw_total = list()
    timings = {'dns': 0.0, 'ping': 0.0, 'groups': []}

    if not active_hosts_list:
        return [], '', (0, 0), timings

    # resolve hostnames from the cache and ping addresses instead of names
    _t = time.time()
    targets, name_map, unresolved = prepare_targets(active_hosts_list, dns_ttl, progress_cb)
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

    # fping cannot mix v4 and v6 targets in one invocation, so every retry-class
    # group above is split again by address family. In the common single-family
    # case this yields exactly one subgroup per group, same as before IPv6 support.
    subgroups = []   # (targets, retries, label, family)
    if ssh_target and jr_active():
        jr_prefetch(targets)                 # one ssh call for all uncached names
    for grp_targets, grp_retries, grp_name in groups:
        by_fam = {'4': [], '6': []}
        for t in grp_targets:
            fam = ip_version_str(t)
            if not fam and ssh_target:             # name resolved on the jump host
                fam = ssh_name_family(t)
            if fam:
                by_fam[fam].append(t)
        for fam in ('4', '6'):
            if by_fam[fam]:
                subgroups.append((by_fam[fam], grp_retries, grp_name, fam))

    lock        = threading.Lock()
    thread_list = []
    parts       = []
    total_pps   = 0.0
    stats       = [[] for _ in subgroups]
    meta        = []
    # the rate budget is shared between what is actually probed this round, not
    # between all known hosts - otherwise slicing would not speed anything up
    probed_total = sum(len(g[0]) for g in subgroups)
    for slot, (grp_targets, grp_retries, grp_name, fam) in enumerate(subgroups):
        procs, interval_ms = tune_group(len(grp_targets), probed_total,
                                        rate_pps, threads_arg, interval_arg)
        if ssh_target:
            procs = min(procs, SSH_MAX_PROCS_NT if os.name == 'nt' else SSH_MAX_PROCS)
        cmd_base = build_fping_cmd(interval_ms, grp_retries, fam)
        for chunk in split_seq(grp_targets, procs):
            thread_list.append(threading.Thread(target=timed_fping,
                                                args=(chunk, lock, cmd_base, stats, slot)))
        if interval_ms > 0:
            total_pps += procs * 1000.0 / interval_ms
        else:
            total_pps = -1.0          # -i 0: unpaced, no meaningful rate
        label = grp_name + ('/v6' if fam == '6' else '')
        if grp_name == 'reduced' and slice_count > 1:
            label = ('reduced/v6' if fam == '6' else 'reduced') + ' slice %d/%d of %d' % (
                     slice_idx % slice_count + 1, slice_count, down_total)
        parts.append('%d %s (-r %s, %d x fping, -i %dms)'
                     % (len(grp_targets), label,
                        retries if grp_retries is None else grp_retries,
                        procs, interval_ms))
        meta.append((grp_name, len(grp_targets),
                     retries if grp_retries is None else grp_retries, procs, interval_ms))
    _t = time.time()
    global _scan_error, _source_fail_reason
    _scan_error = ''
    _source_fail_reason = ''
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
    if ssh_target:
        if _source_fail_reason:
            fping_cmd_output_raw_total = list()    # no result of a broken source: hosts keep their state
            _scan_error = 'SSH SOURCE DOWN (%s): %s - reconnecting' % (SOURCE_LABEL, _source_fail_reason)
        source_set(bool(_source_fail_reason), _source_fail_reason)
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
    if _csv_fb_names:
        scan_desc += ', %d by CSV IP (no DNS)' % len(_csv_fb_names)
    if _scan_error:
        scan_desc += ' | ERROR: ' + _scan_error

    # per group: how long did fping itself actually run?
    for slot, (name, cnt, rr, procs, iv) in enumerate(meta):
        wall = 0.0
        if stats[slot]:
            wall = max(e for _, e in stats[slot]) - min(b for b, _ in stats[slot])
        timings['groups'].append((name, cnt, rr, iv, wall))

    # map the pinged address back to the hostname(s) the user entered
    rows = []
    for row in fping_cmd_output_raw_total:
        names = name_map.get(row[0])
        if not names or (len(names) == 1 and names[0] == row[0]):
            rows.append(row)          # pinged by its own name - nothing to map
            continue
        for display_name in names:
            new_row    = list(row)
            new_row[0] = display_name
            rows.append(new_row)

    if ssh_target and not jr_active() and dns_family == 'auto':
        for r in rows:                       # alternate -4 / -6 for names fping cannot resolve
            if not is_ip_host(r[0]) and 'NO-DNS' in r[1]:
                if r[0] in _ssh_fam6:
                    _ssh_fam6.discard(r[0])
                else:
                    _ssh_fam6.add(r[0])
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
# /api/status: web_state['rows'] is always replaced as a whole, never mutated, so a
# changed object identity means new rows. _rows_track['seq'] counts those changes;
# the browser echoes the last seq it rendered and gets the rows only when newer.
_rows_track      = {'ref': None, 'seq': 0}
web_state = {
    'version'          : VERSION,
    'update_available' : False,
    'datetime'         : '',
    'hostfile_name'    : '',      # FILE OPERATIONS > SAVE HOSTS FILE ON SERVER target,
    'hostfile_active'  : False,   # '' / False if eping.py was started with -df
    'all_csv'          : False,   # reference list carries inventory values (DOWNLOAD ALL HOSTS = .csv)
    'save_csv'         : False,   # shown hosts carry inventory values: SAVE HOSTS FILE writes a .csv
    'rows'             : [],
    'host_list_shown'  : [],   # DOWNLOAD > SHOWN HOSTS - currently displayed hosts
    'host_list_all'    : [],   # DOWNLOAD > ALL HOSTS - the full reference list
    'hosts'            : 0,
    'hosts_up'         : 0,
    'hosts_down'       : 0,
    'hosts_flap'       : 0,
    'pending_wait'     : False,
    'hosts_shown'      : 0,   # after the [M] display filter narrows the view
    'adv_filter'       : {},  # ADV FILTER selection, see adv_filter
    'adv_values'       : {},  # ADV FILTER choices, see adv_values()
    'run_counter'      : 0,
    'run_time'         : '0.00',
    'logging'          : False,
    'logfile'          : '',
    'filter_mode'      : 0,
    'filter_label'     : FILTER_MODES[0][0],
    'addr_mode'        : 0,
    'sort_mode'        : 0,
    'readonly'         : False,
    'learning_phase'   : True,
    'learning_run'     : 0,
    'learning_total'   : 0,
    'wait_time'        : 0.5,
    'stopped'          : False,
    'message'          : '',
    'msg_seq'          : 0,
    'scan_info'        : '',
    'phase_info'       : '',
    'scanning'         : 0.0,
    'report'           : {'status': 'idle', 'error': ''},  # GENERATE REPORT - see run_epinga_report()
}

WEB_INDEX_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>eping.py</title>
<link rel="icon" type="image/svg+xml" href="data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0iIzRhM2IzNCI+CiAgPGVsbGlwc2UgY3g9IjEyIiBjeT0iMTYuNSIgcng9IjUuNCIgcnk9IjQuMyIvPgogIDxlbGxpcHNlIGN4PSI1LjIiIGN5PSIxMC41IiByeD0iMi41IiByeT0iMy4xIi8+CiAgPGVsbGlwc2UgY3g9IjE4LjgiIGN5PSIxMC41IiByeD0iMi41IiByeT0iMy4xIi8+CiAgPGVsbGlwc2UgY3g9IjguOSIgY3k9IjUuNiIgcng9IjIuNCIgcnk9IjMuMSIvPgogIDxlbGxpcHNlIGN4PSIxNS4xIiBjeT0iNS42IiByeD0iMi40IiByeT0iMy4xIi8+Cjwvc3ZnPg==">
<style>
  :root{
    --bg:#0b0f0b; --fg:#c8d6c8; --dim:#5d6b5d; --line:#1e2a1e;
    --up:#3ddc60; --down:#ff4b4b; --acc:#7fd1ff; --panel:#101610;
    --fs:14px; --hostw:26ch;
    /* brighter than --line (structural dividers) so buttons/selects/inputs stand
       out against the near-black panel background */
    --ctrl-line:#42593f;
  }
  *{box-sizing:border-box}
  html,body{height:100%}
  body{margin:0;background:var(--bg);color:var(--fg);overflow:hidden;
       font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,"DejaVu Sans Mono",monospace;
       font-size:13px}
  header{padding:6px 12px;border-bottom:1px solid var(--line);
         display:flex;flex-wrap:wrap;gap:12px;align-items:center;justify-content:space-between}
  .title{display:flex;align-items:center;gap:8px;font-weight:700;letter-spacing:.5px}
  .title svg{flex:none;color:var(--dim)}
  .title small{color:var(--dim);font-weight:400}
  .title a{color:inherit;text-decoration:underline;text-decoration-color:var(--line)}
  .title a:hover{color:var(--acc);text-decoration-color:currentColor}
  .clock{color:var(--dim)}
  .bar{display:flex;flex-wrap:wrap;gap:6px;padding:6px 12px;border-bottom:1px solid var(--line);align-items:center}
  button{background:var(--panel);color:var(--fg);border:1px solid var(--ctrl-line);
         padding:4px 10px;cursor:pointer;font:inherit;border-radius:3px}
  button:hover{border-color:var(--acc);color:var(--acc)}
  button.on{border-color:var(--up);color:var(--up)}
  button.danger:hover{border-color:var(--down);color:var(--down)}
  #deleteFilesBtn{background:var(--down);border-color:var(--down);color:var(--bg);font-weight:600}
  #deleteFilesBtn:hover{background:var(--down);border-color:var(--down);color:var(--bg)}
  #deleteFilesBtn:disabled{opacity:.4;cursor:default}
  .fsbox{display:flex;align-items:center;gap:4px;margin-left:auto;color:var(--dim)}
  .fsbox button{padding:4px 9px}
  input[type=text],input[type=password]{background:var(--panel);color:var(--fg);border:1px solid var(--ctrl-line);
                   padding:4px 8px;font:inherit;border-radius:3px;min-width:200px}
  select{background:var(--panel) url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 10 6'%3E%3Cpath d='M1 1l4 4 4-4' fill='none' stroke='%235d6b5d' stroke-width='1.3' stroke-linecap='round' stroke-linejoin='round'/%3E%3C/svg%3E") no-repeat right 9px center;
         background-size:9px 5px;
         color:var(--fg);border:1px solid var(--ctrl-line);
         padding:4px 22px 4px 8px;font:inherit;border-radius:3px;
         -webkit-appearance:none;-moz-appearance:none;appearance:none}
  select:hover{border-color:var(--acc)}
  select.on{border-color:var(--up);color:var(--up)}
  input[type=text]:focus,input[type=password]:focus{outline:none;border-color:var(--acc)}
  input[type=text].delmode{border-color:var(--down);color:var(--down)}
  input[type=range]{width:110px;accent-color:var(--acc)}
  /* unites an input + its action button(s) as one group - no border/background,
     just keeps them tight while .sep marks the boundary to the next group */
  .grp{display:inline-flex;align-items:center;gap:6px}
  .sep{color:var(--dim);user-select:none}
  .stats{display:flex;flex-wrap:wrap;gap:16px;padding:5px 12px;border-bottom:1px solid var(--line);color:var(--dim)}
  .stats b{color:var(--fg);font-weight:600}
  .stats .u b{color:var(--up)} .stats .d b{color:var(--down)}
  .stats #scrollHint{margin-left:auto;white-space:nowrap}
  .banner{padding:6px 12px;background:#2a1414;color:var(--down);border-bottom:1px solid var(--line)}

  /* ---- compact toolbar for narrow windows (e.g. an 11" tablet) ----
     applied via body.compact, toggled by JS measuring an actual wrap (see
     fitToolbar()) instead of a guessed pixel breakpoint - label widths vary
     with font/zoom, so a fixed media-query threshold reliably breaks somewhere
     else than the one width it was picked for. Keeps the .bar's two rows
     (#ctrlsMain / #ctrlsHosts) each on one line instead of wrapping into a
     third/fourth row: tighter controls, and the font-size A-/A+ buttons +
     slider (a rarely-touched control) shrink out of the way since they cost
     the most horizontal space for the least use. */
  /* stage 1 - cheapest to give up: the font-size A-/A+ buttons + slider (a
     rarely-touched control) shrink first, everything else untouched */
  body.compact-slider .fsbox{gap:2px}
  body.compact-slider #fsMinus, body.compact-slider #fsPlus{display:none}
  body.compact-slider #fsRange{width:60px}
  /* stage 2 - only reached if stage 1 still isn't enough: shrink the actual
     controls too (also implies stage 1, added by JS alongside this class) */
  body.compact .bar{gap:4px;padding:5px 10px}
  body.compact .bar button{padding:3px 6px;font-size:12px}
  body.compact .bar select{padding:3px 18px 3px 6px;font-size:12px;
                            background-position:right 7px center;background-size:9px 5px}

  /* ---- confirmation modal (RESET LOGGING) ---- */
  .modal-overlay{position:fixed;inset:0;background:rgba(0,0,0,.55);
                 display:flex;align-items:center;justify-content:center;z-index:50}
  #hostTip{position:fixed;z-index:60;display:none;pointer-events:none;max-width:420px;
    background:var(--panel);border:1px solid var(--ctrl-line);border-radius:5px;padding:7px 10px;
    box-shadow:0 4px 14px rgba(0,0,0,.55);font-size:12px;line-height:1.45;max-height:calc(100vh - 12px);overflow:auto}
  #hostTip .h{font-weight:700;font-size:13px;margin-bottom:3px;word-break:break-all}
  #hostTip table{border-collapse:collapse}
  #hostTip td{padding:0 0 0 0;vertical-align:top}
  #hostTip td:first-child{color:var(--dim);padding-right:12px;white-space:nowrap}
  #hostTip td:last-child{word-break:break-word}
  #hostTip tr.isep td{border-top:1px solid var(--line);padding-top:3px}
  #hostTip .up{color:var(--up)} #hostTip .down{color:var(--down)}
  #hostTip.pin{pointer-events:auto;user-select:text;-webkit-user-select:text;border-color:var(--acc)}
  #hostTip .hist{margin-top:4px;border-top:1px solid var(--line);padding-top:3px}
  #hostTip .hist .t{color:var(--dim)}
  #hostTip.pin .hist .list{max-height:200px;overflow:auto;padding-right:6px}
  #hostTip .cm{color:var(--acc);word-break:break-word}
  #hostTip .cm .t{color:var(--dim)}
  #hostTip .more{color:var(--dim);font-size:11px}
  #hostTip .top{display:flex;justify-content:space-between;align-items:flex-start;gap:14px}
  #hostTip .bar{flex:0 0 auto;margin:-2px -4px 0 0;user-select:none;-webkit-user-select:none;white-space:nowrap}
  #hostTip .bar span{display:inline-block;margin-left:4px;padding:0 6px;border:1px solid var(--ctrl-line);
    border-radius:3px;color:var(--fg);cursor:pointer;font-size:11px;line-height:16px}
  #hostTip .bar span:hover{border-color:var(--acc);color:var(--acc)}
  #hostTip .bar span.dng{color:var(--down);border-color:var(--down)}
  #hostTip .bar span.dng:hover{background:var(--down);color:var(--bg)}
  .modal-box{background:var(--panel);border:1px solid var(--line);border-radius:5px;
             padding:16px 20px;min-width:280px;max-width:90vw;box-shadow:0 8px 30px rgba(0,0,0,.5)}
  .modal-box h3{margin:0 0 8px;font-size:14px;letter-spacing:.5px;color:var(--fg)}
  .modal-box p{margin:0 0 14px;color:var(--dim);font-size:12px;line-height:1.5}
  .modal-buttons{display:flex;gap:8px;flex-wrap:wrap}
  .modal-buttons button{flex:1 1 auto;white-space:nowrap}
  .modal-box.wide{width:640px;max-width:92vw;max-height:82vh;overflow-y:scroll;
    /* always show the scrollbar, not just while hovering/scrolling - the OS
       default (overlay scrollbars, e.g. macOS) otherwise hides it completely,
       leaving no hint that RESET TO DEFAULT / CLOSE are below the fold on a
       small window. scrollbar-width/-color force it in Firefox; any
       ::-webkit-scrollbar rule opts Chrome/Safari out of overlay mode too. */
    scrollbar-width:auto;scrollbar-color:var(--ctrl-line) var(--panel)}
  .modal-box.wide::-webkit-scrollbar{width:12px}
  .modal-box.wide::-webkit-scrollbar-track{background:var(--panel)}
  .modal-box.wide::-webkit-scrollbar-thumb{background:var(--ctrl-line);border-radius:6px}
  .modal-box.xwide{width:900px}
  .optchk{display:flex;align-items:center;gap:8px;margin:0 0 12px;font-size:12px;color:var(--fg);cursor:pointer}
  #advFilterRows{display:grid;grid-template-columns:repeat(auto-fill,minmax(250px,1fr));gap:12px;margin:0 0 14px}
  .advf-blk{display:flex;flex-direction:column;gap:6px;min-width:0}
  .advf-head{display:flex;justify-content:space-between;align-items:baseline;font-size:12px;font-weight:700}
  .advf-cnt{color:var(--dim);font-weight:400;font-size:11px}
  .advf-q{width:100%;box-sizing:border-box}
  .advf-bar{display:flex;gap:6px}
  .advf-bar button{flex:1 1 auto;padding:3px 6px;font-size:11px;white-space:nowrap}
  .advf-list{height:190px;overflow-y:auto;border:1px solid var(--line);border-radius:3px;padding:3px 0}
  .advf-item{display:flex;align-items:center;gap:6px;padding:1px 6px;font-size:12px;cursor:pointer;white-space:nowrap}
  .advf-item:hover{background:var(--line)}
  .advf-item.zero{color:var(--dim)}
  .advf-item span{overflow:hidden;text-overflow:ellipsis}
  .advf-more{padding:3px 6px;font-size:11px;color:var(--dim)}
  .adv-row{display:flex;flex-direction:column;gap:3px;margin:0 0 12px}
  .adv-row label{font-size:11px;color:var(--fg);font-weight:700;letter-spacing:.3px;cursor:help}
  .adv-row label .adv-desc{color:var(--dim);font-weight:400;letter-spacing:normal}
  .adv-row .adv-input-line{display:flex;align-items:center;gap:6px}
  .adv-row input[type=range]{flex:1 1 auto;width:100%;min-width:0}
  .adv-row button.advStep{flex:0 0 auto;width:22px;height:22px;padding:0;line-height:1;font-size:13px}
  /* overrides the global input[type=text]{min-width:200px} - that floor was
     keeping this box wide no matter what width the inline style asked for.
     Fixed width (not per-row) so every box lines up - 7ch fits the widest
     value in play, '72000'/'25000', with a space either side. Extra left
     margin separates it from the + button instead of crowding it. */
  .adv-row input.advText{flex:0 0 auto;width:7ch;min-width:0;margin-left:6px;
                         font-size:12px;padding:2px 4px;text-align:center}
  /* flashed briefly when the server rejects a value - see advCheckApplied() */
  .adv-row.adv-rejected input.advText{border-color:var(--down);color:var(--down);
                                      transition:border-color .1s,color .1s}

  /* ---- CLI style column grid ---- */
  #ctrls{display:inline-flex;flex-wrap:wrap;gap:6px;align-items:center;flex-basis:100%}
  .ctrls-row{display:inline-flex;flex-wrap:wrap;gap:6px;align-items:center;flex-basis:100%}
  #ctrlsMain{display:inline-flex;flex-wrap:wrap;gap:6px;align-items:center}
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
<div id="srcErr" style="display:none;background:#b3261e;color:#fff;font-weight:bold;text-align:center;padding:6px 10px;position:sticky;top:0;z-index:50"></div>
<div class="layout">
  <div id="banner" class="banner" style="display:none"></div>
  <div id="resetLogModal" class="modal-overlay" style="display:none">
    <div class="modal-box">
      <h3>RESET LOGGING</h3>
      <p id="resetLogText">Delete ALL entries in the current CSV log, or start a new file?<br>
         Keys also work: <b>Y</b>=clear, <b>N</b>=new file, <b>ESC</b>/<b>ENTER</b>=cancel.</p>
      <input type="text" id="resetLogNameInput" maxlength="255"
             placeholder="optional file name for the new file (blank = auto-generated)"
             style="width:100%;box-sizing:border-box;margin-bottom:12px">
      <div class="modal-buttons">
        <button id="modalBtnClearLog" class="danger">CLEAR LOGGING (Y)</button>
        <button id="modalBtnNewLog">NEW FILE (N)</button>
        <button id="modalBtnCancelLog">CANCEL (ESC)</button>
      </div>
    </div>
  </div>
  <div id="saveHostsModal" class="modal-overlay" style="display:none">
    <div class="modal-box" style="width:420px">
      <h3>SAVE HOSTS FILE ON SERVER</h3>
      <p id="saveHostsText">Save the currently shown hosts to the server?</p>
      <input type="text" id="saveHostsNameInput" maxlength="255"
             placeholder="file name (blank = eping-hosts.txt), .txt added automatically"
             style="width:100%;box-sizing:border-box;margin-bottom:12px" autocomplete="off">
      <div id="saveHostsOptsRow" style="display:none">
        <label class="optchk"><input type="checkbox" id="saveHostsOpts" checked> include options (opt: lines)</label>
        <label class="optchk"><input type="checkbox" id="saveHostsTxt"> save as .txt (hosts only, no inventory)</label>
      </div>
      <div class="modal-buttons">
        <button id="modalBtnSaveHostsConfirm" class="danger">SAVE (Y)</button>
        <button id="modalBtnSaveHostsCancel">CANCEL (ESC)</button>
      </div>
    </div>
  </div>
  <div id="dlHostsModal" class="modal-overlay" style="display:none">
    <div class="modal-box" style="width:420px">
      <h3 id="dlHostsTitle">DOWNLOAD HOSTS</h3>
      <p>The hosts carry inventory values (.csv).</p>
      <label class="optchk"><input type="checkbox" id="dlHostsOpts" checked> include options (opt: lines)</label>
      <label class="optchk"><input type="checkbox" id="dlHostsTxt"> save as .txt (hosts only, no inventory)</label>
      <div class="modal-buttons">
        <button id="modalBtnDlHostsOk">DOWNLOAD (Y)</button>
        <button id="modalBtnDlHostsCancel">CANCEL (ESC)</button>
      </div>
    </div>
  </div>
  <div id="stoppedModal" class="modal-overlay" style="display:none">
    <div class="modal-box">
      <h3 style="color:var(--down)">EPING.PY STOPPED</h3>
      <p id="stoppedMsg">The process is no longer running.</p>
      <div class="modal-buttons">
        <button id="modalBtnReload">RELOAD PAGE</button>
        <button id="modalBtnCloseStopped">CLOSE</button>
      </div>
    </div>
  </div>
  <div id="chooseLogModal" class="modal-overlay" style="display:none">
    <div class="modal-box wide xwide">
      <h3>CHOOSE FILE</h3>
      <p>Pick one or more files in this eping.py's working directory to download<br>
        - selecting more than one bundles them into a single ZIP.</p>
      <div style="display:flex;gap:6px;align-items:center;margin-bottom:10px">
        <button type="button" class="chooseLogExtBtn on" data-ext="csv">.CSV</button>
        <button type="button" class="chooseLogExtBtn on" data-ext="txt">.TXT</button>
        <button type="button" class="chooseLogExtBtn on" data-ext="html">.HTML</button>
      </div>
      <div style="display:flex;align-items:center;gap:18px;margin-bottom:8px">
        <label style="display:flex;align-items:center;gap:6px;color:var(--fg);font-size:12px;cursor:pointer">
          <input type="checkbox" id="chooseLogSelectAll"> select all
        </label>
        <label style="display:flex;align-items:center;gap:6px;color:var(--fg);font-size:12px;cursor:pointer"
               title="skip ZIP compression - faster for large files, no CPU cost on the server">
          <input type="checkbox" id="chooseLogNoZip"> no compression
        </label>
      </div>
      <div style="width:100%;max-height:220px;overflow-y:auto;
           margin-bottom:14px;border:1px solid var(--ctrl-line);border-radius:4px;
           padding:6px 10px;box-sizing:border-box">
        <table style="width:100%;border-collapse:collapse">
          <thead>
            <tr id="chooseLogHead" style="font-size:11px;color:var(--dim)">
              <th style="width:20px"></th>
              <th data-sort="name" style="text-align:center;cursor:pointer;user-select:none;padding:2px 10px 4px 0">NAME<span class="sortArrow"></span></th>
              <th data-sort="size" style="text-align:center;cursor:pointer;user-select:none;padding:2px 10px 4px 0">SIZE<span class="sortArrow"></span></th>
              <th data-sort="mtime" style="text-align:center;cursor:pointer;user-select:none;padding:2px 0 4px 0">DATE<span class="sortArrow"></span></th>
            </tr>
          </thead>
          <tbody id="chooseLogList"></tbody>
        </table>
      </div>
      <div class="modal-buttons">
        <button id="modalBtnChooseLogDownload">DOWNLOAD</button>
        <button id="modalBtnChooseLogCancel">CANCEL</button>
      </div>
    </div>
  </div>
  <div id="viewFileModal" class="modal-overlay" style="display:none">
    <div class="modal-box wide xwide">
      <h3>VIEW FILE</h3>
      <p>Pick one or more *.txt/*.csv files - each opens read-only in its own new tab
         (raw content, with COPY and DOWNLOAD buttons).<br>
         Files over <span id="viewFileMaxLabel"></span> can't be viewed inline - use DOWNLOAD instead.</p>
      <div style="display:flex;align-items:center;gap:18px;margin-bottom:8px">
        <label style="display:flex;align-items:center;gap:6px;color:var(--fg);font-size:12px;cursor:pointer">
          <input type="checkbox" id="viewFileSelectAll"> select all
        </label>
      </div>
      <div style="width:100%;max-height:220px;overflow-y:auto;
           margin-bottom:14px;border:1px solid var(--ctrl-line);border-radius:4px;
           padding:6px 10px;box-sizing:border-box">
        <table style="width:100%;border-collapse:collapse">
          <thead>
            <tr id="viewFileHead" style="font-size:11px;color:var(--dim)">
              <th style="width:20px"></th>
              <th data-sort="name" style="text-align:center;cursor:pointer;user-select:none;padding:2px 10px 4px 0">NAME<span class="sortArrow"></span></th>
              <th data-sort="size" style="text-align:center;cursor:pointer;user-select:none;padding:2px 10px 4px 0">SIZE<span class="sortArrow"></span></th>
              <th data-sort="mtime" style="text-align:center;cursor:pointer;user-select:none;padding:2px 0 4px 0">DATE<span class="sortArrow"></span></th>
            </tr>
          </thead>
          <tbody id="viewFileList"></tbody>
        </table>
      </div>
      <div class="modal-buttons">
        <button id="modalBtnViewFileOpen">VIEW</button>
        <button id="modalBtnViewFileCancel">CANCEL</button>
      </div>
    </div>
  </div>
  <div id="deleteFilesModal" class="modal-overlay" style="display:none">
    <div class="modal-box wide xwide">
      <h3>DELETE FILES</h3>
      <p>Pick one or more files in this eping.py's working directory to delete<br>
        - this cannot be undone.</p>
      <div style="display:flex;gap:6px;align-items:center;margin-bottom:10px">
        <button type="button" class="deleteFilesExtBtn on" data-ext="csv">.CSV</button>
        <button type="button" class="deleteFilesExtBtn on" data-ext="txt">.TXT</button>
        <button type="button" class="deleteFilesExtBtn on" data-ext="html">.HTML</button>
      </div>
      <div style="display:flex;align-items:center;gap:18px;margin-bottom:8px">
        <label style="display:flex;align-items:center;gap:6px;color:var(--fg);font-size:12px;cursor:pointer">
          <input type="checkbox" id="deleteFilesSelectAll"> select all
        </label>
      </div>
      <div style="width:100%;max-height:220px;overflow-y:auto;
           margin-bottom:14px;border:1px solid var(--ctrl-line);border-radius:4px;
           padding:6px 10px;box-sizing:border-box">
        <table style="width:100%;border-collapse:collapse">
          <thead>
            <tr id="deleteFilesHead" style="font-size:11px;color:var(--dim)">
              <th style="width:20px"></th>
              <th data-sort="name" style="text-align:center;cursor:pointer;user-select:none;padding:2px 10px 4px 0">NAME<span class="sortArrow"></span></th>
              <th data-sort="size" style="text-align:center;cursor:pointer;user-select:none;padding:2px 10px 4px 0">SIZE<span class="sortArrow"></span></th>
              <th data-sort="mtime" style="text-align:center;cursor:pointer;user-select:none;padding:2px 0 4px 0">DATE<span class="sortArrow"></span></th>
            </tr>
          </thead>
          <tbody id="deleteFilesList"></tbody>
        </table>
      </div>
      <div class="modal-buttons">
        <button id="deleteFilesBtn" class="danger" disabled
                title="delete the selected file(s) from the server - cannot be undone">DELETE</button>
        <button id="modalBtnDeleteFilesCancel">CANCEL</button>
      </div>
    </div>
  </div>
  <div id="addFromServerModal" class="modal-overlay" style="display:none">
    <div class="modal-box wide xwide">
      <h3>ADD FROM SERVER</h3>
      <p>Pick one or more `.txt` files or inventory `.csv` files in this eping.py's working directory to add their hosts.</p>
      <div style="display:flex;align-items:center;gap:18px;margin-bottom:8px">
        <label style="display:flex;align-items:center;gap:6px;color:var(--fg);font-size:12px;cursor:pointer">
          <input type="checkbox" id="addFromServerSelectAll"> select all
        </label>
      </div>
      <div style="width:100%;max-height:220px;overflow-y:auto;
           margin-bottom:14px;border:1px solid var(--ctrl-line);border-radius:4px;
           padding:6px 10px;box-sizing:border-box">
        <table style="width:100%;border-collapse:collapse">
          <thead>
            <tr id="addFromServerHead" style="font-size:11px;color:var(--dim)">
              <th style="width:20px"></th>
              <th data-sort="name" style="text-align:center;cursor:pointer;user-select:none;padding:2px 10px 4px 0">NAME<span class="sortArrow"></span></th>
              <th data-sort="size" style="text-align:center;cursor:pointer;user-select:none;padding:2px 10px 4px 0">SIZE<span class="sortArrow"></span></th>
              <th data-sort="mtime" style="text-align:center;cursor:pointer;user-select:none;padding:2px 0 4px 0">DATE<span class="sortArrow"></span></th>
            </tr>
          </thead>
          <tbody id="addFromServerList"></tbody>
        </table>
      </div>
      <div class="modal-buttons">
        <button id="addFromServerAddBtn" disabled>ADD</button>
        <button id="modalBtnAddFromServerCancel">CANCEL</button>
      </div>
    </div>
  </div>
  <div id="jumpModal" class="modal-overlay" style="display:none">
    <div class="modal-box wide">
      <h3>JUMPHOST</h3>
      <p>Run fping on a jump host via ssh instead of on this computer (the jump host resolves the names and needs fping with ICMP permission). Hosts and states are kept.</p>
      <div id="jumpPrereq" style="font-size:12px;margin-bottom:10px"></div>
      <table style="width:100%;border-collapse:collapse;font-size:12px">
        <tr><td style="padding:3px 8px 3px 0;white-space:nowrap">HOST</td><td><input type="text" id="jumpHost" style="width:100%;box-sizing:border-box" placeholder="jump.example.com or IP" autocomplete="off" spellcheck="false"></td>
            <td style="padding:3px 8px 3px 12px;white-space:nowrap">PORT</td><td><input type="text" id="jumpPort" style="width:64px;min-width:0" placeholder="22" autocomplete="off"></td></tr>
        <tr><td style="padding:3px 8px 3px 0;white-space:nowrap">USER</td><td colspan="3"><input type="text" id="jumpUser" style="width:100%;box-sizing:border-box" placeholder="login name" autocomplete="off" spellcheck="false"></td></tr>
        <tr><td style="padding:3px 8px 3px 0;white-space:nowrap">PASSWORD</td><td colspan="3"><input type="password" id="jumpSecret" style="width:100%;box-sizing:border-box" placeholder="password, or key passphrase (empty = key/agent only)" autocomplete="new-password"></td></tr>
        <tr><td style="padding:3px 8px 3px 0;white-space:nowrap">HOST KEY</td><td colspan="3"><select id="jumpHostKey" style="width:100%;box-sizing:border-box">
          <option value="accept-new">accept new hosts automatically (a changed key is still refused)</option>
          <option value="ask">ask - confirm an unknown host key (TRUST KEY)</option>
          <option value="off">off - no host key check at all (insecure)</option></select></td></tr>
        <tr><td style="padding:3px 8px 3px 0;white-space:nowrap">NAMES</td><td colspan="3"><label style="font-size:12px;cursor:pointer"><input type="checkbox" id="jumpResolve" checked> resolve names on the jump host (getent / dig / nslookup / host; for GET NAMES, PREFER HOSTNAME / IP ADDRESS, IP ONLY)</label></td></tr>
        <tr><td style="padding:3px 8px 3px 0;white-space:nowrap">KEY FILE</td><td colspan="3"><input type="text" id="jumpKey" style="width:100%;box-sizing:border-box" placeholder="optional, path on the computer running eping.py" autocomplete="off" spellcheck="false"></td></tr>
      </table>
      <div id="jumpWarn" style="display:none;font-size:11px;color:var(--flap,#d9a400);margin-top:6px">This page is not served from this computer (HTTP, no encryption): the password would cross the network in clear text. Prefer a key.</div>
      <div id="jumpFp" style="display:none;margin-top:8px;font-size:12px"></div>
      <div id="jumpStatus" style="min-height:34px;margin:10px 0;font-size:12px;color:var(--dim);word-break:break-word">&nbsp;</div>
      <div class="modal-buttons">
        <button id="jumpTestBtn">TEST</button>
        <button id="jumpConnectBtn">CONNECT</button>
        <button id="jumpLocalBtn">USE LOCAL</button>
        <button id="jumpTrustBtn" style="display:none">TRUST KEY</button>
        <button id="jumpCloseBtn">CLOSE</button>
      </div>
    </div>
  </div>
  <div id="hostListModal" class="modal-overlay" style="display:none">
    <div class="modal-box wide">
      <h3>ADD / DELETE HOST LIST</h3>
      <p>Paste hosts: IPv4/IPv6, hostname, IPv4 CIDR - separated by new line, comma, semicolon or blank; `#` starts a comment.</p>
      <textarea id="hostListText" rows="10" spellcheck="false" style="width:100%;box-sizing:border-box;margin-bottom:8px;background:var(--panel);color:var(--fg);border:1px solid var(--ctrl-line);border-radius:4px;padding:6px 8px;font-family:inherit;font-size:12px;resize:vertical"></textarea>
      <div id="hostListInfo" style="min-height:34px;margin-bottom:12px;font-size:12px;color:var(--dim)">&nbsp;</div>
      <div class="modal-buttons">
        <button id="hostListAddBtn" disabled>ADD</button>
        <button id="hostListDelBtn" class="danger" disabled>DELETE</button>
        <button id="hostListCancelBtn">CANCEL</button>
      </div>
    </div>
  </div>
  <div id="addFromClientModal" class="modal-overlay" style="display:none">
    <div class="modal-box">
      <h3>ADD FROM CLIENT</h3>
      <p>Choose a `.txt` or `.csv` hosts file from this computer to add its hosts.</p>
      <input type="file" id="fileInputVis" accept=".txt,.csv,.list,text/plain" style="margin-bottom:14px;color:var(--fg)">
      <div class="modal-buttons">
        <button id="modalBtnAddFromClientCancel">CANCEL</button>
      </div>
    </div>
  </div>
  <div id="reportSrcModal" class="modal-overlay" style="display:none">
    <div class="modal-box wide">
      <h3>SELECT JUMPHOST</h3>
      <p>Active logfile. Select the jump hosts (or local) to analyse - only their
         periods are calculated. ENTER = GENERATE (default: all sources).</p>
      <div id="reportSrcList" style="max-height:220px;overflow-y:auto;margin-bottom:14px;
           border:1px solid var(--ctrl-line);border-radius:4px;padding:6px 10px;box-sizing:border-box"></div>
      <div class="modal-buttons">
        <button id="modalBtnReportSrcGo">GENERATE</button>
        <button id="modalBtnReportSrcCancel">CANCEL</button>
      </div>
    </div>
  </div>
  <div id="chooseReportModal" class="modal-overlay" style="display:none">
    <div class="modal-box wide xwide">
      <h3>CHOOSE LOGFILE</h3>
      <p>Pick one or more *.csv log files to analyse with epinga.py as one combined report -
         max <span id="chooseReportMax"></span> files per report.</p>
      <div style="display:flex;align-items:center;gap:18px;margin-bottom:8px">
        <label style="display:flex;align-items:center;gap:6px;color:var(--fg);font-size:12px;cursor:pointer">
          <input type="checkbox" id="chooseReportSelectAll"> select all
        </label>
      </div>
      <div style="width:100%;max-height:220px;overflow-y:auto;
           margin-bottom:14px;border:1px solid var(--ctrl-line);border-radius:4px;
           padding:6px 10px;box-sizing:border-box">
        <table style="width:100%;border-collapse:collapse">
          <thead>
            <tr id="chooseReportHead" style="font-size:11px;color:var(--dim)">
              <th style="width:20px"></th>
              <th data-sort="name" style="text-align:center;cursor:pointer;user-select:none;padding:2px 10px 4px 0">NAME<span class="sortArrow"></span></th>
              <th data-sort="size" style="text-align:center;cursor:pointer;user-select:none;padding:2px 10px 4px 0">SIZE<span class="sortArrow"></span></th>
              <th data-sort="mtime" style="text-align:center;cursor:pointer;user-select:none;padding:2px 0 4px 0">DATE<span class="sortArrow"></span></th>
            </tr>
          </thead>
          <tbody id="chooseReportList"></tbody>
        </table>
      </div>
      <div class="modal-buttons">
        <button id="modalBtnChooseReportGenerate">GENERATE</button>
        <button id="modalBtnChooseReportCancel">CANCEL</button>
      </div>
    </div>
  </div>
  <div id="hostTip"></div>
  <div id="advFilterModal" class="modal-overlay" style="display:none">
    <div class="modal-box wide xwide">
      <h3>ADV FILTER</h3>
      <p>Inventory filter (hosts .csv). Per field: check values, SHOW ONLY or HIDE. Same field = OR, fields = AND. Nothing checked = field off. Display only, all hosts are still pinged.</p>
      <div id="advFilterRows"></div>
      <div class="modal-buttons">
        <button id="modalBtnAdvFApply">APPLY</button>
        <button id="modalBtnAdvFReset" class="danger">RESET ALL</button>
        <button id="modalBtnAdvFClose">CLOSE</button>
      </div>
    </div>
  </div>
  <div id="advOptionsModal" class="modal-overlay" style="display:none">
    <div class="modal-box wide">
      <h3>ADV OPTIONS</h3>
      <p>Runtime settings for timers, fping and timezone.</p>
      <div id="advOptionsRows"></div>
      <div class="modal-buttons">
        <button id="modalBtnAdvReset" class="danger">RESET TO DEFAULT</button>
        <button id="modalBtnAdvClose">CLOSE</button>
      </div>
    </div>
  </div>
  <header>
    <div class="title">
      <svg width="13" height="13" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
        <ellipse cx="12" cy="16.5" rx="5.4" ry="4.3"/>
        <ellipse cx="5.2" cy="10.5" rx="2.5" ry="3.1"/>
        <ellipse cx="18.8" cy="10.5" rx="2.5" ry="3.1"/>
        <ellipse cx="8.9" cy="5.6" rx="2.4" ry="3.1"/>
        <ellipse cx="15.1" cy="5.6" rx="2.4" ry="3.1"/>
      </svg>
      <span>eping.py <small id="ver"></small> &nbsp;&middot;&nbsp;
      &copy; Ewald Jeitler &nbsp;&middot;&nbsp;
      supervised by <a href="https://jeitler.cc/nelly/" target="_blank" rel="noopener">Nelly</a> &nbsp;&middot;&nbsp;
      <a href="https://tools.jeitler.cc" target="_blank" rel="noopener">tools.jeitler.cc</a> &nbsp;&middot;&nbsp;
      <a href="https://www.jeitler.cc" target="_blank" rel="noopener">www.jeitler.cc</a></span>
      <svg width="13" height="13" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
        <ellipse cx="12" cy="16.5" rx="5.4" ry="4.3"/>
        <ellipse cx="5.2" cy="10.5" rx="2.5" ry="3.1"/>
        <ellipse cx="18.8" cy="10.5" rx="2.5" ry="3.1"/>
        <ellipse cx="8.9" cy="5.6" rx="2.4" ry="3.1"/>
        <ellipse cx="15.1" cy="5.6" rx="2.4" ry="3.1"/>
      </svg>
      <small id="ro"></small></div>
    <div class="clock" id="clock"></div>
  </header>

  <div class="bar">
   <span id="ctrls">
    <span class="ctrls-row" id="ctrlsRow1">
     <span id="ctrlsMain">
      <select id="selFilter" title="display filter: choose which hosts are shown (evaluated live) - all hosts keep being pinged until SET REFERENCE removes the hosts that are not shown">
        <option value="0">ALL HOSTS</option>
        <option value="1">CURRENTLY-UP</option>
        <option value="3">ALWAYS-UP</option>
        <option value="2">UP+FLAPPING</option>
        <option value="4">FLAPPING-ONLY</option>
        <option value="5">ALWAYS-DOWN</option>
        <option value="6">CURRENTLY-DOWN</option>
        <option value="7">DOWN+FLAPPING</option>
        <option value="8">NO-DNS</option>
      </select>
      <select id="sortSel" title="sort order - a flapping host is grouped as FLAP regardless of its current state">
        <option value="0">ADDRESS</option>
        <option value="1">UP/FLAP/DOWN</option>
        <option value="2">DOWN/FLAP/UP</option>
        <option value="3">FLAP/UP/DOWN</option>
        <option value="4">FLAP/DOWN/UP</option>
      </select>
      <button id="btnSetRef" title="use the hosts currently shown as the new reference list - all other hosts are removed and no longer pinged">SET REFERENCE</button>
      <button id="btnZero" title="reset CH-TIME and CH NO for all hosts">ZERO CHANGES</button>
      <button id="btnClear" class="danger" title="remove every host from the list, resets all state">CLEAR ALL</button>
      <select id="selAddrMode" title="Deduplication when the same host is entered as both a hostname and its IP: hostname &amp; ip keeps both as given (no dedup) | prefer hostname: skip a raw IP already covered by a hostname | prefer ip address: skip a hostname already covered by a raw IP | ip only: resolve every hostname to its IP and ping/track it by address">
        <option value="0">HOSTNAME & IP</option>
        <option value="1">PREFER HOSTNAME</option>
        <option value="2">PREFER IP ADDRESS</option>
        <option value="3">SWITCH TO IP ONLY</option>
      </select>
      <button id="btnGetNames" title="reverse-DNS resolve IP hosts and rename them to their hostname">GET NAMES</button>
      <button id="btnAdvOptions" title="adjust fping/timer/timezone options live">ADV OPTIONS</button>
      <button id="btnJump" title="ping from a jump host via ssh instead of from this computer">JUMPHOST</button>
      <button id="btnResetLog" class="danger" title="Y=clear this file, N=start a fresh file (old kept), ESC/ENTER=cancel">RESET LOG</button>
      <select id="selDownload" title="add hosts from a file on the server or from your computer, download the full reference list, only the currently shown hosts, the active logfile, or pick any .csv/.txt/.html file; upload a *.txt/*.csv file to this eping.py's working directory, save the currently shown hosts as the server's hosts file, view a *.txt/*.csv file read-only, or delete files from it">
        <option value="" selected disabled hidden>FILE OPERATIONS</option>
        <option value="add_from_server">ADD HOSTS FILE FROM SERVER</option>
        <option value="add_from_client">ADD HOSTS FILE FROM CLIENT</option>
        <option value="save_hosts_file">SAVE HOSTS FILE ON SERVER</option>
        <option value="hosts_all">DOWNLOAD ALL HOSTS</option>
        <option value="hosts_shown">DOWNLOAD ACTIVE HOSTS</option>
        <option value="logfile">DOWNLOAD ACTIVE LOGFILE</option>
        <option value="choose_logfile">DOWNLOAD SELECTED FILES</option>
        <option value="upload_file">UPLOAD FILE TO SERVER</option>
        <option value="delete_files">DELETE FILES FROM SERVER</option>
        <option value="view_file">VIEW FILE FROM SERVER</option>
      </select>
      <input type="file" id="uploadServerFileInput" accept=".txt,.csv,text/csv,text/plain" style="display:none">
      <button id="btnExit" class="danger" title="stop eping.py">EXIT</button>
     </span>
     <span class="fsbox">
       <button id="fsMinus" title="smaller (-)">A&minus;</button>
       <input type="range" id="fsRange" min="6" max="28" step="1">
       <button id="fsPlus" title="bigger (+)">A+</button>
     </span>
    </span>
    <span class="ctrls-row" id="ctrlsHosts">
     <span class="grp">
      <input type="text" id="matchInput" title="display filter: only matching hosts are shown, every host keeps being pinged regardless" placeholder="Display filter: regex">
      <button id="btnMatchFilter" title="apply display filter">SET</button>
      <button id="btnClearFilter" title="clear display filter">CLEAR</button>
      <button id="btnAdvFilter" title="ADV FILTER (V): display filter on the inventory fields Model, Location, sysLocation, Type, Comment - only matching hosts are shown, every host keeps being pinged">ADV FILTER</button>
     </span>
     <span class="sep">&nbsp;|&nbsp;</span>
     <span class="grp">
      <input type="text" id="addInput" placeholder="IPv4/IPv6, host, IPv4 CIDR, IPv6 /128, ip1-ip2">
      <button id="btnAdd" title="add the given host(s) to the list - same input as DELETE">ADD</button>
      <button id="btnDel" title="remove the given host(s) - same input as ADD">DELETE</button>
      <button id="btnList" title="paste a list of hosts (one per line, or separated by comma/semicolon/blank) to add or delete - also opened by Ctrl/Cmd+V on the page">ADD/DEL LIST</button>
     </span>
     <span class="sep">&nbsp;|&nbsp;</span>
     <span class="grp">
      <input type="text" id="commentInput" title="free text, logged with a timestamp to the CSV (only while logging is on)" placeholder="comment for the log">
      <button id="btnComment" title="append a timestamped comment row to the CSV log">COMMENT</button>
     </span>
     <span class="sep">&nbsp;|&nbsp;</span>
     <input type="file" id="fileInput" accept=".txt,.csv,.list,text/plain" style="display:none">
     <select id="selGenReport" title="analyse a logfile with epinga.py and open the report in a new tab">
       <option value="" selected disabled hidden>GENERATE REPORT</option>
       <option value="active">ACTIVE LOGFILE</option>
       <option value="choose">CHOOSE LOGFILE</option>
       <option value="sources">SELECT JUMPHOST</option>
      </select>
    </span>
   </span>
  </div>

  <div class="stats">
    <span>HOSTS: <b id="sHosts">0</b></span>
    <span>RUNTIME: <b id="sRuntime">0.00</b><b id="sRuntimeUnit">s</b></span>
    <span>RUNS: <b id="sRuns">0</b></span>
    <span class="u">HOSTS-UP: <b id="sUp">0</b></span>
    <span class="d">HOSTS-DOWN: <b id="sDown">0</b></span>
    <span>FLAPPING: <b id="sFlap">0</b></span>
    <span title="hosts shown by the view and display filters, out of all hosts"
          id="sShownWrap">SHOWN: <b id="sShown">0</b></span>
    <span id="sLog"></span>
    <span class="msg" id="msg"></span>
    <span id="scrollHint"></span>
  </div>

  <div class="body">
    <div id="learn" class="learn" style="display:none"></div>
    <div id="grid"></div>
  </div>

  <footer id="foot">connecting ...</footer>
</div>
<div id="probe"></div>

<script>
var sortKey = null, sortDir = 1, lastRows = [], stopped = false, isReadOnly = false;
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
  document.getElementById('fsRange').value       = fontSize;
  if(save !== false) store('eping_fs', fontSize);
  render(lastRows);
}
document.getElementById('fsMinus').onclick = function(){ setFont(fontSize - 1); };
document.getElementById('fsPlus').onclick  = function(){ setFont(fontSize + 1); };
document.getElementById('fsRange').oninput = function(){ setFont(parseInt(this.value,10)); };

/* ---------------- responsive toolbar (staged compact mode) ----------------
   shrinks #ctrlsRow1 (the ALL HOSTS...EXIT button row + the font-size slider)
   in stages, each one MEASURED against an actual line wrap instead of a
   guessed pixel breakpoint - label widths depend on font rendering and
   OS/zoom, so a fixed width threshold reliably breaks at some other width
   than the one it was tuned for. Stops at the first stage that fits, so a
   window with room to spare keeps full-size buttons - only the font-size
   slider (cheapest to give up, rarely touched) shrinks first; buttons/selects
   only shrink too if that alone isn't enough. */
var COMPACT_LABELS = [
  {sel:'#selAddrMode option[value="0"]', full:'HOSTNAME & IP', short:'IP/NAME MODE'},
  {sel:'#selGenReport option[value=""]', full:'GENERATE REPORT',  short:'REPORT'}
];
// stage 3 only - the least-used labels, shortened further once stage 2 alone
// still isn't enough (very small window)
var MICRO_LABELS = [
  {sel:'#btnSetRef',      full:'SET REFERENCE',  short:'SET'},
  {sel:'#btnZero',        full:'ZERO CHANGES',   short:'ZERO'},
  {sel:'#btnClear',       full:'CLEAR ALL',      short:'CLEAR'},
  {sel:'#btnAdvOptions',  full:'ADV OPTIONS',    short:'ADV'},
  {sel:'#btnResetLog',    full:'RESET LOG',      short:'REST'}
];
function applyLabelSet(labels, compact){
  labels.forEach(function(l){
    var el = document.querySelector(l.sel);
    if(el) el.textContent = compact ? l.short : l.full;
  });
}
function rowWrapped(el){
  var kids = el.children, top0 = null;
  for(var i = 0; i < kids.length; i++){
    if(kids[i].offsetParent === null) continue;   // skip hidden (display:none) children
    if(top0 === null){ top0 = kids[i].offsetTop; continue; }
    if(kids[i].offsetTop !== top0) return true;
  }
  return false;
}
function fitToolbar(){
  var row = document.getElementById('ctrlsRow1'), body = document.body;
  if(!row) return;
  // always start from full size - shrinking can only free up space, never
  // require more, so re-measuring from scratch each time never oscillates
  body.classList.remove('compact', 'compact-slider', 'compact-micro');
  applyLabelSet(COMPACT_LABELS, false);
  applyLabelSet(MICRO_LABELS, false);
  if(!rowWrapped(row)) return;                  // stage 0: full size fits
  body.classList.add('compact-slider');
  if(!rowWrapped(row)) return;                  // stage 1: slider-only shrink fits
  body.classList.add('compact');
  applyLabelSet(COMPACT_LABELS, true);
  if(!rowWrapped(row)) return;                  // stage 2: shrink buttons + labels too
  body.classList.add('compact-micro');
  applyLabelSet(MICRO_LABELS, true);            // stage 3: shorten the least-used labels too
}
fitToolbar();
var fitRz;
window.addEventListener('resize', function(){
  clearTimeout(fitRz); fitRz = setTimeout(fitToolbar, 80);
});

/* ---------------- commands ---------------- */
var PENDING = {up_only:'switching view ...', set_filter:'switching view ...', sort:'sorting ...', add:'adding host(s) ...',
               del:'removing host(s) ...', set_ref:'setting reference ...',
               clear:'clearing all hosts ...', zero:'resetting change counters ...',
               addr_mode:'switching address mode ...',
               get_names:'resolving names ...',
               match_filter:'applying filter ...',
               adv_filter:'applying adv filter ...',
               add_comment:'logging comment ...',
               reset_log:'resetting log ...',
               set_option:'applying option ...',
               reset_options:'resetting options ...',
               run_report:'generating report ...',
               save_hosts_file:'saving hosts file ...',
               exit:'stopping eping ...'};
var pending = false, lastMsgSeq = null;
var pendingAddrMode   = null;   // see selAddrMode onchange / poll() below
var pendingFilterMode = null;   // same problem/fix as pendingAddrMode, for selFilter
var pendingSortMode   = null;   // same problem/fix as pendingAddrMode, for sortSel
var lastOptions       = {};    // ADV OPTIONS - latest snapshot from the server, see poll()

var noteClearTimer = null;
function note(text, isPending){
  var m = document.getElementById('msg');
  m.textContent = text || '';
  m.className   = isPending ? 'msg pending' : 'msg';
  pending       = !!isPending;
  clearTimeout(noteClearTimer);
  // a pending '...ing' note is replaced by its own completion note once the
  // action finishes (see poll()'s msg_seq check) - that completion note is
  // the 'done' feedback; it should not linger forever, so auto-clear it
  if(!isPending && text){
    noteClearTimer = setTimeout(function(){ m.textContent = ''; m.className = 'msg'; }, 2000);
  }
}
function post(cmd, value){
  // ADV OPTIONS deliberately never touches the footer - feedback is inline in
  // the modal itself (revert + flash on rejection, see advCheckApplied())
  if(cmd !== 'set_option' && cmd !== 'reset_options'){
    note(PENDING[cmd] || 'working ...', true);   // instant feedback, no waiting
  }
  return fetch('api/command', {method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({cmd:cmd, value:value||''})}).then(function(r){return r.json();});
}
document.getElementById('selFilter').onchange = function(){
  var picked = this.value;
  pendingFilterMode = picked;
  // safety net: stop overriding the poll if the server never echoes this back
  setTimeout(function(){ if(pendingFilterMode === picked) pendingFilterMode = null; }, 10000);
  post('set_filter', picked);
};
document.getElementById('selAddrMode').onchange = function(){
  var picked = this.value;
  pendingAddrMode = picked;
  // safety net: if the server never echoes this value back (e.g. the command
  // got lost), stop overriding the poll after a while instead of freezing the
  // dropdown on a value that will never be confirmed
  setTimeout(function(){ if(pendingAddrMode === picked) pendingAddrMode = null; }, 10000);
  post('addr_mode', picked);
};
document.getElementById('btnGetNames').onclick = function(){ post('get_names'); };
document.getElementById('btnAdvOptions').onclick = openAdvOptions;
document.getElementById('modalBtnAdvClose').onclick = closeAdvOptions;
document.getElementById('modalBtnAdvReset').onclick = function(){
  post('reset_options', '').then(function(){
    setTimeout(function(){ populateAdvOptions(lastOptions); }, 1200);
  });
};
document.getElementById('btnMatchFilter').onclick = function(){
  post('match_filter', document.getElementById('matchInput').value.trim());
};
document.getElementById('btnClearFilter').onclick = function(){
  document.getElementById('matchInput').value = '';
  post('match_filter', '');
};
document.getElementById('matchInput').addEventListener('keydown', function(e){
  if(e.key === 'Enter'){ post('match_filter', this.value.trim()); }
});
document.getElementById('sortSel').onchange = function(){
  sortKey = null;                       // server order wins again after a mode change
  var picked = this.value;
  pendingSortMode = picked;
  // safety net: stop overriding the poll if the server never echoes this back
  setTimeout(function(){ if(pendingSortMode === picked) pendingSortMode = null; }, 10000);
  post('sort', picked);
};
var chooseLogModal = document.getElementById('chooseLogModal');
function chooseLogOpen(){ return chooseLogModal.style.display !== 'none'; }
function closeChooseLog(){ chooseLogModal.style.display = 'none'; }
function humanBytes(n){
  if(n === undefined || n === null) return '';
  if(n < 1024) return n + ' B';
  if(n < 1024*1024) return (n/1024).toFixed(1) + ' KB';
  return (n/1024/1024).toFixed(1) + ' MB';
}
function startIframeDownload(src, label){
  var f = document.createElement('iframe');
  f.style.display = 'none';
  var done = false;
  function finish(ok){
    if(done) return;
    done = true;
    if(f.parentNode) document.body.removeChild(f);
    note(ok ? (label + ': downloaded') : (label + ': download may have failed'), false);
  }
  f.onload  = function(){ finish(true); };
  f.onerror = function(){ finish(false); };
  f.src = src;
  document.body.appendChild(f);
  setTimeout(function(){ finish(true); }, 60000);   // safety net, see comment above
  note('downloading ' + label + ' ...', true);
}
/* ---- shared column sort for file-picker tables (CHOOSE FILE / DELETE FILES / ADD FROM SERVER) ---- */
function sortFileList(files, state){
  var key = state.key, dir = state.dir;
  var out = files.slice();
  out.sort(function(a, b){
    var av = a[key], bv = b[key];
    if(key === 'name'){ av = av.toLowerCase(); bv = bv.toLowerCase(); }
    var cmp = av < bv ? -1 : (av > bv ? 1 : 0);
    return dir === 'desc' ? -cmp : cmp;
  });
  return out;
}
function wireFileSortHead(headEl, state, renderFn){
  Array.prototype.forEach.call(headEl.querySelectorAll('th[data-sort]'), function(th){
    th.onclick = function(){
      var key = this.dataset.sort;
      state.dir = (state.key === key) ? (state.dir === 'asc' ? 'desc' : 'asc') : (key === 'name' ? 'asc' : 'desc');
      state.key = key;
      renderFn();
    };
    th.querySelector('.sortArrow').textContent =
      (state.key === th.dataset.sort) ? (state.dir === 'asc' ? ' \u25B2' : ' \u25BC') : '';
  });
}

var chooseLogFiles = [];                          // raw list from the last /api/logfiles fetch
var chooseLogExts   = {csv: true, txt: true, html: true};   // filter toggle state
var chooseLogSort    = {key: 'mtime', dir: 'desc'};          // matches /api/logfiles' own order
function formatFileDate(ts){
  if(!ts) return '';
  var d = new Date(ts * 1000);
  function p(n){ return (n < 10 ? '0' : '') + n; }
  return d.getFullYear() + '-' + p(d.getMonth() + 1) + '-' + p(d.getDate())
       + ' ' + p(d.getHours()) + ':' + p(d.getMinutes());
}
function updateChooseLogControls(){
  var count  = document.querySelectorAll('.chooseLogCb:checked').length;
  var noZip  = document.getElementById('chooseLogNoZip');
  noZip.disabled = count > 1;
  if(noZip.disabled) noZip.checked = false;
}
function chooseLogRenderList(){
  var list = document.getElementById('chooseLogList');
  var all  = document.getElementById('chooseLogSelectAll');
  var visible = chooseLogFiles.filter(function(f){
    var ext = f.name.split('.').pop().toLowerCase();
    return !!chooseLogExts[ext];
  });
  visible = sortFileList(visible, chooseLogSort);
  list.innerHTML = '';
  all.checked = false;
  wireFileSortHead(document.getElementById('chooseLogHead'), chooseLogSort, chooseLogRenderList);
  if(!visible.length){
    list.innerHTML = '<tr><td style="color:var(--dim);font-size:12px;padding:3px 0">no matching files</td></tr>';
    all.disabled = true;
    return;
  }
  visible.forEach(function(f){
    var tr = document.createElement('tr');
    tr.style.cssText = 'cursor:pointer;font-size:12px';
    var tdCb = document.createElement('td');
    tdCb.style.cssText = 'width:20px;padding:3px 4px 3px 0';
    var cb = document.createElement('input');
    cb.type      = 'checkbox';
    cb.className = 'chooseLogCb';
    cb.value     = f.name;
    tdCb.appendChild(cb);
    var tdName = document.createElement('td');
    tdName.style.cssText = 'padding:3px 10px 3px 0;white-space:nowrap';
    tdName.textContent = f.name + (f.active ? '  (ACTIVE)' : '');
    var tdSize = document.createElement('td');
    tdSize.style.cssText = 'padding:3px 10px 3px 0;text-align:right;white-space:nowrap;color:var(--dim)';
    tdSize.textContent = humanBytes(f.size);
    var tdDate = document.createElement('td');
    tdDate.style.cssText = 'padding:3px 0;text-align:right;white-space:nowrap;color:var(--dim)';
    tdDate.textContent = formatFileDate(f.mtime);
    tr.appendChild(tdCb);
    tr.appendChild(tdName);
    tr.appendChild(tdSize);
    tr.appendChild(tdDate);
    tr.onclick = function(e){ if(e.target !== cb){ cb.checked = !cb.checked; } updateChooseLogControls(); };
    list.appendChild(tr);
  });
  all.disabled = false;
  updateChooseLogControls();
}
function openChooseLog(){
  var list = document.getElementById('chooseLogList');
  var all  = document.getElementById('chooseLogSelectAll');
  list.innerHTML = '<tr><td style="color:var(--dim);font-size:12px;padding:3px 0">loading ...</td></tr>';
  all.checked  = false;
  all.disabled = true;
  chooseLogModal.style.display = 'flex';
  fetch('api/logfiles').then(function(r){ return r.json(); }).then(function(j){
    chooseLogFiles = j.files || [];
    chooseLogRenderList();
  }).catch(function(){
    list.innerHTML = '<tr><td style="color:var(--dim);font-size:12px;padding:3px 0">failed to list files</td></tr>';
  });
}
Array.prototype.forEach.call(document.querySelectorAll('.chooseLogExtBtn'), function(btn){
  btn.onclick = function(){
    var ext = this.dataset.ext;
    chooseLogExts[ext] = !chooseLogExts[ext];
    this.classList.toggle('on', chooseLogExts[ext]);
    chooseLogRenderList();
  };
});
document.getElementById('chooseLogSelectAll').onchange = function(){
  var checked = this.checked;
  Array.prototype.forEach.call(document.querySelectorAll('.chooseLogCb'), function(cb){ cb.checked = checked; });
  updateChooseLogControls();
};
document.getElementById('modalBtnChooseLogCancel').onclick = closeChooseLog;

/* ---- VIEW FILE (FILE OPERATIONS > VIEW FILE FROM SERVER) - read-only, one
   new tab per selected *.txt/*.csv file, raw content + COPY/DOWNLOAD ---- */
// must match VIEW_FILE_MAX_BYTES in eping.py - do_GET rejects larger files with 413
var VIEW_FILE_MAX_BYTES = 200 * 1024 * 1024;
var viewFileFiles = [];
var viewFileSort  = {key: 'mtime', dir: 'desc'};
var viewFileModal = document.getElementById('viewFileModal');
function viewFileOpen(){ return viewFileModal.style.display !== 'none'; }
function closeViewFile(){ viewFileModal.style.display = 'none'; }
function viewFileRenderList(){
  var list = document.getElementById('viewFileList');
  var all  = document.getElementById('viewFileSelectAll');
  var visible = sortFileList(viewFileFiles, viewFileSort);
  list.innerHTML = '';
  all.checked = false;
  wireFileSortHead(document.getElementById('viewFileHead'), viewFileSort, viewFileRenderList);
  if(!visible.length){
    list.innerHTML = '<tr><td style="color:var(--dim);font-size:12px;padding:3px 0">no *.txt/*.csv files found</td></tr>';
    all.disabled = true;
    return;
  }
  visible.forEach(function(f){
    var tooLarge = f.size > VIEW_FILE_MAX_BYTES;
    var tr = document.createElement('tr');
    tr.style.cssText = 'cursor:' + (tooLarge ? 'default' : 'pointer') + ';font-size:12px'
                        + (tooLarge ? ';opacity:0.45' : '');
    var tdCb = document.createElement('td');
    tdCb.style.cssText = 'width:20px;padding:3px 4px 3px 0';
    var cb = document.createElement('input');
    cb.type      = 'checkbox';
    cb.className = 'viewFileCb';
    cb.value     = f.name;
    cb.disabled  = tooLarge;
    tdCb.appendChild(cb);
    var tdName = document.createElement('td');
    tdName.style.cssText = 'padding:3px 10px 3px 0;white-space:nowrap';
    tdName.textContent = f.name + (f.active ? '  (ACTIVE)' : '') + (tooLarge ? '  - TOO LARGE' : '');
    var tdSize = document.createElement('td');
    tdSize.style.cssText = 'padding:3px 10px 3px 0;text-align:right;white-space:nowrap;color:var(--dim)';
    tdSize.textContent = humanBytes(f.size);
    var tdDate = document.createElement('td');
    tdDate.style.cssText = 'padding:3px 0;text-align:right;white-space:nowrap;color:var(--dim)';
    tdDate.textContent = formatFileDate(f.mtime);
    tr.appendChild(tdCb);
    tr.appendChild(tdName);
    tr.appendChild(tdSize);
    tr.appendChild(tdDate);
    if(!tooLarge) tr.onclick = function(e){ if(e.target !== cb){ cb.checked = !cb.checked; } };
    list.appendChild(tr);
  });
  all.disabled = false;
}
function openViewFile(){
  var list = document.getElementById('viewFileList');
  var all  = document.getElementById('viewFileSelectAll');
  list.innerHTML = '<tr><td style="color:var(--dim);font-size:12px;padding:3px 0">loading ...</td></tr>';
  all.checked  = false;
  all.disabled = true;
  document.getElementById('viewFileMaxLabel').textContent = humanBytes(VIEW_FILE_MAX_BYTES);
  viewFileModal.style.display = 'flex';
  fetch('api/logfiles').then(function(r){ return r.json(); }).then(function(j){
    viewFileFiles = (j.files || []).filter(function(f){
      var ext = f.name.split('.').pop().toLowerCase();
      return ext === 'csv' || ext === 'txt';
    });
    viewFileRenderList();
  }).catch(function(){
    list.innerHTML = '<tr><td style="color:var(--dim);font-size:12px;padding:3px 0">failed to list files</td></tr>';
  });
}
document.getElementById('viewFileSelectAll').onchange = function(){
  var checked = this.checked;
  Array.prototype.forEach.call(document.querySelectorAll('.viewFileCb'), function(cb){
    if(!cb.disabled) cb.checked = checked;
  });
};
document.getElementById('modalBtnViewFileCancel').onclick = closeViewFile;

// VIEW FILE FROM SERVER opens api/view_file?name=...&queue=...&queue=... - a
// server-rendered page (see render_view_file_page() in eping.py), not a
// client-built one. Only the FIRST file is opened from here (one genuine
// click = one window.open(), always allowed); every file after that is
// opened by the user clicking a plain <a target="_blank"> link INSIDE that
// page, which every browser treats as ordinary navigation. Earlier attempts
// used window.open() from a click inside the previous tab (Chrome/Firefox
// block that - only Safari allowed it) and a window.opener callback back to
// this window (same result: blocked everywhere but Safari) - a real anchor
// is what actually works across browsers, so the whole client-side queue/
// popup dance is gone.
document.getElementById('modalBtnViewFileOpen').onclick = function(){
  var boxes = document.querySelectorAll('.viewFileCb:checked');
  var names = Array.prototype.map.call(boxes, function(cb){ return cb.value; });
  if(!names.length) return;
  closeViewFile();
  var qs = 'name=' + encodeURIComponent(names[0]);
  for(var i = 1; i < names.length; i++) qs += '&queue=' + encodeURIComponent(names[i]);
  if(!window.open('/api/view_file?' + qs, '_blank')){
    note('tab blocked by the browser’s popup blocker', false);
  }
};

/* ---- DELETE FILES (FILE ACTIONS > DELETE FILES) - own modal, was CHOOSE
   FILE's DELETE button up to v3.25 ---- */
var deleteFilesFiles = [];
var deleteFilesExts  = {csv: true, txt: true, html: true};
var deleteFilesSort  = {key: 'mtime', dir: 'desc'};
var deleteFilesModal = document.getElementById('deleteFilesModal');
function deleteFilesOpen(){ return deleteFilesModal.style.display !== 'none'; }
function closeDeleteFiles(){ deleteFilesModal.style.display = 'none'; }
function updateDeleteFilesControls(){
  var count = document.querySelectorAll('.deleteFilesCb:checked').length;
  document.getElementById('deleteFilesBtn').disabled = count === 0;
}
function deleteFilesRenderList(){
  var list = document.getElementById('deleteFilesList');
  var all  = document.getElementById('deleteFilesSelectAll');
  var visible = deleteFilesFiles.filter(function(f){
    var ext = f.name.split('.').pop().toLowerCase();
    return !!deleteFilesExts[ext];
  });
  visible = sortFileList(visible, deleteFilesSort);
  list.innerHTML = '';
  all.checked = false;
  wireFileSortHead(document.getElementById('deleteFilesHead'), deleteFilesSort, deleteFilesRenderList);
  if(!visible.length){
    list.innerHTML = '<tr><td style="color:var(--dim);font-size:12px;padding:3px 0">no matching files</td></tr>';
    all.disabled = true;
    updateDeleteFilesControls();
    return;
  }
  visible.forEach(function(f){
    var tr = document.createElement('tr');
    tr.style.cssText = f.active
      ? 'font-size:12px;opacity:.45;cursor:not-allowed'
      : 'cursor:pointer;font-size:12px';
    var tdCb = document.createElement('td');
    tdCb.style.cssText = 'width:20px;padding:3px 4px 3px 0';
    var cb = document.createElement('input');
    cb.type      = 'checkbox';
    cb.className = 'deleteFilesCb';
    cb.value     = f.name;
    if(f.active) cb.disabled = true;   // active logfile - server refuses deleting it, see /api/delete_logfile
    tdCb.appendChild(cb);
    var tdName = document.createElement('td');
    tdName.style.cssText = 'padding:3px 10px 3px 0;white-space:nowrap';
    tdName.textContent = f.name + (f.active ? '  (ACTIVE)' : '');
    var tdSize = document.createElement('td');
    tdSize.style.cssText = 'padding:3px 10px 3px 0;text-align:right;white-space:nowrap;color:var(--dim)';
    tdSize.textContent = humanBytes(f.size);
    var tdDate = document.createElement('td');
    tdDate.style.cssText = 'padding:3px 0;text-align:right;white-space:nowrap;color:var(--dim)';
    tdDate.textContent = formatFileDate(f.mtime);
    tr.appendChild(tdCb);
    tr.appendChild(tdName);
    tr.appendChild(tdSize);
    tr.appendChild(tdDate);
    if(!f.active){
      tr.onclick = function(e){ if(e.target !== cb){ cb.checked = !cb.checked; } updateDeleteFilesControls(); };
    }
    list.appendChild(tr);
  });
  all.disabled = false;
  updateDeleteFilesControls();
}
function openDeleteFiles(){
  var list = document.getElementById('deleteFilesList');
  var all  = document.getElementById('deleteFilesSelectAll');
  list.innerHTML = '<tr><td style="color:var(--dim);font-size:12px;padding:3px 0">loading ...</td></tr>';
  all.checked  = false;
  all.disabled = true;
  deleteFilesModal.style.display = 'flex';
  fetch('api/logfiles').then(function(r){ return r.json(); }).then(function(j){
    deleteFilesFiles = j.files || [];
    deleteFilesRenderList();
  }).catch(function(){
    list.innerHTML = '<tr><td style="color:var(--dim);font-size:12px;padding:3px 0">failed to list files</td></tr>';
  });
}
Array.prototype.forEach.call(document.querySelectorAll('.deleteFilesExtBtn'), function(btn){
  btn.onclick = function(){
    var ext = this.dataset.ext;
    deleteFilesExts[ext] = !deleteFilesExts[ext];
    this.classList.toggle('on', deleteFilesExts[ext]);
    deleteFilesRenderList();
  };
});
document.getElementById('deleteFilesSelectAll').onchange = function(){
  var checked = this.checked;
  Array.prototype.forEach.call(document.querySelectorAll('.deleteFilesCb'), function(cb){
    if(!cb.disabled) cb.checked = checked;
  });
  updateDeleteFilesControls();
};
document.getElementById('deleteFilesBtn').onclick = function(){
  var boxes = document.querySelectorAll('.deleteFilesCb:checked');
  var names = Array.prototype.map.call(boxes, function(cb){ return cb.value; });
  if(!names.length) return;
  if(!confirm('Delete ' + names.length + ' file(s)? This cannot be undone.')) return;
  fetch('api/delete_logfile', {method: 'POST', headers: {'Content-Type': 'application/json'},
                               body: JSON.stringify({names: names})})
    .then(function(r){ return r.json(); })
    .then(function(j){
      var deleted = j.deleted || [];
      if(deleted.length){
        deleteFilesFiles = deleteFilesFiles.filter(function(f){ return deleted.indexOf(f.name) === -1; });
        deleteFilesRenderList();
      }
      if(j.errors && j.errors.length){
        note(deleted.length + ' deleted, ' + j.errors.length + ' failed', false);
      } else {
        note('deleted ' + deleted.length + ' file(s)', false);
      }
    })
    .catch(function(){ note('delete failed', false); });
};
document.getElementById('modalBtnDeleteFilesCancel').onclick = closeDeleteFiles;
document.getElementById('modalBtnChooseLogDownload').onclick = function(){
  var boxes = document.querySelectorAll('.chooseLogCb:checked');
  var names = Array.prototype.map.call(boxes, function(cb){ return cb.value; });
  if(!names.length) return;
  closeChooseLog();
  var qs = names.map(function(n){ return 'name=' + encodeURIComponent(n); }).join('&');
  if(document.getElementById('chooseLogNoZip').checked) qs += '&nozip=1';
  var label = names.length === 1 ? names[0] : (names.length + ' file(s)');
  startIframeDownload('api/download/choose_logfile?' + qs, label);
};
var resetLogModal = document.getElementById('resetLogModal');
var loggingOn = false;   // kept in sync from every status poll, see render()
var hostfileActive  = false;   // FILE OPERATIONS > SAVE HOSTS FILE ON SERVER -
var hostfileName    = '';      // all three kept in sync from every status poll,
var shownHostsCount = 0;       // see render()
var allCsv          = false;   // reference list carries inventory values: DOWNLOAD ALL HOSTS is a .csv
var saveCsv         = false;   // shown hosts carry inventory values: SAVE writes a .csv
var reportWindow = null; // blank tab opened by GENERATE REPORT, filled in once ready - see poll()
function resetLogOpen(){ return resetLogModal.style.display !== 'none'; }
function closeResetLog(){ resetLogModal.style.display = 'none'; }
function openResetLog(){
  // shown for BOTH states now - OFF just skips the CLEAR button and Y/N text,
  // since there's nothing to clear yet, but still offers a custom file name
  var clearBtn = document.getElementById('modalBtnClearLog');
  var newBtn   = document.getElementById('modalBtnNewLog');
  var text     = document.getElementById('resetLogText');
  document.getElementById('resetLogNameInput').value = '';
  if(loggingOn){
    clearBtn.style.display = '';
    newBtn.textContent = 'NEW FILE (N)';
    text.innerHTML = 'Delete ALL entries in the current CSV log, or start a new file?<br>' +
      'Optional name for the new file below (blank = auto-generated).<br>' +
      'Keys also work: <b>Y</b>=clear, <b>N</b>=new file, <b>ESC</b>/<b>ENTER</b>=cancel.';
  } else {
    clearBtn.style.display = 'none';
    newBtn.textContent = 'START LOGGING (N)';
    text.innerHTML = 'Start logging to a new CSV file.<br>' +
      'Optional name below (blank = auto-generated).<br>' +
      'Keys also work: <b>N</b>/<b>ENTER</b>=start, <b>ESC</b>=cancel.';
  }
  resetLogModal.style.display = 'flex';
  document.getElementById('resetLogNameInput').focus();
}
function runResetLog(action){
  // action: 'y' | 'new' - the optional custom name (if any) is appended to
  // 'new' as 'new=<name>'; OFF state sends the name alone (see the three
  // reset_log handlers server-side for this same encoding).
  var name = document.getElementById('resetLogNameInput').value.trim();
  closeResetLog();
  if(!loggingOn){ post('reset_log', name); return; }
  post('reset_log', action === 'new' && name ? 'new=' + name : action);
}

/* ---- FILE OPERATIONS > SAVE HOSTS FILE ON SERVER ---- */
var saveHostsModal = document.getElementById('saveHostsModal');
function saveHostsOpen(){ return saveHostsModal.style.display !== 'none'; }
function closeSaveHosts(){ saveHostsModal.style.display = 'none'; }
function openSaveHosts(){
  var input = document.getElementById('saveHostsNameInput');
  var text  = document.getElementById('saveHostsText');
  input.value = '';
  input.style.display = '';
  var ext  = saveCsv ? '.csv' : '.txt';
  // an inventory is saved as .csv - same rule as resolve_save_target() server-side
  var tgt  = (saveCsv && !/\.csv$/i.test(hostfileName)) ? hostfileName.replace(/\.[^.\/\\]*$/, '') + '.csv' : hostfileName;
  var kind = saveCsv ? ' (inventory .csv with the Model/Location/... columns)' : '';
  if(hostfileActive){
    text.innerHTML = 'Overwrite <b>' + esc(tgt) + '</b> on the server with the '
      + shownHostsCount + ' host(s) currently shown' + kind + ' - or type a new name below to '
      + 'save as a different file instead:';
    input.placeholder = 'blank = overwrite ' + tgt + ', or new file name (' + ext + ' added automatically)';
  } else {
    text.innerHTML = 'eping.py was started without a hosts file. Save the '
      + shownHostsCount + ' host(s) currently shown' + kind + ' as a new file on the server:';
    input.placeholder = 'file name (blank = eping-hosts' + ext + '), ' + ext + ' added automatically';
  }
  document.getElementById('saveHostsOpts').checked = true;       // default: with options
  document.getElementById('saveHostsTxt').checked = false;       // default: inventory .csv
  document.getElementById('saveHostsOptsRow').style.display = saveCsv ? '' : 'none';
  saveHostsModal.style.display = 'flex';
  input.focus();
}
function runSaveHostsFile(){
  // a typed name always means "save as this (possibly new) file" server-side,
  // even with a hostfile already active - blank means "overwrite the active
  // hostfile" when one is active, or the default eping-hosts.txt otherwise
  // (see sanitize_hostfile_save_name())
  var name = document.getElementById('saveHostsNameInput').value.trim();
  var withOpts = !saveCsv || document.getElementById('saveHostsOpts').checked;
  var asTxt    = saveCsv && document.getElementById('saveHostsTxt').checked;
  closeSaveHosts();
  post(asTxt ? (withOpts ? 'save_hosts_txt' : 'save_hosts_txt_noopt')
              : (withOpts ? 'save_hosts_file' : 'save_hosts_noopt'), name);
}
document.getElementById('modalBtnSaveHostsConfirm').onclick = runSaveHostsFile;
document.getElementById('modalBtnSaveHostsCancel').onclick  = closeSaveHosts;

// key, label, unit, sliderMin, sliderMax, step, longDesc (full mouseover tooltip),
// shortDesc (few words, shown inline next to the label).
// Same order and same hard bounds as ADV_OPTIONS server-side (BACKOFF_MIN etc.) -
// one set of limits, enforced on both ends; apply_adv_option() re-validates every
// value anyway, this is just what the slider itself can be dragged to.
// The (unit) shown after the label always names the unit, never a sentinel note
// (0=off, -1=auto etc.) - those live in longDesc/shortDesc instead.
var ADV_OPTIONS_UI = [
  ['backoff',        'BACKOFF',        '×',    1,   2,    0.1,
    'Exponential backoff factor: fping multiplies TIMEOUT by this after every failed retry, so the wait time grows the longer a host stays unreachable',
    'retry timeout multiplier'],
  ['timeout',        'TIMEOUT',        'ms',  10,  5000, 10,
    'Initial per-target timeout: how long fping waits for a reply to the first probe before retrying',
    'initial per-host timeout'],
  ['retries',        'RETRIES',        'tries', 0,   5,    1,
    'Number of retries per host before it is reported DOWN (hosts already confirmed DOWN use DOWN RETRIES instead)',
    'retries before DOWN'],
  ['down_retries',   'DOWN RETRIES',   'tries', 0,   5,    1,
    'Retries for hosts already known to be DOWN - fewer retries here shortens the round since DOWN hosts dominate its length. 0 = disabled, every host gets the full RETRIES budget',
    'retries once already DOWN'],
  ['interval',       'INTERVAL',       'ms',  -1,  250,  1,
    'Fixed interval between individual pings in ms, overrides RATE. -1 = auto (unset, use RATE instead). 0 = no pacing at all, needs the privileges fping was installed with',
    'fixed ping spacing'],
  ['num_of_threads', 'THREADS',        'procs', 0,   32,   1,
    'fping processes run in parallel per retry group. 0 = auto (one process). Higher values finish a round faster but cost measurement accuracy - see the README',
    'fping processes per group'],
  ['waittime',       'WAIT TIME',      's',   0,   600,  0.5,
    'Pause between the end of one ping round and the start of the next',
    'pause between rounds'],
  ['confirm',        'CONFIRM',        'obs', 1,   10,   1,
    'Consecutive DOWN observations required before a host leaves the UP state. 1 = report every single observation, higher values damp flapping at the cost of slower DOWN detection',
    'DOWN confirmations needed'],
  ['rate_pps',       'RATE',           'pps', 10,  25000,10,
    'Target aggregate ICMP packets per second across all fping processes combined',
    'packets per second'],
  ['flap_window',    'FLAP WINDOW',    'min', 1,   72000,10,
    'Minutes since a host\'s last state change for it to still count as flapping',
    'flapping detection window'],
  ['down_slices',    'DOWN SLICES',    'rounds', 1,   20,   1,
    'Spreads known-DOWN hosts over N rounds instead of probing all of them every round, shortening the cycle for UP hosts. 1 = probe every DOWN host every round',
    'DOWN hosts spread over N rounds'],
  ['full_sweep',     'FULL SWEEP',     'rounds', 0,   50,   1,
    'Every Nth round probes every host with the full retry budget, ignoring DOWN RETRIES/DOWN SLICES for that round. 0 = disabled, never',
    'full-retry sweep interval'],
  ['dns_ttl',        'DNS TTL',        's',   0,   3600, 10,
    'Seconds a resolved hostname stays cached before being looked up again. 0 = let fping resolve it fresh every round',
    'hostname cache lifetime'],
  ['tz_offset',      'TIMEZONE',       'h',   -24, 24,   1,
    'Hour offset applied to every timestamp shown in the web gui and written to the CSV log',
    'timestamp offset'],
  ['log_max_size',   'MAX LOG SIZE',   'MB',   0,   2500, 50,
    'Max size of the current CSV log file before rolling over to a new one. 0 = no limit (range 100-2500 when set)',
    'log rotation size'],
  ['log_max_files',  'MAX LOG FILES',  '',     0,   500,  10,
    'Max number of eping-log_*.csv files kept - the oldest is deleted once a rollover exceeds this. 0 = unlimited',
    'log files kept']
];
var advOptionsModal = document.getElementById('advOptionsModal');
var advRowsBuilt     = false;

// ADV OPTIONS has no footer feedback (see post()) - this is the whole feedback
// path instead: after a value is posted, wait for it to round-trip through a
// poll (lastOptions, updated in poll() below), then check whether the server
// actually took it. A rejected/out-of-range value leaves the server's value
// unchanged, so a mismatch here means 'rejected' - revert the field to what the
// server actually has and flash it red briefly, no text needed.
//
// advPending tracks (at most) one outstanding check per key - a newer edit to
// the same key simply overwrites the older pending entry, so there is never a
// stale check left comparing against a value that has already moved on.
//
// A queued option change is only actually applied server-side the next time
// run_web_mode() drains web_commands, at the top of its loop - it can sit
// queued for as long as the CURRENT fping round takes (many hosts, or a high
// TIMEOUT/RETRIES/BACKOFF itself, easily exceed a couple of seconds). So this
// is checked on every poll() tick (see below) against a generous timeout,
// instead of a single fixed-delay check - a slow round is not the same as the
// server rejecting the value, and treating it as one was causing the field to
// flash red and jump back even though the change would have landed fine.
var advPending = {};              // key -> {row, sl, tx, sentVal, deadline}
var ADV_CHECK_TIMEOUT_MS = 20000; // generous - covers even a slow round on a big host list
function advCheckApplied(row, sl, tx, key, sentVal){
  advPending[key] = {row: row, sl: sl, tx: tx, sentVal: sentVal,
                     deadline: Date.now() + ADV_CHECK_TIMEOUT_MS};
}
function advPollCheck(){
  for(var key in advPending){
    var p = advPending[key];
    var actual = lastOptions[key];
    if(actual === undefined) continue;   // no options snapshot yet
    var a = parseFloat(actual), e = parseFloat(p.sentVal);
    var same = (!isNaN(a) && !isNaN(e)) ? Math.abs(a - e) < 0.05 : (String(actual) === String(p.sentVal));
    if(same){ delete advPending[key]; continue; }
    if(Date.now() < p.deadline) continue;   // still might land - keep waiting
    if(p.sl && !isNaN(a)) p.sl.value = actual;
    if(p.tx) p.tx.value = actual;
    p.row.classList.add('adv-rejected');
    (function(rw){ setTimeout(function(){ rw.classList.remove('adv-rejected'); }, 1600); })(p.row);
    delete advPending[key];
  }
}
function buildAdvRows(){
  if(advRowsBuilt) return;
  var c = document.getElementById('advOptionsRows');
  ADV_OPTIONS_UI.forEach(function(o){
    var key = o[0], label = o[1], unit = o[2], lo = o[3], hi = o[4], step = o[5];
    var desc = o[6] || '', shortDesc = o[7] || '';
    var row = document.createElement('div');
    row.className = 'adv-row';
    row.title = desc;
    // textbox width is fixed (same for every row) via .adv-row input.advText -
    // see that CSS rule for why. Label line: 'NAME (unit) | short description',
    // full description is the mouseover tooltip on the whole row
    row.innerHTML = '<label title="' + esc(desc) + '">' + esc(label)
      + (unit ? ' (' + esc(unit) + ')' : '')
      + (shortDesc ? ' <span class="adv-desc">| ' + esc(shortDesc) + '</span>' : '')
      + '</label>'
      + '<div class="adv-input-line">'
      + '<button type="button" class="advStep advMinus" data-key="' + key + '" title="decrease">&minus;</button>'
      + '<input type="range" class="advSlider" data-key="' + key + '" min="' + lo + '" max="' + hi + '" step="' + step + '" title="' + esc(desc) + '">'
      + '<button type="button" class="advStep advPlus" data-key="' + key + '" title="increase">+</button>'
      + '<input type="text" class="advText" data-key="' + key + '" inputmode="decimal" title="' + esc(desc) + '">'
      + '</div>';
    c.appendChild(row);
    var sl = row.querySelector('.advSlider');
    var tx = row.querySelector('.advText');
    var mi = row.querySelector('.advMinus');
    var pl = row.querySelector('.advPlus');
    function sendOption(val){
      post('set_option', key + '=' + val);
      advCheckApplied(row, sl, tx, key, val);
    }
    sl.addEventListener('input',  function(){ tx.value = sl.value; });
    sl.addEventListener('change', function(){ sendOption(sl.value); });
    function commitText(){
      var v = parseFloat(tx.value.trim());
      if(isNaN(v)) v = lo;
      if(v < lo) v = lo;
      if(v > hi) v = hi;
      v = Math.round(v * 1000) / 1000;   // avoid float drift (0.1 steps)
      sl.value = v; tx.value = v;
      sendOption(v);
    }
    tx.addEventListener('change', commitText);
    tx.addEventListener('keydown', function(e){ if(e.key === 'Enter') tx.blur(); });
    function step_by(dir){
      var cur = parseFloat(sl.value);
      if(isNaN(cur)) cur = lo;
      var next = Math.round((cur + dir * step) * 1000) / 1000;   // avoid float drift (0.1 steps)
      if(next < lo) next = lo;
      if(next > hi) next = hi;
      sl.value = next; tx.value = next;
      sendOption(next);
    }
    mi.addEventListener('click', function(){ step_by(-1); });
    pl.addEventListener('click', function(){ step_by(1); });
  });
  advRowsBuilt = true;
}
function populateAdvOptions(opts){
  ADV_OPTIONS_UI.forEach(function(o){
    var key = o[0], val = opts[key];
    if(val === undefined) return;
    var sl = document.querySelector('#advOptionsRows .advSlider[data-key="' + key + '"]');
    var tx = document.querySelector('#advOptionsRows .advText[data-key="' + key + '"]');
    if(tx) tx.value = val;
    // a range input silently ignores a non-numeric .value assignment (stays
    // wherever it was) - guard against that instead of a mismatched thumb
    if(sl && val !== '' && !isNaN(parseFloat(val))) sl.value = val;
  });
}
function openAdvOptions(){
  buildAdvRows();
  populateAdvOptions(lastOptions);
  advOptionsModal.style.display = 'flex';
}
function closeAdvOptions(){ advOptionsModal.style.display = 'none'; }
function advOptionsOpen(){ return advOptionsModal.style.display !== 'none'; }

/* ---------------- ADV FILTER ---------------- */
var advFilterModal = document.getElementById('advFilterModal');
var lastAdv = {values: {}, filter: {}};     // latest snapshot from the server, see poll()
var ADV_NONE = '\u0001none';
var ADV_MAXROWS = 500;                       // rendered rows per list, rest via search
var ADV_FIELD_UI = [['model', 'Model'], ['location', 'Location'], ['sysloc', 'sysLocation'],
                    ['type', 'Type'], ['comment', 'Comment']];
var advDraft = {};      // key -> {mode: 'in'|'out', sel: {value: true}}
var advView  = {};      // key -> {values: [[v, n], ...], empty: n} as currently offered
var advSearch = {};     // key -> search text
// Excel-style: per field check values; mode 'in' = show only the checked ones,
// 'out' = hide the checked ones; OR within a field, AND across fields.
function advDraftFrom(filter){
  var d = {};
  Object.keys(filter || {}).forEach(function(k){
    var f = filter[k], sel = {};
    (f.values || []).forEach(function(v){ sel[v] = true; });
    d[k] = {mode: f.mode === 'out' ? 'out' : 'in', sel: sel};
  });
  return d;
}
function advFilterSelection(){
  var o = {};
  Object.keys(advDraft).forEach(function(k){
    var vals = Object.keys(advDraft[k].sel);
    if(vals.length) o[k] = {mode: advDraft[k].mode, values: vals};
  });
  return o;
}
function advDraftOf(k){
  if(!advDraft[k]) advDraft[k] = {mode: 'in', sel: {}};
  return advDraft[k];
}
// one list entry: label, count, key (value or ADV_NONE)
function advEntries(k){
  var v = advView[k] || {values: [], empty: 0}, out = [], seen = {};
  v.values.forEach(function(x){ out.push([x[0], x[0], x[1]]); seen[x[0]] = true; });
  if(v.empty){ out.push([ADV_NONE, '(empty)', v.empty]); seen[ADV_NONE] = true; }
  // a checked value that is no longer possible stays visible with (0)
  Object.keys(advDraftOf(k).sel).forEach(function(x){
    if(!seen[x]) out.push([x, x === ADV_NONE ? '(empty)' : x, 0]);
  });
  return out;
}
function advRenderList(k){
  var box = document.getElementById('advl_' + k);
  if(!box) return;
  var dr = advDraftOf(k), q = (advSearch[k] || '').toLowerCase();
  var ents = advEntries(k).filter(function(e){ return !q || e[1].toLowerCase().indexOf(q) >= 0; });
  box.innerHTML = '';
  ents.slice(0, ADV_MAXROWS).forEach(function(e){
    var lab = document.createElement('label');
    lab.className = 'advf-item' + (e[2] === 0 ? ' zero' : '');
    var cb = document.createElement('input');
    cb.type = 'checkbox';
    cb.checked = !!dr.sel[e[0]];
    cb.onchange = function(){
      if(cb.checked) dr.sel[e[0]] = true; else delete dr.sel[e[0]];
      advChanged(k);
    };
    var t = document.createElement('span');
    t.textContent = e[1] + '  (' + e[2] + ')';
    lab.appendChild(cb); lab.appendChild(t); box.appendChild(lab);
  });
  if(ents.length > ADV_MAXROWS){
    var more = document.createElement('div');
    more.className = 'advf-more';
    more.textContent = '+ ' + (ents.length - ADV_MAXROWS) + ' more - use the search';
    box.appendChild(more);
  }
  if(!ents.length){
    var none = document.createElement('div');
    none.className = 'advf-more';
    none.textContent = 'no values';
    box.appendChild(none);
  }
  advRenderHead(k);
}
function advRenderHead(k){
  var dr = advDraftOf(k), n = Object.keys(dr.sel).length;
  var m = document.getElementById('advm_' + k), c = document.getElementById('advc_' + k);
  if(m){ m.textContent = dr.mode === 'in' ? 'SHOW ONLY CHECKED' : 'HIDE CHECKED';
         m.className = dr.mode === 'out' ? 'danger' : ''; }
  if(c) c.textContent = n ? '(' + n + ' ' + (dr.mode === 'in' ? 'shown' : 'hidden') + ')' : '';
}
function advSetVisible(k, on){        // ALL / NONE act on the entries matching the search
  var dr = advDraftOf(k), q = (advSearch[k] || '').toLowerCase();
  advEntries(k).forEach(function(e){
    if(q && e[1].toLowerCase().indexOf(q) < 0) return;
    if(on) dr.sel[e[0]] = true; else delete dr.sel[e[0]];
  });
  advChanged(k);
}
// each list only offers what is still possible with the OTHER lists' selection -
// asks the server (draft selection, nothing applied yet)
var advReqSeq = 0;
function advChanged(changedKey){
  advRenderList(changedKey);
  var selection = advFilterSelection(), seq = ++advReqSeq;
  fetch('api/advvalues', {method: 'POST', headers: {'Content-Type': 'application/json'},
                          body: JSON.stringify({filter: selection})})
    .then(function(r){ return r.json(); })
    .then(function(d){
      if(seq !== advReqSeq || !d || !d.values) return;     // a newer change is on its way
      ADV_FIELD_UI.forEach(function(f){
        if(f[0] !== changedKey && d.values[f[0]]){ advView[f[0]] = d.values[f[0]]; advRenderList(f[0]); }
      });
    }).catch(function(){});
}
function populateAdvFilter(){
  var c = document.getElementById('advFilterRows');
  c.innerHTML = '';
  advDraft = advDraftFrom(lastAdv.filter);
  advView = {}; advSearch = {};
  var any = false;
  ADV_FIELD_UI.forEach(function(f){
    var k = f[0];
    if(!lastAdv.values[k]) return;
    any = true;
    advView[k] = lastAdv.values[k];
    var blk = document.createElement('div');
    blk.className = 'advf-blk';
    var h = document.createElement('div');
    h.className = 'advf-head';
    h.innerHTML = '<b></b><span id="advc_' + k + '" class="advf-cnt"></span>';
    h.firstChild.textContent = f[1];
    var q = document.createElement('input');
    q.type = 'text'; q.placeholder = 'search ...'; q.className = 'advf-q';
    q.oninput = function(){ advSearch[k] = q.value; advRenderList(k); };
    var bar = document.createElement('div');
    bar.className = 'advf-bar';
    var bAll = document.createElement('button'); bAll.textContent = 'ALL';
    bAll.title = 'check all listed (respects the search)';
    bAll.onclick = function(){ advSetVisible(k, true); };
    var bNone = document.createElement('button'); bNone.textContent = 'NONE';
    bNone.title = 'uncheck all listed (respects the search)';
    bNone.onclick = function(){ advSetVisible(k, false); };
    var bMode = document.createElement('button'); bMode.id = 'advm_' + k;
    bMode.title = 'toggle: show only the checked values / hide the checked values';
    bMode.onclick = function(){
      var dr = advDraftOf(k); dr.mode = dr.mode === 'in' ? 'out' : 'in'; advChanged(k);
    };
    bar.appendChild(bAll); bar.appendChild(bNone); bar.appendChild(bMode);
    var list = document.createElement('div');
    list.id = 'advl_' + k; list.className = 'advf-list';
    blk.appendChild(h); blk.appendChild(q); blk.appendChild(bar); blk.appendChild(list);
    c.appendChild(blk);
    advRenderList(k);
  });
  if(!any){
    c.innerHTML = '<p>No inventory values loaded - load a hosts .csv, template: eping-hosts-sample.csv (in the working directory).</p>';
  }
  document.getElementById('modalBtnAdvFApply').disabled = !any;
  document.getElementById('modalBtnAdvFReset').disabled = !any;
}
function openAdvFilter(){ populateAdvFilter(); advFilterModal.style.display = 'flex'; }
function closeAdvFilter(){ advFilterModal.style.display = 'none'; }
function advFilterOpen(){ return advFilterModal.style.display !== 'none'; }
document.getElementById('btnAdvFilter').onclick = openAdvFilter;
document.getElementById('modalBtnAdvFClose').onclick = closeAdvFilter;
document.getElementById('modalBtnAdvFApply').onclick = function(){
  post('adv_filter', JSON.stringify(advFilterSelection()));
  closeAdvFilter();
};
document.getElementById('modalBtnAdvFReset').onclick = function(){
  post('adv_filter', '{}');
  closeAdvFilter();
};

var stoppedModal        = document.getElementById('stoppedModal');
var stoppedMsg           = document.getElementById('stoppedMsg');
var stoppedDismissed     = false;   // user closed it - don't keep popping it back up
var stoppedByUnreachable = false;   // set in poll()'s catch() - cleared once poll() succeeds again
var reconnectTimer       = null;    // graceful-stop case only - poll() itself stops retrying, see below
function openStoppedModal(text){
  if(stoppedDismissed) return;
  stoppedMsg.textContent = text;
  stoppedModal.style.display = 'flex';
}
function startReconnectTimer(){
  if(reconnectTimer || stoppedDismissed) return;
  reconnectTimer = setInterval(function(){
    fetch('api/status').then(function(){ location.reload(); }).catch(function(){});   // still down - try again in 5s
  }, 5000);
}
document.getElementById('modalBtnReload').onclick = function(){ location.reload(); };
document.getElementById('modalBtnCloseStopped').onclick = function(){
  // browsers only allow script to close a tab it opened itself (window.open()) -
  // a normally navigated-to tab silently ignores window.close(), with no way to
  // detect that it was ignored, so this is a best-effort attempt, not a guarantee.
  window.close();
  stoppedDismissed = true;
  stoppedModal.style.display = 'none';
  if(reconnectTimer){ clearInterval(reconnectTimer); reconnectTimer = null; }
};
document.getElementById('btnResetLog').onclick = openResetLog;   // both states go through the
                                                                   // modal now - OFF just skips CLEAR
document.getElementById('modalBtnClearLog').onclick = function(){ runResetLog('y'); };
document.getElementById('modalBtnNewLog').onclick   = function(){ runResetLog('new'); };
document.getElementById('modalBtnCancelLog').onclick = function(){ closeResetLog(); };
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
function sendComment(){
  var el = document.getElementById('commentInput');
  var v = el.value.trim();
  if(!v){ el.focus(); return; }
  post('add_comment', v).then(function(){ el.value=''; });
}
document.getElementById('btnComment').onclick = function(){ sendComment(); };
document.getElementById('commentInput').addEventListener('keydown', function(e){
  if(e.key === 'Enter'){ sendComment(); }
});
document.getElementById('btnClear').onclick  = function(){
  if(confirm('Remove ALL hosts and reset their state?')){ post('clear'); } };

/* ---- JUMPHOST window: test / connect / back to local ---- */
var jumpModal = document.getElementById('jumpModal');
var jumpStatus = document.getElementById('jumpStatus');
var jumpBusy = false;
function jumpOpen(){ return jumpModal.style.display === 'flex'; }
function closeJump(){ jumpModal.style.display = 'none'; document.getElementById('jumpSecret').value = ''; }
function jumpSay(text, cls){
  jumpStatus.textContent = text || '\u00a0';
  jumpStatus.style.color = cls === 'ok' ? 'var(--up,#3fb950)' : (cls === 'err' ? 'var(--down,#f85149)' : 'var(--dim)');
}
function jumpFields(action){
  return {action: action, host: document.getElementById('jumpHost').value, port: document.getElementById('jumpPort').value,
          user: document.getElementById('jumpUser').value, key: document.getElementById('jumpKey').value,
          hostkey: document.getElementById('jumpHostKey').value,
          resolve: document.getElementById('jumpResolve').checked,
          secret: document.getElementById('jumpSecret').value};
}
function jumpButtons(){
  var blocked = jumpBusy || (window.jumpNoSsh === true);
  ['jumpTestBtn','jumpConnectBtn'].forEach(function(id){ document.getElementById(id).disabled = blocked; });
  document.getElementById('jumpLocalBtn').disabled = jumpBusy;
}
function jumpCall(action, busyText){
  jumpBusy = true; jumpButtons(); jumpSay(busyText, '');
  document.getElementById('jumpFp').style.display = 'none';
  document.getElementById('jumpTrustBtn').style.display = 'none';
  return fetch('api/jumphost', {method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify(jumpFields(action))}).then(function(r){ return r.json(); }).then(function(j){
      jumpBusy = false; jumpButtons();
      if(j.ok){ jumpSay(j.message || ('OK' + (j.version ? ' - ' + j.version : '')), 'ok'); }
      else { jumpSay(j.error || 'failed', 'err'); }
      if(j.code === 'hostkey'){
        var fp = document.getElementById('jumpFp');
        fp.textContent = 'Fingerprint(s): ' + (j.fingerprints && j.fingerprints.length ? j.fingerprints.join('  |  ') : 'not readable (ssh-keyscan missing)');
        fp.style.display = 'block';
        document.getElementById('jumpTrustBtn').style.display = (j.fingerprints && j.fingerprints.length) ? '' : 'none';
      }
      return j;
    }).catch(function(){ jumpBusy = false; jumpButtons(); jumpSay('request failed', 'err'); });
}
function openJump(){
  jumpModal.style.display = 'flex';
  document.getElementById('jumpWarn').style.display =
    (['localhost','127.0.0.1','[::1]'].indexOf(location.hostname) < 0) ? 'block' : 'none';
  jumpSay('', '');
  fetch('api/jumphost', {method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({action:'info'})}).then(function(r){ return r.json(); }).then(function(j){
      var pre = document.getElementById('jumpPrereq');
      window.jumpNoSsh = !(j.ssh && j.ssh.ok);
      if(j.ssh && j.ssh.ok){
        pre.style.color = 'var(--dim)';
        pre.textContent = 'ssh client: ' + (j.ssh.version || 'found') + (j.ssh.keyscan ? '' : ' (ssh-keyscan missing: unknown host keys cannot be trusted here)') +
          ' | source: ' + (j.active ? j.active : 'local') + (j.pending ? ' (switching to ' + j.pending + ')' : '') +
          (j.active ? ' | names: ' + (j.resolver ? 'jump host (' + j.resolver + ')' : 'local') : '');
      } else {
        pre.style.color = 'var(--down,#f85149)';
        pre.textContent = (j.ssh && j.ssh.hint) || 'OpenSSH client not found on this computer.';
      }
      if(j.last){
        if(j.last.hostkey) document.getElementById('jumpHostKey').value = j.last.hostkey;
        if(typeof j.last.resolve === 'boolean') document.getElementById('jumpResolve').checked = j.last.resolve;
        ['host','port','user','key'].forEach(function(k){
          var el = document.getElementById('jump' + k.charAt(0).toUpperCase() + k.slice(1));
          if(el && !el.value) el.value = j.last[k] || '';
        });
      }
      jumpButtons();
    }).catch(function(){});
  jumpButtons();
}
document.getElementById('btnJump').onclick = openJump;
document.getElementById('jumpCloseBtn').onclick = closeJump;
document.getElementById('jumpHostKey').onchange = function(){
  jumpSay(this.value === 'off' ? 'Host key check OFF: a man-in-the-middle would not be noticed.' : '', this.value === 'off' ? 'err' : ''); };
document.getElementById('jumpTestBtn').onclick = function(){ jumpCall('test', 'testing connection ...'); };
document.getElementById('jumpConnectBtn').onclick = function(){
  jumpCall('connect', 'connecting ...').then(function(j){ if(j && j.ok){ setTimeout(closeJump, 1200); } }); };
document.getElementById('jumpLocalBtn').onclick = function(){
  jumpCall('local', 'switching ...').then(function(j){ if(j && j.ok){ setTimeout(closeJump, 1200); } }); };
document.getElementById('jumpTrustBtn').onclick = function(){
  jumpCall('trust', 'saving host key ...').then(function(j){ if(j && j.ok){ jumpCall('test', 'testing connection ...'); } }); };

/* ---- ADD/DEL LIST window (paste a host list), preview before applying ---- */
var hostListModal = document.getElementById('hostListModal');
var hostListText  = document.getElementById('hostListText');
var hostListInfo  = document.getElementById('hostListInfo');
var hostListAddBtn = document.getElementById('hostListAddBtn');
var hostListDelBtn = document.getElementById('hostListDelBtn');
var hostListTimer = null, hostListSeq = 0, hostListInList = 0, hostListNew = 0;
function hostListOpen(){ return hostListModal.style.display === 'flex'; }
function closeHostList(){ hostListModal.style.display = 'none'; hostListText.value = ''; }
function openHostList(text){
  hostListText.value = text || '';
  hostListModal.style.display = 'flex';
  hostListPreviewNow();
  hostListText.focus();
}
function hostListPost(action){
  return fetch('api/hostlist', {method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({text: hostListText.value, action: action})}).then(function(r){ return r.json(); });
}
function hostListPreviewNow(){
  var seq = ++hostListSeq;
  if(!hostListText.value.trim()){
    hostListInfo.innerHTML = '&nbsp;'; hostListAddBtn.disabled = true; hostListDelBtn.disabled = true; return;
  }
  hostListPost('preview').then(function(j){
    if(seq !== hostListSeq || !j.ok) return;
    hostListInList = j.in_list; hostListNew = j.new;
    var t = j.found + ' host(s) found: ' + j.new + ' new (ADD), ' + j.in_list + ' already in list (DELETE)';
    if(j.csv) t += ' - CSV: existing hosts are updated with its data' + (j.renamed ? ' (' + j.renamed + ' IP entries renamed to hostname)' : '');
    if(j.networks) t += ' - ' + j.networks + ' network(s) expanded';
    if(j.ignored) t += ' - ' + j.ignored + ' ignored: ' + j.ignored_sample.join(', ') + (j.ignored > j.ignored_sample.length ? ' ...' : '');
    if(j.skipped.length) t += ' - mask out of range: ' + j.skipped.join(', ');
    hostListInfo.textContent = t;
    hostListAddBtn.disabled = !(j.new || (j.csv && (j.in_list || j.renamed)));
    hostListDelBtn.disabled = !j.in_list;
  }).catch(function(){});
}
hostListText.addEventListener('input', function(){
  clearTimeout(hostListTimer); hostListTimer = setTimeout(hostListPreviewNow, 300); });
function hostListRun(action){
  note(action === 'add' ? 'adding host list ...' : 'removing host list ...', true);
  hostListPost(action).then(function(j){ if(!j.ok){ note('list failed: ' + (j.error||''), false); } })
    .catch(function(){ note('list failed', false); });
  closeHostList();
}
hostListAddBtn.onclick = function(){ hostListRun('add'); };
hostListDelBtn.onclick = function(){
  if(hostListInList > 20 && !confirm('Remove ' + hostListInList + ' hosts from the list?')) return;
  hostListRun('del'); };
document.getElementById('hostListCancelBtn').onclick = closeHostList;
document.getElementById('btnList').onclick = function(){ openHostList(''); };
/* Ctrl/Cmd+V with no field focused and no window open: open the window with the clipboard text */
document.addEventListener('paste', function(e){
  var a = document.activeElement, tn = a && a.tagName;
  if(isReadOnly || hostListOpen() || tn === 'INPUT' || tn === 'TEXTAREA' || tn === 'SELECT') return;
  if(document.querySelector('.modal-overlay[style*="flex"]')) return;
  var t = e.clipboardData && e.clipboardData.getData('text');
  if(!t || !t.trim()) return;
  e.preventDefault();
  openHostList(t);
});

/* ---- host file upload ---- */
var fileInput = document.getElementById('fileInput');
var fileInputVis = document.getElementById('fileInputVis');
var addFromClientModal = document.getElementById('addFromClientModal');
function closeAddFromClient(){ addFromClientModal.style.display = 'none'; fileInputVis.value = ''; }
function addFromClientOpen(){ return addFromClientModal.style.display === 'flex'; }
document.getElementById('modalBtnAddFromClientCancel').onclick = closeAddFromClient;
fileInputVis.addEventListener('change', function(){
  var f = fileInputVis.files && fileInputVis.files[0];
  closeAddFromClient();
  if(f) uploadHostsFile(f, null);
});
fileInput.addEventListener('change', function(){
  var f = fileInput.files && fileInput.files[0];
  if(f) uploadHostsFile(f, fileInput);
});
function uploadHostsFile(f, inp){
  var rd = new FileReader();
  rd.onload = function(){
    note('uploading ' + f.name + ' ...', true);
    fetch('api/upload', {method:'POST', headers:{'Content-Type':'text/plain; charset=utf-8'},
      body: rd.result}).then(function(r){ return r.json(); }).then(function(j){
        if(!j.ok){ note('upload failed: ' + (j.error||''), false); }
      }).catch(function(){ note('upload failed', false); });
    if(inp) inp.value = '';
  };
  rd.readAsText(f);
}

var uploadServerFileInput = document.getElementById('uploadServerFileInput');
uploadServerFileInput.addEventListener('change', function(){
  var f = uploadServerFileInput.files && uploadServerFileInput.files[0];
  if(!f) return;
  var rd = new FileReader();
  rd.onload = function(){
    note('uploading ' + f.name + ' ...', true);
    fetch('api/upload_server_file?name=' + encodeURIComponent(f.name),
      {method: 'POST', headers: {'Content-Type': 'text/plain; charset=utf-8'},
       body: rd.result}).then(function(r){ return r.json(); }).then(function(j){
        if(j.ok){ note('uploaded as ' + j.name, false); }
        else { note('upload failed: ' + (j.error || ''), false); }
      }).catch(function(){ note('upload failed', false); });
    uploadServerFileInput.value = '';
  };
  rd.readAsText(f);
});

/* ---- add hosts from a .txt file already on the server ---- */
var addFromServerFiles = [];
var addFromServerSort  = {key: 'mtime', dir: 'desc'};
var addFromServerModal = document.getElementById('addFromServerModal');
function closeAddFromServer(){ addFromServerModal.style.display = 'none'; }
function addFromServerUpdateControls(){
  var count = document.querySelectorAll('.addFromServerCb:checked').length;
  document.getElementById('addFromServerAddBtn').disabled = count === 0;
}
function addFromServerRenderList(){
  var list = document.getElementById('addFromServerList');
  var all  = document.getElementById('addFromServerSelectAll');
  var visible = sortFileList(addFromServerFiles, addFromServerSort);
  list.innerHTML = '';
  all.checked = false;
  wireFileSortHead(document.getElementById('addFromServerHead'), addFromServerSort, addFromServerRenderList);
  if(!visible.length){
    list.innerHTML = '<tr><td style="color:var(--dim);font-size:12px;padding:3px 0">no .txt/.csv files found</td></tr>';
    all.disabled = true;
    addFromServerUpdateControls();
    return;
  }
  visible.forEach(function(f){
    var tr = document.createElement('tr');
    tr.style.cssText = 'cursor:pointer;font-size:12px';
    var tdCb = document.createElement('td');
    tdCb.style.cssText = 'width:20px;padding:3px 4px 3px 0';
    var cb = document.createElement('input');
    cb.type      = 'checkbox';
    cb.className = 'addFromServerCb';
    cb.value     = f.name;
    tdCb.appendChild(cb);
    var tdName = document.createElement('td');
    tdName.style.cssText = 'padding:3px 10px 3px 0;white-space:nowrap';
    tdName.textContent = f.name + (f.active ? '  (ACTIVE)' : '');
    var tdSize = document.createElement('td');
    tdSize.style.cssText = 'padding:3px 10px 3px 0;text-align:right;white-space:nowrap;color:var(--dim)';
    tdSize.textContent = humanBytes(f.size);
    var tdDate = document.createElement('td');
    tdDate.style.cssText = 'padding:3px 0;text-align:right;white-space:nowrap;color:var(--dim)';
    tdDate.textContent = formatFileDate(f.mtime);
    tr.appendChild(tdCb);
    tr.appendChild(tdName);
    tr.appendChild(tdSize);
    tr.appendChild(tdDate);
    tr.onclick = function(e){ if(e.target !== cb){ cb.checked = !cb.checked; } addFromServerUpdateControls(); };
    list.appendChild(tr);
  });
  all.disabled = false;
  addFromServerUpdateControls();
}
function openAddFromServer(){
  var list = document.getElementById('addFromServerList');
  var all  = document.getElementById('addFromServerSelectAll');
  list.innerHTML = '<tr><td style="color:var(--dim);font-size:12px;padding:3px 0">loading ...</td></tr>';
  all.checked  = false;
  all.disabled = true;
  addFromServerModal.style.display = 'flex';
  fetch('api/logfiles').then(function(r){ return r.json(); }).then(function(j){
    addFromServerFiles = (j.files || []).filter(function(f){
      var ext = f.name.split('.').pop().toLowerCase();
      return ext === 'txt' || ext === 'csv';
    });
    addFromServerRenderList();
  }).catch(function(){
    list.innerHTML = '<tr><td style="color:var(--dim);font-size:12px;padding:3px 0">failed to list files</td></tr>';
  });
}
document.getElementById('addFromServerSelectAll').onchange = function(){
  var checked = this.checked;
  Array.prototype.forEach.call(document.querySelectorAll('.addFromServerCb'), function(cb){ cb.checked = checked; });
  addFromServerUpdateControls();
};
document.getElementById('addFromServerAddBtn').onclick = function(){
  var boxes = document.querySelectorAll('.addFromServerCb:checked');
  var names = Array.prototype.map.call(boxes, function(cb){ return cb.value; });
  if(!names.length) return;
  closeAddFromServer();
  note('adding ' + names.length + ' file(s) ...', true);
  fetch('api/add_from_server', {method: 'POST', headers: {'Content-Type': 'application/json'},
                                body: JSON.stringify({names: names})})
    .then(function(r){ return r.json(); })
    .then(function(j){
      var added = j.added || [];
      if(j.errors && j.errors.length){
        note(added.length + ' file(s) added, ' + j.errors.length + ' failed', false);
      } else {
        note(added.length + ' file(s) added', false);
      }
    })
    .catch(function(){ note('add from server failed', false); });
};
document.getElementById('modalBtnAddFromServerCancel').onclick = closeAddFromServer;

// GENERATE REPORT's holding page, written into the blank tab right away (see
// below) so the user sees a wait message instead of a blank window while
// epinga.py runs - same colors as the main page, no dependency on it (a
// popup window has no access to this page's stylesheet).
var REPORT_WAIT_HTML = '<!doctype html><html><head><meta charset="UTF-8">'
  + '<title>epinga report</title><style>'
  + 'body{margin:0;height:100vh;display:flex;align-items:center;justify-content:center;'
  + 'background:#0b0f0b;color:#c8d6c8;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,'
  + '"DejaVu Sans Mono",monospace;font-size:15px}'
  + '.wrap{text-align:center;animation:pulse 1.4s ease-in-out infinite}'
  + '@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}'
  + '</style></head><body><div class="wrap">'
  + 'Generating report with epinga.py &hellip;<br>'
  + '<small style="color:#5d6b5d">please wait - this tab will update automatically</small>'
  + '</div></body></html>';
// must match REPORT_MAX_FILES in eping.py - do_POST silently truncates beyond
// this, so the picker below enforces the same cap instead of letting the user
// select more and lose files without any indication.
var REPORT_MAX_FILES = 25;
function runReport(values, sources){
  // window.open() must happen synchronously in the click handler or browsers
  // treat it as a popup and block it - open a blank tab now, fill it in once
  // poll() sees the report become ready (or close it again on error).
  reportWindow = window.open('', '_blank');
  if(reportWindow){
    reportWindow.document.write(REPORT_WAIT_HTML);
    reportWindow.document.close();
  }
  note(PENDING.run_report, true);
  postReport(Array.isArray(values) ? values : (values ? [values] : []), sources || null);
}
function reportAbort(msg){
  if(reportWindow && !reportWindow.closed) reportWindow.close();
  reportWindow = null;
  note(msg, false);
}
function postReport(names, sources){
  // post() only carries a single 'value' string - multi-file selection needs
  // its own 'values' array, so this bypasses post().
  var body = names.length ? {cmd: 'run_report', values: names} : {cmd: 'run_report', value: ''};
  if(sources) body.sources = sources;
  fetch('api/command', {method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(body)})
    .then(function(r){ return r.json().then(function(j){ return {ok: r.ok && j.ok, err: j.error}; }); })
    .then(function(res){
      // a rejected request (bad/now-missing filename, e.g. pruned by a size
      // rotation between picking it and clicking GENERATE) never flips
      // web_state['report'] to 'error' server-side - without this, the blank
      // tab above would sit on "please wait" forever with no explanation.
      if(!res.ok) reportAbort('report failed: ' + (res.err || 'request rejected'));
    })
    .catch(function(){ reportAbort('report failed: request error'); });
}
var reportSrcModal = document.getElementById('reportSrcModal');
function reportSrcOpen(){ return reportSrcModal.style.display === 'flex'; }
function openReportSourcesPick(){
  // SELECT SOURCES: sources of the active logfile -> pick -> report
  fetch('api/log_sources', {method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({names: []})})
    .then(function(r){ return r.json(); })
    .then(function(j){
      if(j && j.sources && j.sources.length > 1){ openReportSources(j.sources); }
      else { note('the active logfile has only one jump host / source' + (j && j.sources && j.sources.length ? ' (' + j.sources[0] + ')' : ''), false); }
    })
    .catch(function(){ note('failed to read the sources', false); });
}
function openReportSources(sources){
  var list = document.getElementById('reportSrcList');
  list.innerHTML = '';
  sources.forEach(function(sname){
    var lab = document.createElement('label');
    lab.style.cssText = 'display:flex;align-items:center;gap:8px;padding:3px 0;color:var(--fg);font-size:12px;cursor:pointer';
    var cb = document.createElement('input');
    cb.type = 'checkbox'; cb.className = 'reportSrcCb'; cb.value = sname; cb.checked = true;
    cb.onchange = function(){
      document.getElementById('modalBtnReportSrcGo').disabled = !document.querySelectorAll('.reportSrcCb:checked').length;
    };
    lab.appendChild(cb);
    lab.appendChild(document.createTextNode(sname));
    list.appendChild(lab);
  });
  document.getElementById('modalBtnReportSrcGo').disabled = false;
  reportSrcModal.style.display = 'flex';
  document.getElementById('modalBtnReportSrcGo').focus();
}
function closeReportSources(){ reportSrcModal.style.display = 'none'; }
function runReportSources(){
  if(!reportSrcOpen()) return;
  var all = document.querySelectorAll('.reportSrcCb');
  var sel = document.querySelectorAll('.reportSrcCb:checked');
  if(!sel.length) return;
  closeReportSources();
  runReport('', sel.length === all.length ? null
    : Array.prototype.map.call(sel, function(cb){ return cb.value; }));
}
document.getElementById('modalBtnReportSrcGo').onclick = runReportSources;
document.getElementById('modalBtnReportSrcCancel').onclick = function(){
  closeReportSources();
};
document.getElementById('selGenReport').onchange = function(){
  var what = this.value;
  this.value = '';                              // reset - a select, not a toggle
  if(what === 'active'){ runReport(''); }
  else if(what === 'choose'){ openChooseReport(); }
  else if(what === 'sources'){ openReportSourcesPick(); }
};
var chooseReportFiles = [];
var chooseReportSort  = {key: 'mtime', dir: 'desc'};
var chooseReportModal = document.getElementById('chooseReportModal');
function updateChooseReportControls(){
  var boxes   = document.querySelectorAll('.chooseReportCb');
  var checked = document.querySelectorAll('.chooseReportCb:checked');
  Array.prototype.forEach.call(boxes, function(cb){
    if(!cb.checked) cb.disabled = checked.length >= REPORT_MAX_FILES;
  });
  document.getElementById('modalBtnChooseReportGenerate').disabled = !checked.length;
}
function chooseReportRenderList(){
  var list = document.getElementById('chooseReportList');
  var all  = document.getElementById('chooseReportSelectAll');
  var visible = sortFileList(chooseReportFiles, chooseReportSort);
  list.innerHTML = '';
  all.checked = false;
  wireFileSortHead(document.getElementById('chooseReportHead'), chooseReportSort, chooseReportRenderList);
  if(!visible.length){
    list.innerHTML = '<tr><td style="color:var(--dim);font-size:12px;padding:3px 0">no *.csv files found</td></tr>';
    all.disabled = true;
    return;
  }
  visible.forEach(function(f){
    var tr = document.createElement('tr');
    tr.style.cssText = 'cursor:pointer;font-size:12px';
    var tdCb = document.createElement('td');
    tdCb.style.cssText = 'width:20px;padding:3px 4px 3px 0';
    var cb = document.createElement('input');
    cb.type      = 'checkbox';
    cb.className = 'chooseReportCb';
    cb.value     = f.name;
    cb.onchange  = updateChooseReportControls;
    tdCb.appendChild(cb);
    var tdName = document.createElement('td');
    tdName.style.cssText = 'padding:3px 10px 3px 0;white-space:nowrap';
    tdName.textContent = f.name + (f.active ? '  (ACTIVE)' : '');
    var tdSize = document.createElement('td');
    tdSize.style.cssText = 'padding:3px 10px 3px 0;text-align:right;white-space:nowrap;color:var(--dim)';
    tdSize.textContent = humanBytes(f.size);
    var tdDate = document.createElement('td');
    tdDate.style.cssText = 'padding:3px 0;text-align:right;white-space:nowrap;color:var(--dim)';
    tdDate.textContent = formatFileDate(f.mtime);
    tr.appendChild(tdCb);
    tr.appendChild(tdName);
    tr.appendChild(tdSize);
    tr.appendChild(tdDate);
    tr.onclick = function(e){ if(e.target !== cb){ cb.checked = !cb.checked; } updateChooseReportControls(); };
    list.appendChild(tr);
  });
  all.disabled = false;
  updateChooseReportControls();
}
function openChooseReport(){
  var list = document.getElementById('chooseReportList');
  var all  = document.getElementById('chooseReportSelectAll');
  document.getElementById('chooseReportMax').textContent = REPORT_MAX_FILES;
  list.innerHTML = '<tr><td style="color:var(--dim);font-size:12px;padding:3px 0">loading ...</td></tr>';
  all.checked  = false;
  all.disabled = true;
  chooseReportModal.style.display = 'flex';
  fetch('api/logfiles').then(function(r){ return r.json(); }).then(function(j){
    chooseReportFiles = (j.files || []).filter(function(f){
      return f.name.split('.').pop().toLowerCase() === 'csv';
    });
    chooseReportRenderList();
  }).catch(function(){
    list.innerHTML = '<tr><td style="color:var(--dim);font-size:12px;padding:3px 0">failed to list files</td></tr>';
  });
}
document.getElementById('chooseReportSelectAll').onchange = function(){
  var checked = this.checked;
  var boxes = document.querySelectorAll('.chooseReportCb');
  Array.prototype.forEach.call(boxes, function(cb, i){
    cb.checked = checked && i < REPORT_MAX_FILES;
  });
  updateChooseReportControls();
};
document.getElementById('modalBtnChooseReportCancel').onclick = function(){
  chooseReportModal.style.display = 'none';
};
document.getElementById('modalBtnChooseReportGenerate').onclick = function(){
  var boxes = document.querySelectorAll('.chooseReportCb:checked');
  var names = Array.prototype.map.call(boxes, function(cb){ return cb.value; });
  if(!names.length) return;
  chooseReportModal.style.display = 'none';
  runReport(names);
};
document.getElementById('selDownload').onchange = function(){
  var what  = this.value;
  var label = this.options[this.selectedIndex].text;
  this.value = '';                              // reset - a select, not a toggle
  if(!what) return;
  if(what === 'add_from_server'){ openAddFromServer(); return; }
  if(what === 'add_from_client'){ addFromClientModal.style.display = 'flex'; return; }   // visible input: Safari blocks click() from select change
  if(what === 'choose_logfile'){ openChooseLog(); return; }
  if(what === 'delete_files'){ openDeleteFiles(); return; }
  if(what === 'view_file'){ openViewFile(); return; }
  if(what === 'upload_file'){ uploadServerFileInput.click(); return; }
  if(what === 'save_hosts_file'){ openSaveHosts(); return; }
  if(what === 'logfile'){
    // hidden iframe, not fetch+blob and not a real <a> click - the log can be
    // large, and fetch+blob buffers the whole response in JS before the
    // download even starts (no visible transfer/progress until it's fully in
    // memory); a real <a> click, even to an 'attachment' response, is a
    // navigation attempt from the browser's point of view, and some browsers
    // abort other in-flight requests (like poll()'s api/status) while they
    // decide it isn't one, which showed a spurious 'eping.py stopped' - a
    // hidden iframe download never touches top-level navigation, so poll()
    // is unaffected either way; the server sends the filename via
    // Content-Disposition, browser handles it as a native download.
    startIframeDownload('api/download/logfile', label);
    return;
  }
  if((what === 'hosts_all' && allCsv) || (what === 'hosts_shown' && saveCsv)){
    openDlHosts(what, label); return;       // .csv: ask whether the options go in
  }
  runDownload(what, label, '');
};
var dlHostsModal = document.getElementById('dlHostsModal'), dlHostsWhat = '', dlHostsLabel = '';
function dlHostsOpen(){ return dlHostsModal.style.display !== 'none'; }
function closeDlHosts(){ dlHostsModal.style.display = 'none'; }
function openDlHosts(what, label){
  dlHostsWhat = what; dlHostsLabel = label;
  document.getElementById('dlHostsTitle').textContent = label;
  document.getElementById('dlHostsOpts').checked = true;          // default: with options
  document.getElementById('dlHostsTxt').checked = false;          // default: inventory .csv
  dlHostsModal.style.display = 'flex';
}
function runDlHosts(){
  var qa = [];
  if(!document.getElementById('dlHostsOpts').checked) qa.push('opts=0');
  if(document.getElementById('dlHostsTxt').checked) qa.push('txt=1');
  var q = qa.length ? '?' + qa.join('&') : '';
  closeDlHosts();
  runDownload(dlHostsWhat, dlHostsLabel, q);
}
document.getElementById('modalBtnDlHostsOk').onclick     = runDlHosts;
document.getElementById('modalBtnDlHostsCancel').onclick = closeDlHosts;
function runDownload(what, label, query){
  note('downloading ' + label + ' ...', true);
  fetch('api/download/' + what + query).then(function(r){
    if(!r.ok){
      return r.text().then(function(t){ note(label + ': ' + (t || 'download failed'), false); });
    }
    var cd = r.headers.get('Content-Disposition') || '';
    var m  = /filename="([^"]+)"/.exec(cd);
    var filename = m ? m[1] : (what + '.txt');
    return r.blob().then(function(b){
      var url = URL.createObjectURL(b);
      var a   = document.createElement('a');
      a.href = url; a.download = filename;
      document.body.appendChild(a); a.click(); document.body.removeChild(a);
      URL.revokeObjectURL(url);
      note(label + ': downloaded', false);
    });
  }).catch(function(){ note(label + ': download failed', false); });
}
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

function cycleSortMode(){
  var sel = document.getElementById('sortSel');
  sel.selectedIndex = (sel.selectedIndex + 1) % sel.options.length;
  sel.dispatchEvent(new Event('change'));
}

/* Letter shortcuts mirror the CLI keys 1:1 where a direct action exists
   (buttons are .click()'ed so confirm() on EXIT/CLEAR and the RESET LOGGING modal still fire);
   where the CLI opens an input dialog (ADD, DEL, DISPLAY FILTER, COMMENT) the
   matching field is focused instead, since the web field is persistent, not
   a one-shot dialog. R has no curses screen to redraw, so it forces an
   immediate status refresh. Disabled entirely while the page is read-only,
   and while a text field has focus, so normal typing and Ctrl+C keep working. */
document.addEventListener('keydown', function(e){
  if(resetLogOpen()){
    if(e.key === 'Escape'){ closeResetLog(); e.preventDefault(); return; }
    if(document.activeElement && document.activeElement.id === 'resetLogNameInput'){
      if(e.key === 'Enter'){ runResetLog('new'); e.preventDefault(); }
      return;   // any other key types normally into the name field
    }
    var rk = e.key.toLowerCase();
    if(loggingOn && rk === 'y'){ runResetLog('y'); e.preventDefault(); }
    else if(rk === 'n'){ runResetLog('new'); e.preventDefault(); }
    else if(e.key === 'Enter'){
      if(!loggingOn){ runResetLog('new'); } else { closeResetLog(); }
      e.preventDefault();
    }
    return;   // any other key is ignored, the modal stays open
  }
  if(dlHostsOpen()){
    if(e.key === 'Escape'){ closeDlHosts(); e.preventDefault(); return; }
    if(e.key.toLowerCase() === 'y' || e.key === 'Enter'){ runDlHosts(); e.preventDefault(); }
    return;
  }
  if(saveHostsOpen()){
    if(e.key === 'Escape'){ closeSaveHosts(); e.preventDefault(); return; }
    if(document.activeElement && document.activeElement.id === 'saveHostsNameInput'){
      if(e.key === 'Enter'){ runSaveHostsFile(); e.preventDefault(); }
      return;   // any other key types normally into the name field
    }
    var sk = e.key.toLowerCase();
    if(sk === 'y' || e.key === 'Enter'){ runSaveHostsFile(); e.preventDefault(); }
    return;
  }
  if(reportSrcOpen()){
    if(e.key === 'Escape'){ closeReportSources(); e.preventDefault(); }
    else if(e.key === 'Enter'){ runReportSources(); e.preventDefault(); }
    return;
  }
  if(jumpOpen()){
    if(e.key === 'Escape'){ closeJump(); e.preventDefault(); }
    return;
  }
  if(hostListOpen()){
    if(e.key === 'Escape'){ closeHostList(); e.preventDefault(); }
    return;
  }
  if(addFromClientOpen()){
    if(e.key === 'Escape'){ closeAddFromClient(); e.preventDefault(); }
    return;
  }
  if(chooseLogOpen()){
    if(e.key === 'Escape'){ closeChooseLog(); e.preventDefault(); }
    return;
  }
  if(viewFileOpen()){
    if(e.key === 'Escape'){ closeViewFile(); e.preventDefault(); }
    return;
  }
  if(deleteFilesOpen()){
    if(e.key === 'Escape'){ closeDeleteFiles(); e.preventDefault(); }
    return;
  }
  if(advFilterOpen()){
    if(e.key === 'Escape'){ closeAdvFilter(); e.preventDefault(); }
    return;
  }
  if(advOptionsOpen()){
    if(e.key === 'Escape'){ closeAdvOptions(); e.preventDefault(); }
    else if(e.key.toLowerCase() === 'r' && document.activeElement.tagName !== 'INPUT'){
      document.getElementById('modalBtnAdvReset').click(); e.preventDefault();
    }
    return;   // any other key (e.g. typing in a slider's text field) passes through untouched
  }
  // typing into any text field (host/filter/comment input, etc.) must never be
  // hijacked by a global shortcut - this used to sit only in front of the
  // switch below, so '-' typed into a field (e.g. a hyphenated hostname) still
  // hit the FONT SIZE shortcut instead of being typed
  if(document.activeElement && document.activeElement.tagName === 'INPUT') return;
  if(e.ctrlKey || e.metaKey || e.altKey || e.shiftKey) return;
  if(e.key === '+' || e.key === '='){ setFont(fontSize + 1); return; }
  if(e.key === '-' || e.key === '_'){ setFont(fontSize - 1); return; }
  if(isReadOnly) return;
  switch(e.key.toLowerCase()){
    case 'u': {
      var curFm = parseInt(document.getElementById('selFilter').value, 10) || 0;
      var nextFm = (curFm < 3) ? (curFm + 1) % 3 : 0;   // mirrors FILTER_MODES cycling server-side
      pendingFilterMode = String(nextFm);
      setTimeout(function(){ if(pendingFilterMode === String(nextFm)) pendingFilterMode = null; }, 10000);
      post('up_only');
      break;   // dropdown stays in sync via poll(), pendingFilterMode guards against flicker
    }
    case 'p': { var pv = (document.getElementById('selAddrMode').value === '1') ? '0' : '1';
                pendingAddrMode = pv; post('addr_mode', pv); } break;
    case 'i': { var iv = (document.getElementById('selAddrMode').value === '3') ? '0' : '3';
                pendingAddrMode = iv; post('addr_mode', iv); } break;
    case 'g': document.getElementById('btnGetNames').click(); break;
    case 'm': document.getElementById('matchInput').focus();
              document.getElementById('matchInput').select(); break;
    case 'v': document.getElementById('btnAdvFilter').click(); break;
    case 'o': cycleSortMode(); break;
    case 'a': setMode('add'); document.getElementById('addInput').focus(); break;
    case 'd': setMode('del'); document.getElementById('addInput').focus(); break;
    case 'f': fileInput.click(); break;
    case 's': document.getElementById('btnSetRef').click(); break;
    case 'z': document.getElementById('btnZero').click(); break;
    case 't': document.getElementById('commentInput').focus(); break;
    case 'c': document.getElementById('btnClear').click(); break;
    case 'r': poll(); break;
    case 'l': document.getElementById('btnResetLog').click(); break;
    case 'e': document.getElementById('btnExit').click(); break;
    default: return;
  }
  e.preventDefault();
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
    +'<td class="host">'+esc(o.host)+'</td>'
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

function setFoot(text){
  var f = document.getElementById('foot');
  f.textContent   = text || '';
  f.style.display = text ? '' : 'none';
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
    setFoot(firstRunDone
      ? 'no hosts - add a host above, upload a file or drop one onto this page'
      : 'scanning - please wait ...');
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
  document.getElementById('scrollHint').textContent =
    fits ? '' : 'SCROLL RIGHT FOR MORE - reduce font size to fit';
  setFoot('');
}

/* ---------------- host details popup (mouse over a host row) ---------------- */
/* one small GET api/host?name=... per hovered host (after a short delay), cached until
   the next host-table version - the polled status payload does not carry these data */
var tipPinned = false, tipData = null, tipName = '', tipTimer = null, tipCache = {}, tipCacheSeq = -1, tipX = 0, tipY = 0, tipReq = 0;
function tipBox(){ return document.getElementById('hostTip'); }
function fmtDur(s){
  s = Math.floor(s);
  var d = Math.floor(s/86400), h = Math.floor(s%86400/3600), m = Math.floor(s%3600/60), x = s%60;
  return (d ? d+'d ' : '') + ((d||h) ? h+'h ' : '') + ((d||h||m) ? m+'m ' : '') + x + 's';
}
function tipRowsOf(d){
  var up = d.state.indexOf('UP') !== -1;
  var r = [];
  function add(k, v, cls, sep){
    if(v === '' || v === null || v === undefined) return;
    r.push({k: k, v: String(v), cls: cls || '', sep: !!sep});
  }
  add('state', d.state, up ? 'up' : 'down');
  if(d.changes > 0) add('previous', d.prev);
  if(d.dns_fb) add('dns', 'no DNS record - pinged by the CSV address', 'down');
  if(d.ip && d.ip !== d.host) add('address', d.ip);
  add('rtt (ms)', d.rtt && d.rtt.indexOf('-') !== 0 ? d.rtt : '');
  add('last check', d.last_check);
  add('changes', d.changes > 0 ? String(d.changes) : '');
  add('last change', d.change_ts ? d.change_ts + (d.since_s !== null ? '  (' + fmtDur(d.since_s) + ' ago)' : '') : '');
  var inv = [['hostname', d.csv_hostname], ['ip (csv)', d.csv_ip], ['serial', d.serial], ['model', d.model],
             ['location', d.location], ['sysLocation', d.sysloc], ['type', d.type], ['comment', d.comment]];
  var first = true;
  for(var i = 0; i < inv.length; i++){
    if(inv[i][1] !== '' && inv[i][1] !== d.host){ add(inv[i][0], inv[i][1], '', first); first = false; }
  }
  return r;
}
function tipHistHTML(d, pinned){
  var h = d.hist || [];
  if(!h.length) return '';
  var show = pinned ? h : h.slice(0, 6), s = [];
  var nch = 0;
  for(var k = 0; k < h.length; k++) if(h[k][1] !== '#') nch++;
  for(var i = 0; i < show.length; i++){
    if(show[i][1] === '#'){
      s.push('<div class="cm"><span class="t">'+esc(show[i][0])+'</span>  # '+esc(show[i][2])+'</div>');
    } else {
      s.push('<div><span class="t">'+esc(show[i][0])+'</span>  '+esc(show[i][1])+' &rarr; <span class="'
        +(show[i][2].indexOf('UP') !== -1 ? 'up' : 'down')+'">'+esc(show[i][2])+'</span></div>');
    }
  }
  var more = (!pinned && h.length > show.length)
    ? '<div class="more">... '+(h.length - show.length)+' more - click the host to keep this window</div>' : '';
  return '<div class="hist"><div class="t">history ('+nch+' changes'+(h.length > nch ? ' and comments' : '')+', newest first)</div><div class="list">'
    + s.join('') + '</div>' + more + '</div>';
}
function tipHTML(d, pinned){
  var rows = tipRowsOf(d), s = [];
  for(var i = 0; i < rows.length; i++){
    var o = rows[i];
    s.push('<tr'+(o.sep?' class="isep"':'')+'><td>'+esc(o.k)+'</td><td'+(o.cls?' class="'+o.cls+'"':'')+'>'+esc(o.v)+'</td></tr>');
  }
  return '<div class="top"><div class="h">'+esc(d.host)+'</div>'
    + (pinned ? '<div class="bar">'+(isReadOnly ? '' : '<span id="tipDel" class="dng" title="remove this host (no confirmation)">DELETE</span>')+'<span id="tipCopy" title="copy all">COPY</span><span id="tipClose" title="close (ESC)">&times;</span></div>' : '')
    + '</div><table>'+s.join('')+'</table>' + tipHistHTML(d, pinned);
}
function tipText(d){
  var rows = tipRowsOf(d), s = ['host: ' + d.host];
  for(var i = 0; i < rows.length; i++) s.push(rows[i].k + ': ' + rows[i].v);
  var h = d.hist || [];
  if(h.length){
    s.push('history (newest first):');
    for(var j = 0; j < h.length; j++)
      s.push('  ' + h[j][0] + '  ' + (h[j][1] === '#' ? '# ' + h[j][2] : h[j][1] + ' -> ' + h[j][2]));
  }
  return s.join('\n');
}
function copyText(txt){
  function fallback(){
    var ta = document.createElement('textarea');
    ta.value = txt; ta.style.position = 'fixed'; ta.style.opacity = '0';
    document.body.appendChild(ta); ta.select();
    try{ document.execCommand('copy'); }catch(e){}
    document.body.removeChild(ta);
  }
  if(navigator.clipboard && navigator.clipboard.writeText){
    navigator.clipboard.writeText(txt).catch(fallback);
  } else { fallback(); }
}
function tipPlace(){
  var el = tipBox(), w = el.offsetWidth, h = el.offsetHeight;
  var x = tipX + 16, y = tipY + 16;
  if(x + w > window.innerWidth - 4) x = Math.max(4, tipX - w - 12);
  if(y + h > window.innerHeight - 4) y = Math.max(4, window.innerHeight - h - 4);
  el.style.left = x + 'px'; el.style.top = y + 'px';
}
function tipShow(d, pin){
  var el = tipBox();
  if(pin) tipPinned = true;
  tipData = d;
  el.className = tipPinned ? 'pin' : '';
  el.innerHTML = tipHTML(d, tipPinned); el.style.display = 'block'; tipPlace();
}
function tipHide(){
  clearTimeout(tipTimer); tipName = ''; tipReq++; tipPinned = false; tipData = null;
  var el = tipBox(); el.style.display = 'none'; el.className = '';
}
function tipLoad(name, pin){
  if(tipCacheSeq !== lastRowsSeq){ tipCache = {}; tipCacheSeq = lastRowsSeq; }
  if(tipCache[name]){ tipShow(tipCache[name], pin); return; }
  var my = ++tipReq;
  fetch('api/host?name=' + encodeURIComponent(name))
    .then(function(r){ return r.ok ? r.json() : null; })
    .then(function(d){
      if(!d || my !== tipReq || tipName !== name) return;
      tipCache[name] = d; tipShow(d, pin);
    })
    .catch(function(){});
}
function tipRowName(e){
  // only the hostname cell triggers the popup, not the rest of the row
  var td = e.target && e.target.closest ? e.target.closest('#grid tbody td.host') : null;
  return td ? td.textContent : '';
}
document.addEventListener('mousemove', function(e){
  tipX = e.clientX; tipY = e.clientY;
  if(tipPinned) return;                      // a clicked popup stays where it is
  var name = tipRowName(e);
  if(!name){ if(tipName) tipHide(); return; }
  if(name !== tipName){
    tipHide(); tipName = name;
    tipTimer = setTimeout(function(){ tipLoad(name, false); }, 350);
  } else if(tipBox().style.display === 'block'){ tipPlace(); }
});
/* click on a host row pins the popup (text selectable, COPY button); click elsewhere or ESC closes it */
document.addEventListener('mousedown', function(e){
  if(e.target && e.target.closest && e.target.closest('#hostTip')) return;
  var name = tipRowName(e);
  if(name && e.button === 0){
    clearTimeout(tipTimer); tipPinned = false; tipName = name; tipX = e.clientX; tipY = e.clientY;
    tipLoad(name, true);
  } else { tipHide(); }
});
document.addEventListener('click', function(e){
  var c = e.target && e.target.closest ? e.target.closest('#tipCopy, #tipClose, #tipDel') : null;
  if(!c) return;
  if(c.id === 'tipClose'){ tipHide(); return; }
  if(c.id === 'tipDel'){
    if(tipData && !isReadOnly){ var h = tipData.host; tipCache = {}; tipHide(); post('del', h); }
    return;
  }
  if(tipData){ copyText(tipText(tipData)); c.textContent = 'COPIED'; setTimeout(function(){ if(c) c.textContent = 'COPY'; }, 1200); }
});
document.addEventListener('keydown', function(e){ if(e.key === 'Escape' && tipPinned) tipHide(); });
document.addEventListener('mouseleave', function(){ if(!tipPinned) tipHide(); });
document.addEventListener('scroll', function(){ if(!tipPinned) tipHide(); }, true);

var rz;
window.addEventListener('resize', function(){
  clearTimeout(rz); rz = setTimeout(function(){ render(lastRows); }, 80); });

/* ---------------- polling ---------------- */
var pollSeq = 0, lastAppliedSeq = 0;
var lastRowsSeq = 0;   // newest host-table version rendered - the server omits rows we already have
function poll(){
  if(stopped) return;
  var mySeq = ++pollSeq;
  fetch('api/status?rs=' + lastRowsSeq).then(function(r){return r.json();}).then(function(s){
    // overlapping polls can resolve out of order - drop a response older than
    // the newest one already applied, instead of letting it flash stale state
    if(mySeq < lastAppliedSeq) return;
    lastAppliedSeq = mySeq;
    document.getElementById('ver').textContent   = 'v'+s.version;
    if(s.readonly){
      document.getElementById('ctrlsMain').style.display = 'none';
      document.getElementById('ctrlsHosts').style.display = 'none';
      document.getElementById('ro').textContent = '- read only, controlled from the terminal';
    }
    isReadOnly = !!s.readonly;
    var bj = document.getElementById('btnJump');
    if(bj){
      var se = document.getElementById('srcErr');
      if(se){ se.textContent = s.source_error || ''; se.style.display = s.source_error ? 'block' : 'none'; }
      bj.style.borderColor = s.source ? 'var(--acc)' : '';
      bj.title = s.source ? ('pinging via jump host ' + s.source + ' - click to change') : 'ping from a jump host via ssh instead of from this computer';
    }
    document.getElementById('clock').textContent = s.datetime;
    document.getElementById('sHosts').textContent   = s.hosts;
    document.getElementById('sRuntime').textContent = s.run_time;
    document.getElementById('sRuntimeUnit').style.display = (s.run_time === 'n/a') ? 'none' : '';
    document.getElementById('sRuns').textContent    = s.run_counter;
    document.getElementById('sUp').textContent      = s.hosts_up;
    document.getElementById('sDown').textContent    = s.hosts_down;
    document.getElementById('sFlap').textContent    = s.hosts_flap;
    var swrap = document.getElementById('sShownWrap');
    var advOn = !!(s.adv_filter && Object.keys(s.adv_filter).length);
    swrap.style.display = '';   // SHOWN is always visible
    lastAdv = {values: s.adv_values || {}, filter: s.adv_filter || {}};
    document.getElementById('btnAdvFilter').className = advOn ? 'on' : '';
    document.getElementById('sShown').textContent   = s.hosts_shown;
    lastOptions = s.options || {};
    advPollCheck();
    var rep = s.report || {};
    if(rep.status === 'ready' && reportWindow){
      if(!reportWindow.closed) reportWindow.location = 'api/report';
      reportWindow = null;
      note('report ready', false);
    } else if(rep.status === 'error' && reportWindow){
      if(!reportWindow.closed) reportWindow.close();
      reportWindow = null;
      note('report failed: ' + (rep.error || ''), false);
    }
    document.getElementById('sLog').innerHTML = s.logging
      ? 'LOGGING-ON: <b>'+esc(s.logfile)+'</b>' : 'LOGGING-OFF';
    loggingOn = !!s.logging;
    saveCsv        = !!s.save_csv;
    allCsv         = !!s.all_csv;
    hostfileActive = !!s.hostfile_active;
    hostfileName   = s.hostfile_name || '';
    shownHostsCount = s.hosts_shown || 0;
    var brl = document.getElementById('btnResetLog');
    brl.textContent = loggingOn ? 'RESET LOG' : 'START LOG';
    brl.title = loggingOn
      ? 'Y=clear this file, N=start a fresh file (old kept), ESC/ENTER=cancel'
      : 'start logging right away, no confirmation needed';
    var sf = document.getElementById('selFilter');
    if(document.activeElement !== sf){
      if(pendingFilterMode !== null && String(s.filter_mode) === String(pendingFilterMode)){
        pendingFilterMode = null;
      }
      if(pendingFilterMode === null) sf.value = s.filter_mode;
    }
    var sa = document.getElementById('selAddrMode');
    // two separate problems, two guards: (1) while the select is focused - which
    // stays true for as long as its native dropdown popup is open, in every
    // browser - never touch .value at all; setting it out from under an open
    // native popup is what made Firefox silently drop the user's click (no
    // 'change' event ever fired, so nothing was even sent to the server). (2)
    // once focus is gone, a status poll can still land between the click and the
    // server actually applying it (DNS resolution takes real time) - pendingAddrMode
    // keeps the picked value showing until the server echoes it back.
    // nothing about this element is touched while it's focused - not just .value:
    // Firefox's native dropdown popup stays open for as long as the select has
    // focus, and any DOM write to the select while that popup is open (even a
    // className change) can make Firefox drop the click that was about to commit,
    // with no 'change' event firing at all and nothing sent to the server.
    if(document.activeElement !== sa){
      if(pendingAddrMode !== null && String(s.addr_mode) === String(pendingAddrMode)){
        pendingAddrMode = null;
      }
      if(pendingAddrMode === null) sa.value = s.addr_mode || 0;
      sa.className = s.addr_mode ? 'on' : '';
    }
    var bm = document.getElementById('btnMatchFilter');
    bm.className   = s.match_filter ? 'on' : '';
    var mi = document.getElementById('matchInput');
    if(document.activeElement !== mi) mi.value = s.match_filter || '';
    var ss = document.getElementById('sortSel');
    if(document.activeElement !== ss){
      if(pendingSortMode !== null && String(s.sort_mode || 0) === String(pendingSortMode)){
        pendingSortMode = null;
      }
      if(pendingSortMode === null) ss.value = String(s.sort_mode || 0);
      ss.className = s.sort_mode ? 'on' : '';
    }
    // keep the local 'working ...' note until the server actually answers something new
    // msg_seq (not text) drives this: two commands in a row can produce the exact
    // same message text ("comment logged" twice) - comparing text alone would miss
    // the second completion and leave the "... ing" pending note stuck on screen.
    if(s.msg_seq !== lastMsgSeq){ lastMsgSeq = s.msg_seq; note(s.message || '', !!s.pending_wait); }

    var b = document.getElementById('banner');
    if(s.update_available){ b.style.display='block';
      b.innerHTML = 'Update available &ndash; please visit '
        +'<a style="color:inherit" href="https://www.jeitler.cc" target="_blank" rel="noopener">https://www.jeitler.cc</a>'; }
    else { b.style.display='none'; }

    var lz = document.getElementById('learn');
    if(!s.learning_phase){ lz.style.display='block';
      lz.textContent = 'PLEASE WAIT - scanning hosts for UP status - LEARNING PHASE '
        + s.learning_run + ' of ' + s.learning_total; }
    else { lz.style.display='none'; }

    hasData = true;
    if(s.run_counter > 0) firstRunDone = true;
    if(s.rows !== undefined){      // absent = unchanged since the last render
      render(s.rows);
      lastRowsSeq = s.rows_seq;
      if(tipName && !tipPinned && tipBox().style.display === 'block') tipLoad(tipName, false);   // keep an open hover popup current
    }

    document.body.classList.remove('off');   // reachable again - undo a previous catch()
    if(stoppedByUnreachable){   // was showing "not reachable" - close it in place, no reload
      stoppedByUnreachable = false;
      stoppedModal.style.display = 'none';
    }
    if(s.stopped){ stopped = true;
      document.body.classList.add('off');
      openStoppedModal('eping.py stopped - THX for using eping.py');
      startReconnectTimer();   // poll() itself won't retry any more once 'stopped' is set
    }
  }).catch(function(){
    // covers every way the process can go away without telling us first (kill -9,
    // a crash, the terminal closing) - the graceful exits (Ctrl+C, [E], EXIT button)
    // already set s.stopped above before the socket disappears, this is the backstop
    document.body.classList.add('off');
    stoppedByUnreachable = true;
    openStoppedModal('eping.py is not reachable - the process stopped or the connection was lost.');
  });
}

setFont(parseInt(load('eping_fs') || '13', 10), false);
poll();
setInterval(poll, 1000);
</script>
</body>
</html>
"""


_report_lock = threading.Lock()   # guards _report_file_path (separate from web_lock,
                                   # held only briefly - never nested inside web_lock)
_report_file_path = None          # last successfully generated report HTML, or None
_report_running   = False         # guards against overlapping GENERATE REPORT runs

def merge_logfiles(paths):
    """Merge multiple CSV logfiles (same header) into one temp CSV, for
    GENERATE REPORT's multi-file selection - the merged file is analysed by
    epinga.py as a single logfile, then removed by the caller.

    The files are merged by the TIMESTAMP of their rows (streamed, constant memory),
    not by file date: epinga.py needs every host's rows in time order, and file dates
    are unreliable (copies, parallel runs). Each file is read in order; on equal
    timestamps the older file (by mtime) comes first. Only the first header is kept.
    Returns the temp file path, or None on error.
    """
    ordered = sorted(paths, key=lambda p: os.path.getmtime(p) if os.path.exists(p) else 0)
    fd, tmp_path = tempfile.mkstemp(prefix='eping-merged_', suffix='.csv', dir='.')

    def rows_of(f):
        rd = csv.reader(f)
        hdr = next(rd, None)
        if hdr is None:
            return None, iter(())
        ti = hdr.index('TIMESTAMP') if 'TIMESTAMP' in hdr else 0
        def gen():
            last = ''                       # a row without a usable timestamp keeps the previous key
            for r in rd:
                if not r:
                    continue
                if len(r) > ti and r[ti].strip():
                    last = r[ti].strip()
                yield last, r
        return hdr, gen()

    try:
        with contextlib.ExitStack() as stack, os.fdopen(fd, 'w', encoding='UTF8', newline='') as out:
            writer = csv.writer(out)
            gens, header = [], None
            for p in ordered:
                f = stack.enter_context(open(p, 'r', encoding='UTF-8', newline=''))
                hdr, g = rows_of(f)
                if hdr is None:
                    continue
                if header is None:
                    header = hdr
                    writer.writerow(hdr)
                gens.append(g)
            for _key, row in heapq.merge(*gens, key=lambda kr: kr[0]):
                writer.writerow(row)
    except OSError:
        try:
            os.remove(tmp_path)
        except OSError:
            pass
        return None
    return tmp_path


def render_view_file_page(name, content, queue_names):
    """VIEW FILE FROM SERVER - server-rendered viewer page for GET /api/view_file.

    Raw content (read-only), COPY/DOWNLOAD buttons, and - when queue_names is
    non-empty - a plain <a target="_blank"> link to open the next selected file.
    Deliberately NOT a JS window.open() call: every browser trusts a real
    anchor click as ordinary navigation and opens the new tab, whereas a
    script-triggered popup - even one opened from a genuine click a moment
    earlier, even chained back through window.opener from a previously opened
    tab - gets blocked by Chrome and Firefox (Safari was the only one that
    accepted it, which is exactly why this page exists: real anchors are what
    consistently works everywhere).
    """
    next_banner = ''
    if queue_names:
        next_name = queue_names[0]
        rest      = queue_names[1:]
        qs = 'name=' + urllib.parse.quote(next_name, safe='')
        for q in rest:
            qs += '&queue=' + urllib.parse.quote(q, safe='')
        next_banner = (
            '<div class="nextWrap"><div class="nextBox">'
            '<span>' + str(len(queue_names)) + ' more file(s) selected</span>'
            # absolute path, not relative - this page's own URL is already
            # under /api/, so a relative 'api/view_file' would resolve to the
            # wrong, doubled /api/api/view_file
            '<a id="next" class="next" href="/api/view_file?' + qs + '" '
            'target="_blank" rel="noopener">OPEN NEXT FILE</a>'
            '</div></div>')
    return (
        '<!doctype html><html><head><meta charset="UTF-8"><title>' + html.escape(name) + '</title><style>'
        'body{margin:0;background:#0b0f0b;color:#c8d6c8;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,'
        '"DejaVu Sans Mono",monospace;font-size:13px}'
        '.bar{position:sticky;top:0;background:#141914;padding:8px 12px;display:flex;gap:8px;'
        'align-items:center;flex-wrap:wrap;border-bottom:1px solid #263026;z-index:1}'
        '.bar b{margin-right:auto;font-size:13px;color:#c8d6c8;word-break:break-all}'
        'button{background:#1c231c;color:#c8d6c8;border:1px solid #2e3a2e;border-radius:4px;'
        'padding:5px 12px;font:inherit;cursor:pointer;text-decoration:none;display:inline-block}'
        'button:hover{background:#263026}'
        'pre{margin:0;padding:12px;white-space:pre-wrap;word-break:break-word}'
        # centered, fixed overlay - same placement as the eping.py window's
        # own selection prompts, just relocated into this tab (see comment
        # on render_view_file_page() above for why it lives here at all)
        '.nextWrap{position:fixed;top:50%;left:50%;transform:translate(-50%,-50%);z-index:2}'
        '.nextBox{display:flex;flex-direction:column;align-items:center;gap:10px;padding:16px 20px;'
        'background:#141914;color:#c8d6c8;border:1px solid #2e3a2e;border-radius:6px;'
        'box-shadow:0 4px 24px rgba(0,0,0,.5);font-size:12px;text-align:center}'
        '.next{background:#1c231c;border:1px solid #3a5a3a;color:#9fe89f;border-radius:4px;'
        'padding:5px 12px;font:inherit;cursor:pointer;text-decoration:none;display:inline-block}'
        '.next:hover{background:#263026}'
        '</style></head><body>'
        '<div class="bar"><b>' + html.escape(name) + '</b>'
        '<button id="btnCopy" type="button">COPY</button>'
        '<button id="btnDownload" type="button">DOWNLOAD</button>'
        '</div>'
        + next_banner +
        '<pre id="content">' + html.escape(content) + '</pre>'
        '<script>'
        'var NAME = ' + json.dumps(name) + ';'
        'document.getElementById("btnCopy").onclick = function(){'
        '  var btn = this, text = document.getElementById("content").textContent;'
        '  function done(ok){ btn.textContent = ok ? "COPIED" : "COPY FAILED"; '
        '    setTimeout(function(){ btn.textContent = "COPY"; }, 1500); }'
        '  if(navigator.clipboard && navigator.clipboard.writeText){'
        '    navigator.clipboard.writeText(text).then(function(){ done(true); }).catch(function(){ done(false); });'
        '  } else {'
        '    var ta = document.createElement("textarea"); ta.value = text;'
        '    ta.style.position = "fixed"; ta.style.opacity = "0";'
        '    document.body.appendChild(ta); ta.select();'
        '    var ok = false; try{ ok = document.execCommand("copy"); }catch(e){}'
        '    document.body.removeChild(ta); done(ok);'
        '  }'
        '};'
        'document.getElementById("btnDownload").onclick = function(){'
        '  var text = document.getElementById("content").textContent;'
        '  var blob = new Blob([text], {type: "text/plain;charset=utf-8"});'
        '  var url = URL.createObjectURL(blob);'
        '  var a = document.createElement("a"); a.href = url; a.download = NAME;'
        '  document.body.appendChild(a); a.click(); document.body.removeChild(a);'
        '  URL.revokeObjectURL(url);'
        '};'
        '</script></body></html>'
    )


def log_sources(paths):
    """Distinct SOURCE values of the given logfiles ('local' first); [] without SOURCE column."""
    out = set()
    for p in paths:
        try:
            with open(p, 'r', encoding='utf-8', errors='replace', newline='') as f:
                rd = csv.reader(f)
                hdr = next(rd, None)
                if not hdr or 'SOURCE' not in hdr or 'HOSTNAME' not in hdr:
                    continue
                i, h = hdr.index('SOURCE'), hdr.index('HOSTNAME')
                for r in rd:
                    if len(r) > i and len(r) > h and r[h] not in ('#COMMENT#', '#INFO#'):
                        out.add(r[i].strip() or 'local')
        except OSError:
            pass
    return sorted(out, key=lambda x: (x != 'local', x))


def generate_epinga_report(logpaths, sources=None):
    """Run epinga.py against one or more logfiles and produce an HTML report -
    core logic shared by the web gui's GENERATE REPORT (run_epinga_report, below)
    and the curses [N] ANALYSE NOW key. logpaths is a single path (str) or a
    list of paths; more than one path is merged first (see merge_logfiles())
    and analysed as one combined logfile. Headless invocation: -q suppresses
    epinga.py's own console output, --html writes the report, --no-version-check
    skips a network call. stdin=DEVNULL makes epinga.py's end-of-run "open in
    browser?" prompt fail fast with EOFError instead of blocking - harmless, the
    report is already written to disk by that point.
    Returns (report_path, None) on success, (None, error_message) on failure.
    """
    if isinstance(logpaths, str):
        logpaths = [logpaths] if logpaths else []
    logpaths = [p for p in logpaths if p]
    if not logpaths or any(not os.path.exists(p) or os.path.getsize(p) == 0 for p in logpaths):
        return None, 'no active logfile with data yet'
    epinga_path = find_epinga_path()
    if not epinga_path:
        return None, 'epinga.py not found next to eping.py or in PATH'
    merged_tmp = None
    if len(logpaths) > 1:
        merged_tmp = merge_logfiles(logpaths)
        if not merged_tmp:
            return None, 'failed to merge selected logfiles'
        analyse_path = merged_tmp
        report_base  = os.path.splitext(min(logpaths, key=os.path.getmtime))[0] + '_merged'
    else:
        analyse_path = logpaths[0]
        report_base  = os.path.splitext(analyse_path)[0]
    # never overwrite a previous report for this logfile - suffix -1, -2, ...
    report_path = report_base + '_report.html'
    suffix = 1
    while os.path.exists(report_path):
        report_path = report_base + '_report-' + str(suffix) + '.html'
        suffix += 1
    try:
        src_args = []
        for _s in (sources or []):
            src_args += ['--source', _s]
        proc = subprocess.run([sys.executable, epinga_path, '-f', analyse_path, '-q',
                               '--html', report_path, '--no-version-check', '--no-open'] + src_args,
                              env=dict(os.environ, PYTHONIOENCODING='utf-8'),
                              stdin=subprocess.DEVNULL,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              encoding='utf-8', errors='replace')
    except Exception as e:
        return None, str(e)
    finally:
        if merged_tmp:
            try:
                os.remove(merged_tmp)
            except OSError:
                pass
    if not os.path.exists(report_path) or os.path.getsize(report_path) == 0:
        err = (proc.stderr or '').strip().splitlines()
        return None, ('epinga.py did not produce a report'
                      + ((': ' + err[-1]) if err else ''))
    return report_path, None


def run_epinga_report(target_paths=None, sources=None):
    """GENERATE REPORT (web gui): analyse one or more logfiles with epinga.py
    and make the resulting HTML available at /api/report. target_paths picks
    one or more arbitrary *.csv files (DOWNLOAD... CHOOSE LOGFILE picker -
    already validated by the caller); None (or the ACTIVE LOGFILE choice)
    uses the currently active one instead.

    Runs in its own thread - epinga.py can take a while on large logfiles, and
    must never block run_web_mode()'s fping loop or the HTTP request thread.
    """
    global _report_file_path, _report_running
    if target_paths:
        logpaths = target_paths
    else:
        with web_lock:
            logpaths = web_state.get('logfile') or ''
    report_path, err = generate_epinga_report(logpaths, sources)
    if report_path:
        with _report_lock:
            _report_file_path = report_path
        with web_lock:
            web_state['report'] = {'status': 'ready', 'error': ''}
    else:
        with web_lock:
            web_state['report'] = {'status': 'error', 'error': err}
    with web_lock:
        _report_running = False


def content_disposition(filename):
    """Attachment header value with a safe ASCII fallback and an RFC 5987 UTF-8
    name - quotes, CR/LF and other control characters can never reach the header."""
    clean = ''.join(c for c in filename if c >= ' ' and c not in '"\\')
    ascii_name = clean.encode('ascii', 'replace').decode('ascii').replace('?', '_') or 'download'
    utf8_name  = urllib.parse.quote(clean, safe='')
    return ('attachment; filename="' + ascii_name + '"; filename*=UTF-8\'\''
            + utf8_name)


def safe_cwd_filename(name, exts):
    """True if name is a plain file name (no path parts), has one of exts and does
    not point at a symlink - the single validation used by every file endpoint."""
    if not isinstance(name, str) or not name or os.path.basename(name) != name:
        return False
    if name in ('.', '..') or not name.lower().endswith(exts):
        return False
    return not os.path.islink(name)


def hosts_have_inventory(hosts):
    """True if any of the host entries carries inventory CSV values."""
    return any(h in host_meta for h in hosts)


def hostfile_save_target(args, as_csv=False):
    """The file FILE OPERATIONS > SAVE HOSTS FILE ON SERVER overwrites - the
    first -f/--hostfile path if eping.py was started with one (as_csv: with its
    extension changed to .csv, so an inventory is never written into a .txt), else
    None (no hostfile is active - the caller falls back to
    sanitize_hostfile_save_name() to ask for a name instead)."""
    if args.disable_hostfile:
        return None
    paths = split_hostfile_list(args.hostfile)
    if not paths:
        return None
    path = paths[0]
    if as_csv and not path.lower().endswith('.csv'):
        path = os.path.splitext(path)[0] + '.csv'
    return path


def sanitize_hostfile_save_name(name, as_csv=False):
    """Turn a user-typed 'save hosts file' name into a safe .txt (as_csv: .csv)
    filename, or None if unusable - used when hostfile_save_target() returned
    None (eping.py was started with -df, nothing to overwrite). Blank defaults to
    'eping-hosts.txt' / '.csv'; the extension is appended once (not doubled; a
    .txt name becomes .csv when as_csv); rejects path separators/traversal via
    safe_cwd_filename(). Existing files ARE allowed - this command's whole purpose
    is (over)writing a hosts file, and the client already asks for confirmation
    before sending the request.
    """
    name = (name or '').strip()
    ext  = '.csv' if as_csv else '.txt'
    if not name:
        name = 'eping-hosts' + ext
    elif as_csv:
        if name.lower().endswith('.txt'):
            name = name[:-4]
        if not name.lower().endswith('.csv'):
            name += '.csv'
    elif not name.lower().endswith(('.txt', '.csv')):
        name += '.txt'
    return name if safe_cwd_filename(name, ('.txt', '.csv')) else None


def resolve_save_target(args, typed, shown_hosts, force_txt=False):
    """(target path or None, as_csv) for SAVE HOSTS FILE ON SERVER. A typed name
    always saves as that (possibly new) file, even with a hostfile already active;
    blank overwrites the active hostfile, or falls back to the default name if none
    is active. as_csv: the shown hosts carry inventory values - written as .csv, unless
    force_txt (hosts only, no inventory: a .csv name becomes .txt)."""
    as_csv = hosts_have_inventory(shown_hosts) and not force_txt
    typed  = (typed or '').strip()
    if typed:
        target = sanitize_hostfile_save_name(typed, as_csv)
    else:
        target = hostfile_save_target(args, as_csv)
        if target is None:
            target = sanitize_hostfile_save_name('', as_csv)
    if force_txt and target and target.lower().endswith('.csv'):
        target = os.path.splitext(target)[0] + '.txt'
    return target, as_csv


INVENTORY_CSV_HEADER = ['Hostname', 'IP Address', 'Serial Number', 'Model', 'Location',
                        'sysLocation', 'Type', 'Comment']

def inventory_csv_text(hosts):
    """Inventory CSV (';' delimited, same columns eping.py reads) for the host
    entries: the inventory values where known, else just Hostname or IP Address."""
    out = io.StringIO()
    w = csv.writer(out, delimiter=';', lineterminator='\n')
    w.writerow(INVENTORY_CSV_HEADER)
    for h in hosts:
        meta = host_meta.get(h) or _EMPTY_META
        is_ip = is_ip_host(h)
        ip = host_csv_ip.get(h) or (h if is_ip else '')
        w.writerow([meta[0] or ('' if is_ip else h), ip] + list(meta[1:]))
    return out.getvalue()


# set in main(): the parsed arguments and the parser defaults (see opt_lines_text)
_OPT_ARGS     = None
_ARG_DEFAULTS = {}
# flag-less switches: dest -> flag
_OPT_SWITCHES = (('disable_versioncheck', '-du'), ('force_ipv4', '-4'), ('force_ipv6', '-6'),
                 ('diag', '-dg'), ('no_check_source', '-ncs'), ('no_csv_fallback', '-ncf'), ('web', '-web'),
                 ('web_view', '-wv'), ('web_view_control', '-wvc'))
# ADV OPTIONS key -> argparse dest of its default
_OPT_KEY_DEST = {'backoff': 'backoff', 'timeout': 'timeout', 'retries': 'retries',
                 'down_retries': 'down_retries', 'interval': 'interval',
                 'num_of_threads': 'num_of_threads', 'waittime': 'waittime',
                 'confirm': 'confirm', 'rate_pps': 'rate_pps', 'flap_window': 'flap_window',
                 'down_slices': 'down_slices', 'full_sweep': 'full_sweep',
                 'dns_ttl': 'dns_ttl', 'tz_offset': 'time_zone_adjust',
                 'log_max_size': 'log_max_size', 'log_max_files': 'log_max_files'}

def _same_opt_value(a, b):
    try:
        return float(a) == float(b)
    except (TypeError, ValueError):
        return str(a) == str(b)

def opt_lines_text(args, options=None, addr_mode=None, logging_on=None):
    """'opt: <flag> <value>' lines (one per option) for every option that differs from
    the parser default - start-up flags plus live ADV OPTIONS changes ('options' as from
    adv_option_values(), 'addr_mode' 0..3, 'logging_on'). Written at the top of saved/
    downloaded host files, read back at start-up by extract_opt_lines().
    Not included: -f/-df/-n/-r (host sources), -o/-up/-setref/-gn/-cl (one-shot)."""
    if args is None or not _ARG_DEFAULTS:
        return ''
    d, out = _ARG_DEFAULTS, []
    opts = options or {}
    for key, flag in ADV_OPTION_CLI_FLAG.items():
        cur = opts.get(key)
        if cur is None:
            cur = getattr(args, _OPT_KEY_DEST[key], None)
            if key == 'interval' and cur == '':
                cur = '-1'
            if key == 'num_of_threads' and cur == 'auto':
                cur = '0'
        dflt = d.get(_OPT_KEY_DEST[key])
        if dflt == '' and key == 'interval':
            dflt = '-1'
        if dflt == 'auto' and key == 'num_of_threads':
            dflt = '0'
        if cur is not None and not _same_opt_value(cur, dflt):
            out.append('opt: ' + flag + ' ' + ('auto' if (key == 'num_of_threads' and str(cur) == '0') else str(cur)))
    for dest, flag in _OPT_SWITCHES:
        if getattr(args, dest, False):
            out.append('opt: ' + flag)
    mode = addr_mode if addr_mode is not None else (3 if args.ip_only else (1 if args.prefer_hostname else 0))
    if mode == 1:
        out.append('opt: -ph')
    elif mode == 3:
        out.append('opt: -ipo')
    on = logging_on if logging_on is not None else args.disable_logging
    if not on:
        out.append('opt: -dl')
    if not _same_opt_value(args.web_port, d.get('web_port')):
        out.append('opt: -port ' + str(args.web_port))
    if args.web_bind != d.get('web_bind'):
        out.append('opt: -bind ' + str(args.web_bind))
    return ''.join(l + '\n' for l in out)


def hosts_file_text(hosts, as_csv=None, opt_text=''):
    """Content of a host file: opt_text (the options) first, then an inventory CSV when
    the hosts carry inventory values (or as_csv), else one host per line.
    Returns (text, is_csv)."""
    if as_csv is None:
        as_csv = hosts_have_inventory(hosts)
    body = inventory_csv_text(hosts) if as_csv else ''.join(h + '\n' for h in hosts)
    return opt_text + body, as_csv


def save_hosts_file(path, hosts, opt_text=''):
    """Overwrite path - FILE OPERATIONS > SAVE HOSTS FILE ON SERVER: an inventory
    CSV (see inventory_csv_text) for a .csv path, else one host per line (LF),
    preceded by opt_text (the non-default options). Returns True on success,
    False on any OSError."""
    try:
        text = hosts_file_text(hosts, path.lower().endswith('.csv'), opt_text)[0]
        with open(path, 'w', encoding='utf-8', newline='') as f:
            f.write(text)
        return True
    except OSError:
        return False


# SAVE HOSTS FILE variants: '_noopt' = without the opt: lines, '_txt' = hosts only (.txt)
SAVE_HOSTS_CMDS = ('save_hosts_file', 'save_hosts_noopt', 'save_hosts_txt', 'save_hosts_txt_noopt')
WEB_COMMANDS_MAX = 1000   # queued browser commands before the server answers 429
REPORT_MAX_FILES = 25     # GENERATE REPORT: max *.csv files mergeable into one report


class EpingWebHandler(http.server.BaseHTTPRequestHandler):
    server_version  = 'eping/' + VERSION
    protocol_version = 'HTTP/1.1'

    def log_message(self, *a):
        pass  # keep the console quiet

    def _respond(self, code, ctype, body, filename=None):
        # filename set: send as a download (DOWNLOAD dropdown - HOST LIST/LOGFILE)
        # instead of an inline body, so window.location-style navigation would not
        # replace the running gui page.
        if isinstance(body, str):
            body = body.encode('utf-8')
        # gzip large JSON/HTML bodies when the client accepts it (every browser
        # does) - /api/status is polled every second and its JSON is highly
        # repetitive (thousands of near-identical host rows), so this cuts the
        # per-poll bandwidth of a large host count by roughly 5-10x for free.
        # Skipped for downloads (filename set) - those are usually already
        # compressed (zip) or the client expects the raw byte stream as-is.
        encoding = None
        if (not filename and len(body) > 512
                and 'gzip' in (self.headers.get('Accept-Encoding') or '')):
            try:
                body     = gzip.compress(body, compresslevel=6)
                encoding = 'gzip'
            except Exception:
                encoding = None
        try:
            self.send_response(code)
            self.send_header('Content-Type', ctype)
            if encoding:
                self.send_header('Content-Encoding', encoding)
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            if filename:
                self.send_header('Content-Disposition', content_disposition(filename))
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _stream_zip(self, files, zip_name, compress=True):
        """Send one or more (path, arcname) pairs as a single ZIP download,
        streamed straight to the socket - zipfile falls back to its own
        non-seekable-stream mode for a plain socket file object (no
        .tell()/.seek()), so this never buffers a whole file or the whole zip
        in memory: RAM stays a few MB regardless of file size or file count
        (tested at ~500MB source: ~12MB peak RSS). Final size isn't known
        ahead of time, so Content-Length is skipped in favour of closing the
        connection - fine for a one-shot download. compress=False (DOWNLOAD >
        CHOOSE FILE 'no compression') uses ZIP_STORED - no CPU cost, larger
        file - still a single .zip so multi-file selection stays one download.
        """
        ctype = zipfile.ZIP_DEFLATED if compress else zipfile.ZIP_STORED
        self.send_response(200)
        self.send_header('Content-Type', 'application/zip')
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Connection', 'close')
        self.send_header('Content-Disposition', content_disposition(zip_name + '.zip'))
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.end_headers()
        self.close_connection = True
        try:
            with zipfile.ZipFile(self.wfile, mode='w',
                                 compression=ctype, compresslevel=6 if compress else None) as zf:
                for path, arcname in files:
                    zi = zipfile.ZipInfo(arcname, date_time=time.localtime()[:6])
                    zi.compress_type = ctype
                    with zf.open(zi, mode='w') as zdst, open(path, 'rb') as src:
                        while True:
                            chunk = src.read(1024 * 1024)
                            if not chunk:
                                break
                            zdst.write(chunk)
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass

    def _stream_file(self, path):
        """Send a single file exactly as stored, no ZIP wrapper - DOWNLOAD >
        CHOOSE FILE 'no compression' with exactly one file selected."""
        try:
            size = os.path.getsize(path)
        except OSError:
            self._respond(404, 'text/plain; charset=utf-8', 'file not found')
            return
        ctype = {'.csv': 'text/csv', '.txt': 'text/plain',
                '.html': 'text/html'}.get(os.path.splitext(path)[1].lower(),
                                          'application/octet-stream')
        self.send_response(200)
        self.send_header('Content-Type', ctype + '; charset=utf-8')
        self.send_header('Content-Length', str(size))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Connection', 'close')
        self.send_header('Content-Disposition', content_disposition(os.path.basename(path)))
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.end_headers()
        self.close_connection = True
        try:
            with open(path, 'rb') as src:
                while True:
                    chunk = src.read(1024 * 1024)
                    if not chunk:
                        break
                    self.wfile.write(chunk)
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass

    def do_GET(self):
        path = self.path.split('?')[0]
        if path in ('/', '/index.html'):
            self._respond(200, 'text/html; charset=utf-8', WEB_INDEX_HTML)
        elif path in ('/api/host', 'api/host'):
            name = urllib.parse.parse_qs(self.path.partition('?')[2]).get('name', [''])[0][:256]
            try:
                _tz = int(web_state.get('options', {}).get('tz_offset', 0) or 0)
            except (TypeError, ValueError):
                _tz = 0
            info = host_details(name, _tz) if name else None
            if info is None:
                self._respond(404, 'application/json', '{"error":"unknown host"}')
            else:
                self._respond(200, 'application/json', json.dumps(info))
        elif path in ('/api/status', 'api/status'):
            try:
                client_rows_seq = int(urllib.parse.parse_qs(
                    self.path.partition('?')[2]).get('rs', [''])[0])
            except (TypeError, ValueError):
                client_rows_seq = -1
            with web_lock:
                snapshot = dict(web_state)   # values are replaced, never mutated in place
                if snapshot.get('rows') is not _rows_track['ref']:
                    _rows_track['ref'] = snapshot.get('rows')
                    _rows_track['seq'] += 1
                rows_seq = _rows_track['seq']
            # the host table is the bulk of the payload and only changes once per
            # round or on a command - while the browser already holds this version
            # it is left out, so a 40000-host page is not re-sent, re-parsed and
            # re-rendered every second (that kept the browser busy for seconds per
            # poll and delayed every click: sorting, view switch, ...)
            snapshot['rows_seq'] = rows_seq
            if client_rows_seq == rows_seq:
                snapshot.pop('rows', None)
            # host_list_shown/host_list_all are two full copies of every host name,
            # only ever used server-side by /api/download/hosts_shown|hosts_all
            # (read straight from web_state there) - the client only needs their
            # counts (already in hosts_shown/hosts), never the names themselves, so
            # they're dropped from the polled payload; at large host counts this is
            # the majority of the per-poll size. web_state itself keeps them intact.
            snapshot.pop('host_list_shown', None)
            snapshot.pop('host_list_all', None)
            # 'datetime' is otherwise only refreshed by web_publish() once a round
            # completes - on a long round (many hosts) the clock would sit still
            # for that whole time. Recomputed here on every poll instead, so it
            # ticks every second regardless of round length.
            try:
                _tz = int(snapshot.get('options', {}).get('tz_offset', 0) or 0)
            except (TypeError, ValueError):
                _tz = 0
            snapshot['datetime'] = now_local(_tz).strftime("%d/%m/%Y %H:%M:%S")
            snapshot['source'] = SOURCE_LABEL if ssh_cfg else ''
            snapshot['source_error'] = _source_alert if ssh_cfg else ''
            body = json.dumps(snapshot)      # serialize outside the lock - no stall of the ping loop
            self._respond(200, 'application/json; charset=utf-8', body)
        elif path in ('/api/logfiles', 'api/logfiles'):
            # DOWNLOAD > CHOOSE FILE - every .csv/.txt/.html in the working
            # directory (see DOWNLOAD_FILE_EXTS), not just eping-log_*.csv -
            # the client applies its own extension filter on top of this list.
            with web_lock:
                active = web_state.get('logfile') or ''
            active = os.path.basename(active) if active else ''
            files = []
            try:
                for name in os.listdir('.'):
                    if name.lower().endswith(DOWNLOAD_FILE_EXTS) and os.path.isfile(name):
                        try:
                            st = os.stat(name)
                        except OSError:
                            continue
                        files.append({'name': name, 'size': st.st_size,
                                     'mtime': st.st_mtime, 'active': name == active})
            except OSError:
                pass
            files.sort(key=lambda f: f['mtime'], reverse=True)
            for f in files:
                f['mtime'] = int(f['mtime'])   # seconds - client formats it for display
            self._respond(200, 'application/json; charset=utf-8', json.dumps({'files': files}))
        elif path in ('/api/download/hosts_shown', 'api/download/hosts_shown',
                      '/api/download/hosts_all', 'api/download/hosts_all'):
            # DOWNLOAD > SHOWN HOSTS / ALL HOSTS - the non-default options ('opt:' lines)
            # first, then an inventory .csv if the hosts carry inventory values, else
            # one host per line (.txt) - both formats can be loaded again.
            key = 'host_list_shown' if 'hosts_shown' in path else 'host_list_all'
            with web_lock:
                hosts = list(web_state.get(key) or [])
            with web_lock:
                _o, _am, _lg = (dict(web_state.get('options') or {}), web_state.get('addr_mode'),
                                web_state.get('logging'))
            _q = urllib.parse.parse_qs(self.path.partition('?')[2])
            _noopt = _q.get('opts', ['1'])[0] == '0'      # opts=0: no opt: lines
            _txt   = _q.get('txt', ['0'])[0] == '1'       # txt=1: hosts only, no inventory
            body, is_csv = hosts_file_text(hosts, False if _txt else None,
                                           '' if _noopt else opt_lines_text(_OPT_ARGS, _o, _am, _lg))
            tag   = 'shown' if key == 'host_list_shown' else 'all'
            fname = ('eping-hosts_' + tag + '_'
                    + datetime.datetime.now().strftime('%Y-%m-%d_%H%M%S')
                    + ('.csv' if is_csv else '.txt'))
            self._respond(200, 'text/csv; charset=utf-8' if is_csv else 'text/plain; charset=utf-8',
                          body, fname)
        elif path in ('/api/download/logfile', 'api/download/logfile'):
            # DOWNLOAD > ACTIVE LOGFILE - the currently active CSV log, read
            # fresh from disk (not cached) so the download always reflects the
            # latest rows, zipped on the fly (see _stream_zip()).
            with web_lock:
                logpath = web_state.get('logfile') or ''
            if not logpath or not os.path.exists(logpath):
                self._respond(404, 'text/plain; charset=utf-8', 'no active logfile')
                return
            try:
                with open(logpath, 'rb'):
                    pass
            except OSError:
                self._respond(404, 'text/plain; charset=utf-8', 'logfile not readable')
                return
            self._stream_zip([(logpath, os.path.basename(logpath))], os.path.basename(logpath))
        elif path in ('/api/download/choose_logfile', 'api/download/choose_logfile'):
            qs      = urllib.parse.urlsplit(self.path).query
            qparams = urllib.parse.parse_qs(qs)
            names   = qparams.get('name') or []
            nozip   = bool(qparams.get('nozip'))
            if not names:
                self._respond(400, 'text/plain; charset=utf-8', 'no filename given')
                return
            files = []
            for name in names:
                if not safe_cwd_filename(name, DOWNLOAD_FILE_EXTS):
                    self._respond(400, 'text/plain; charset=utf-8', 'invalid filename: ' + name)
                    return
                if not os.path.isfile(name):
                    self._respond(404, 'text/plain; charset=utf-8', 'file not found: ' + name)
                    return
                try:
                    with open(name, 'rb'):
                        pass
                except OSError:
                    self._respond(404, 'text/plain; charset=utf-8', 'file not readable: ' + name)
                    return
                files.append((name, name))
            if nozip and len(files) == 1:
                self._stream_file(files[0][0])
                return
            if len(files) == 1:
                zip_name = files[0][1]
            else:
                zip_name = ('eping-logfiles_' + str(len(files)) + '_'
                           + datetime.datetime.now().strftime('%Y-%m-%d_%H%M%S'))
            self._stream_zip(files, zip_name, compress=not nozip)
        elif path in ('/api/view_file', 'api/view_file'):
            # VIEW FILE FROM SERVER - a real, server-rendered page (not a JS
            # fetch+document.write dance) so that opening file 2, 3, ... via
            # the OPEN NEXT FILE link is plain browser navigation, not a
            # script-triggered popup - see render_view_file_page().
            qs      = urllib.parse.urlsplit(self.path).query
            qparams = urllib.parse.parse_qs(qs)
            name    = (qparams.get('name') or [''])[0]
            queue   = [q for q in qparams.get('queue') or [] if safe_cwd_filename(q, VIEW_FILE_EXTS)]
            if not name or not safe_cwd_filename(name, VIEW_FILE_EXTS):
                self._respond(400, 'text/plain; charset=utf-8', 'invalid filename')
                return
            if not os.path.isfile(name):
                self._respond(404, 'text/plain; charset=utf-8', 'file not found: ' + name)
                return
            try:
                if os.path.getsize(name) > VIEW_FILE_MAX_BYTES:
                    self._respond(413, 'text/plain; charset=utf-8',
                                  'file too large to view inline (max '
                                  + str(VIEW_FILE_MAX_BYTES // (1024 * 1024)) + ' MB) - use DOWNLOAD instead')
                    return
                with open(name, 'r', encoding='utf-8', errors='replace') as f:
                    content = f.read()
            except OSError as e:
                self._respond(404, 'text/plain; charset=utf-8', 'file not readable: ' + str(e))
                return
            self._respond(200, 'text/html; charset=utf-8', render_view_file_page(name, content, queue))
        elif path in ('/api/report', 'api/report'):
            # GENERATE REPORT result - the epinga.py HTML report from the last
            # completed run_epinga_report(), served inline (not as a download)
            # so the GENERATE REPORT button's new tab renders it directly.
            with _report_lock:
                report_path = _report_file_path
            if not report_path or not os.path.exists(report_path):
                self._respond(404, 'text/plain; charset=utf-8', 'no report generated yet')
                return
            try:
                with open(report_path, 'rb') as f:
                    body = f.read()
            except OSError:
                self._respond(404, 'text/plain; charset=utf-8', 'report not readable')
                return
            self._respond(200, 'text/html; charset=utf-8', body)
        else:
            self._respond(404, 'text/plain; charset=utf-8', 'not found')

    def _read_body(self, max_bytes):
        """Read the request body. Returns None when it exceeds max_bytes - the body is
        then drained (or the connection closed) so the next keep-alive request does
        not start in the middle of it."""
        try:
            length = int(self.headers.get('Content-Length') or 0)
        except ValueError:
            length = 0
        if length <= 0:
            return b''
        if length > max_bytes:
            self._drain_body(length)
            return None
        return self.rfile.read(length)

    def _drain_body(self, length):
        if length > 4 * WEB_MAX_UPLOAD:
            self.close_connection = True   # not worth reading - drop the connection
            return
        remaining = length
        while remaining > 0:
            chunk = self.rfile.read(min(65536, remaining))
            if not chunk:
                break
            remaining -= len(chunk)

    def do_POST(self):
        path = self.path.split('?')[0]

        if web_readonly:
            self._read_body(0)
            self._respond(403, 'application/json; charset=utf-8',
                          json.dumps({'ok': False, 'error': 'read only view'}))
            return

        # --- ADV FILTER window: what is still selectable given a draft selection ---
        if path in ('/api/advvalues', 'api/advvalues'):
            raw = self._read_body(65536) or b'{}'
            try:
                sel = json.loads(raw.decode('utf-8') or '{}').get('filter') or {}
            except Exception:
                sel = {}
            sel = adv_parse(sel)
            with web_lock:
                hosts = list(web_state.get('host_list_all') or [])
            self._respond(200, 'application/json; charset=utf-8',
                          json.dumps({'ok': True, 'values': adv_values(hosts, sel)}))
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
            if not self._queue_command(('upload', text)):
                return
            self._respond(200, 'application/json; charset=utf-8', json.dumps({'ok': True}))
            return

        # --- JUMPHOST window: info / test / trust key / connect / local ---
        if path in ('/api/jumphost', 'api/jumphost'):
            raw = self._read_body(65536) or b'{}'
            try:
                req = json.loads(raw.decode('utf-8', 'replace') or '{}')
            except Exception:
                req = {}
            try:
                res = jump_handle(req if isinstance(req, dict) else {})
            except Exception as e:
                res = {'ok': False, 'code': 'conn', 'error': 'internal error: ' + str(e)}
            self._respond(200, 'application/json; charset=utf-8', json.dumps(res))
            return

        # --- ADD/DEL LIST window: preview (no change) or queue add_list/del_list ---
        if path in ('/api/hostlist', 'api/hostlist'):
            raw = self._read_body(WEB_MAX_UPLOAD)
            if raw is None:
                self._respond(413, 'application/json; charset=utf-8',
                              json.dumps({'ok': False, 'error': 'text too large'}))
                return
            try:
                req = json.loads(raw.decode('utf-8', 'replace') or '{}')
            except Exception:
                req = {}
            text   = str(req.get('text', ''))
            action = str(req.get('action', 'preview'))
            if action in ('add', 'del'):
                if not self._queue_command((action + '_list', text)):
                    return
                self._respond(200, 'application/json; charset=utf-8', json.dumps({'ok': True}))
                return
            pstats = {}
            _m0, _c0 = set(host_meta), set(host_csv_ip)
            found  = parse_hosts_from_text(text, pstats, True)
            with web_lock:
                present = set(web_state.get('host_list_all') or [])
            n_ren = (sum(1 for h in found if h not in present and host_csv_ip.get(h) in present
                         and host_csv_ip.get(h) != h) if pstats.get('csv') else 0)
            for _k in set(host_meta) - _m0:           # preview only - keep no CSV data of it
                host_meta.pop(_k, None)
            for _k in set(host_csv_ip) - _c0:
                host_csv_ip.pop(_k, None)
            n_in = sum(1 for h in found if h in present)
            self._respond(200, 'application/json; charset=utf-8', json.dumps({
                'ok': True, 'found': len(found), 'in_list': n_in,
                'csv': bool(pstats.get('csv')), 'renamed': n_ren,
                'new': len(found) - n_in - n_ren, 'networks': pstats.get('networks', 0),
                'ignored': len(pstats.get('ignored', [])),
                'ignored_sample': pstats.get('ignored', [])[:8],
                'skipped': pstats.get('skipped', [])[:5]}))
            return

        # --- FILE ACTIONS > UPLOAD: save a *.txt/*.csv file as-is, no host
        # parsing (see /api/upload above for that) ---
        if path in ('/api/upload_server_file', 'api/upload_server_file'):
            qs      = urllib.parse.urlsplit(self.path).query
            qparams = urllib.parse.parse_qs(qs)
            name    = (qparams.get('name') or [''])[0]
            if not safe_cwd_filename(name, ('.txt', '.csv')):
                self._respond(400, 'application/json; charset=utf-8',
                              json.dumps({'ok': False, 'error': 'invalid filename - must be *.txt or *.csv'}))
                return
            raw = self._read_body(WEB_MAX_UPLOAD)
            if raw is None:
                self._respond(413, 'application/json; charset=utf-8',
                              json.dumps({'ok': False, 'error': 'file too large'}))
                return
            base, ext = os.path.splitext(name)
            save_name = name
            suffix = 1
            while os.path.exists(save_name):
                save_name = base + '-' + str(suffix) + ext
                suffix += 1
            try:
                with open(save_name, 'wb') as fh:
                    fh.write(raw)
            except OSError as e:
                self._respond(500, 'application/json; charset=utf-8',
                              json.dumps({'ok': False, 'error': str(e)}))
                return
            self._respond(200, 'application/json; charset=utf-8',
                          json.dumps({'ok': True, 'name': save_name}))
            return

        # --- add hosts from one or more *.txt files already on the server ---
        if path in ('/api/add_from_server', 'api/add_from_server'):
            raw = self._read_body(WEB_MAX_UPLOAD)
            try:
                data = json.loads(raw.decode('utf-8', 'replace')) if raw else {}
            except Exception:
                data = {}
            names = data.get('names') if isinstance(data, dict) else None
            if not isinstance(names, list) or not names:
                self._respond(400, 'application/json; charset=utf-8',
                              json.dumps({'ok': False, 'error': 'no filenames given'}))
                return
            added, errors, texts = [], [], []
            for name in names:
                if not safe_cwd_filename(name, ('.txt', '.csv')) or not os.path.isfile(name):
                    errors.append(name)
                    continue
                try:
                    with open(name, encoding='utf-8', errors='replace') as fh:
                        text = fh.read(WEB_MAX_UPLOAD + 1)
                except OSError:
                    errors.append(name)
                    continue
                # a *.csv must be an inventory CSV (not e.g. an eping logfile)
                if name.lower().endswith('.csv') and parse_inventory_csv_header(text) is None:
                    errors.append(name)
                    continue
                texts.append(text)
                added.append(name)
            if texts and not self._queue_command(('upload', '\n\x00\n'.join(texts))):
                return
            self._respond(200, 'application/json; charset=utf-8',
                          json.dumps({'ok': not errors, 'added': added, 'errors': errors}))
            return

        if path in ('/api/log_sources', 'api/log_sources'):
            # SOURCE values of the logfile(s) a report would analyse (empty names = active logfile)
            raw = self._read_body(WEB_MAX_UPLOAD)
            try:
                data = json.loads(raw.decode('utf-8', 'replace')) if raw else {}
            except Exception:
                data = {}
            names = data.get('names') if isinstance(data, dict) else None
            names = [str(n)[:256] for n in names[:REPORT_MAX_FILES]] if isinstance(names, list) else []
            paths = []
            for n in names:
                if not safe_cwd_filename(n, ('.csv',)) or not os.path.isfile(n):
                    self._respond(400, 'application/json; charset=utf-8',
                                  json.dumps({'ok': False, 'error': 'invalid filename'}))
                    return
                paths.append(n)
            if not paths:
                with web_lock:
                    act = web_state.get('logfile') or ''
                paths = [act] if act and os.path.isfile(act) else []
            self._respond(200, 'application/json; charset=utf-8',
                          json.dumps({'ok': True, 'sources': log_sources(paths)}))
            return

        if path in ('/api/delete_logfile', 'api/delete_logfile'):
            raw = self._read_body(WEB_MAX_UPLOAD)
            try:
                data = json.loads(raw.decode('utf-8', 'replace')) if raw else {}
            except Exception:
                data = {}
            names = data.get('names') if isinstance(data, dict) else None
            if not isinstance(names, list) or not names:
                self._respond(400, 'application/json; charset=utf-8',
                              json.dumps({'ok': False, 'error': 'no filenames given'}))
                return
            with web_lock:
                active = web_state.get('logfile') or ''
            active = os.path.basename(active) if active else ''
            deleted, errors = [], []
            for name in names:
                if not safe_cwd_filename(name, DOWNLOAD_FILE_EXTS):
                    errors.append(name)
                    continue
                if name == active:
                    errors.append(name)   # never delete the logfile currently being written to
                    continue
                try:
                    os.remove(name)
                    deleted.append(name)
                except OSError:
                    errors.append(name)
            self._respond(200, 'application/json; charset=utf-8',
                          json.dumps({'ok': not errors, 'deleted': deleted, 'errors': errors}))
            return

        if path not in ('/api/command', 'api/command'):
            self._read_body(0)   # drain, keeps the keep-alive stream in sync
            self._respond(404, 'text/plain; charset=utf-8', 'not found')
            return
        raw = self._read_body(65536) or b'{}'
        try:
            payload = json.loads(raw.decode('utf-8') or '{}')
        except Exception:
            payload = {}
        cmd   = str(payload.get('cmd', ''))
        value = str(payload.get('value', ''))[:(8192 if cmd == 'adv_filter' else 256)]
        if cmd not in ('up_only', 'set_filter', 'add', 'del', 'set_ref', 'clear', 'zero', 'sort', 'exit', 'addr_mode', 'get_names', 'match_filter', 'adv_filter', 'add_comment', 'reset_log', 'set_option', 'reset_options', 'run_report') + SAVE_HOSTS_CMDS:
            self._respond(400, 'application/json; charset=utf-8', json.dumps({'ok': False}))
            return
        if cmd == 'run_report':
            # GENERATE REPORT - runs in its own background thread (epinga.py can
            # take a while on a large logfile), not via web_commands/run_web_mode -
            # it needs no access to that loop's locals, only web_state['logfile']
            # (ACTIVE LOGFILE) or the validated target_paths below (CHOOSE LOGFILE,
            # one or more *.csv - multiple are merged, see merge_logfiles()).
            global _report_running
            raw_names = payload.get('values')
            if isinstance(raw_names, list) and raw_names:
                names = [str(n)[:256] for n in raw_names[:REPORT_MAX_FILES]]
            elif value:
                names = [value]
            else:
                names = []
            raw_src = payload.get('sources')
            report_sources = [str(x)[:256] for x in raw_src[:64]] if isinstance(raw_src, list) and raw_src else None
            target_paths = None
            if names:
                target_paths = []
                for name in names:
                    if not safe_cwd_filename(name, ('.csv',)):
                        self._respond(400, 'application/json; charset=utf-8',
                                      json.dumps({'ok': False, 'error': 'invalid filename'}))
                        return
                    if not os.path.isfile(name):
                        self._respond(404, 'application/json; charset=utf-8',
                                      json.dumps({'ok': False, 'error': 'file not found'}))
                        return
                    target_paths.append(name)
            with web_lock:
                already_running = _report_running
                if not already_running:
                    _report_running = True
                    web_state['report'] = {'status': 'running', 'error': ''}
            if not already_running:
                threading.Thread(target=run_epinga_report, args=(target_paths, report_sources), daemon=True).start()
            self._respond(200, 'application/json; charset=utf-8', json.dumps({'ok': True}))
            return
        if not self._queue_command((cmd, value)):
            return
        self._respond(200, 'application/json; charset=utf-8', json.dumps({'ok': True}))

    def _queue_command(self, item):
        """Append to web_commands unless the queue is full (429). Returns True if queued."""
        with web_lock:
            if len(web_commands) >= WEB_COMMANDS_MAX:
                full = True
            else:
                web_commands.append(item)
                full = False
        if full:
            self._respond(429, 'application/json; charset=utf-8',
                          json.dumps({'ok': False, 'error': 'command queue full'}))
        return not full


class EpingWebServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def handle_error(self, request, client_address):
        # a traceback on stderr would destroy the curses screen in --web_view mode
        pass


def _port_in_use(bind_addr, port):
    """True if a listener already answers on the address we are about to bind. BSD/macOS lets a
    wildcard socket and a specific one share a port (SO_REUSEADDR), so bind() alone does not
    detect another instance bound to 127.0.0.1."""
    host = {'': '127.0.0.1', '0.0.0.0': '127.0.0.1', '::': '::1'}.get(bind_addr, bind_addr)
    try:
        with socket.create_connection((host, port), timeout=0.5):
            return True
    except OSError:
        return False

def start_web_server(bind_addr, port):
    if _port_in_use(bind_addr, port):
        error_handler('ERROR: unable to bind web gui to ' + str(bind_addr) + ':' + str(port) + ' - address already in use')
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


def host_details(name, tz_offset=0):
    """All known data of one host for the web GUI mouse-over popup (GET /api/host),
    or None if the host is unknown. Read-only, one host at a time - the polled
    /api/status payload stays small."""
    row = host_state.get(name)
    if row is None:
        return None
    ip = row[8] if len(row) > 8 else ''
    meta = host_meta.get(name) or (host_meta.get(ip) if ip else None) or _EMPTY_META
    since = None
    cts = row[6]
    try:
        if not isinstance(cts, datetime.datetime):
            cts = datetime.datetime.strptime(str(cts), "%d/%m/%Y %H:%M:%S")
        since = max(0, int((now_local(tz_offset) - cts).total_seconds()))
    except (ValueError, TypeError):
        pass
    return {'host': name, 'ip': ip or '', 'state': str(row[1]).strip(),
            'prev': str(row[4]).strip() if row[4] else '', 'last_check': str(row[2]),
            'rtt': str(row[3]), 'changes': row[5], 'change_ts': str(row[6] or ''),
            'since_s': since, 'csv_ip': host_csv_ip.get(name, ''),
            'dns_fb': name in _csv_fb_names,
            'csv_hostname': meta[0], 'serial': meta[1], 'model': meta[2],
            'location': meta[3], 'sysloc': meta[4], 'type': meta[5], 'comment': meta[6],
            'hist': hist_list(name, tz_offset)}


def web_publish(display_list, run_counter, run_time, hosts_up, hosts_down,
                filter_mode, learning_phase, learning_run, learning_total,
                logging_enabled, logfile_file_name, update_available, tz_offset, message='',
                scan_info='', sort_mode=0, addr_mode=0,
                match_filter='', original_hosts_list=None, hosts_shown=None, options=None,
                hosts_flap=None, pending_wait=False):
    now  = now_local(tz_offset)
    rows = web_rows(display_list)
    with web_lock:
        web_state.update({
            'datetime'        : now.strftime("%d/%m/%Y %H:%M:%S"),
            'rows'            : rows,
            'hosts'           : hosts_up + hosts_down,   # whole view, not just the shown rows
            # DOWNLOAD - SHOWN HOSTS: only what's currently displayed (view, address
            # mode and display filter already applied via display_list/rows above);
            # ALL HOSTS: the full reference list, unfiltered.
            'host_list_shown' : [r['host'] for r in rows],
            'host_list_all'   : list(original_hosts_list) if original_hosts_list is not None else [],
            'hosts_up'        : hosts_up,
            'hosts_down'      : hosts_down,
            'hosts_flap'      : hosts_flap if hosts_flap is not None else 0,
            'pending_wait'    : bool(pending_wait),
            # hosts actually visible with the [M] display filter applied - hosts_up/
            # hosts_down above stay the totals for the whole current view regardless
            # of that filter, so HOSTS/HOSTS-UP/HOSTS-DOWN don't collapse to whatever
            # the filter matches; without a filter this just equals 'hosts'.
            'hosts_shown'     : hosts_shown if hosts_shown is not None else len(rows),
            'run_counter'     : run_counter,
            'run_time'        : run_time,
            'logging'         : bool(logging_enabled),
            'logfile'         : logfile_file_name if logging_enabled else '',
            'filter_mode'     : filter_mode,
            'filter_label'    : WEB_VIEW_MODES[filter_mode][0],
            'addr_mode'       : addr_mode,
            'sort_mode'       : sort_mode,
            'learning_phase'  : learning_phase,
            'learning_run'    : learning_run,
            'learning_total'  : learning_total,
            'update_available': update_available,
            'message'         : message,
            'scan_info'       : scan_info,
            'match_filter'    : match_filter,
            'adv_filter'      : adv_export(),
            'adv_values'      : adv_values(original_hosts_list or [], adv_filter),
            'save_csv'        : hosts_have_inventory(r['host'] for r in rows),
            'all_csv'         : hosts_have_inventory(original_hosts_list or []),
            'options'         : options if options is not None else web_state.get('options', {}),
        })


# --- ADV OPTIONS: runtime-adjustable timer/fping settings (web gui only) ---
# (key, kind, lo, hi, step, unit, auto_sentinel) - order matches the web gui modal.
# These are the SAME hard bounds the CLI parser validates (see BACKOFF_MIN etc. and
# the -B/-t/-re/-i/-p/-w/... validation block) - one set of limits, enforced twice.
# auto_sentinel: the value the slider/textbox sends for "auto"/"disabled"/"unset" -
# translated to the field's real off-value (''/'auto'/None) in apply_adv_option().
ADV_OPTIONS = [
    ('backoff',         'float', BACKOFF_MIN, BACKOFF_MAX,       0.1, '',    None),
    ('timeout',         'int',   TIMEOUT_MIN_MS, TIMEOUT_MAX_MS, 10,  'ms',  None),
    ('retries',         'int',   0,   RETRIES_MAX,               1,   '',    None),
    ('down_retries',    'int',   0,   RETRIES_MAX,               1,   '',    0),    # 0 = disabled
    ('interval',        'int',   -1,  INTERVAL_ARG_MAX,          1,   'ms',  -1),   # -1 = auto (unset, use --rate)
    ('num_of_threads',  'int',   0,   THREADS_MANUAL_MAX,        1,   '',    0),    # 0 = auto
    ('waittime',        'float', 0,   WAITTIME_MAX,              0.1, 's',   None),
    ('confirm',         'int',   1,   10,                        1,   '',    None),
    ('rate_pps',        'int',   MIN_RATE_PPS, MAX_RATE_PPS,     10,  'pps', None),
    ('flap_window',     'int',   1,   FLAP_WINDOW_MAX,           10,  'min', None),
    ('down_slices',     'int',   1,   DOWN_SLICES_MAX,           1,   '',    None),
    ('full_sweep',      'int',   0,   FULL_SWEEP_MAX,            1,   '',    None),  # 0 = disabled
    ('dns_ttl',         'int',   0,   DNS_TTL_MAX,               10,  's',   None),
    ('tz_offset',       'int',   -24, 24,                        1,   'h',   None),
    ('log_max_size',    'int',   LOG_MAX_SIZE_MIN, LOG_MAX_SIZE_MAX, 50, 'MB', 0),   # 0 = no limit
    ('log_max_files',   'int',   0,   LOG_MAX_FILES_MAX,         10,  '',    None),  # 0 = unlimited
]
ADV_OPTION_KEYS = set(o[0] for o in ADV_OPTIONS)

# [X] ADV OPTIONS panel (curses) friendly labels - ranges/units/steps stay in
# ADV_OPTIONS above (single source of truth), only the display label lives here.
# Same labels as ADV_OPTIONS_UI (web gui JS), kept in the same order.
ADV_OPTION_LABELS = {
    'backoff':         'BACKOFF',
    'timeout':         'TIMEOUT',
    'retries':         'RETRIES',
    'down_retries':    'DOWN RETRIES',
    'interval':        'INTERVAL',
    'num_of_threads':  'THREADS',
    'waittime':        'WAIT TIME',
    'confirm':         'CONFIRM',
    'rate_pps':        'RATE',
    'flap_window':     'FLAP WINDOW',
    'down_slices':     'DOWN SLICES',
    'full_sweep':      'FULL SWEEP',
    'dns_ttl':         'DNS TTL',
    'tz_offset':       'TIMEZONE',
    'log_max_size':    'MAX LOG SIZE',
    'log_max_files':   'MAX LOG FILES',
}

# keys kept as local variables inside run_web_mode() (not read from args each
# round) - the caller applies the returned value itself, see run_web_mode()
ADV_OPTION_LOCAL_KEYS = set(['down_retries', 'flap_window', 'confirm',
                             'down_slices', 'full_sweep', 'tz_offset'])


def apply_adv_option(key, raw, args):
    """Validate one ADV OPTIONS change and apply it where possible.

    args-backed keys (waittime/interval/rate_pps/num_of_threads/dns_ttl) are
    written straight into args, since run_web_mode() re-reads args.X live each
    round. backoff/timeout/retries are true module globals (see build_fping_cmd()).
    The ADV_OPTION_LOCAL_KEYS are local variables in run_web_mode() - this
    function only validates/parses them, the caller assigns the returned value.

    Returns (ok, value, message).
    """
    global backoff, timeout, retries
    spec = next((o for o in ADV_OPTIONS if o[0] == key), None)
    if spec is None:
        return False, None, 'unknown option: ' + str(key)
    _, kind, lo, hi, _step, _unit, auto_sentinel = spec
    raw = str(raw).strip()
    try:
        if key == 'num_of_threads' and raw.lower() == 'auto':
            val = 'auto'
        elif key == 'interval' and raw == '':
            val = ''
        else:
            num = float(raw) if kind == 'float' else int(raw)
            if auto_sentinel is not None and num == auto_sentinel:
                # 'auto'/'off' sentinel, per field: interval (-1) -> '' (unset,
                # use --rate), num_of_threads (0) -> 'auto', down_retries (0) -> None
                if key == 'interval':
                    val = ''
                elif key == 'num_of_threads':
                    val = 'auto'
                elif key == 'log_max_size':
                    val = 0
                else:
                    val = None
            elif num < lo or num > hi:
                return False, None, key + ': must be between ' + str(lo) + ' and ' + str(hi)
            else:
                val = round(num, 2) if kind == 'float' else int(num)
    except ValueError:
        return False, None, key + ': invalid value'

    if key == 'down_retries' and val is not None and val > int(retries):
        return False, None, 'down_retries must not be larger than retries (' + str(retries) + ')'

    if key == 'waittime':
        args.waittime = str(val)
    elif key == 'interval':
        args.interval = '' if val in ('', None) else str(int(val))
    elif key == 'rate_pps':
        args.rate_pps = str(int(val))
    elif key == 'num_of_threads':
        args.num_of_threads = 'auto' if val == 'auto' else str(int(val))
    elif key == 'dns_ttl':
        args.dns_ttl = str(int(val))
    elif key == 'log_max_size':
        args.log_max_size = str(int(val))
    elif key == 'log_max_files':
        args.log_max_files = str(int(val))
    elif key == 'retries':
        retries = str(int(val))
    elif key == 'backoff':
        backoff = str(val)
    elif key == 'timeout':
        timeout = str(int(val))
    # else: ADV_OPTION_LOCAL_KEYS - caller applies 'val' to its own local var
    return True, val, key + ' set to ' + str(val)


def adv_option_values(args, down_retries, flap_window, confirm, down_slices,
                      full_sweep, tz_offset):
    """Snapshot of all ADV OPTIONS current values, as raw strings the client/
    apply_adv_option() round-trip understands. Used for the web gui's options
    modal and for the -reset to default- snapshot taken at run_web_mode() start."""
    return {
        'waittime':       args.waittime,
        'interval':       args.interval if args.interval != '' else '-1',
        'rate_pps':       args.rate_pps,
        # 0, not the word 'auto' - a <input type=range> silently ignores a
        # non-numeric .value assignment (stays wherever it was); down_retries
        # is int-backed already so it never hits this problem
        'num_of_threads': '0' if args.num_of_threads == 'auto' else str(args.num_of_threads),
        'dns_ttl':        args.dns_ttl,
        'down_retries':   str(down_retries) if down_retries is not None else '0',
        'flap_window':    str(flap_window),
        'confirm':        str(confirm),
        'down_slices':    str(down_slices),
        'full_sweep':     str(full_sweep),
        'tz_offset':      str(tz_offset),
        'log_max_size':   args.log_max_size,
        'log_max_files':  args.log_max_files,
        'backoff':        str(backoff),
        'timeout':        str(timeout),
        'retries':        str(retries),
    }


# ADV OPTIONS key -> its CLI flag, for #INFO# logging (write_log_info()) - one
# ADV OPTIONS change is logged as that single CLI-equivalent flag, see
# format_option_cli() below.
# a slider drag or held +/- button fires set_option many times per second -
# a value is only #INFO#-logged once this many seconds pass with no further
# change to that key (see pending_info in run_web_mode)
INFO_DEBOUNCE_SECONDS = 1.0

ADV_OPTION_CLI_FLAG = {
    'backoff':         '-B',
    'timeout':         '-t',
    'retries':         '-re',
    'down_retries':    '-dr',
    'interval':        '-i',
    'num_of_threads':  '-p',
    'waittime':        '-w',
    'confirm':         '-cf',
    'rate_pps':        '-ra',
    'flap_window':     '-fw',
    'down_slices':     '-ds',
    'full_sweep':      '-fs',
    'dns_ttl':         '-dns',
    'tz_offset':       '-tz',
    'log_max_size':    '-lms',
    'log_max_files':   '-lmf',
}


def format_option_cli(key, val):
    """One ADV OPTIONS change as its single CLI-flag equivalent, e.g. '-B 2.0'.

    val is apply_adv_option()'s already-normalized return value - this only
    maps the auto/off sentinels back to the CLI's own spelling (interval=''
    -> -1, num_of_threads='auto' stays 'auto', down_retries=None -> 0).
    """
    flag = ADV_OPTION_CLI_FLAG[key]
    if key == 'interval':
        shown = '-1' if val in ('', None) else str(int(val))
    elif key == 'num_of_threads':
        shown = 'auto' if val == 'auto' else str(int(val))
    elif key == 'down_retries':
        shown = '0' if val is None else str(int(val))
    else:
        shown = str(val)
    return flag + ' ' + shown


def current_option_value(key, args, backoff, timeout, retries, down_retries,
                         flap_window, confirm, down_slices, full_sweep, tz_offset):
    """One ADV OPTIONS key's current value, normalized the same way
    apply_adv_option()'s return value is - so it can be diffed/logged with
    format_option_cli() after a RESET TO DEFAULT (see reset_options).
    """
    if key == 'backoff':        return float(backoff)
    if key == 'timeout':        return int(timeout)
    if key == 'retries':        return int(retries)
    if key == 'down_retries':   return down_retries
    if key == 'interval':       return '' if args.interval == '' else int(args.interval)
    if key == 'num_of_threads': return 'auto' if args.num_of_threads == 'auto' else int(args.num_of_threads)
    if key == 'waittime':       return float(args.waittime)
    if key == 'confirm':        return confirm
    if key == 'rate_pps':       return int(args.rate_pps)
    if key == 'flap_window':    return flap_window
    if key == 'down_slices':    return down_slices
    if key == 'full_sweep':     return full_sweep
    if key == 'dns_ttl':        return int(args.dns_ttl)
    if key == 'tz_offset':      return tz_offset
    if key == 'log_max_size':   return int(args.log_max_size)
    if key == 'log_max_files':  return int(args.log_max_files)
    return None


def build_cli_snapshot(args, backoff, timeout, retries, down_retries, flap_window,
                       confirm, down_slices, full_sweep, tz_offset):
    """Full current configuration as one CLI-flag-style string, for the
    startup #INFO# log line (write_log_info()) - reconstructs the equivalent
    'eping.py ...' command line for every currently active setting.

    One-shot actions with no persistent 'current value' (-cl/--clean,
    -setref/--set_reference, -gn/--get_names as a startup action) are left
    out - they describe something that already happened, not a setting.
    Flags left at their inactive/empty value (-n, -r, -df, -o, -du, -4/-6,
    -ph, -ipo, -dg, -ncs, -web, -wv) are omitted, same as a user would simply
    not pass them.
    """
    parts = ['-f ' + args.hostfile]
    if args.disable_hostfile:
        parts.append('-df')
    if args.network_cidr:
        parts.append('-n ' + args.network_cidr)
    if args.network_range:
        parts.append('-r ' + args.network_range)
    parts.append('-B ' + str(backoff))
    parts.append('-t ' + str(timeout))
    parts.append('-re ' + str(retries))
    parts.append('-i ' + ('-1' if args.interval == '' else str(args.interval)))
    if args.logfile:
        parts.append('-o ' + args.logfile)
    if not args.disable_logging:
        parts.append('-dl')
    parts.append('-up ' + str(args.up_hosts_check))
    parts.append('-p ' + ('auto' if args.num_of_threads == 'auto' else str(args.num_of_threads)))
    parts.append('-tz ' + str(tz_offset))
    parts.append('-w ' + str(args.waittime))
    if args.disable_versioncheck:
        parts.append('-du')
    parts.append('-ra ' + str(args.rate_pps))
    parts.append('-dns ' + str(args.dns_ttl))
    if args.force_ipv4:
        parts.append('-4')
    if args.force_ipv6:
        parts.append('-6')
    if args.prefer_hostname:
        parts.append('-ph')
    if args.ip_only:
        parts.append('-ipo')
    parts.append('-dr ' + ('0' if down_retries is None else str(down_retries)))
    if args.diag:
        parts.append('-dg')
    parts.append('-fw ' + str(flap_window))
    parts.append('-cf ' + str(confirm))
    parts.append('-ds ' + str(down_slices))
    parts.append('-fs ' + str(full_sweep))
    parts.append('-lms ' + str(args.log_max_size))
    parts.append('-lmf ' + str(args.log_max_files))
    if args.no_check_source:
        parts.append('-ncs')
    if args.no_csv_fallback:
        parts.append('-ncf')
    if args.web:
        parts.append('-web')
    if args.web_view:
        parts.append('-wv')
    if args.web_view_control:
        parts.append('-wvc')
    parts.append('-port ' + str(args.web_port))
    parts.append('-bind ' + args.web_bind)
    if getattr(args, 'ssh', None):
        parts.append('-ssh ' + args.ssh)
        if getattr(args, 'ssh_key', None):
            parts.append('-sshkey ' + args.ssh_key)
        if getattr(args, 'ssh_hostkey', 'accept-new') != 'accept-new':
            parts.append('-sshhk ' + args.ssh_hostkey)
        if getattr(args, 'ssh_no_resolve', False):
            parts.append('-sshnr')
    return ' '.join(parts)


def host_spec_cli(action, value):
    """ADD/DEL host input as its CLI-flag equivalent, for #INFO# logging.

    Reuses the real -n (CIDR/single host as /32 or /128) and -r (range)
    flags - no invented flag for a single add/remove. 'action' ('ADD'/'DEL')
    is a plain label, not a flag, since eping.py has no startup flag for
    removing a host.
    """
    v = value.strip()
    if match_re(v, cidr_ipv4_re):
        spec = '-n ' + v
    elif ('-' in v and v.count('-') == 1
          and all(match_re(p.strip(), ip_re) for p in v.split('-'))):
        spec = '-r ' + v
    elif ip_version_str(v) == '6':
        spec = '-n ' + v + '/128'
    elif is_ip_host(v):
        spec = '-n ' + v + '/32'
    else:
        spec = '-n ' + v   # hostname - no real flag fits; kept for a readable trail
    return action + ' ' + spec


def run_web_mode(original_hosts_list, host_state, args, logfile_file_name,
                 update_available, up_check_runs, down_retries=None, full_sweep=0,
                 confirm=1, down_slices=1, flap_window=FLAP_WINDOW_DEF):
    """Headless main loop - same logic as the CLI loop, output goes to the web gui."""
    global _logfile_file_name   # kept in sync with logfile_file_name - see _web_sigint()
    global backoff, timeout, retries   # ADV OPTIONS - mutated by apply_adv_option()
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
        print(' no hosts yet - use ADD or FILE OPERATIONS > ADD HOSTS FILE in the web gui')
    print(' press CTRL-C to stop\n')

    with web_lock:
        web_state['wait_time'] = float(args.waittime)

    tz_offset         = int(args.time_zone_adjust)
    # ADV OPTIONS: snapshot of every startup value, for RESET TO DEFAULT
    start_option_values = adv_option_values(args, down_retries, flap_window,
                                            confirm, down_slices, full_sweep, tz_offset)
    # published right away - without this the ADV OPTIONS modal shows empty
    # fields/sliders at their minimum until the first round completes and a
    # later web_publish()/set_option call fills web_state['options'] in
    with web_lock:
        web_state['options'] = start_option_values
    active_hosts_list = list(original_hosts_list)
    filter_mode       = 0
    # web gui only: one mutually-exclusive address mode replaces the separate
    # PREFER HOSTNAME / IP ONLY toggles - see ADDR_MODE_LABELS above.
    addr_mode         = 0
    ip_only_map       = {}
    sort_mode         = 0
    down_streak       = {}
    learning_done     = (up_check_runs == 0)
    up_seen           = set()
    run_counter       = 1
    message           = ''
    gn_thread         = None   # [G] background PTR lookup - see get_names_start/finish
    gn_result         = None
    gn_candidates     = []
    match_filter_re   = None   # [M] display-only regex filter - active_hosts_list unaffected
    match_filter_text = ''
    pending_info      = {}   # ADV OPTIONS #INFO# debounce - key -> (val, last_change_ts),
                              # see set_option/flush below
    pending_add_hosts = set()   # just-added hosts not yet in host_state - see ADD/UPLOAD
                                 # below and the completion check after update_host_state()

    def apply_addr_mode(lst):
        if addr_mode == 1:
            return apply_prefer_hostname(lst, int(args.dns_ttl))
        if addr_mode == 2:
            return apply_prefer_ip(lst, int(args.dns_ttl))
        return lst

    # -gn / -ph / -ipo: applied once, before the first ping round
    if args.get_names:
        apply_get_names(original_hosts_list, active_hosts_list, host_state,
                        up_seen, down_streak, int(args.dns_ttl))
    if args.ip_only:
        ip_only_map, _ = apply_ip_only_on_web(original_hosts_list, active_hosts_list,
                                             host_state, up_seen, down_streak, int(args.dns_ttl))
        # everything apply_ip_only_on_web could resolve is now a raw IP in the list -
        # what is still a hostname here failed to resolve (NO-DNS); drop it from
        # what gets shown/pinged while IP ONLY stays active (original_hosts_list is
        # untouched, so it reappears when switching to a different address mode)
        active_hosts_list = [h for h in active_hosts_list if is_ip_host(h)]
        addr_mode = 3
    elif args.prefer_hostname:
        addr_mode = 1
    if addr_mode == 1:
        _n_names = sum(1 for h in active_hosts_list if not is_ip_host(h))
        active_hosts_list = run_with_wait_box(
            ['PLEASE WAIT', 'resolving ' + str(_n_names) + ' hostnames'],
            lambda: apply_addr_mode(active_hosts_list))
    else:
        active_hosts_list = apply_addr_mode(active_hosts_list)

    while True:
        # --- [G] background PTR lookup: apply results once the thread is done ---
        gn_just_finished = False
        if gn_thread is not None and not gn_thread.is_alive():
            message = get_names_finish(gn_candidates, gn_result, original_hosts_list,
                                       active_hosts_list, host_state, up_seen, down_streak)
            gn_thread         = None
            gn_just_finished  = True

        # --- commands coming from the browser ---
        with web_lock:
            cmds = list(web_commands)
            del web_commands[:]
        for cmd, value in cmds:
            if cmd == 'up_only':
                # [U] / web keyboard shortcut - always cycles the original 3 CLI
                # views; jumping in from a web-only extended view (3-6, picked via
                # the dropdown) resets to ALL HOSTS first, then continues cycling
                next_mode = (filter_mode + 1) % len(FILTER_MODES) if filter_mode < len(FILTER_MODES) else 0
                next_list = filter_hosts(next_mode, original_hosts_list, host_state,
                                         tz_offset, flap_window, up_seen)
                if next_list or next_mode == 0:
                    filter_mode       = next_mode
                    message = 'view: ' + FILTER_MODES[filter_mode][0]
                    write_log_info(args.disable_logging, logfile_file_name,
                                   'FILTER ' + FILTER_MODES[filter_mode][0], tz_offset)
                else:
                    message = 'no hosts match ' + FILTER_MODES[next_mode][0]
            elif cmd == 'set_filter':
                # direct selection from the web gui dropdown, no cycling - covers all
                # views in WEB_VIEW_MODES, not just the 3 the CLI's [U] key cycles
                try:
                    target_mode = int(value)
                except (TypeError, ValueError):
                    target_mode = filter_mode
                if 0 <= target_mode < len(WEB_VIEW_MODES) and target_mode != filter_mode:
                    target_list = filter_hosts(target_mode, original_hosts_list, host_state,
                                               tz_offset, flap_window, up_seen)
                    if target_list or target_mode == 0:
                        filter_mode       = target_mode
                        message = 'view: ' + WEB_VIEW_MODES[filter_mode][0]
                        write_log_info(args.disable_logging, logfile_file_name,
                                       'FILTER ' + WEB_VIEW_MODES[filter_mode][0], tz_offset)
                    else:
                        message = 'no hosts match ' + WEB_VIEW_MODES[target_mode][0]
            elif cmd == 'addr_mode':
                # web-gui-only dropdown: off / prefer hostname / prefer ip / ip only
                # - mutually exclusive, replaces the old separate prefer_hostname
                # and ip_only toggles (see ADDR_MODE_LABELS)
                try:
                    target_mode = int(value)
                except (TypeError, ValueError):
                    target_mode = -1
                if not (0 <= target_mode < len(ADDR_MODE_LABELS)):
                    message = 'invalid address mode'
                elif target_mode != addr_mode:
                    if addr_mode == 3:
                        # leaving IP ONLY: restore the renamed hostnames first
                        apply_ip_only_off(ip_only_map, original_hosts_list,
                                          active_hosts_list, host_state,
                                          up_seen, down_streak)
                        ip_only_map = {}
                    addr_mode = target_mode
                    if addr_mode == 3:
                        ip_only_map, message = apply_ip_only_on_web(
                            original_hosts_list, active_hosts_list, host_state,
                            up_seen, down_streak, int(args.dns_ttl))
                        # drop unresolved (NO-DNS) hostnames from view/ping while
                        # IP ONLY is active - see the startup (-ipo) path above
                        active_hosts_list = [h for h in active_hosts_list if is_ip_host(h)]
                    else:
                        active_hosts_list = apply_addr_mode(list(original_hosts_list))
                        message = 'address mode: ' + ADDR_MODE_LABELS[addr_mode]
            elif cmd == 'get_names':
                if gn_thread is not None and gn_thread.is_alive():
                    message = 'get names: already running'
                else:
                    gn_thread, gn_result, gn_candidates = get_names_start(
                        original_hosts_list, int(args.dns_ttl))
                    if gn_thread is None:
                        message = ('get names: not available - the jump host has no working resolver (or it is switched off)'
                                   if (ssh_target and not jr_active()) else 'get names: no eligible IP host(s)')
                    else:
                        message = ('get names: running in background (%d host(s))'
                                  % len(gn_candidates))
                        write_log_info(args.disable_logging, logfile_file_name, '-gn', tz_offset)
            elif cmd == 'match_filter':
                value = value.strip()
                if not value:
                    match_filter_re, match_filter_text = None, ''
                    message = 'match filter: off'
                else:
                    try:
                        match_filter_re   = re.compile(value, re.IGNORECASE)
                        match_filter_text = value
                        message = 'display filter: on'
                    except re.error as e:
                        message = 'display filter: invalid regex - ' + str(e)
            elif cmd == 'adv_filter':
                err = adv_filter_set(value)
                if err:
                    message = 'adv filter: ' + err
                elif adv_filter:
                    message = 'adv filter: on (' + adv_text() + ')'
                else:
                    message = 'adv filter: off'
            elif cmd == 'sort':
                try:
                    sort_mode = int(value) % len(SORT_MODES)
                except ValueError:
                    sort_mode = 0
                message = 'sort: ' + SORT_MODES[sort_mode][0]
            elif cmd == 'add':
                add_stats = {}
                new_hosts = parse_host_input(value, add_stats)
                if not new_hosts:
                    message = add_stats.get('error') or ('invalid host: ' + value)
                else:
                    before_active = set(active_hosts_list)
                    added, err = add_hosts_to(new_hosts, active_hosts_list, original_hosts_list)
                    if err:
                        message = err
                    elif added:
                        pending_add_hosts |= (set(new_hosts) - before_active)
                        message = 'added ' + str(added) + ' host(s) - please wait, pinging ...'
                        write_log_info(args.disable_logging, logfile_file_name,
                                       host_spec_cli('ADD', value), tz_offset)
                    else:
                        message = 'added 0 host(s)'
            elif cmd == 'del':
                del_stats = {}
                del_hosts = parse_host_input(value, del_stats)
                if not del_hosts:
                    message = del_stats.get('error') or ('invalid host: ' + value)
                else:
                    removed = remove_hosts_from(del_hosts, active_hosts_list,
                                                original_hosts_list, host_state)
                    up_seen.difference_update(del_hosts)
                    for _h in del_hosts:
                        down_streak.pop(_h, None)
                    forget_names(del_hosts)
                    message = 'removed ' + str(removed) + ' host(s)'
                    if removed:
                        write_log_info(args.disable_logging, logfile_file_name,
                                       host_spec_cli('DEL', value), tz_offset)
            elif cmd == 'upload':
                up_stats  = {}
                new_hosts = parse_hosts_from_text(value, up_stats, addr_mode not in (2, 3))
                if not new_hosts and up_stats.get('skipped'):
                    message = ('upload: mask must be /%d../%d: %s'
                               % (CIDR_MIN_MASK, CIDR_MAX_MASK, up_stats['skipped'][0]))
                elif not new_hosts:
                    message = 'upload: no valid host found in file'
                else:
                    before_active = set(active_hosts_list)
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
                        if up_stats.get('csv_ignored'):
                            message += (', %d csv row(s) ignored (no valid IP)' % up_stats['csv_ignored'])
                        if up_stats.get('csv_dups'):
                            message += (', %d csv row(s) duplicate' % up_stats['csv_dups'])
                        if added:
                            pending_add_hosts |= (set(new_hosts) - before_active)
                            message += ' - please wait, pinging ...'
                            write_log_info(args.disable_logging, logfile_file_name,
                                           'ADD -f (uploaded, ' + str(added) + ' host(s))', tz_offset)
            elif cmd in ('add_list', 'del_list'):
                lst_stats = {}
                lst_hosts = parse_hosts_from_text(value, lst_stats, addr_mode not in (2, 3))
                if not lst_hosts:
                    message = ('list: mask must be /%d../%d: %s'
                               % (CIDR_MIN_MASK, CIDR_MAX_MASK, lst_stats['skipped'][0])
                               if lst_stats.get('skipped') else 'list: no valid host found')
                elif cmd == 'add_list':
                    renamed = (merge_csv_ips_into_lists(lst_hosts, original_hosts_list,
                                                        active_hosts_list, host_state,
                                                        up_seen, down_streak)
                               if lst_stats.get('csv') else 0)
                    before_active = set(active_hosts_list)
                    added, err = add_hosts_to(lst_hosts, active_hosts_list, original_hosts_list)
                    if err:
                        message = 'list ' + err
                    else:
                        message = ('list: ' + str(added) + ' new host(s) of '
                                   + str(len(lst_hosts)) + ' found')
                        if lst_stats.get('csv'):
                            message += (', %d existing host(s) updated (%d renamed to hostname)'
                                        % (len(lst_hosts) - added, renamed))
                        if lst_stats.get('ignored'):
                            message += ', %d ignored' % len(lst_stats['ignored'])
                        if added:
                            pending_add_hosts |= (set(lst_hosts) - before_active)
                            message += ' - please wait, pinging ...'
                            write_log_info(args.disable_logging, logfile_file_name,
                                           'ADD list (' + str(added) + ' host(s))', tz_offset)
                else:
                    removed = remove_hosts_from(lst_hosts, active_hosts_list,
                                                original_hosts_list, host_state)
                    up_seen.difference_update(lst_hosts)
                    for _h in lst_hosts:
                        down_streak.pop(_h, None)
                    forget_names(lst_hosts)
                    message = ('list: removed ' + str(removed) + ' of '
                               + str(len(lst_hosts)) + ' host(s) found')
                    if removed:
                        write_log_info(args.disable_logging, logfile_file_name,
                                       'DEL list (' + str(removed) + ' host(s))', tz_offset)
            elif cmd == 'set_ref':
                # what is actually shown becomes the new reference list - the view
                # filter (active_hosts_list) AND the [M]/display filter (display_list
                # narrows it further) both apply, see quick/quick_rows just below
                shown_hosts = [o[0] for o in build_display(view_hosts(filter_mode, active_hosts_list, host_state, tz_offset, flap_window), host_state,
                                                            sort_mode, tz_offset, flap_window)]
                if match_filter_re is not None or adv_filter:
                    shown_hosts = [h for h in shown_hosts
                                  if host_visible(match_filter_re, h,
                                                host_state[h][8] if h in host_state and len(host_state[h]) > 8 else '')]
                _keep = set(shown_hosts)   # built once - a set() per element made this O(n^2)
                dropped = [h for h in original_hosts_list if h not in _keep]
                prune_dropped_hosts(dropped, host_state, up_seen, down_streak)
                original_hosts_list[:] = shown_hosts
                active_hosts_list      = shown_hosts
                filter_mode = 0
                match_filter_re, match_filter_text = None, ''
                adv_filter.clear()
                message = 'reference set to the ' + str(len(shown_hosts)) + ' host(s) shown'
                write_log_info(args.disable_logging, logfile_file_name, '-setref', tz_offset)
            elif cmd == 'zero':
                for _entry in host_state.values():
                    _entry[5] = 0
                    _entry[6] = ''
                host_hist.clear()
                message = 'change counters reset'
                write_log_info(args.disable_logging, logfile_file_name, 'ZERO', tz_offset)
            elif cmd == 'add_comment':
                value = value.strip()
                if not args.disable_logging:
                    message = 'logging is off - comment not saved'
                elif not value:
                    message = 'comment: empty, not saved'
                else:
                    write_log_comment(args.disable_logging, logfile_file_name, value, tz_offset)
                    message = 'comment logged'
            elif cmd == 'reset_log':
                # value encoding (see the web gui's runResetLog()): OFF state -
                # the raw value IS the optional custom name (blank = auto-
                # generated); ON state - 'y' (clear), 'new' or 'new=<custom
                # name>' (new file)
                raw = value.strip()
                action, _, custom_raw = raw.partition('=')
                action = action.lower()
                if not args.disable_logging:
                    # logging is currently OFF - START LOG turns it on right away,
                    # no y/n confirmation needed (there is nothing to lose yet)
                    new_name = validate_custom_logfile_name(raw) if raw else new_logfile_name(tz_offset)
                    if new_name is None:
                        message = 'invalid file name - logging not started'
                    elif reset_logfile(new_name):
                        args.disable_logging = True   # True means 'logging enabled' (see -dl)
                        logfile_file_name = new_name
                        _logfile_file_name = new_name   # keep _web_sigint() in sync
                        message = 'logging started: ' + logfile_file_name
                        # fresh file - same full snapshot as a program startup, see main()
                        write_log_info(args.disable_logging, logfile_file_name,
                                       build_cli_snapshot(args, backoff, timeout, retries,
                                                          down_retries, flap_window, confirm,
                                                          down_slices, full_sweep, tz_offset),
                                       tz_offset)
                    else:
                        message = 'failed to start logging'
                else:
                    if action == 'y':
                        if reset_logfile(logfile_file_name):
                            message = 'logging reset - ' + logfile_file_name + ' cleared'
                            write_log_info(args.disable_logging, logfile_file_name,
                                           build_cli_snapshot(args, backoff, timeout, retries,
                                                              down_retries, flap_window, confirm,
                                                              down_slices, full_sweep, tz_offset),
                                           tz_offset)
                        else:
                            message = 'failed to reset log file'
                    elif action == 'new':
                        new_name = validate_custom_logfile_name(custom_raw) if custom_raw else new_logfile_name(tz_offset)
                        if new_name is None:
                            message = 'invalid file name - new logfile not created'
                        elif reset_logfile(new_name):
                            logfile_file_name  = new_name
                            _logfile_file_name = new_name   # keep _web_sigint() in sync
                            message = 'new logfile: ' + logfile_file_name
                            write_log_info(args.disable_logging, logfile_file_name,
                                           build_cli_snapshot(args, backoff, timeout, retries,
                                                              down_retries, flap_window, confirm,
                                                              down_slices, full_sweep, tz_offset),
                                           tz_offset)
                        else:
                            message = 'failed to create new logfile'
                    else:
                        message = 'reset cancelled'
            elif cmd in SAVE_HOSTS_CMDS:
                # FILE OPERATIONS > SAVE HOSTS FILE ON SERVER - client already
                # asked for confirmation. A typed name always saves as that
                # (possibly new) file, even with a hostfile already active;
                # blank overwrites the active hostfile, or falls back to the
                # default name if none is active (sanitize_hostfile_save_name())
                with web_lock:
                    shown_now = list(web_state.get('host_list_shown') or [])
                target, _as_csv = resolve_save_target(args, value, shown_now, '_txt' in cmd)
                if target is None:
                    message = 'invalid file name - hosts file not saved'
                else:
                    if save_hosts_file(target, shown_now, ('' if 'noopt' in cmd else opt_lines_text(
                            args, adv_option_values(args, down_retries, flap_window, confirm,
                                                    down_slices, full_sweep, tz_offset),
                            addr_mode, args.disable_logging))):
                        message = 'saved ' + str(len(shown_now)) + ' host(s) to ' + target
                        write_log_info(args.disable_logging, logfile_file_name,
                                       'SAVE HOSTS FILE: ' + target, tz_offset)
                    else:
                        message = 'failed to save hosts file'
            elif cmd == 'set_option':
                # ADV OPTIONS feedback is inline in the modal (revert + flash on
                # rejection, see advCheckApplied() client-side), not the footer -
                # 'message'/msg_seq deliberately untouched here, see reset_options
                key, _, raw = str(value).partition('=')
                ok, val, _opt_msg = apply_adv_option(key, raw, args)
                if ok and key in ADV_OPTION_LOCAL_KEYS:
                    if key == 'down_retries':
                        down_retries = val
                    elif key == 'flap_window':
                        flap_window = val
                    elif key == 'confirm':
                        confirm = val
                    elif key == 'down_slices':
                        down_slices = val
                    elif key == 'full_sweep':
                        full_sweep = val
                    elif key == 'tz_offset':
                        tz_offset = val
                if ok:
                    # debounced - a dragged slider/held +/- fires many set_option
                    # calls per second; only the value it settles on gets logged,
                    # see INFO_DEBOUNCE_SECONDS flush below
                    pending_info[key] = (val, time.time())
                # Publish the new value right away, not at the end of this fping
                # round - a round can easily take longer than advCheckApplied()'s
                # check delay (especially right after raising backoff/timeout/
                # retries, which lengthens the round itself), which was making the
                # client see a stale value and wrongly revert+flash a just-accepted
                # change as rejected.
                with web_lock:
                    web_state['options'] = adv_option_values(args, down_retries, flap_window,
                                                             confirm, down_slices, full_sweep, tz_offset)
            elif cmd == 'reset_options':
                # same as set_option above: no footer message on purpose
                _before_reset = {_k: current_option_value(_k, args, backoff, timeout, retries,
                                                          down_retries, flap_window, confirm,
                                                          down_slices, full_sweep, tz_offset)
                                 for _k in ADV_OPTION_KEYS}
                for _key, _raw in start_option_values.items():
                    _ok, _val, _ = apply_adv_option(_key, _raw, args)
                    if _ok and _key in ADV_OPTION_LOCAL_KEYS:
                        if _key == 'down_retries':
                            down_retries = _val
                        elif _key == 'flap_window':
                            flap_window = _val
                        elif _key == 'confirm':
                            confirm = _val
                        elif _key == 'down_slices':
                            down_slices = _val
                        elif _key == 'full_sweep':
                            full_sweep = _val
                        elif _key == 'tz_offset':
                            tz_offset = _val
                # only log keys RESET TO DEFAULT actually changed - a reset that
                # touches nothing (already at defaults) should stay silent
                for _key in ADV_OPTION_KEYS:
                    _after = current_option_value(_key, args, backoff, timeout, retries,
                                                  down_retries, flap_window, confirm,
                                                  down_slices, full_sweep, tz_offset)
                    if _after != _before_reset[_key]:
                        write_log_info(args.disable_logging, logfile_file_name,
                                       format_option_cli(_key, _after), tz_offset)
                # same immediate-publish reasoning as set_option above
                with web_lock:
                    web_state['options'] = adv_option_values(args, down_retries, flap_window,
                                                             confirm, down_slices, full_sweep, tz_offset)
            elif cmd == 'clear':
                active_hosts_list   = []
                original_hosts_list[:] = []
                host_state.clear()
                host_hist.clear()
                host_meta.clear()
                host_csv_ip.clear()
                adv_filter.clear()
                up_seen.clear()
                down_streak.clear()
                _dns_cache.clear()
                _addr_redundancy_cache.clear()
                filter_mode = 0
                message = 'all hosts cleared'
                write_log_info(args.disable_logging, logfile_file_name, 'CLEAR', tz_offset)
            elif cmd == 'exit':
                with web_lock:
                    web_state['stopped'] = True
                    web_state['message'] = 'stopped'
                time.sleep(1.5)   # let the browser pick up the final status
                print(f'THX for using eping.py v{VERSION} - www.jeitler.cc')
                if is_newer_version(_remote_version, VERSION):
                    print_update_notice(_remote_version)
                # flush any not-yet-settled ADV OPTIONS change - see set_option
                for _key, (_val, _t) in pending_info.items():
                    write_log_info(args.disable_logging, logfile_file_name,
                                   format_option_cli(_key, _val), tz_offset)
                pending_info.clear()
                # no maybe_run_epinga() prompt in web mode - GENERATE REPORT in the
                # web GUI already covers on-demand analysis, and a terminal [y/N]
                # prompt makes no sense for a headless/background web server
                sys.stdout.flush()
                # os._exit(), not sys.exit(): see sigint_handler() for why - a
                # running [G] GET NAMES lookup must not delay shutdown.
                ssh_shutdown()
                os._exit(0)

        # ADV OPTIONS #INFO# debounce - a value that hasn't changed again in
        # INFO_DEBOUNCE_SECONDS is done settling, log it now (see set_option)
        if pending_info:
            _now = time.time()
            for _key in list(pending_info.keys()):
                _val, _t = pending_info[_key]
                if _now - _t >= INFO_DEBOUNCE_SECONDS:
                    write_log_info(args.disable_logging, logfile_file_name,
                                   format_option_cli(_key, _val), tz_offset)
                    del pending_info[_key]

        if cmds or gn_just_finished:
            # view and order are pure display changes - show them at once instead of
            # letting the browser wait for the running round, same as the CLI does
            # HOSTS / HOSTS-UP / HOSTS-DOWN count all hosts, the view and the display
            # filters only narrow what is SHOWN
            quick_all = build_display(active_hosts_list, host_state, sort_mode,
                                      tz_offset, flap_window)
            quick_up = sum(1 for e in quick_all if 'UP' in e[1])
            quick_total = len(quick_all)
            quick    = view_rows(quick_all, filter_mode, host_state, tz_offset, flap_window)
            if match_filter_re is not None or adv_filter:
                quick = apply_match_filter(quick, match_filter_re)
            with web_lock:
                web_state['message']      = message
                web_state['pending_wait'] = bool(pending_add_hosts)
                web_state['msg_seq']      = web_state.get('msg_seq', 0) + 1
                quick_rows                = web_rows(quick)
                web_state['rows']         = quick_rows
                # DOWNLOAD - SHOWN/ALL HOSTS, see web_publish()
                web_state['host_list_shown'] = [r['host'] for r in quick_rows]
                web_state['host_list_all']   = list(original_hosts_list)
                web_state['hosts']        = quick_total
                web_state['hosts_up']     = quick_up
                web_state['hosts_down']   = quick_total - quick_up
                web_state['hosts_shown']  = len(quick)
                web_state['filter_mode']  = filter_mode
                web_state['filter_label'] = WEB_VIEW_MODES[filter_mode][0]
                web_state['addr_mode'] = addr_mode
                web_state['sort_mode']    = sort_mode
                web_state['match_filter'] = match_filter_text
                web_state['adv_filter']   = adv_export()
                web_state['adv_values']   = adv_values(original_hosts_list, adv_filter)
                web_state['save_csv']     = hosts_have_inventory(web_state['host_list_shown'])
                web_state['all_csv']      = hosts_have_inventory(original_hosts_list)
                # logging state can flip live (START LOG) - keep the quick path in sync too
                web_state['logging']      = bool(args.disable_logging)
                web_state['logfile']      = logfile_file_name if args.disable_logging else ''
                web_state['options']      = adv_option_values(args, down_retries, flap_window,
                                                              confirm, down_slices, full_sweep, tz_offset)

        # --- learning phase ---
        if not learning_done:
            if run_counter <= up_check_runs:
                learning_phase = False
            else:
                learning_done = True
                if args.set_reference:
                    # -setref: same as the 'set_ref' web command, once learning ends
                    _up_list = apply_addr_mode(sorted(up_seen, key=lambda h: (
                        int(ipaddress.ip_address(h)) if is_ip_host(h) else float('inf'))))
                    _keep = set(_up_list)   # once, not per element (was O(n^2))
                    prune_dropped_hosts([h for h in original_hosts_list if h not in _keep],
                                        host_state, up_seen, down_streak)
                    original_hosts_list = list(_up_list)
                    active_hosts_list   = _up_list
                    filter_mode = 0
                else:
                    filter_mode = 1    # UP view (display filter), every host is still pinged
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
        if args.disable_logging:
            _new_lf = rotate_log_if_needed(logfile_file_name, int(args.log_max_size),
                                           int(args.log_max_files), tz_offset)
            if _new_lf != logfile_file_name:
                logfile_file_name  = _new_lf
                _logfile_file_name = _new_lf
                write_log_info(args.disable_logging, logfile_file_name,
                              build_cli_snapshot(args, backoff, timeout, retries,
                                                 down_retries, flap_window, confirm,
                                                 down_slices, full_sweep, tz_offset), tz_offset)
        if pending_add_hosts and pending_add_hosts <= set(host_state):
            pending_add_hosts.clear()
            message = 'done'
            with web_lock:
                web_state['msg_seq'] = web_state.get('msg_seq', 0) + 1
        phase['state'] = time.time() - _t

        _t = time.time()
        display_all = build_display(active_hosts_list, host_state, sort_mode,
                                    tz_offset, flap_window)
        # HOSTS/HOSTS-UP/HOSTS-DOWN/FLAPPING count all hosts - the view and the [M] /
        # ADV display filters only narrow what is SHOWN (hosts_count_shown below).
        hosts_count_up   = sum(1 for e in display_all if 'UP' in e[1])
        hosts_count_down = len(display_all) - hosts_count_up
        hosts_count_flap = sum(1 for e in display_all
                               if host_is_flapping(e, now_local(tz_offset), flap_window))
        display_list = view_rows(display_all, filter_mode, host_state, tz_offset, flap_window)
        if match_filter_re is not None or adv_filter:
            display_list = apply_match_filter(display_list, match_filter_re)
        hosts_count_shown = len(display_list)
        phase['build'] = time.time() - _t

        # --- wait ---
        _t = time.time()
        if run_counter >= 2:
            remaining = float(args.waittime) - (datetime.datetime.now() - time1).total_seconds()
            # -w 0 (or an empty host list) must not spin at 100% CPU
            time.sleep(max(remaining, 0.05))
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
                    tz_offset, message, scan_info, sort_mode, addr_mode,
                    match_filter_text, original_hosts_list, hosts_shown=hosts_count_shown,
                    options=adv_option_values(args, down_retries, flap_window, confirm,
                                              down_slices, full_sweep, tz_offset),
                    hosts_flap=hosts_count_flap, pending_wait=bool(pending_add_hosts))

        run_counter += 1


# MAIN MAIN MAIN
def _early_interrupt_hook(tp, val, tb):
    """Ctrl+C before the normal SIGINT handler is installed (startup, ssh setup, ...): leave quietly
    instead of printing a traceback; restore the terminal if curses is already active."""
    if issubclass(tp, KeyboardInterrupt):
        try:
            curses.endwin()
        except Exception:
            pass
        try:
            ssh_shutdown()
        except Exception:
            pass
        try:
            sys.stdout.flush()
        except Exception:
            pass
        os._exit(130)
    sys.__excepthook__(tp, val, tb)

if __name__=='__main__':

    sys.excepthook = _early_interrupt_hook

    if os.name == 'nt':
        # portable Windows folder: fping.exe + cygwin1.dll next to this script
        os.environ['PATH'] = os.path.dirname(os.path.abspath(__file__)) + os.pathsep + os.environ.get('PATH', '')
        for _s in (sys.stdout, sys.stderr):
            try:
                _s.reconfigure(encoding='utf-8', errors='replace')
            except Exception:
                pass

    if (not is_program_installed("fping")
            and not any(a in ('-ssh', '--ssh') or a.startswith(('-ssh=', '--ssh=')) for a in sys.argv[1:])):
        error_handler("ERROR: The command 'fping' was not found. \n Install it via 'sudo apt install fping' (Debian/Ubuntu), 'brew install fping' (macOS), or however it works on your system.")

    default_hostfile = 'eping-hosts.txt'
    min_required_version = (3,6)
    # raise soft FD limit for large host counts
    raise_fd_limit()

    if not check_python_version(min_required_version):
        error_handler('ERROR: Your Python interpreter must be ' + str(min_required_version[0]) + '.' + str(min_required_version[1]) +' or greater' )

    now = datetime.datetime.now()
    parser = argparse.ArgumentParser()

    # adding optional argument
    parser.add_argument('-f', '--hostfile', default=default_hostfile, dest='hostfile', help="hosts filename, one or more, comma and/or space separated, e.g. hosts1.txt,hosts2.txt or \"hosts1.txt hosts2.txt\"" )
    parser.add_argument('-df', '--disable_hostfile', action="store_true", help="disable hostsfile")
    parser.add_argument('-n', '--network', default='', dest='network_cidr', help='one or more CIDR networks, comma separated, e.g. 172.17.17.0/24,10.0.0.0/30  minimum mask: /' + str(CIDR_MIN_MASK) )
    parser.add_argument('-r', '--network_range', default='', dest='network_range', help='one or more IP ranges, comma separated, e.g. 10.180.0.0-10.180.3.255,172.19.0.0-1.13,172.20.2.0-15 - the end may be shortened to its last 1-3 octets, borrowed from the start address')
    parser.add_argument('-B', '--backoff', default='1.5', dest='backoff', help="set exponential backoff factor to N (default: 1.5, range: 1-2)" )
    parser.add_argument('-t', '--timeout', default='250', dest='timeout', help="individual target initial timeout (default: 250ms, range: 10-5000)")
    parser.add_argument('-re', '--retries', default='3', dest='retries', help="number of retries per host (default: 3, range: 0-5)")
    parser.add_argument('-i', '--interval', default='', dest='interval', help="interval between sending pings in ms, range 0-250; overrides --rate. -1 = auto (unset, same as omitting this flag). 0 = no pacing at all (fastest, needs the privileges fping was installed with, sends one hard burst)")
    parser.add_argument('-o', '--logfile', default='', dest='logfile', help="logging filename" )
    parser.add_argument('-dl', '--disable_logging', action="store_false", help="disable logging")
    parser.add_argument('-cl', '--clean', action="store_true", dest='delete_files', help="delete ALL files starting with 'eping-*' in the current directory - logs, reports AND the hosts file eping-hosts.txt")
    parser.add_argument('-up', '--up', default='0', dest='up_hosts_check', help="display and check only host the are up x runs" )
    parser.add_argument('-setref', '--set_reference', action="store_true", dest='set_reference', help="with -up: once the learning phase ends, use the hosts found UP as the new reference list (same as pressing [S]/SET REFERENCE)" )
    parser.add_argument('-p', '--threads', default='auto', dest='num_of_threads', help="fping processes per retry group, range 0-" + str(THREADS_MANUAL_MAX) + " (default: auto = " + str(PROCS_PER_GROUP) + "; 0 is an alias for auto; higher values cost accuracy)" )
    parser.add_argument('-tz', '--timezone', default='0', dest='time_zone_adjust', help="default is 0 range from -24 to 24" )
    parser.add_argument('-w', '--wait', default ='0.5', dest='waittime', help="wait time between rounds in seconds, range 0-" + str(WAITTIME_MAX) )
    parser.add_argument('-du', '--disable_versioncheck', action="store_true", help="disable online versioncheck")
    parser.add_argument('-ra', '--rate', default=str(DEFAULT_RATE_PPS), dest='rate_pps', help="ICMP packets per second, range " + str(MIN_RATE_PPS) + "-" + str(MAX_RATE_PPS) + " (default: " + str(DEFAULT_RATE_PPS) + "; -i cannot go below 1ms, so one process per group tops out near 1000 - higher values have no effect. Use -i 0 to remove the limit entirely)")
    parser.add_argument('-dns', '--dns_ttl', default=str(DNS_CACHE_TTL), dest='dns_ttl', help="seconds a resolved hostname is cached, range 0-" + str(DNS_TTL_MAX) + " (default: " + str(DNS_CACHE_TTL) + ", 0 = let fping resolve every run)")
    parser.add_argument('-lms', '--log_max_size', default='0', dest='log_max_size', help="max CSV log file size in MB before rotating to a new file, range " + str(LOG_MAX_SIZE_MIN) + "-" + str(LOG_MAX_SIZE_MAX) + " (default: 0 = no limit)")
    parser.add_argument('-lmf', '--log_max_files', default='0', dest='log_max_files', help="max number of eping-log_*.csv files to keep, oldest deleted first once exceeded, range 0-" + str(LOG_MAX_FILES_MAX) + " (default: 0 = unlimited)")
    family_group = parser.add_mutually_exclusive_group()
    family_group.add_argument('-4', '--force_ipv4', action="store_true", dest='force_ipv4', help="prefer IPv4 (A records); falls back to IPv6 if a name has no A record (default preference)")
    family_group.add_argument('-6', '--force_ipv6', action="store_true", dest='force_ipv6', help="prefer IPv6 (AAAA records); falls back to IPv4 if a name has no AAAA record")
    parser.add_argument('-ph', '--prefer_hostname', action="store_true", dest='prefer_hostname', help="start with PREFER HOSTNAMES active - skip a raw IP host when the same address is already covered by a hostname entry (toggle later with [P] / the web button)")
    parser.add_argument('-ipo', '--ip_only', action="store_true", dest='ip_only', help="start with IP ONLY active - resolve every hostname to its address (v4 or v6, whichever resolves - not distinguished) and ping/track it by IP instead of by name (toggle later with [I] / the web button)")
    parser.add_argument('-gn', '--get_names', action="store_true", dest='get_names', help="once at startup, reverse-DNS every raw IP host and rename it to its hostname if one is found (same as [G] / GET NAMES, but only once before the first ping round)")
    parser.add_argument('-dr', '--down_retries', default=str(DOWN_RETRIES_DEF), dest='down_retries', help="retries for hosts already known to be DOWN, range 0-" + str(RETRIES_MAX) + " (default: " + str(DOWN_RETRIES_DEF) + ", 0 = disabled - treat them like every other host)")
    parser.add_argument('-dg', '--diag', action="store_true", dest='diag', help="show where the cycle time goes: fping wall time per retry group plus dns/state/build/wait/draw")
    parser.add_argument('-fw', '--flap_window', default=str(FLAP_WINDOW_DEF), dest='flap_window', help="minutes since the last state change for a host to count as flapping (default: " + str(FLAP_WINDOW_DEF) + " = 50 days, max)")
    parser.add_argument('-cf', '--confirm', default=str(CONFIRM_DEF), dest='confirm', help="consecutive DOWN observations before a host leaves UP (default: " + str(CONFIRM_DEF) + ", 1 = report every single observation)")
    parser.add_argument('-ds', '--down_slices', default=str(DOWN_SLICES_DEF), dest='down_slices', help="spread the known DOWN hosts over N rounds, range 1-" + str(DOWN_SLICES_MAX) + " (default: " + str(DOWN_SLICES_DEF) + ", 1 = probe all of them every round)")
    parser.add_argument('-fs', '--full_sweep', default=str(FULL_SWEEP_DEF), dest='full_sweep', help="every Nth run probes every host with full retries, range 0-" + str(FULL_SWEEP_MAX) + " (default: " + str(FULL_SWEEP_DEF) + ", 0 = disabled/never)")
    parser.add_argument('-ssh', '--ssh', dest='ssh', metavar='[USER@]HOST[:PORT]', default=None, help="run fping on this jump host via ssh instead of locally (system ssh; password or key passphrase is asked at startup; the jump host resolves the names and needs a working fping)")
    parser.add_argument('-sshkey', '--ssh_key', dest='ssh_key', metavar='FILE', default=None, help="private key file for -ssh (default: ssh agent / default keys)")
    parser.add_argument('-sshnr', '--ssh_no_resolve', action="store_true", dest='ssh_no_resolve', help="with -ssh: do not resolve names on the jump host (default: GET NAMES, PREFER HOSTNAME / IP ADDRESS and IP ONLY use getent / dig / nslookup / host there when available; otherwise the local resolver is used)")
    parser.add_argument('-sshhk', '--ssh_hostkey', dest='ssh_hostkey', choices=SSH_HOSTKEY_MODES, default='accept-new', help="host key check for -ssh: accept-new = trust hosts seen for the first time, a changed key is refused (default); ask = confirm an unknown key; off = no check at all (insecure)")
    parser.add_argument('-ncf', '--no_csv_fallback', action="store_true", dest='no_csv_fallback', help="do not ping the CSV address of a host whose name does not resolve (default: it is pinged by the CSV IP and marked in the host popup)")
    parser.add_argument('-ncs', '--no_check_source', action="store_true", dest='no_check_source', help="do not pass --check-source to fping (only needed for hosts replying from a different address)")
    parser.add_argument('-web', '--web', action="store_true", dest='web', help="start the web gui instead of the terminal (CLI) output")
    parser.add_argument('-wv', '--web_view', action="store_true", dest='web_view', help="CLI mode plus a read-only web view on --port (browser shows the same data, no controls)")
    parser.add_argument('-wvc', '--web_view_control', action="store_true", dest='web_view_control', help="like --web_view, but the browser can also drive - both the terminal and the browser control the same run")
    parser.add_argument('-port', '--port', default=str(WEB_DEFAULT_PORT), dest='web_port', help="http port for --web and --web_view (default: " + str(WEB_DEFAULT_PORT) + ")")
    parser.add_argument('-bind', '--bind', default=WEB_DEFAULT_BIND, dest='web_bind', help="bind address for --web and --web_view (default: " + WEB_DEFAULT_BIND + " = all interfaces)")

    # host file 'opt:'/'OPT:' lines let a host file carry its own CLI options (e.g.
    # a per-site file that should always run with -ph -du). Found via a lightweight
    # pre-parse with the same parser, so -f/--hostfile and -df/--disable_hostfile are
    # resolved exactly like the real parse below; any opt: tokens found are prepended
    # to argv, so real command-line flags still win on conflict (argparse keeps the
    # last occurrence of a flag). Only the initial -f load is scanned this way - [F]
    # ADD FILE and the web GUI upload only ever add hosts, never options.
    try:
        _pre_args, _ = parser.parse_known_args()
        if not _pre_args.disable_hostfile:
            _opt_tokens = []
            for _hf in split_hostfile_list(_pre_args.hostfile):
                with open(_hf, 'r', encoding='utf-8', errors='replace') as _f:
                    _opt_tokens.extend(extract_opt_lines(_f.read(WEB_MAX_UPLOAD + 1)))
            if _opt_tokens:
                sys.argv = [sys.argv[0]] + _opt_tokens + sys.argv[1:]
    except SystemExit:
        raise   # a genuinely bad command line (or -h/--help) - let argparse handle it
    except Exception:
        pass    # a hosts file missing/unreadable at this point - the real parse below
                # reports it properly once -f itself is actually validated

    # read arguments from command line
    _ARG_DEFAULTS = vars(parser.parse_args([]))
    args = parser.parse_args()
    _OPT_ARGS = args
    if curses is None:
        if args.web_view or args.web_view_control:
            error_handler("ERROR: -wv/-wvc need curses (not available here) - use -web")
        args.web = True
    backoff = args.backoff
    timeout = args.timeout
    retries = args.retries
    interval = args.interval
    use_check_source = not args.no_check_source
    csv_ip_fallback = not args.no_csv_fallback
    dns_family = '4' if args.force_ipv4 else ('6' if args.force_ipv6 else 'auto')

    # check online current version
    if not args.disable_versioncheck:
        url = "https://raw.githubusercontent.com/ewaldj/eping/refs/heads/main/eversions"
        remote_version = check_version_online(url, "eping.py")
    else:
        remote_version = VERSION

    _remote_version = remote_version

    # ip_re / fqdn_re / cidr_ipv4_re live at module level (importable, testable)

    hosts_list_ipv4 = []
    hosts_list_fqdn = []

    # delete files eping-*.......
    if args.delete_files:
        delete_files('eping-*')   # matches the -cl help text: logs, reports, hosts file

    # --- network range(s) -r: comma separated, 'start-end', end may be shortened
    if args.network_range:
        try:
            hosts_list_ipv4.extend(parse_ranges_arg(args.network_range, MAX_IPS_PER_RANGE))
        except Exception as e:
            error_handler(f"Range error: {e}")

    # --- cidr network(s) -n: comma separated
    if args.network_cidr:
        try:
            hosts_list_ipv4.extend(parse_cidrs_arg(args.network_cidr, CIDR_MIN_MASK, CIDR_MAX_MASK))
        except Exception as e:
            error_handler(f"CIDR error: {e}")

    # time_zone_range -24 to +24 check
    try:
        tz = int(args.time_zone_adjust)
        if tz < -24 or tz > 24:
            error_handler("ERROR: -tz: must be between -24 and 24")
    except ValueError:
            error_handler("ERROR: -tz: must be between -24 and 24")

    # -B: fping exponential backoff factor
    try:
        bo = float(args.backoff)
        if bo < BACKOFF_MIN or bo > BACKOFF_MAX:
            error_handler("ERROR: -B: must be between " + str(BACKOFF_MIN) + " and " + str(BACKOFF_MAX))
    except ValueError:
        error_handler("ERROR: -B: must be between " + str(BACKOFF_MIN) + " and " + str(BACKOFF_MAX))

    # -t: fping initial per-target timeout (ms)
    try:
        to = int(args.timeout)
        if to < TIMEOUT_MIN_MS or to > TIMEOUT_MAX_MS:
            error_handler("ERROR: -t: must be between " + str(TIMEOUT_MIN_MS) + " and " + str(TIMEOUT_MAX_MS) + " (ms)")
    except ValueError:
        error_handler("ERROR: -t: must be between " + str(TIMEOUT_MIN_MS) + " and " + str(TIMEOUT_MAX_MS) + " (ms)")

    # -re: retries per host
    try:
        r = int(args.retries)
        if r < 0 or r > RETRIES_MAX:
            error_handler("ERROR: -re: must be between 0 and " + str(RETRIES_MAX))
    except ValueError:
        error_handler("ERROR: -re: must be between 0 and " + str(RETRIES_MAX))

    # -p: fping processes per retry group. 0 is an alias for 'auto' (PROCS_PER_GROUP),
    # same sentinel convention as ADV OPTIONS' THREADS slider
    if args.num_of_threads in ('auto', '0'):
        args.num_of_threads = 'auto'
        _threads_auto = True
    else:
        _threads_auto = False
        try:
            threads = int(args.num_of_threads)
            if threads < 1 or threads > THREADS_MANUAL_MAX:
                error_handler("ERROR: -p: must be between 0 (auto) and " + str(THREADS_MANUAL_MAX))
        except ValueError:
                error_handler("ERROR: -p: must be between 0 (auto) and " + str(THREADS_MANUAL_MAX))

    # -w: wait time between rounds (seconds)
    try:
        wait_time = float(args.waittime)
        if wait_time < 0 or wait_time > WAITTIME_MAX:
            error_handler("ERROR: -w: must be between 0 and " + str(WAITTIME_MAX))
    except ValueError:
        error_handler("ERROR: -w: must be between 0 and " + str(WAITTIME_MAX))

    # -i: interval (ms) between individual pings. -1 = auto (unset, use --rate instead) -
    # normalized to '' right away so every other reader only ever sees '' or a real
    # non-negative interval. 0 is a distinct, valid value: no pacing at all.
    if args.interval == '-1':
        args.interval = ''
    if args.interval:
        try:
            iv = int(args.interval)
            if iv < 0 or iv > INTERVAL_ARG_MAX:
                error_handler("ERROR: -i: must be between 0 and " + str(INTERVAL_ARG_MAX) + " (ms), or -1 for auto")
        except ValueError:
            error_handler("ERROR: -i: must be between 0 and " + str(INTERVAL_ARG_MAX) + " (ms), or -1 for auto")
    interval = args.interval   # re-sync the legacy module-level alias, see its capture above

    # packet rate budget
    try:
        rate_pps = int(args.rate_pps)
        if rate_pps < MIN_RATE_PPS or rate_pps > MAX_RATE_PPS:
            error_handler("ERROR: --rate: must be between " + str(MIN_RATE_PPS) + " and " + str(MAX_RATE_PPS))
    except ValueError:
        error_handler("ERROR: --rate: must be between " + str(MIN_RATE_PPS) + " and " + str(MAX_RATE_PPS))

    # retries for hosts already known to be down. 0 disables the retry classes -
    # every host gets the full --retries budget (same sentinel convention as -p above)
    try:
        down_retries = int(args.down_retries)
        if down_retries < 0 or down_retries > RETRIES_MAX:
            error_handler("ERROR: --down_retries: must be between 0 and " + str(RETRIES_MAX))
        if down_retries > int(args.retries):
            error_handler("ERROR: --down_retries must not be larger than --retries")
    except ValueError:
        error_handler("ERROR: --down_retries: must be between 0 and " + str(RETRIES_MAX))
    if down_retries == 0:
        down_retries = None          # disabled - every host gets the full budget

    # flap window
    try:
        flap_window = int(args.flap_window)
        if flap_window < 1 or flap_window > FLAP_WINDOW_MAX:
            error_handler("ERROR: --flap_window: must be between 1 and " + str(FLAP_WINDOW_MAX) + " (minutes)")
    except ValueError:
        error_handler("ERROR: --flap_window: must be between 1 and " + str(FLAP_WINDOW_MAX) + " (minutes)")

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
        if down_slices < 1 or down_slices > DOWN_SLICES_MAX:
            error_handler("ERROR: --down_slices: must be between 1 and " + str(DOWN_SLICES_MAX))
    except ValueError:
        error_handler("ERROR: --down_slices: must be between 1 and " + str(DOWN_SLICES_MAX))

    # full sweep interval - 0 = disabled (never sweep)
    try:
        full_sweep = int(args.full_sweep)
        if full_sweep < 0 or full_sweep > FULL_SWEEP_MAX:
            error_handler("ERROR: --full_sweep: must be between 0 and " + str(FULL_SWEEP_MAX))
    except ValueError:
        error_handler("ERROR: --full_sweep: must be between 0 and " + str(FULL_SWEEP_MAX))

    # dns cache ttl
    try:
        dns_ttl = int(args.dns_ttl)
        if dns_ttl < 0 or dns_ttl > DNS_TTL_MAX:
            error_handler("ERROR: --dns_ttl: must be between 0 and " + str(DNS_TTL_MAX))
    except ValueError:
        error_handler("ERROR: --dns_ttl: must be between 0 and " + str(DNS_TTL_MAX))

    # log rotation: max CSV log file size in MB before starting a new file (0 = no limit)
    try:
        log_max_size = int(args.log_max_size)
        if log_max_size != 0 and (log_max_size < LOG_MAX_SIZE_MIN or log_max_size > LOG_MAX_SIZE_MAX):
            error_handler("ERROR: --log_max_size: must be 0 (no limit) or between "
                          + str(LOG_MAX_SIZE_MIN) + " and " + str(LOG_MAX_SIZE_MAX))
    except ValueError:
        error_handler("ERROR: --log_max_size: must be 0 (no limit) or between "
                      + str(LOG_MAX_SIZE_MIN) + " and " + str(LOG_MAX_SIZE_MAX))

    # log rotation: max number of eping-log_*.csv files kept (0 = unlimited)
    try:
        log_max_files = int(args.log_max_files)
        if log_max_files < 0 or log_max_files > LOG_MAX_FILES_MAX:
            error_handler("ERROR: --log_max_files: must be between 0 and " + str(LOG_MAX_FILES_MAX))
    except ValueError:
        error_handler("ERROR: --log_max_files: must be between 0 and " + str(LOG_MAX_FILES_MAX))

    # -setref only makes sense together with a learning phase
    try:
        up_hosts_check_int = int(args.up_hosts_check)
    except ValueError:
        error_handler("ERROR: --up: must be a whole number")
    if args.set_reference and up_hosts_check_int <= 0:
        error_handler("ERROR: --set_reference requires --up N (N > 0)")

    # web gui port check (relevant with --web and --web_view/--web_view_control)
    if args.web or args.web_view or args.web_view_control:
        try:
            web_port = int(args.web_port)
            if web_port < 1 or web_port > 65535:
                error_handler("ERROR: --port: must be between 1 and 65535")
        except ValueError:
            error_handler("ERROR: --port: must be between 1 and 65535")

    # create sample file if not exists and no special file is given
    if not args.disable_hostfile and (args.hostfile == default_hostfile):
        data = [
                # --- hosts -----------------------------------------------------------
                "127.0.0.1\n", "no-dns.test 1.1.1.1 1.0.0.1 208.67.222.222\n", "208.67.220.220\n",
                "www.heise.de 193.99.144.85\n", "www.google.com\n", "localhost 8.8.8.8 8.8.4.4\n",
                "ö3.at www.orf.at\n", "::1\n", "ipv4.jeitler.cc\n", "ipv6.jeitler.cc\n",
                "www.jeitler.cc\n", "2603:c020:8016:1313::10\n",
                "\n",
                # --- description -------------------------------------------------------
                "# eping hosts - IPs, hostnames and CIDR networks, '#' starts a comment\n",
                "# a network is expanded to every address in it, e.g.: 192.168.99.0/29 2603:c020:8016:1313::10 2603:c020:8016:1313::10/128\n",
                "#\n",
                "# a line starting with exactly 'opt:' or 'OPT:' carries CLI options that are\n",
                "# applied as if typed on the command line (several such lines are allowed and\n",
                "# are joined in file order; a real CLI option always wins over one from here).\n",
                "\n",
                # --- options -----------------------------------------------------------
                "# every available CLI option, commented out below with its default value -\n",
                "# remove the leading '# ' on a line (keep the 'opt: ') to activate it.\n",
                "#\n",
                "# opt: -f eping-hosts.txt          # hosts filename(s), comma/space separated\n",
                "# opt: -df                          # disable hostsfile\n",
                "# opt: -n 192.168.0.0/24            # CIDR network(s), comma separated\n",
                "# opt: -r 10.10.10.1-11.12          # IP range(s), comma separated\n",
                "# opt: -B 1.5                       # exponential backoff factor\n",
                "# opt: -t 250                       # initial per-target timeout (ms)\n",
                "# opt: -re 3                        # retries per host\n",
                "# opt: -i                           # interval between pings (ms), overrides -ra\n",
                "# opt: -o                           # logging filename\n",
                "# opt: -dl                          # disable logging\n",
                "# opt: -cl                          # delete all 'eping-l*' files\n",
                "# opt: -up 0                        # check only hosts UP for x runs\n",
                "# opt: -setref                      # after -up learning: UP hosts become the reference list\n",
                "# opt: -p auto                      # fping processes per retry group\n",
                "# opt: -tz 0                        # timezone adjust, -24..24\n",
                "# opt: -w 0.5                       # wait time between rounds\n",
                "# opt: -du                          # disable online versioncheck\n",
                "# opt: -ra 1000                     # ICMP packets per second\n",
                "# opt: -dns 300                     # seconds a resolved hostname is cached\n",
                "# opt: -4                           # prefer IPv4\n",
                "# opt: -6                           # prefer IPv6\n",
                "# opt: -ph                          # start with PREFER HOSTNAMES active\n",
                "# opt: -ipo                         # start with IP ONLY active\n",
                "# opt: -gn                          # reverse-DNS raw IPs to hostnames once at startup\n",
                "# opt: -dr 1                        # retries for hosts already known DOWN\n",
                "# opt: -dg                          # show per-phase cycle time diagnostics\n",
                "# opt: -fw 72000                    # flapping window, minutes\n",
                "# opt: -cf 2                        # consecutive DOWN observations before UP -> DOWN\n",
                "# opt: -ds 4                        # spread known DOWN hosts over N rounds\n",
                "# opt: -fs 10                       # every Nth run: full retries for everyone (0 = never)\n",
                "# opt: -ncs                         # do not pass --check-source to fping\n",
                "# opt: -ncf                         # CSV: do not ping the CSV IP of a name without DNS record\n",
                "# opt: -web                         # start the web gui instead of the CLI\n",
                "# opt: -wv                          # CLI mode plus a read-only web view\n",
                "# opt: -port 8080                   # http port for -web / -wv\n",
                "# opt: -bind 0.0.0.0                # bind address for -web / -wv\n",
                ]
        try:
            _txt_new = not os.path.exists(default_hostfile)
            _csv_new = not os.path.exists(SAMPLE_CSV_NAME)
            if _csv_new and _txt_new:
                create_sample_csv()          # shown together with the hosts file INFO
                create_file_if_not_exists(default_hostfile, data, SAMPLE_CSV_INFO)
            else:
                create_file_if_not_exists(default_hostfile, data)
                if create_sample_csv():
                    print('\n\n' + SAMPLE_CSV_INFO + '\n\n')
                    time.sleep(INFO_DELAY)
        except TypeError as error_msg:
            error_handler(error_msg)

    # get ip's, networks, hostname's and fqdn's from file(s) - one or more, comma
    # separated - same parser as the web upload and [F]=ADD FILE, so all three
    # understand CIDR networks and comments; entries from every file are combined,
    # duplicates removed the same way as always (below)
    if not args.disable_hostfile:
        hostfile_paths = split_hostfile_list(args.hostfile)
        if not hostfile_paths:
            error_handler('ERROR: --hostfile: no file given')
        hostfile_skipped = []
        for hostfile_path in hostfile_paths:
            try:
                with open(hostfile_path, 'r', encoding='utf-8', errors='replace') as f:
                    hostfile_text = f.read()
            except Exception:
                error_handler('ERROR: Unable to open hosts file: ' + str(hostfile_path))
            file_stats = {}
            for entry in parse_hosts_from_text(hostfile_text, file_stats, not args.ip_only, hostfile_path):
                if is_ip_host(entry):
                    hosts_list_ipv4.append(entry)
                else:
                    hosts_list_fqdn.append(entry)
            if file_stats.get('skipped'):
                hostfile_skipped.extend(hostfile_path + ': ' + s for s in file_stats['skipped'])
            if file_stats.get('csv_ignored') or file_stats.get('csv_dups'):
                print('\n INFO: ' + str(hostfile_path) + ': csv rows ignored - '
                      + str(file_stats.get('csv_ignored', 0)) + ' without valid IP, '
                      + str(file_stats.get('csv_dups', 0)) + ' duplicate\n')
                time.sleep(1)
        if hostfile_skipped:
            print('\n WARNING: network(s) ignored, mask must be /'
                  + str(CIDR_MIN_MASK) + ' .. /' + str(CIDR_MAX_MASK) + ': '
                  + ', '.join(hostfile_skipped[:5]) + '\n')
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

    if args.ssh:
        ssh_init(args.ssh, args.ssh_key, args.ssh_hostkey, not args.ssh_no_resolve)
    elif args.ssh_key:
        error_handler("ERROR: -sshkey needs -ssh")

    # processes and -i are derived per round and per retry group (tune_group),
    # so args.num_of_threads keeps its value ('auto' or the number the user asked for)

    run_counter = 1

    # create logfile_file_name
    now_logfile = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
    now_logfile_tmp = datetime.datetime.strptime(now_logfile, "%Y-%m-%d %H:%M:%S.%f")
    now_logfile = now_logfile_tmp + datetime.timedelta(hours=int(args.time_zone_adjust))
    filename_timextension = now_logfile.strftime(LOG_TS_FMT)
    logfile_file_name = 'eping-log_' + filename_timextension +'.csv'

    # create logfile
    if args.logfile:
        logfile_file_name = args.logfile

    if args.disable_logging:
        header = LOG_HEADER
        try:
            with open(logfile_file_name, 'w', encoding='UTF8', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(header)
        except OSError as e:
            error_handler('ERROR: failed to create logfile: ' + logfile_file_name + ' (' + str(e) + ')')
        # #INFO# startup snapshot - full CLI-equivalent of every current setting
        startup_snapshot = build_cli_snapshot(args, backoff, timeout, retries,
                                              down_retries, flap_window, confirm,
                                              down_slices, full_sweep,
                                              int(args.time_zone_adjust))
        write_log_info(args.disable_logging, logfile_file_name, startup_snapshot,
                       int(args.time_zone_adjust))

    _logfile_file_name = logfile_file_name
    _logging_enabled = args.disable_logging

    # --- state dict: hostname -> [hostname, state, timestamp, rtt, prev_state, changes, change_ts, tbd, resolved_ip]
    host_state = {}

    # =================================================================
    # WEB GUI MODE - no curses at all, everything runs headless
    # =================================================================
    if args.web:
        _update_available = is_newer_version(remote_version, VERSION)
        with web_lock:
            web_state['version'] = version
            # FILE OPERATIONS > SAVE HOSTS FILE ON SERVER - static for the run,
            # tells the client whether to show a confirm-only or a name-prompt
            # dialog (see hostfile_save_target())
            _save_target = hostfile_save_target(args)
            web_state['hostfile_name']   = _save_target or ''
            web_state['hostfile_active'] = _save_target is not None
        def _web_sigint(sig, frame):
            # same as the web GUI's own EXIT button - tell the browser right away
            with web_lock:
                web_state['stopped'] = True
                web_state['message'] = 'stopped'
            time.sleep(1.5)   # guarantee the browser's next poll sees the status
            print(f'\nTHX for using eping.py v{VERSION} - www.jeitler.cc')
            if is_newer_version(_remote_version, VERSION):
                print_update_notice(_remote_version)
            # no maybe_run_epinga() prompt in web mode - see the 'exit' cmd handler
            sys.stdout.flush()
            # os._exit(), not sys.exit(): see sigint_handler() for why.
            ssh_shutdown()
            os._exit(0)
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

    if args.web_view or args.web_view_control:
        shown_bind = '127.0.0.1' if args.web_bind in ('0.0.0.0', '') else args.web_bind
        kind = 'controllable' if args.web_view_control else 'read-only'
        print('\n ' + kind + ' web view on http://' + shown_bind + ':' + str(args.web_port) + '\n')
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
    # translate arrow/function-key escape sequences into curses.KEY_* constants
    # (KEY_UP/DOWN/LEFT/RIGHT/PPAGE/NPAGE/HOME/END) - required for list_picker_dialog()
    # and adv_options_dialog() navigation; without this getch() returns the raw
    # ESC-prefixed byte sequence instead, which the ESC=cancel check swallows.
    screen.keypad(True)
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

    def run_background_pings(stop_event):
        """Keep pinging while a CLI input dialog is open (see input_dialog below).

        Typing a hostname or a comment can take a while - without this, the whole
        scan would sit idle for that long, so a real outage during that time is
        detected late (or its retries/CSV timestamps land wrong). This runs the
        exact same round logic as the main loop (retry classes, state update,
        CSV logging), just with no screen/keyboard access at all (progress_cb=None
        - see run_ping_round) since curses is main-thread-only; input_dialog()
        redraws the host table itself once it returns. Deliberately skipped: the
        learning-phase transition and any list rebuild - those only ever change
        what's on screen, so applying them a few seconds late (once the dialog
        closes and the main loop's own round runs) changes nothing but the timing.
        """
        global run_counter, logfile_file_name, _logfile_file_name, run_time, pending_add_hosts
        while not stop_event.is_set():
            run_time = RUNTIME_UNAVAILABLE
            t0 = datetime.datetime.now()
            sweep_now = (down_retries is None
                        or (full_sweep > 0 and (run_counter - 1) % full_sweep == 0))
            down_now  = None if sweep_now else set(
                h for h, e in host_state.items() if 'UP' not in e[1])
            fping_result_data_sorted, _scan, _split, _phase = run_ping_round(
                active_hosts_list, args.num_of_threads, int(args.rate_pps),
                args.interval, int(args.dns_ttl), down_now, down_retries, None,
                run_counter - 1, down_slices)
            update_host_state(host_state, fping_result_data_sorted, tz_offset,
                              learning_done, learning_phase, up_seen,
                              args.disable_logging, logfile_file_name,
                              confirm, down_streak)
            if args.disable_logging:
                _new_lf = rotate_log_if_needed(logfile_file_name, int(args.log_max_size),
                                               int(args.log_max_files), tz_offset)
                if _new_lf != logfile_file_name:
                    logfile_file_name  = _new_lf
                    _logfile_file_name = _new_lf
                    write_log_info(args.disable_logging, logfile_file_name,
                                  build_cli_snapshot(args, backoff, timeout, retries,
                                                     down_retries, flap_window, confirm,
                                                     down_slices, full_sweep, tz_offset), tz_offset)
            if pending_add_hosts and pending_add_hosts <= set(host_state):
                pending_add_hosts.clear()
                web_sync('done', bump=True)
            run_counter += 1
            remaining = float(args.waittime) - (datetime.datetime.now() - t0).total_seconds()
            stop_event.wait(max(remaining, 0.05))

    def input_dialog(title, prompt):
        """Show a single line input dialog and return the entered string (may be empty).

        Pinging keeps running in the background for as long as the dialog is open -
        see run_background_pings().
        """
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

        stop_event = threading.Event()
        bg_thread  = threading.Thread(target=run_background_pings, args=(stop_event,), daemon=True)
        bg_thread.start()
        try:
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
        finally:
            stop_event.set()
            bg_thread.join(timeout=float(args.waittime) + 10.0)

        curses.curs_set(0)
        screen.nodelay(True)
        screen.clear()
        # the background round(s) may have changed host state while the dialog was
        # open - repaint at once instead of waiting for the next scheduled round
        if have_data:
            rebuild_display()
            draw_screen()
            screen.refresh()
        return input_str.strip()

    def jumphost_dialog():
        """[J] JUMPHOST - curses form: HOST/PORT/USER/PASSWORD/KEY FILE + TEST, CONNECT, USE LOCAL.
        Same actions as the web gui window (jump_handle). Pinging keeps running meanwhile."""
        rows, cols = screen.getmaxyx()
        dw = min(76, max(40, cols - 4))
        dh = 19
        dy = max(0, rows // 2 - dh // 2)
        dx = max(0, cols // 2 - dw // 2)
        labels  = ['HOST', 'PORT', 'USER', 'PASSWORD', 'HOST KEY', 'NAMES', 'KEY FILE']
        keys    = ['host', 'port', 'user', 'secret', 'hostkey', 'resolve', 'key']
        vals    = [_jump_last.get('host', ''), _jump_last.get('port', ''), _jump_last.get('user', ''),
                   '', _jump_last.get('hostkey', 'accept-new'),
                   'on' if _jump_last.get('resolve', True) else 'off', _jump_last.get('key', '')]
        nm_text = {'on': 'resolve on the jump host', 'off': 'resolve locally'}
        hk_text = {'ask': 'ask (confirm unknown key)', 'accept-new': 'accept new hosts', 'off': 'OFF - no check (insecure)'}
        pre     = ssh_prereq()
        status  = ['']
        status_cls = 1
        fps     = []
        can_trust = False
        focus   = 0
        busy    = {'t': None, 'res': None, 'act': ''}
        spin    = '|/-\\'
        tick    = 0

        def buttons():
            b = [('TEST', 'test'), ('CONNECT', 'connect'), ('USE LOCAL', 'local')]
            if can_trust:
                b.append(('TRUST KEY', 'trust'))
            b.append(('CLOSE', 'close'))
            return b

        def wrap(text, width):
            out, line = [], ''
            for w in str(text).split():
                if len(line) + len(w) + 1 > width and line:
                    out.append(line)
                    line = w
                else:
                    line = (line + ' ' + w).strip()
            if line:
                out.append(line)
            return out or ['']

        def draw():
            for y in range(dh):
                screen_output(dy + y, dx, ' ' * dw, 1, 0)
            screen_output(dy, dx, '┌' + '─' * (dw - 2) + '┐', 1, 1)
            screen_output(dy + 1, dx, '│' + 'JUMPHOST'.center(dw - 2) + '│', 1, 1)
            screen_output(dy + 2, dx, '│' + '─' * (dw - 2) + '│', 1, 0)
            if pre['ok']:
                info = 'ssh: ' + (pre['version'] or 'found') + ' | source: ' + (SOURCE_LABEL if ssh_cfg else 'local')
                cls = 1
            else:
                info = pre['hint']
                cls = 3
            screen_output(dy + 3, dx, '│' + (' ' + info)[:dw - 2].ljust(dw - 2) + '│', cls, 0)
            fw = dw - 16
            for i, lab in enumerate(labels):
                shown = ('*' * len(vals[i])) if keys[i] == 'secret' else (
                    hk_text[vals[i]] + '  [ENTER/SPACE=change]' if keys[i] == 'hostkey' else
                    nm_text[vals[i]] + '  [ENTER/SPACE=change]' if keys[i] == 'resolve' else vals[i])
                shown = shown[-fw:] if len(shown) > fw else shown
                line = ' ' + lab.ljust(10) + (shown + '_' * 0).ljust(fw) + ' '
                screen_output(dy + 4 + i, dx, '│' + line[:dw - 2].ljust(dw - 2) + '│', 2 if focus == i else 1, 1 if focus == i else 0)
            screen_output(dy + 11, dx, '│' + ' ' * (dw - 2) + '│', 1, 0)
            lines = []
            for t in status:
                lines.extend(wrap(t, dw - 4))
            for f in fps:
                lines.extend(wrap(f, dw - 4))
            for i in range(4):
                txt = lines[i] if i < len(lines) else ''
                screen_output(dy + 12 + i, dx, '│' + (' ' + txt)[:dw - 2].ljust(dw - 2) + '│', status_cls, 0)
            bl = buttons()
            col = dx + 2
            screen_output(dy + 16, dx, '│' + ' ' * (dw - 2) + '│', 1, 0)
            for i, (name, _a) in enumerate(bl):
                lab = ' [' + name + '] '
                hi = (focus == len(labels) + i)
                screen_output(dy + 16, col, lab, 2 if hi else 1, 1 if hi else 0)
                col += len(lab) + 1
            screen_output(dy + 17, dx, '│' + ' TAB/arrows=move  ENTER=select  ESC=close'.ljust(dw - 2) + '│', 1, 0)
            screen_output(dy + 18, dx, '└' + '─' * (dw - 2) + '┘', 1, 1)
            if focus < len(labels) and keys[focus] not in ('hostkey', 'resolve') and not busy['t']:
                curses.curs_set(1)
                shown_len = min(len(vals[focus]), fw)
                screen.move(dy + 4 + focus, dx + 12 + shown_len)
            else:
                curses.curs_set(0)
            screen.refresh()

        def start(action):
            nonlocal status, status_cls, fps, can_trust
            req = {'action': action}
            for k, v in zip(keys, vals):
                req[k] = v
            status, status_cls, fps, can_trust = [{'test': 'testing connection ...', 'connect': 'connecting ...',
                                                   'trust': 'saving host key ...', 'local': 'switching ...'}[action]], 1, [], False
            busy['act'] = action
            busy['res'] = None

            def work():
                try:
                    busy['res'] = jump_handle(req)
                except Exception as e:
                    busy['res'] = {'ok': False, 'code': 'conn', 'error': 'internal error: ' + str(e)}
            busy['t'] = threading.Thread(target=work, daemon=True)
            busy['t'].start()

        stop_event = threading.Event()
        bg_thread  = threading.Thread(target=run_background_pings, args=(stop_event,), daemon=True)
        bg_thread.start()
        done_msg = None
        screen.timeout(150)
        try:
            while True:
                draw()
                if busy['t'] is not None and not busy['t'].is_alive():
                    res, act = busy['res'] or {}, busy['act']
                    busy['t'] = None
                    if res.get('ok'):
                        status = [res.get('message') or ('OK' + (' - ' + res['version'] if res.get('version') else ''))]
                        status_cls = 2
                        if act in ('connect', 'local'):
                            done_msg = status[0]
                            break
                        if act == 'trust':
                            start('test')
                    else:
                        status = [res.get('error') or 'failed']
                        status_cls = 3
                        if res.get('code') == 'hostkey':
                            fps = ['Fingerprint: ' + f for f in (res.get('fingerprints') or [])] or \
                                  ['Fingerprint not readable (ssh-keyscan missing)']
                            can_trust = bool(res.get('fingerprints'))
                            if can_trust:
                                focus = len(labels) + len(buttons()) - 2      # TRUST KEY: ENTER = yes
                                status = status + ['Press ENTER to trust this key (or set HOST KEY to accept/off).']
                    continue
                ch = screen.getch()
                if busy['t'] is not None:
                    tick += 1
                    status[0] = status[0].rstrip(' |/-\\') + ' ' + spin[tick % 4]
                    continue                       # busy: keys are ignored until the answer is in
                if ch == -1:
                    continue
                nfocus = len(labels) + len(buttons())
                if ch == 27:
                    break
                elif ch in (9, curses.KEY_DOWN):
                    focus = (focus + 1) % nfocus
                elif ch in (curses.KEY_UP, getattr(curses, 'KEY_BTAB', -2)):
                    focus = (focus - 1) % nfocus
                elif ch in (10, 13, 32) and focus < len(labels) and keys[focus] == 'hostkey':
                    vals[focus] = SSH_HOSTKEY_MODES[(SSH_HOSTKEY_MODES.index(vals[focus]) + 1) % 3]
                elif ch in (10, 13, 32) and focus < len(labels) and keys[focus] == 'resolve':
                    vals[focus] = 'off' if vals[focus] == 'on' else 'on'
                elif ch in (10, 13):
                    if focus < len(labels):
                        focus = (focus + 1) % nfocus
                    else:
                        name, act = buttons()[focus - len(labels)]
                        if act == 'close':
                            break
                        if act in ('test', 'connect') and not pre['ok']:
                            status, status_cls = [pre['hint']], 3
                        else:
                            start(act)
                elif focus < len(labels) and keys[focus] not in ('hostkey', 'resolve'):
                    if ch in (curses.KEY_BACKSPACE, 127, 8):
                        vals[focus] = vals[focus][:-1]
                    elif 32 <= ch <= 126 and len(vals[focus]) < 255:
                        vals[focus] += chr(ch)
        finally:
            stop_event.set()
            bg_thread.join(timeout=float(args.waittime) + 10.0)
            screen.timeout(-1)
            for i in range(len(vals)):
                vals[i] = ''                       # drop the typed secret
            curses.curs_set(0)
            screen.nodelay(True)
            screen.clear()
            if have_data:
                rebuild_display()
                draw_screen()
                screen.refresh()
        if done_msg:
            notice('JUMPHOST: ' + done_msg.upper(), 2, 3)

    def key_confirm_dialog(title, lines, valid_keys):
        """Show a message box and wait for a single keypress out of valid_keys
        (lowercase chars). ESC or ENTER cancels (returns None); any other key is
        ignored and the dialog keeps waiting. Pinging keeps running in the
        background, same as input_dialog().
        """
        rows, cols = screen.getmaxyx()
        dialog_w = min(70, max(20, cols - 4))
        dialog_h = len(lines) + 4
        dialog_y = max(0, rows // 2 - dialog_h // 2)
        dialog_x = max(0, cols // 2 - dialog_w // 2)

        screen.nodelay(False)
        for dy in range(dialog_h):
            screen_output(dialog_y + dy, dialog_x, ' ' * dialog_w, 1, 0)
        screen_output(dialog_y,     dialog_x, '┌' + '─' * (dialog_w - 2) + '┐', 1, 1)
        screen_output(dialog_y + 1, dialog_x, '│' + title.center(dialog_w - 2) + '│', 1, 1)
        screen_output(dialog_y + 2, dialog_x, '│' + '─' * (dialog_w - 2) + '│', 1, 0)
        for i, line in enumerate(lines):
            screen_output(dialog_y + 3 + i, dialog_x,
                          '│' + line[:dialog_w - 2].ljust(dialog_w - 2) + '│', 1, 0)
        screen_output(dialog_y + dialog_h - 1, dialog_x, '└' + '─' * (dialog_w - 2) + '┘', 1, 1)
        screen.refresh()

        stop_event = threading.Event()
        bg_thread  = threading.Thread(target=run_background_pings, args=(stop_event,), daemon=True)
        bg_thread.start()
        result = None
        try:
            while True:
                ch = screen.getch()
                if ch in (27, 10, 13):             # ESC or ENTER = cancel
                    break
                if 0 <= ch < 256 and chr(ch).lower() in valid_keys:
                    result = chr(ch).lower()
                    break
        finally:
            stop_event.set()
            bg_thread.join(timeout=float(args.waittime) + 10.0)

        screen.nodelay(True)
        screen.clear()
        if have_data:
            rebuild_display()
            draw_screen()
            screen.refresh()
        return result

    def adv_multi_dialog(title, entries, mode, checked):
        """Multi-select list for one ADV FILTER field. entries = [(key, label, count)].
        [SPACE] check/uncheck, [I] toggle show-only / hide, [A] check all, [N] uncheck
        all, [ENTER] ok, [ESC] cancel. Returns (mode, set_of_checked_keys) or None.
        Pinging keeps running in the background."""
        rows, cols = screen.getmaxyx()
        dialog_w = min(64, max(34, cols - 4))
        foot_l   = _wrap_footer('[SPACE]=check [I]=show/hide [A]=all [N]=none [ENTER]=ok [ESC]=cancel',
                                dialog_w - 4)
        visible  = max(3, min(len(entries), rows - 7 - len(foot_l)))
        dialog_h = visible + 5 + len(foot_l)
        dialog_y = max(0, rows // 2 - dialog_h // 2)
        dialog_x = max(0, cols // 2 - dialog_w // 2)
        checked  = set(checked)
        sel, top = 0, 0
        n = len(entries)
        screen.nodelay(False)
        stop_event = threading.Event()
        bg_thread  = threading.Thread(target=run_background_pings, args=(stop_event,), daemon=True)
        bg_thread.start()
        result = None
        try:
            while True:
                if sel < top:
                    top = sel
                elif sel >= top + visible:
                    top = sel - visible + 1
                for dy in range(dialog_h):
                    screen_output(dialog_y + dy, dialog_x, ' ' * dialog_w, 1, 0)
                head = ' %s - %s (%d checked) ' % (title, 'SHOW ONLY CHECKED' if mode == 'in'
                                                   else 'HIDE CHECKED', len(checked))
                screen_output(dialog_y,     dialog_x, '┌' + '─' * (dialog_w - 2) + '┐', 1, 1)
                screen_output(dialog_y + 1, dialog_x, '│' + head[:dialog_w - 2].center(dialog_w - 2) + '│', 1, 1)
                screen_output(dialog_y + 2, dialog_x, '│' + '─' * (dialog_w - 2) + '│', 1, 0)
                for row in range(visible):
                    i = top + row
                    if i < n:
                        key, label, cnt = entries[i]
                        line = '%s [%s] %s  (%d)' % ('>' if i == sel else ' ',
                                                     'x' if key in checked else ' ', label, cnt)
                    else:
                        line = ''
                    screen_output(dialog_y + 3 + row, dialog_x,
                                  '│' + line[:dialog_w - 2].ljust(dialog_w - 2) + '│',
                                  2 if i == sel else 1, 1 if i == sel else 0)
                screen_output(dialog_y + 3 + visible, dialog_x,
                              '│' + '─' * (dialog_w - 2) + '│', 1, 0)
                for fi, fl in enumerate(foot_l):
                    screen_output(dialog_y + 4 + visible + fi, dialog_x,
                                  '│' + (' ' + fl)[:dialog_w - 2].ljust(dialog_w - 2) + '│', 1, 0)
                screen_output(dialog_y + dialog_h - 1, dialog_x,
                              '└' + '─' * (dialog_w - 2) + '┘', 1, 1)
                screen.refresh()
                ch = screen.getch()
                if ch in (curses.KEY_UP, ord('k')):
                    sel = max(0, sel - 1)
                elif ch in (curses.KEY_DOWN, ord('j')):
                    sel = min(n - 1, sel + 1)
                elif ch == curses.KEY_PPAGE:
                    sel = max(0, sel - visible)
                elif ch == curses.KEY_NPAGE:
                    sel = min(n - 1, sel + visible)
                elif ch == curses.KEY_HOME:
                    sel = 0
                elif ch == curses.KEY_END:
                    sel = n - 1
                elif ch == ord(' ') and n:
                    checked ^= {entries[sel][0]}
                elif ch in (ord('i'), ord('I')):
                    mode = 'out' if mode == 'in' else 'in'
                elif ch in (ord('a'), ord('A')):
                    checked = {e[0] for e in entries}
                elif ch in (ord('n'), ord('N')):
                    checked = set()
                elif ch in (10, 13):
                    result = (mode, checked)
                    break
                elif ch == 27:
                    break
        finally:
            stop_event.set()
            bg_thread.join(timeout=float(args.waittime) + 10.0)
        screen.nodelay(True)
        screen.clear()
        if have_data:
            rebuild_display()
            draw_screen()
            screen.refresh()
        return result

    def adv_filter_dialog():
        """[V] ADV FILTER window (Excel-style): per inventory field (Model, Location,
        sysLocation, Type, Comment) check values and choose show-only / hide. OR within
        a field, AND across fields - display only, ANDed with the view and the [M]
        regex, every host keeps being pinged. Works on a draft; APPLY activates it,
        ESC discards it. Pinging keeps running while the window is open."""
        vals   = adv_values(original_hosts_list)
        fields = [(k, label) for k, label, _i in ADV_FIELDS if k in vals]
        if not fields:
            notice('ADV FILTER: NO INVENTORY VALUES - SEE ' + SAMPLE_CSV_NAME, 3)
            return
        draft = {k: v for k, v in adv_filter.items() if k in vals}     # key -> (mode, values)

        def entries(k):
            v = vals.get(k) or {'values': [], 'empty': 0}
            ent = [(x, x, c) for x, c in v['values']]
            if v['empty']:
                ent.append((ADV_NONE, '(empty)', v['empty']))
            known = {e[0] for e in ent}
            for x in sorted(draft.get(k, ('in', ()))[1]):              # no longer possible
                if x not in known:
                    ent.append((x, '(empty)' if x == ADV_NONE else x, 0))
            return ent

        def summary(k):
            if k not in draft:
                return 'ALL'
            mode, vs = draft[k]
            return '%s %d' % ('show only' if mode == 'in' else 'hide', len(vs))

        items  = fields + [('@apply', 'APPLY'), ('@reset', 'RESET ALL'), ('@cancel', 'CANCEL')]
        sel    = 0
        result = None
        lw     = max(len(label) for _k, label in fields)
        foot_l = None
        screen.nodelay(False)
        stop_event = threading.Event()
        bg_thread  = threading.Thread(target=run_background_pings, args=(stop_event,), daemon=True)
        bg_thread.start()
        try:
            while True:
                # each field only offers what is still possible with the others' choice
                vals = adv_values(original_hosts_list, draft)
                rows, cols = screen.getmaxyx()
                dialog_w = min(70, max(30, cols - 4))
                foot_l   = _wrap_footer('[UP/DN]=field [ENTER]=values [A]=apply [R]=reset [ESC]=cancel',
                                        dialog_w - 4)
                dialog_h = len(items) + 5 + len(foot_l)
                dialog_y = max(0, rows // 2 - dialog_h // 2)
                dialog_x = max(0, cols // 2 - dialog_w // 2)
                for dy in range(dialog_h):
                    screen_output(dialog_y + dy, dialog_x, ' ' * dialog_w, 1, 0)
                screen_output(dialog_y,     dialog_x, '┌' + '─' * (dialog_w - 2) + '┐', 1, 1)
                screen_output(dialog_y + 1, dialog_x, '│' + ' ADV FILTER '.center(dialog_w - 2) + '│', 1, 1)
                screen_output(dialog_y + 2, dialog_x, '│' + '─' * (dialog_w - 2) + '│', 1, 0)
                for i, (k, label) in enumerate(items):
                    if k.startswith('@'):
                        line = ('> ' if i == sel else '  ') + '[ ' + label + ' ]'
                    else:
                        line = ('> ' if i == sel else '  ') + label.ljust(lw) + ' : ' + summary(k)
                    screen_output(dialog_y + 3 + i, dialog_x,
                                  '│' + line[:dialog_w - 2].ljust(dialog_w - 2) + '│',
                                  2 if i == sel else 1, 1 if i == sel else 0)
                screen_output(dialog_y + 3 + len(items), dialog_x,
                              '│' + '─' * (dialog_w - 2) + '│', 1, 0)
                for fi, fl in enumerate(foot_l):
                    screen_output(dialog_y + 4 + len(items) + fi, dialog_x,
                                  '│' + (' ' + fl)[:dialog_w - 2].ljust(dialog_w - 2) + '│', 1, 0)
                screen_output(dialog_y + dialog_h - 1, dialog_x,
                              '└' + '─' * (dialog_w - 2) + '┘', 1, 1)
                screen.refresh()

                ch = screen.getch()
                k = items[sel][0]
                if ch in (curses.KEY_UP, ord('k')):
                    sel = (sel - 1) % len(items)
                elif ch in (curses.KEY_DOWN, ord('j'), 9):
                    sel = (sel + 1) % len(items)
                elif ch in (ord('r'), ord('R')):
                    draft.clear()
                elif ch in (ord('a'), ord('A')):
                    result = dict(draft)
                    break
                elif ch == 27:
                    break
                elif ch in (10, 13):
                    if k == '@apply':
                        result = dict(draft)
                        break
                    elif k == '@reset':
                        draft.clear()
                    elif k == '@cancel':
                        break
                    else:
                        # the multi-select runs its own background pings - hand over
                        stop_event.set()
                        bg_thread.join(timeout=float(args.waittime) + 10.0)
                        cur_mode, cur_vals = draft.get(k, ('in', frozenset()))
                        picked = adv_multi_dialog(dict(fields)[k].upper(), entries(k),
                                                  cur_mode, cur_vals)
                        screen.nodelay(False)
                        stop_event = threading.Event()
                        bg_thread  = threading.Thread(target=run_background_pings,
                                                      args=(stop_event,), daemon=True)
                        bg_thread.start()
                        if picked is not None:
                            if picked[1]:
                                draft[k] = (picked[0], frozenset(picked[1]))
                            else:
                                draft.pop(k, None)
        finally:
            stop_event.set()
            bg_thread.join(timeout=float(args.waittime) + 10.0)

        screen.nodelay(True)
        screen.clear()
        if result is not None:
            adv_filter.clear()
            adv_filter.update(result)
        if have_data:
            rebuild_display()
            draw_screen()
            screen.refresh()
        if result is not None:
            if adv_filter:
                notice('ADV FILTER: ON (%d OF %d SHOWN)' % (len(display_list), len(active_hosts_list)), 2)
            else:
                notice('ADV FILTER: OFF', 2)

    def list_picker_dialog(title, items, current_idx):
        """[V] view-filter picker (and reusable for any future single-choice list):
        show items (list of display strings) in a bordered box, arrow keys/j/k move
        the selection, ENTER confirms, ESC cancels. Returns the selected index, or
        None on cancel. Scrolls when the list is taller than the terminal allows.
        Pinging keeps running in the background, same as input_dialog()/
        key_confirm_dialog()."""
        rows, cols = screen.getmaxyx()
        dialog_w  = min(50, max(30, cols - 4))
        max_rows  = max(3, rows - 6)              # leave room for border/title/footer
        visible   = min(len(items), max_rows)
        dialog_h  = visible + 5
        dialog_y  = max(0, rows // 2 - dialog_h // 2)
        dialog_x  = max(0, cols // 2 - dialog_w // 2)

        sel  = max(0, min(current_idx, len(items) - 1))
        top  = max(0, min(sel - visible // 2, len(items) - visible))

        screen.nodelay(False)
        stop_event = threading.Event()
        bg_thread  = threading.Thread(target=run_background_pings, args=(stop_event,), daemon=True)
        bg_thread.start()
        result = None
        try:
            while True:
                if sel < top:
                    top = sel
                elif sel >= top + visible:
                    top = sel - visible + 1
                for dy in range(dialog_h):
                    screen_output(dialog_y + dy, dialog_x, ' ' * dialog_w, 1, 0)
                screen_output(dialog_y,     dialog_x, '┌' + '─' * (dialog_w - 2) + '┐', 1, 1)
                screen_output(dialog_y + 1, dialog_x, '│' + title.center(dialog_w - 2) + '│', 1, 1)
                screen_output(dialog_y + 2, dialog_x, '│' + '─' * (dialog_w - 2) + '│', 1, 0)
                for row in range(visible):
                    i = top + row
                    if i >= len(items):
                        line = ''
                        is_sel = False
                    else:
                        is_sel = (i == sel)
                        marker = '>' if is_sel else ' '
                        line = marker + ' ' + items[i]
                    screen_output(dialog_y + 3 + row, dialog_x,
                                  '│' + line[:dialog_w - 2].ljust(dialog_w - 2) + '│',
                                  2 if is_sel else 1, 1 if is_sel else 0)
                footer = ' [UP/DOWN]=move  [ENTER]=select  [ESC]=cancel'
                screen_output(dialog_y + 3 + visible, dialog_x,
                              '│' + footer[:dialog_w - 2].ljust(dialog_w - 2) + '│', 1, 0)
                screen_output(dialog_y + dialog_h - 1, dialog_x,
                              '└' + '─' * (dialog_w - 2) + '┘', 1, 1)
                screen.refresh()

                ch = screen.getch()
                if ch in (curses.KEY_UP, ord('k')):
                    sel = max(0, sel - 1)
                elif ch in (curses.KEY_DOWN, ord('j')):
                    sel = min(len(items) - 1, sel + 1)
                elif ch == curses.KEY_PPAGE:
                    sel = max(0, sel - visible)
                elif ch == curses.KEY_NPAGE:
                    sel = min(len(items) - 1, sel + visible)
                elif ch == curses.KEY_HOME:
                    sel = 0
                elif ch == curses.KEY_END:
                    sel = len(items) - 1
                elif ch in (10, 13):                   # ENTER = confirm
                    result = sel
                    break
                elif ch == 27:                          # ESC = cancel
                    break
        finally:
            stop_event.set()
            bg_thread.join(timeout=float(args.waittime) + 10.0)

        screen.nodelay(True)
        screen.clear()
        if have_data:
            rebuild_display()
            draw_screen()
            screen.refresh()
        return result

    def adv_options_dialog():
        """[X] ADV OPTIONS panel - curses equivalent of the web gui's options modal
        (see ADV_OPTIONS_UI). UP/DOWN selects a row, LEFT/RIGHT (or -/+) steps its
        value by its own step size, ENTER opens a free-text edit (also accepts
        'auto'/'off' where that option supports it), 'D' resets the selected row
        to its startup value, 'R' resets ALL rows, ESC/'X' closes. Applies live
        via apply_adv_option() - same validation/effect as the web gui's
        set_option/reset_options, just triggered one key at a time instead of a
        dragged slider, so every accepted change is logged immediately (no
        debounce needed - see run_web_mode()'s pending_info for why the web gui
        needs one and curses does not)."""
        global down_retries, flap_window, confirm, down_slices, full_sweep, tz_offset

        def _assign_local(key, val):
            global down_retries, flap_window, confirm, down_slices, full_sweep, tz_offset
            if key == 'down_retries':
                down_retries = val
            elif key == 'flap_window':
                flap_window = val
            elif key == 'confirm':
                confirm = val
            elif key == 'down_slices':
                down_slices = val
            elif key == 'full_sweep':
                full_sweep = val
            elif key == 'tz_offset':
                tz_offset = val

        def _cur(key):
            return current_option_value(key, args, backoff, timeout, retries,
                                        down_retries, flap_window, confirm,
                                        down_slices, full_sweep, tz_offset)

        def _numeric(key, spec):
            _, _kind, lo, _hi, _step, _unit, auto_sentinel = spec
            val = _cur(key)
            if val in ('', None) or val == 'auto':
                return auto_sentinel if auto_sentinel is not None else lo
            return val

        def _display(key, spec):
            _, kind, _lo, _hi, _step, unit, _auto_sentinel = spec
            val = _cur(key)
            if val in ('', None):
                return 'OFF' if key == 'down_retries' else 'AUTO'
            if val == 'auto':
                return 'AUTO'
            shown = ('%.2f' % val) if kind == 'float' else str(val)
            return shown + (' ' + unit if unit else '')

        def _apply(key, raw, log=True):
            ok, val, msg = apply_adv_option(key, raw, args)
            if ok and key in ADV_OPTION_LOCAL_KEYS:
                _assign_local(key, val)
            if ok and log:
                write_log_info(args.disable_logging, logfile_file_name,
                               format_option_cli(key, val), tz_offset)
            return ok, val, msg

        rows, cols = screen.getmaxyx()
        dialog_w  = min(56, max(30, cols - 4))
        max_rows  = max(3, rows - 8)
        visible   = min(len(ADV_OPTIONS), max_rows)
        dialog_h  = visible + 6
        dialog_y  = max(0, rows // 2 - dialog_h // 2)
        dialog_x  = max(0, cols // 2 - dialog_w // 2)

        sel, top = 0, 0
        screen.nodelay(False)
        stop_event = threading.Event()
        bg_thread  = threading.Thread(target=run_background_pings, args=(stop_event,), daemon=True)
        bg_thread.start()
        try:
            while True:
                if sel < top:
                    top = sel
                elif sel >= top + visible:
                    top = sel - visible + 1
                for dy in range(dialog_h):
                    screen_output(dialog_y + dy, dialog_x, ' ' * dialog_w, 1, 0)
                screen_output(dialog_y,     dialog_x, '┌' + '─' * (dialog_w - 2) + '┐', 1, 1)
                screen_output(dialog_y + 1, dialog_x, '│' + 'ADV OPTIONS'.center(dialog_w - 2) + '│', 1, 1)
                screen_output(dialog_y + 2, dialog_x, '│' + '─' * (dialog_w - 2) + '│', 1, 0)
                for row in range(visible):
                    i = top + row
                    if i >= len(ADV_OPTIONS):
                        continue
                    r_spec  = ADV_OPTIONS[i]
                    r_key   = r_spec[0]
                    r_label = ADV_OPTION_LABELS.get(r_key, r_key.upper())
                    r_value = _display(r_key, r_spec)
                    is_sel  = (i == sel)
                    line = (('>' if is_sel else ' ') + ' ' + r_label).ljust(dialog_w - 14) + r_value.rjust(12)
                    screen_output(dialog_y + 3 + row, dialog_x,
                                  '│' + line[:dialog_w - 2].ljust(dialog_w - 2) + '│',
                                  2 if is_sel else 1, 1 if is_sel else 0)
                footer1 = ' [UP/DN]=select [+/-]=step [ENTER]=type'
                footer2 = ' [D]=default [R]=reset all [ESC/X]=close'
                screen_output(dialog_y + 3 + visible, dialog_x,
                              '│' + footer1[:dialog_w - 2].ljust(dialog_w - 2) + '│', 1, 0)
                screen_output(dialog_y + 4 + visible, dialog_x,
                              '│' + footer2[:dialog_w - 2].ljust(dialog_w - 2) + '│', 1, 0)
                screen_output(dialog_y + dialog_h - 1, dialog_x,
                              '└' + '─' * (dialog_w - 2) + '┘', 1, 1)
                screen.refresh()

                ch = screen.getch()
                spec = ADV_OPTIONS[sel]
                key  = spec[0]
                label = ADV_OPTION_LABELS.get(key, key.upper())
                _, kind, lo, hi, step, unit, _auto_sentinel = spec

                if ch in (curses.KEY_UP,):
                    sel = max(0, sel - 1)
                elif ch in (curses.KEY_DOWN,):
                    sel = min(len(ADV_OPTIONS) - 1, sel + 1)
                elif ch == curses.KEY_PPAGE:
                    sel = max(0, sel - visible)
                elif ch == curses.KEY_NPAGE:
                    sel = min(len(ADV_OPTIONS) - 1, sel + visible)
                elif ch in (curses.KEY_LEFT, ord('-'), ord('_')):
                    cur = _numeric(key, spec) - step
                    cur = max(lo, min(hi, round(cur, 2) if kind == 'float' else int(cur)))
                    ok, _val, msg = _apply(key, str(cur))
                    if not ok:
                        notice(msg.upper(), 3, 1.2)
                elif ch in (curses.KEY_RIGHT, ord('+'), ord('=')):
                    cur = _numeric(key, spec) + step
                    cur = max(lo, min(hi, round(cur, 2) if kind == 'float' else int(cur)))
                    ok, _val, msg = _apply(key, str(cur))
                    if not ok:
                        notice(msg.upper(), 3, 1.2)
                elif ch in (10, 13):                    # ENTER = type exact value
                    unit_txt = (' ' + unit) if unit else ''
                    typed = input_dialog('SET ' + label,
                                         label + ' (' + str(lo) + '..' + str(hi) + unit_txt + '):')
                    if typed:
                        ok, _val, msg = _apply(key, typed)
                        if not ok:
                            notice(msg.upper(), 3, 1.6)
                elif ch in (ord('d'), ord('D')):        # reset THIS row to startup value
                    _apply(key, str(start_option_values[key]))
                elif ch in (ord('r'), ord('R')):        # reset ALL rows to startup values
                    before = {k2: _cur(k2) for k2 in ADV_OPTION_KEYS}
                    for k2, raw2 in start_option_values.items():
                        _apply(k2, raw2, log=False)
                    for k2 in ADV_OPTION_KEYS:
                        after = _cur(k2)
                        if after != before[k2]:
                            write_log_info(args.disable_logging, logfile_file_name,
                                           format_option_cli(k2, after), tz_offset)
                elif ch in (27, ord('x'), ord('X')):
                    break
        finally:
            stop_event.set()
            bg_thread.join(timeout=float(args.waittime) + 10.0)

        screen.nodelay(True)
        screen.clear()
        if have_data:
            rebuild_display()
            draw_screen()
            screen.refresh()

    def apply_browser_command(bcmd, bval):
        """--web_view_control: apply one command posted by the browser. Mirrors
        run_web_mode()'s own per-cmd handling (same low-level functions:
        filter_hosts/apply_prefer_*/apply_ip_only_on-off/apply_adv_option/
        add_hosts_to/...), just applied to curses's own state variables instead
        of run_web_mode()'s - the two loops stay independent implementations of
        the same behaviour, same as the keyboard handlers below already are.
        Keep in sync with both if either side's command handling changes.
        'run_report' is not handled here - do_POST() runs it directly against
        web_state['logfile'], no curses state needed (see run_epinga_report())."""
        global filter_mode, active_hosts_list, original_hosts_list, prefer_hostname
        global prefer_ip, ip_only_mode, ip_only_map, sort_mode, match_filter_re
        global match_filter_text, gn_thread, gn_result, gn_candidates
        global logfile_file_name, _logfile_file_name, down_retries, flap_window
        global confirm, down_slices, full_sweep, tz_offset, pending_add_hosts

        message = 'done'   # default footer text - overridden below where a more
                            # specific one applies; always sent so the pending
                            # '...ing' note (see PENDING/note() in the JS) is
                            # replaced and then auto-cleared, never stuck

        if bcmd == 'up_only':
            next_mode = (filter_mode + 1) % len(FILTER_MODES) if filter_mode < len(FILTER_MODES) else 0
            next_list = filter_hosts(next_mode, original_hosts_list, host_state,
                                     tz_offset, flap_window, up_seen)
            if next_list or next_mode == 0:
                filter_mode       = next_mode
                screen.clear()
                write_log_info(args.disable_logging, logfile_file_name,
                               'FILTER ' + WEB_VIEW_MODES[filter_mode][0], tz_offset)
                message = 'view: ' + WEB_VIEW_MODES[filter_mode][0]
            else:
                notice('NO HOSTS MATCH ' + WEB_VIEW_MODES[next_mode][0], 3)
                message = 'no hosts match ' + WEB_VIEW_MODES[next_mode][0]

        elif bcmd == 'set_filter':
            try:
                target_mode = int(bval)
            except (TypeError, ValueError):
                target_mode = filter_mode
            if 0 <= target_mode < len(WEB_VIEW_MODES) and target_mode != filter_mode:
                target_list = filter_hosts(target_mode, original_hosts_list, host_state,
                                           tz_offset, flap_window, up_seen)
                if target_list or target_mode == 0:
                    filter_mode       = target_mode
                    screen.clear()
                    write_log_info(args.disable_logging, logfile_file_name,
                                   'FILTER ' + WEB_VIEW_MODES[filter_mode][0], tz_offset)
                    message = 'view: ' + WEB_VIEW_MODES[filter_mode][0]
                else:
                    notice('NO HOSTS MATCH ' + WEB_VIEW_MODES[target_mode][0], 3)
                    message = 'no hosts match ' + WEB_VIEW_MODES[target_mode][0]

        elif bcmd == 'addr_mode':
            try:
                target_mode = int(bval)
            except (TypeError, ValueError):
                target_mode = -1
            cur_mode = (3 if ip_only_mode else (2 if prefer_ip else (1 if prefer_hostname else 0)))
            if 0 <= target_mode < len(ADDR_MODE_LABELS) and target_mode != cur_mode:
                if ip_only_mode:
                    apply_ip_only_off(ip_only_map, original_hosts_list, active_hosts_list,
                                      host_state, up_seen, down_streak)
                    ip_only_map  = {}
                    ip_only_mode = False
                prefer_hostname = (target_mode == 1)
                prefer_ip       = (target_mode == 2)
                if target_mode == 3:
                    # non-dropping web variant - same as pure -web mode; the
                    # CLI [I] key keeps the drop-on-collision apply_ip_only_on
                    ip_only_map, io_msg = apply_ip_only_on_web(
                        original_hosts_list, active_hosts_list, host_state,
                        up_seen, down_streak, int(args.dns_ttl))
                    active_hosts_list = [h for h in active_hosts_list if is_ip_host(h)]
                    ip_only_mode = True
                    notice(io_msg.upper(), 2)
                    message = io_msg
                else:
                    _full = list(original_hosts_list)
                    active_hosts_list = (apply_prefer_ip(_full, int(args.dns_ttl)) if prefer_ip
                                         else apply_prefer_hostname(_full, int(args.dns_ttl))
                                         if prefer_hostname else _full)
                    message = 'address mode: ' + ADDR_MODE_LABELS[target_mode]
            elif not (0 <= target_mode < len(ADDR_MODE_LABELS)):
                message = 'invalid address mode'
            else:
                message = 'address mode: ' + ADDR_MODE_LABELS[cur_mode]

        elif bcmd == 'sort':
            try:
                sort_mode = int(bval) % len(SORT_MODES)
            except ValueError:
                sort_mode = 0
            screen.clear()
            message = 'sort: ' + SORT_MODES[sort_mode][0]

        elif bcmd == 'add':
            add_stats = {}
            new_hosts = parse_host_input(bval, add_stats)
            if not new_hosts:
                err_text = add_stats.get('error') or ('invalid host: ' + bval)
                notice(err_text.upper(), 3)
                message = err_text
            else:
                before_active = set(active_hosts_list)
                added, err = add_hosts_to(new_hosts, active_hosts_list, original_hosts_list)
                if err:
                    notice(err.upper(), 3)
                    message = err
                elif added:
                    write_log_info(args.disable_logging, logfile_file_name,
                                   host_spec_cli('ADD', bval), tz_offset)
                    pending_add_hosts |= (set(new_hosts) - before_active)
                    message = 'added ' + str(added) + ' host(s) - please wait, pinging ...'
                else:
                    message = 'no new host(s) added'

        elif bcmd == 'del':
            del_stats = {}
            del_hosts = parse_host_input(bval, del_stats)
            if not del_hosts:
                err_text = del_stats.get('error') or ('invalid host: ' + bval)
                notice(err_text.upper(), 3)
                message = err_text
            else:
                removed = remove_hosts_from(del_hosts, active_hosts_list,
                                            original_hosts_list, host_state)
                up_seen.difference_update(del_hosts)
                for _h in del_hosts:
                    down_streak.pop(_h, None)
                forget_names(del_hosts)
                notice('REMOVED ' + str(removed) + ' HOST(S)', 2 if removed else 3)
                message = 'removed ' + str(removed) + ' host(s)'
                if removed:
                    write_log_info(args.disable_logging, logfile_file_name,
                                   host_spec_cli('DEL', bval), tz_offset)

        elif bcmd in ('add_list', 'del_list'):
            lst_stats = {}
            lst_hosts = parse_hosts_from_text(bval, lst_stats, not (prefer_ip or ip_only_mode))
            if not lst_hosts:
                message = ('list: mask must be /%d..%d: %s'
                           % (CIDR_MIN_MASK, CIDR_MAX_MASK, lst_stats['skipped'][0])
                           if lst_stats.get('skipped') else 'list: no valid host found')
                notice(message.upper(), 3)
            elif bcmd == 'add_list':
                renamed = (merge_csv_ips_into_lists(lst_hosts, original_hosts_list,
                                                    active_hosts_list, host_state,
                                                    up_seen, down_streak)
                           if lst_stats.get('csv') else 0)
                before_active = set(active_hosts_list)
                added, err = add_hosts_to(lst_hosts, active_hosts_list, original_hosts_list)
                if err:
                    notice(('LIST ' + err).upper(), 3)
                    message = 'list ' + err
                else:
                    message = ('list: ' + str(added) + ' new host(s) of '
                               + str(len(lst_hosts)) + ' found')
                    if lst_stats.get('csv'):
                        message += (', %d existing host(s) updated (%d renamed to hostname)'
                                    % (len(lst_hosts) - added, renamed))
                    if lst_stats.get('ignored'):
                        message += ', %d ignored' % len(lst_stats['ignored'])
                    notice(message.upper(), 2)
                    if added:
                        pending_add_hosts |= (set(lst_hosts) - before_active)
                        message += ' - please wait, pinging ...'
                        write_log_info(args.disable_logging, logfile_file_name,
                                       'ADD list (' + str(added) + ' host(s))', tz_offset)
            else:
                removed = remove_hosts_from(lst_hosts, active_hosts_list,
                                            original_hosts_list, host_state)
                up_seen.difference_update(lst_hosts)
                for _h in lst_hosts:
                    down_streak.pop(_h, None)
                forget_names(lst_hosts)
                message = ('list: removed ' + str(removed) + ' of '
                           + str(len(lst_hosts)) + ' host(s) found')
                notice(message.upper(), 2 if removed else 3)
                if removed:
                    write_log_info(args.disable_logging, logfile_file_name,
                                   'DEL list (' + str(removed) + ' host(s))', tz_offset)

        elif bcmd == 'upload':
            up_stats  = {}
            new_hosts = parse_hosts_from_text(bval, up_stats, not (prefer_ip or ip_only_mode))
            if not new_hosts and up_stats.get('skipped'):
                err_text = ('upload: mask must be /%d..%d: %s'
                           % (CIDR_MIN_MASK, CIDR_MAX_MASK, up_stats['skipped'][0]))
                notice(err_text.upper(), 3)
                message = err_text
            elif not new_hosts:
                notice('UPLOAD: NO VALID HOST FOUND IN FILE', 3)
                message = 'upload: no valid host found in file'
            else:
                before_active = set(active_hosts_list)
                added, err = add_hosts_to(new_hosts, active_hosts_list, original_hosts_list)
                if err:
                    notice(('UPLOAD ' + err).upper(), 3)
                    message = 'upload ' + err
                else:
                    msg = 'UPLOADED: ' + str(added) + ' NEW HOST(S) OF ' + str(len(new_hosts)) + ' FOUND'
                    notice(msg, 2)
                    message = msg.lower()
                    if added:
                        pending_add_hosts |= (set(new_hosts) - before_active)
                        message += ' - please wait, pinging ...'
                        write_log_info(args.disable_logging, logfile_file_name,
                                       'ADD -f (uploaded, ' + str(added) + ' host(s))', tz_offset)

        elif bcmd == 'set_ref':
            # what is actually shown becomes the new reference list - see the
            # matching comment in run_web_mode()'s own set_ref for why display_list
            # (the [M]/display filter applied) is used, not just active_hosts_list
            shown_hosts = [o[0] for o in display_list]
            _keep = set(shown_hosts)   # built once - a set() per element made this O(n^2)
            dropped = [h for h in original_hosts_list if h not in _keep]
            prune_dropped_hosts(dropped, host_state, up_seen, down_streak)
            original_hosts_list[:] = shown_hosts
            active_hosts_list      = shown_hosts
            filter_mode = 0
            match_filter_re, match_filter_text = None, ''
            adv_filter.clear()
            screen.clear()
            write_log_info(args.disable_logging, logfile_file_name, '-setref', tz_offset)
            message = 'reference set to the ' + str(len(shown_hosts)) + ' host(s) shown'

        elif bcmd == 'clear':
            active_hosts_list[:]   = []
            original_hosts_list[:] = []
            host_state.clear()
            host_hist.clear()
            host_meta.clear()
            host_csv_ip.clear()
            adv_filter.clear()
            up_seen.clear()
            down_streak.clear()
            _dns_cache.clear()
            _addr_redundancy_cache.clear()
            filter_mode = 0
            screen.clear()
            write_log_info(args.disable_logging, logfile_file_name, 'CLEAR', tz_offset)
            message = 'cleared all hosts'

        elif bcmd == 'zero':
            for _entry in host_state.values():
                _entry[5] = 0
                _entry[6] = ''
            host_hist.clear()
            notice('CHANGE COUNTERS RESET', 2)
            write_log_info(args.disable_logging, logfile_file_name, 'ZERO', tz_offset)
            message = 'change counters reset'

        elif bcmd == 'get_names':
            if gn_thread is not None and gn_thread.is_alive():
                notice('GET NAMES: ALREADY RUNNING', 3)
                message = 'get names: already running'
            else:
                gn_thread, gn_result, gn_candidates = get_names_start(
                    original_hosts_list, int(args.dns_ttl))
                if gn_thread is None:
                    notice('GET NAMES: NOT AVAILABLE VIA JUMP HOST' if (ssh_target and not jr_active())
                           else 'GET NAMES: NO ELIGIBLE IP HOST(S)', 2, 3)
                    message = 'get names: no eligible ip host(s)'
                else:
                    notice('GET NAMES: RUNNING IN BACKGROUND (%d HOST(S))'
                          % len(gn_candidates), 2)
                    write_log_info(args.disable_logging, logfile_file_name, '-gn', tz_offset)
                    message = 'get names: running in background (%d host(s))' % len(gn_candidates)

        elif bcmd == 'match_filter':
            bval = bval.strip()
            if not bval:
                match_filter_re, match_filter_text = None, ''
                notice('DISPLAY FILTER: OFF', 2)
                message = 'display filter: off'
            else:
                try:
                    new_re = re.compile(bval, re.IGNORECASE)
                except re.error as e:
                    notice(('INVALID REGEX: ' + str(e)).upper(), 3)
                    message = 'invalid regex: ' + str(e)
                else:
                    match_filter_re, match_filter_text = new_re, bval
                    notice('DISPLAY FILTER: ON', 2)
                    message = 'display filter: on'
            rebuild_display()
            draw_screen()
            screen.refresh()

        elif bcmd == 'adv_filter':
            err = adv_filter_set(bval)
            if err:
                notice(('ADV FILTER: ' + err).upper(), 3)
                message = 'adv filter: ' + err
            elif adv_filter:
                notice('ADV FILTER: ON', 2)
                message = 'adv filter: on (' + adv_text() + ')'
            else:
                notice('ADV FILTER: OFF', 2)
                message = 'adv filter: off'
            rebuild_display()
            draw_screen()
            screen.refresh()

        elif bcmd == 'add_comment':
            bval = bval.strip()
            if not args.disable_logging:
                notice('LOGGING IS OFF - COMMENT NOT SAVED', 3)
                message = 'logging is off - comment not saved'
            elif bval:
                write_log_comment(args.disable_logging, logfile_file_name, bval, tz_offset)
                notice('COMMENT LOGGED', 2)
                message = 'comment logged'
            else:
                message = 'comment empty - not logged'

        elif bcmd == 'reset_log':
            # value encoding (see the web gui's runResetLog()): OFF state - the
            # raw value IS the optional custom name (blank = auto-generated);
            # ON state - 'y' (clear), 'new' or 'new=<custom name>' (new file)
            raw = bval.strip()
            action, _, custom_raw = raw.partition('=')
            action = action.lower()
            if not args.disable_logging:
                new_name = validate_custom_logfile_name(raw) if raw else new_logfile_name(tz_offset)
                if new_name is None:
                    notice('NAME ALREADY EXISTS OR INVALID - LOGGING NOT STARTED', 3)
                    message = 'invalid file name - logging not started'
                elif reset_logfile(new_name):
                    args.disable_logging = True
                    logfile_file_name  = new_name
                    _logfile_file_name = new_name
                    notice('LOGGING STARTED: ' + logfile_file_name, 2)
                    message = 'logging started: ' + logfile_file_name
                    write_log_info(args.disable_logging, logfile_file_name,
                                   build_cli_snapshot(args, backoff, timeout, retries, down_retries,
                                                      flap_window, confirm, down_slices, full_sweep,
                                                      tz_offset), tz_offset)
                else:
                    notice('FAILED TO START LOGGING', 3)
                    message = 'failed to start logging'
            elif action == 'y':
                if reset_logfile(logfile_file_name):
                    notice('LOGGING RESET - ' + logfile_file_name + ' CLEARED', 2)
                    message = 'logging reset - ' + logfile_file_name + ' cleared'
                    write_log_info(args.disable_logging, logfile_file_name,
                                   build_cli_snapshot(args, backoff, timeout, retries, down_retries,
                                                      flap_window, confirm, down_slices, full_sweep,
                                                      tz_offset), tz_offset)
                else:
                    notice('FAILED TO RESET LOGFILE', 3)
                    message = 'failed to reset logfile'
            elif action == 'new':
                new_name = validate_custom_logfile_name(custom_raw) if custom_raw else new_logfile_name(tz_offset)
                if new_name is None:
                    notice('NAME ALREADY EXISTS OR INVALID - NEW LOGFILE NOT CREATED', 3)
                    message = 'invalid file name - new logfile not created'
                elif reset_logfile(new_name):
                    logfile_file_name  = new_name
                    _logfile_file_name = new_name
                    notice('NEW LOGFILE: ' + logfile_file_name, 2)
                    message = 'new logfile: ' + logfile_file_name
                    write_log_info(args.disable_logging, logfile_file_name,
                                   build_cli_snapshot(args, backoff, timeout, retries, down_retries,
                                                      flap_window, confirm, down_slices, full_sweep,
                                                      tz_offset), tz_offset)
                else:
                    notice('FAILED TO CREATE NEW LOGFILE', 3)
                    message = 'failed to create new logfile'
            else:
                notice('RESET CANCELLED', 3)
                message = 'reset cancelled'

        elif bcmd in SAVE_HOSTS_CMDS:
            # FILE OPERATIONS > SAVE HOSTS FILE ON SERVER - client already asked
            # for confirmation. A typed name always saves as that (possibly new)
            # file, even with a hostfile already active; blank overwrites the
            # active hostfile, or falls back to the default name if none is
            # active (sanitize_hostfile_save_name())
            with web_lock:
                shown_now = list(web_state.get('host_list_shown') or [])
            target, _as_csv = resolve_save_target(args, bval, shown_now, '_txt' in bcmd)
            if target is None:
                notice('INVALID FILE NAME - HOSTS FILE NOT SAVED', 3)
                message = 'invalid file name - hosts file not saved'
            else:
                if save_hosts_file(target, shown_now, ('' if 'noopt' in bcmd else opt_lines_text(
                        args, adv_option_values(args, down_retries, flap_window, confirm,
                                                down_slices, full_sweep, tz_offset),
                        (3 if ip_only_mode else (2 if prefer_ip else (1 if prefer_hostname else 0))),
                        args.disable_logging))):
                    notice('SAVED ' + str(len(shown_now)) + ' HOST(S) TO ' + target, 2)
                    message = 'saved ' + str(len(shown_now)) + ' host(s) to ' + target
                    write_log_info(args.disable_logging, logfile_file_name,
                                   'SAVE HOSTS FILE: ' + target, tz_offset)
                else:
                    notice('FAILED TO SAVE HOSTS FILE', 3)
                    message = 'failed to save hosts file'

        elif bcmd == 'set_option':
            key, _, raw = str(bval).partition('=')
            ok, val, msg = apply_adv_option(key, raw, args)
            if ok and key in ADV_OPTION_LOCAL_KEYS:
                if key == 'down_retries':   down_retries = val
                elif key == 'flap_window':  flap_window = val
                elif key == 'confirm':      confirm = val
                elif key == 'down_slices':  down_slices = val
                elif key == 'full_sweep':   full_sweep = val
                elif key == 'tz_offset':    tz_offset = val
            if ok:
                write_log_info(args.disable_logging, logfile_file_name,
                               format_option_cli(key, val), tz_offset)
            else:
                notice(msg.upper(), 3, 1.2)

        elif bcmd == 'reset_options':
            before = {k: current_option_value(k, args, backoff, timeout, retries, down_retries,
                                              flap_window, confirm, down_slices, full_sweep, tz_offset)
                     for k in ADV_OPTION_KEYS}
            for key, raw in start_option_values.items():
                ok, val, _ = apply_adv_option(key, raw, args)
                if ok and key in ADV_OPTION_LOCAL_KEYS:
                    if key == 'down_retries':   down_retries = val
                    elif key == 'flap_window':  flap_window = val
                    elif key == 'confirm':      confirm = val
                    elif key == 'down_slices':  down_slices = val
                    elif key == 'full_sweep':   full_sweep = val
                    elif key == 'tz_offset':    tz_offset = val
            for key in ADV_OPTION_KEYS:
                after = current_option_value(key, args, backoff, timeout, retries, down_retries,
                                             flap_window, confirm, down_slices, full_sweep, tz_offset)
                if after != before[key]:
                    write_log_info(args.disable_logging, logfile_file_name,
                                   format_option_cli(key, after), tz_offset)

        elif bcmd == 'exit':
            # same effect/order as the keyboard [E] EXIT handler further below -
            # kept as its own copy here (not a shared call) since the keyboard
            # handler's control flow can't safely be invoked from mid-loop.
            # no maybe_run_epinga() prompt here - this exit was triggered from
            # the browser, not the terminal, so nobody is there to answer the
            # "[y/N]" input() prompt; same as the pure -web mode's exit handler.
            with web_lock:
                web_state['stopped'] = True
                web_state['message'] = 'stopped'
            time.sleep(1.5)
            curses.endwin()
            print('THX for using eping.py v' + VERSION + '  -  www.jeitler.cc')
            if is_newer_version(remote_version, VERSION):
                print_update_notice(remote_version)
            sys.stdout.flush()
            ssh_shutdown()
            os._exit(0)

        if have_data:
            rebuild_display()
            draw_screen()
            screen.refresh()
            web_sync(message, bump=True)

    def notice(text, color=3, seconds=1.4):
        """Show a short message box in the middle of the screen.

        Also mirrors the text to a connected web GUI (-wv/-wvc) via cli_message -
        it no-ops for plain CLI (web_sync() checks args.web_view/web_view_control).
        Most CLI actions only ever surface their result through this box, so
        without this the web side never heard about them.
        """
        global cli_message
        cli_message = text.lower()
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
    # [X] ADV OPTIONS: snapshot of every startup value, for RESET TO DEFAULT -
    # same reasoning as run_web_mode()'s start_option_values.
    start_option_values = adv_option_values(args, down_retries, flap_window,
                                            confirm, down_slices, full_sweep, tz_offset)
    if args.web_view or args.web_view_control:
        # published right away - without this the browser's ADV OPTIONS modal
        # shows empty fields/sliders at their minimum until the first round
        # completes and web_sync() fills web_state['options'] in
        with web_lock:
            web_state['options'] = start_option_values

    down_streak = {}
    last_draw_time = 0.0
    # False until the first round has produced something to look at; until then the
    # progress callback shows a 'please wait' box instead of an empty screen
    have_data      = False
    filter_mode    = 0
    prefer_hostname = bool(args.prefer_hostname)
    prefer_ip      = False   # [K] PREFER IP ADDRESS - curses mirror of the web
                              # addr_mode dropdown's 3rd option (apply_prefer_ip)
    ip_only_mode   = False
    ip_only_map    = {}
    sort_mode      = 0
    display_list   = []
    hosts_count_up = 0
    hosts_count_down = 0
    hosts_count_flap  = 0
    hosts_count_shown = 0
    run_time       = '0.00'
    phase          = {}
    used_scan      = ''
    learning_phase = True
    update_available_cli = is_newer_version(remote_version, VERSION)
    gn_thread      = None   # [G] background PTR lookup - see get_names_start/finish
    gn_result      = None
    gn_candidates  = []
    report_thread  = None   # [N] ANALYSE NOW - background epinga.py report generation
    report_result  = None   # mutable [(path, err)] set by the thread when done
    match_filter_re   = None   # [M] display-only regex filter - active_hosts_list unaffected
    match_filter_text = ''
    pending_add_hosts = set()   # just-added hosts not yet in host_state - see ADD/UPLOAD
                                 # in apply_browser_command() and the completion check
                                 # after update_host_state() below and in run_background_pings()
    cli_message       = None    # text for the next 'if cmd and have_data' web_sync() call -
                                 # see notice() and the keyboard command handlers below

    # -gn / -ph: applied once, before the first ping round - by then original/active
    # host list, host_state, up_seen and down_streak all exist in this scope
    if args.get_names:
        apply_get_names(original_hosts_list, active_hosts_list, host_state,
                        up_seen, down_streak, int(args.dns_ttl))
    if args.ip_only:
        ip_only_map, _ = apply_ip_only_on(original_hosts_list, active_hosts_list,
                                          host_state, up_seen, down_streak, int(args.dns_ttl))
        ip_only_mode = True
    if prefer_hostname:
        _n_names = sum(1 for h in active_hosts_list if not is_ip_host(h))
        active_hosts_list = run_with_wait_box(
            ['PLEASE WAIT', 'resolving ' + str(_n_names) + ' hostnames'],
            lambda: apply_prefer_hostname(active_hosts_list, int(args.dns_ttl)))

    # --web_view/--web_view_control: browser view next to the terminal, read only
    # or (with -wvc) also controllable. The curses loop stays the only driver -
    # one process, one scan, two ways to look at and/or drive it. Two separate
    # eping processes would mean two fping groups stealing each other's replies.
    if args.web_view or args.web_view_control:
        web_readonly = not args.web_view_control
        with web_lock:
            web_state['version']  = version
            web_state['readonly'] = web_readonly
            _save_target = hostfile_save_target(args)
            web_state['hostfile_name']   = _save_target or ''
            web_state['hostfile_active'] = _save_target is not None
        start_web_server(args.web_bind, int(args.web_port))

    def web_sync(msg='', bump=False):
        if not (args.web_view or args.web_view_control):
            return
        # mirror the same fix as run_web_mode(): HOSTS-UP/DOWN in the web view should
        # be the totals for the current view, not narrowed by the [M] display filter
        # the way the curses screen's own hosts_count_up/down are (left untouched here).
        total_list = build_display(active_hosts_list, host_state, sort_mode,
                                   tz_offset, flap_window)
        total_up   = sum(1 for e in total_list if 'UP' in e[1])
        total_down = len(total_list) - total_up
        total_flap = sum(1 for e in total_list
                         if host_is_flapping(e, now_local(tz_offset), flap_window))
        # ADV OPTIONS current values - only actually looked at by the browser's
        # options modal in -wvc (harmless, cheap dict build otherwise)
        opts = adv_option_values(args, down_retries, flap_window, confirm,
                                 down_slices, full_sweep, tz_offset)
        web_publish(display_list, run_counter, run_time, total_up, total_down,
                    filter_mode, learning_phase, run_counter, up_check_runs,
                    args.disable_logging, logfile_file_name, update_available_cli,
                    tz_offset, msg, used_scan, sort_mode,
                    (3 if ip_only_mode else (2 if prefer_ip else (1 if prefer_hostname else 0))),
                    match_filter_text, original_hosts_list, hosts_shown=len(display_list),
                    options=opts, hosts_flap=total_flap, pending_wait=bool(pending_add_hosts))
        if bump:
            with web_lock:
                web_state['msg_seq'] = web_state.get('msg_seq', 0) + 1


    def rebuild_display():
        """Recompute the visible list straight from host_state - no ping needed.

        UP-ONLY, SET REFERENCE, DEL HOST and ZERO CHANGES are pure display operations,
        so they can take effect at once instead of after the next scan round.
        """
        global display_list, hosts_count_up, hosts_count_down, hosts_count_flap
        global hosts_count_shown
        display_all = build_display(active_hosts_list, host_state, sort_mode,
                                    tz_offset, flap_window)
        # HOSTS/UP/DOWN/FLAPPING count all hosts - the view, [M] and ADV FILTER only
        # narrow what is shown (SHOWN), every host is still pinged
        _now_ref = now_local(tz_offset)
        hosts_count_up   = sum(1 for e in display_all if 'UP' in e[1])
        hosts_count_down = len(display_all) - hosts_count_up
        hosts_count_flap = sum(1 for e in display_all
                               if host_is_flapping(e, _now_ref, flap_window))
        display_list = view_rows(display_all, filter_mode, host_state, tz_offset, flap_window)
        if match_filter_re is not None or adv_filter:
            display_list = apply_match_filter(display_list, match_filter_re)
        hosts_count_shown = len(display_list)

    def draw_screen():
        """Paint the whole screen from the data of the last completed round.

        Decoupled from the scan on purpose: it can be called any time, also while
        fping is still running, so a resize or a filter change shows immediately.
        """
        rows, cols = screen.getmaxyx()
        if _source_alert:
            screen_print_center_top(_source_alert[:max(10, cols - 2)], 3)
        elif is_newer_version(remote_version, VERSION):
            screen_print_center_top('Update available - please visit https://www.jeitler.cc', 3)
        elif gn_thread is not None and gn_thread.is_alive():
            screen_print_center_top(
                'GET NAMES running in background (%d host(s))...' % len(gn_candidates), 2)
        elif match_filter_re is not None or adv_filter:
            _ft = []
            if match_filter_re is not None:
                _ft.append("'%s'" % match_filter_text)
            if adv_filter:
                _ft.append('ADV ' + adv_text())
            screen_print_center_top(
                ("DISPLAY FILTER %s active (%d of %d hosts shown, all still pinged)"
                 % (' + '.join(_ft), len(display_list), len(active_hosts_list)))[:max(10, cols - 4)], 2)
        else:
            screen_print_center_top('eping.py version ' + version + ' by Ewald Jeitler', 1)

        screen_print_date_time(1, tz_offset)
        screen_print_horizontal_line('-', 1, 1)
        screen_print_horizontal_line('-', 1, 3)
        screen_print_horizontal_line('-', 1, rows - 2)

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
            except IndexError:
                pass

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
        # 'HOST UP: n DOWN: n FLAPPING: n' replaces the old, wider
        # 'HOSTS-UP: n   HOSTS-DOWN: n' pair - shorter and adds the flap count.
        # Each count is left-padded to 6 digits (the max host count, see
        # *Host sources*), and every fixed column below is spaced to fit that
        # width - a narrower count just leaves trailing blanks, same as before.
        hosts_up   = '{m: <6}'.format(m=hosts_count_up)
        hosts_down = '{m: <6}'.format(m=hosts_count_down)
        hosts_flap = '{m: <6}'.format(m=hosts_count_flap)
        screen_output(rows - 1, 1,  'HOSTS: '   + str(hosts_count_up + hosts_count_down), 1, 1)
        _runtime_txt = ('RUNTIME: ' + run_time if run_time == RUNTIME_UNAVAILABLE
                        else 'RUNTIME: ' + str(run_time) + 's')
        screen_output(rows - 1, 14, _runtime_txt, 1, 1)
        screen_output(rows - 1, 35, 'RUNS: '    + str(run_counter), 1, 1)
        screen_output(rows - 1, 50, '| HOST UP: ', 1, 1)
        screen_output(rows - 1, 61, hosts_up, 2, 1)
        screen_output(rows - 1, 67, 'DOWN: ', 1, 1)
        screen_output(rows - 1, 73, hosts_down, 3, 1)
        screen_output(rows - 1, 79, 'FLAPPING: ', 1, 1)
        screen_output(rows - 1, 89, hosts_flap.rstrip(), 1, 1)
        screen_output(rows - 1, 96, 'SHOWN: ', 1, 1)
        screen_output(rows - 1, 103, ('{m: <6}'.format(m=hosts_count_shown)).rstrip() + ' |', 1, 1)
        if args.disable_logging:
            screen_output(rows - 1, 113, 'LOGGING-ON: ' + logfile_file_name, 1, 1)
        else:
            screen_output(rows - 1, 113, 'LOGGING-OFF', 1, 1)
        if num_of_hosts > 0 and maxhosts < num_of_hosts:
            tts_text = ' | TERMINAL TOO SMALL '
            screen_output(rows - 1, cols - len(tts_text), tts_text, 3, 2)

        # key bar - four label sets so it still fits on narrow terminals. [U] and [O]
        # show the view and the order that are active right now.
        fm = WEB_VIEW_MODES[filter_mode]   # filter_mode can be any WEB_VIEW_MODES
                                            # index now - see [V] VIEW_PICKER
        sm = SORT_MODES[sort_mode]
        # order: U, M, A, D, F, O, T, S, Z, C, P, I, G, R, E - grouped by how often
        # each is used, rather than the historical add-order
        l_full  = ' [L]=RESET LOGGING ' if args.disable_logging else ' [L]=START LOG '
        l_short = ' [L]=RESET LOG '     if args.disable_logging else ' [L]=START LOG '
        l_tiny  = ' [L]RSTLOG '         if args.disable_logging else ' [L]STARTLOG '
        keys_full  = [' [U]=' + fm[0] + ' ', ' [M]=DISPLAY FILTER ', ' [V]=ADV FILTER ', ' [A]=ADD ', ' [D]=DELETE ', ' [F]=ADD FILE ',
                      ' [O]=SORT ' + sm[0] + ' ', ' [T]=COMMENT ', ' [S]=SET REFERENCE ', ' [Z]=ZERO CHANGES ',
                      ' [C]=CLEAR ALL ', ' [P]=ADDR MODE ', ' [X]=ADV OPTIONS ', ' [J]=JUMPHOST ',
                      ' [N]=ANALYSE NOW ', ' [G]=GET NAMES ', ' [R]=SCREEN REFRESH ', l_full, ' [E]=EXIT ']
        keys_short = [' [U]=' + fm[1] + ' ', ' [M]=FILTER ', ' [V]=ADV FLT ', ' [A]=ADD ', ' [D]=DEL ', ' [F]=FILE ',
                      ' [O]=' + sm[1] + ' ', ' [T]=COMMENT ', ' [S]=SET REF ', ' [Z]=ZERO ',
                      ' [C]=CLEAR ', ' [P]=ADDR ', ' [X]=ADV OPT ', ' [J]=JUMP ',
                      ' [N]=ANALYSE ', ' [G]=NAMES ', ' [R]=REFRESH ', l_short, ' [E]=EXIT ']
        keys_tiny  = [' [U]' + fm[2] + ' ', ' [M]FLT ', ' [V]AFLT ', ' [A]ADD ', ' [D]DEL ', ' [F]FILE ',
                      ' [O]' + sm[1] + ' ', ' [T]CMT ', ' [S]REF ', ' [Z]ZERO ',
                      ' [C]CLR ', ' [P]ADDR ', ' [X]ADV ', ' [J]JMP ',
                      ' [N]ANLZ ', ' [G]NAME ', ' [R]RFR ', l_tiny, ' [E]EXIT ']
        keys_micro = [' U ', ' M ', ' V ', ' A ', ' D ', ' F ', ' O ', ' T ', ' S ', ' Z ', ' C ', ' P ', ' X ', ' J ', ' N ', ' G ', ' R ', ' L ', ' E ']
        for keys in (keys_full, keys_short, keys_tiny, keys_micro):
            if sum(len(k) for k in keys) + 2 <= cols:
                break
        key_col = 2
        for idx, label in enumerate(keys):
            highlight = ((idx == 0 and filter_mode != 0) or (idx == 1 and match_filter_re is not None)
                        or (idx == 2 and bool(adv_filter))
                        or (idx == 6 and sort_mode != 0)
                        or (idx == 11 and (prefer_hostname or prefer_ip))
                        or (idx == 13 and bool(ssh_cfg)))
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
        draw_wait_box(['PLEASE WAIT',
                       'scanning ' + str(host_count) + ' hosts',
                       '%.1f sec' % elapsed])

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
        # -wvc: a command posted by the browser (EXIT included) must cut the round
        # short too, same as a local keypress below - otherwise it sits in
        # web_commands until the current round ends on its own, which on a large
        # host count can take minutes. Mirrors web_progress()'s own check in pure
        # -web mode; apply_browser_command() picks it up at the top of the next
        # loop iteration once this round is aborted.
        if args.web_view_control:
            with web_lock:
                if web_commands:
                    return True
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
    screen_print_horizontal_line('-', 1, 1)
    scan_box(0.0, len(active_hosts_list))
    screen.refresh()

    run_counter = 1
    while True:

        # --- [G] background PTR lookup: apply results once the thread is done ---
        if gn_thread is not None and not gn_thread.is_alive():
            gn_msg    = get_names_finish(gn_candidates, gn_result, original_hosts_list,
                                         active_hosts_list, host_state, up_seen, down_streak)
            gn_thread = None
            if have_data:
                rebuild_display()
                draw_screen()
                screen.refresh()
            notice(gn_msg.upper(), 2, 3)

        # --- [N] ANALYSE NOW: apply the epinga.py report result once it's done ---
        if report_thread is not None and not report_thread.is_alive():
            _rpt_path, _rpt_err = report_result[0]
            report_thread = None
            if _rpt_path:
                notice('REPORT READY: ' + _rpt_path, 2, 3)
            else:
                notice('ANALYSIS FAILED: ' + str(_rpt_err).upper(), 3, 3)

        # --- --web_view_control: drain commands posted by the browser ---
        if args.web_view_control:
            with web_lock:
                _browser_cmds = list(web_commands)
                del web_commands[:]
            for _bcmd, _bval in _browser_cmds:
                apply_browser_command(_bcmd, _bval)

        # --- keyboard: drain all buffered keys ---
        cmd = None
        while True:
            k = screen.getch()
            if k == -1:
                break
            if k == curses.KEY_RESIZE:
                screen.clear()          # geometry handled below, not a command
            elif k in (ord('u'), ord('U')):
                cmd = 'VIEW_PICKER'
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
            elif k in (ord('p'), ord('P')):
                cmd = 'ADDR_MODE_PICKER'
            elif k in (ord('x'), ord('X')):
                cmd = 'ADV_OPTIONS'
            elif k in (ord('j'), ord('J')):
                cmd = 'JUMPHOST'
            elif k in (ord('n'), ord('N')):
                cmd = 'ANALYSE_NOW'
            elif k in (ord('g'), ord('G')):
                cmd = 'GET_NAMES'
            elif k in (ord('m'), ord('M')):
                cmd = 'MATCH_FILTER'
            elif k in (ord('v'), ord('V')):
                cmd = 'ADV_FILTER'
            elif k in (ord('c'), ord('C')):
                cmd = 'CLEAR'
            elif k in (ord('r'), ord('R')):
                cmd = 'SCREENREFRESH'
            elif k in (ord('l'), ord('L')):
                cmd = 'RESET_LOGGING'
            elif k in (ord('e'), ord('E')):
                cmd = 'EXIT'
            elif k in (ord('t'), ord('T')):
                cmd = 'ADD_COMMENT'
        if cmd == 'SET_REFERENCE':
            # the currently displayed host list becomes the new reference list -
            # display_list already has both the [U] view filter (active_hosts_list)
            # and the [M]/display filter applied, see rebuild_display()
            shown_hosts = [o[0] for o in display_list]
            _keep = set(shown_hosts)   # built once - a set() per element made this O(n^2)
            dropped = [h for h in original_hosts_list if h not in _keep]
            prune_dropped_hosts(dropped, host_state, up_seen, down_streak)
            # two independent list objects - do not bind both names to the same
            # object here, or a later add_hosts_to()/remove_hosts_from() call
            # (which mutates active_list and original_list as if separate) will
            # apply its change twice to the one underlying list
            original_hosts_list = list(shown_hosts)
            active_hosts_list   = shown_hosts
            filter_mode = 0            # active == reference, so no filter is active
            match_filter_re, match_filter_text = None, ''   # already absorbed into the new reference
            adv_filter.clear()
            screen.clear()
            write_log_info(args.disable_logging, logfile_file_name, '-setref', tz_offset)
            cli_message = 'reference set to the ' + str(len(shown_hosts)) + ' host(s) shown'
        elif cmd == 'CLEAR':
            active_hosts_list   = []
            original_hosts_list = []
            host_state.clear()
            host_hist.clear()
            host_meta.clear()
            host_csv_ip.clear()
            adv_filter.clear()
            up_seen.clear()
            down_streak.clear()
            _dns_cache.clear()
            _addr_redundancy_cache.clear()
            filter_mode = 0
            screen.clear()
            write_log_info(args.disable_logging, logfile_file_name, 'CLEAR', tz_offset)
            cli_message = 'cleared'
        elif cmd == 'VIEW_PICKER':
            # [U] opens the view picker directly - the curses equivalent of the
            # web gui's <select id="selFilter"> (same pattern as [O]/[P]: one
            # key, one menu). Reaches all of WEB_VIEW_MODES, in the same display
            # order as the web dropdown - see VIEW_PICKER_ORDER above.
            items    = [WEB_VIEW_MODES[m][0] for m in VIEW_PICKER_ORDER]
            cur_pos  = (VIEW_PICKER_ORDER.index(filter_mode)
                       if filter_mode in VIEW_PICKER_ORDER else 0)
            picked   = list_picker_dialog('SELECT VIEW', items, cur_pos)
            if picked is not None:
                new_mode = VIEW_PICKER_ORDER[picked]
                new_list = filter_hosts(new_mode, original_hosts_list, host_state,
                                        tz_offset, flap_window, up_seen)
                if new_list or new_mode == 0:
                    filter_mode       = new_mode
                    screen.clear()
                    write_log_info(args.disable_logging, logfile_file_name,
                                   'FILTER ' + WEB_VIEW_MODES[filter_mode][0], tz_offset)
                    cli_message = 'view: ' + WEB_VIEW_MODES[filter_mode][0]
                else:
                    notice('NO HOSTS MATCH ' + WEB_VIEW_MODES[new_mode][0], 3)
        elif cmd == 'ADV_OPTIONS':
            adv_options_dialog()
        elif cmd == 'JUMPHOST':
            jumphost_dialog()
        elif cmd == 'ANALYSE_NOW':
            # [N] curses equivalent of the web gui's GENERATE REPORT button -
            # runs epinga.py against the current logfile in the background (see
            # generate_epinga_report()) so the ping loop is not blocked while it
            # runs; the result is picked up by the poll block above once done.
            if not args.disable_logging:            # True means 'logging enabled', see -dl
                notice('LOGGING IS DISABLED - NO LOG TO ANALYSE', 3)
            elif report_thread is not None and report_thread.is_alive():
                notice('ANALYSIS ALREADY RUNNING...', 3)
            else:
                report_result = [None]
                def _report_worker(_holder=report_result, _logpath=logfile_file_name):
                    _holder[0] = generate_epinga_report(_logpath)
                report_thread = threading.Thread(target=_report_worker, daemon=True)
                report_thread.start()
                notice('ANALYSING LOGFILE IN BACKGROUND...', 2, 1.4)
        elif cmd == 'ADDR_MODE_PICKER':
            # [P] full address-mode picker - the curses equivalent of the web
            # gui's addr_mode dropdown (see ADDR_MODE_LABELS). [K]/[I] remain as
            # quick individual toggles, same relationship as [U]/[V] for views.
            cur_mode = (3 if ip_only_mode else (2 if prefer_ip else (1 if prefer_hostname else 0)))
            items    = [l.upper() for l in ADDR_MODE_LABELS]
            picked   = list_picker_dialog('SELECT ADDRESS MODE', items, cur_mode)
            if picked is not None and picked != cur_mode:
                if ip_only_mode:
                    # leaving IP ONLY: restore the renamed hostnames first
                    io_msg = apply_ip_only_off(ip_only_map, original_hosts_list,
                                               active_hosts_list, host_state,
                                               up_seen, down_streak)
                    ip_only_map  = {}
                    ip_only_mode = False
                prefer_hostname = (picked == 1)
                prefer_ip       = (picked == 2)
                if picked == 3:
                    ip_only_map, io_msg = apply_ip_only_on(
                        original_hosts_list, active_hosts_list, host_state,
                        up_seen, down_streak, int(args.dns_ttl))
                    ip_only_mode = True
                    notice(io_msg.upper(), 2)
                else:
                    _full = list(original_hosts_list)
                    active_hosts_list = (apply_prefer_ip(_full, int(args.dns_ttl)) if prefer_ip
                                         else apply_prefer_hostname(_full, int(args.dns_ttl))
                                         if prefer_hostname else _full)
                    notice('ADDRESS MODE: ' + items[picked], 2)
        elif cmd == 'GET_NAMES':
            if gn_thread is not None and gn_thread.is_alive():
                notice('GET NAMES: ALREADY RUNNING', 3)
            else:
                gn_thread, gn_result, gn_candidates = get_names_start(
                    original_hosts_list, int(args.dns_ttl))
                if gn_thread is None:
                    notice('GET NAMES: NOT AVAILABLE VIA JUMP HOST' if (ssh_target and not jr_active())
                           else 'GET NAMES: NO ELIGIBLE IP HOST(S)', 2, 3)
                else:
                    notice('GET NAMES: RUNNING IN BACKGROUND (%d HOST(S))'
                          % len(gn_candidates), 2)
                    write_log_info(args.disable_logging, logfile_file_name, '-gn', tz_offset)
        elif cmd == 'MATCH_FILTER':
            value = input_dialog(' DISPLAY FILTER ',
                                 ' regex to match hostname/IP/inventory fields, case-insensitive - empty to disable:')
            if value:
                try:
                    new_re = re.compile(value, re.IGNORECASE)
                except re.error as e:
                    notice(('INVALID REGEX: ' + str(e)).upper(), 3)
                else:
                    match_filter_re, match_filter_text = new_re, value
                    rebuild_display()
                    draw_screen()
                    screen.refresh()
                    notice('DISPLAY FILTER: ON (%d OF %d SHOWN)'
                          % (len(display_list), len(active_hosts_list)), 2)
            elif match_filter_re is not None:
                match_filter_re, match_filter_text = None, ''
                rebuild_display()
                draw_screen()
                screen.refresh()
                notice('DISPLAY FILTER: OFF', 2)
        elif cmd == 'ADV_FILTER':
            adv_filter_dialog()
        elif cmd == 'ORDER':
            # [O] opens the sort-order picker directly - the curses equivalent
            # of the web gui's <select id="sortSel"> (same pattern as [P] for
            # address mode: one key, one menu, no separate cycle-only key).
            items  = [m[0] for m in SORT_MODES]
            picked = list_picker_dialog('SELECT SORT ORDER', items, sort_mode)
            if picked is not None:
                sort_mode = picked
                screen.clear()
                cli_message = 'sort: ' + SORT_MODES[sort_mode][0]
        elif cmd == 'ADD':
            value     = input_dialog(' ADD HOSTS ',
                                     ' IPv4/IPv6, hostname, IPv4 CIDR /%d../%d, IPv6 /128 or ip1-ip2:'
                                     % (CIDR_MIN_MASK, CIDR_MAX_MASK))
            if value:
                add_stats = {}
                new_hosts = parse_host_input(value, add_stats)
                if not new_hosts:
                    notice((add_stats.get('error') or ('invalid host: ' + value)).upper(), 3)
                else:
                    before_active = set(active_hosts_list)
                    added, err = add_hosts_to(new_hosts, active_hosts_list, original_hosts_list)
                    if err:
                        notice(err.upper(), 3)
                    elif added:
                        write_log_info(args.disable_logging, logfile_file_name,
                                       host_spec_cli('ADD', value), tz_offset)
                        pending_add_hosts |= (set(new_hosts) - before_active)
                        cli_message = ('added ' + str(added)
                                       + ' host(s) - please wait, pinging ...')
        elif cmd == 'ADD_FILE':
            value = input_dialog(' ADD HOSTS FROM FILE ', ' Enter path of the host file:')
            if value:
                new_hosts, err = load_hosts_file(value, not (prefer_ip or ip_only_mode))
                if err:
                    notice(err.upper(), 3)
                else:
                    before_active = set(active_hosts_list)
                    added, err = add_hosts_to(new_hosts, active_hosts_list, original_hosts_list)
                    if err:
                        notice(err.upper(), 3)
                    else:
                        notice('ADDED ' + str(added) + ' NEW HOST(S) OF ' + str(len(new_hosts)) + ' FOUND', 2)
                        if added:
                            pending_add_hosts |= (set(new_hosts) - before_active)
                            write_log_info(args.disable_logging, logfile_file_name,
                                           'ADD -f ' + value, tz_offset)
        elif cmd == 'DEL':
            value = input_dialog(' DELETE HOSTS ',
                                 ' IPv4/IPv6, hostname, IPv4 CIDR /%d../%d, IPv6 /128 or ip1-ip2:'
                                 % (CIDR_MIN_MASK, CIDR_MAX_MASK))
            if value:
                del_stats = {}
                del_hosts = parse_host_input(value, del_stats)
                if not del_hosts:
                    notice((del_stats.get('error') or ('invalid host: ' + value)).upper(), 3)
                else:
                    removed = remove_hosts_from(del_hosts, active_hosts_list,
                                                original_hosts_list, host_state)
                    up_seen.difference_update(del_hosts)
                    for _h in del_hosts:
                        down_streak.pop(_h, None)
                    forget_names(del_hosts)
                    notice('REMOVED ' + str(removed) + ' HOST(S)', 2 if removed else 3)
                    if removed:
                        write_log_info(args.disable_logging, logfile_file_name,
                                       host_spec_cli('DEL', value), tz_offset)
        elif cmd == 'ZERO':
            # forget the change history, keep the current UP/DOWN state
            for _entry in host_state.values():
                _entry[5] = 0
                _entry[6] = ''
            host_hist.clear()
            notice('CHANGE COUNTERS RESET', 2)
            write_log_info(args.disable_logging, logfile_file_name, 'ZERO', tz_offset)
        elif cmd == 'ADD_COMMENT':
            if not args.disable_logging:
                notice('LOGGING IS OFF - COMMENT NOT SAVED', 3)
            else:
                value = input_dialog(' ADD COMMENT ',
                                     ' free text, logged with a timestamp to the CSV:')
                if value:
                    write_log_comment(args.disable_logging, logfile_file_name, value, tz_offset)
                    notice('COMMENT LOGGED', 2)
        elif cmd == 'SCREENREFRESH':
            screen.clear()
        elif cmd == 'RESET_LOGGING':
            if not args.disable_logging:
                # logging is currently OFF - [L]/START LOG turns it on right away
                # (no Y/N confirmation - there is nothing to lose yet), but still
                # offers an optional custom file name (blank = auto-generated)
                custom = input_dialog(' START LOGGING ',
                    'optional file name (blank = auto-generated), .csv added automatically:')
                new_name = validate_custom_logfile_name(custom) if custom else new_logfile_name(tz_offset)
                if new_name is None:
                    notice('NAME ALREADY EXISTS OR INVALID - LOGGING NOT STARTED', 3)
                elif reset_logfile(new_name):
                    args.disable_logging = True   # True means 'logging enabled' (see -dl)
                    logfile_file_name  = new_name
                    _logfile_file_name = new_name   # keep sigint_handler() in sync
                    notice('LOGGING STARTED: ' + logfile_file_name, 2)
                    # fresh file - same full snapshot as a program startup, see main()
                    write_log_info(args.disable_logging, logfile_file_name,
                                   build_cli_snapshot(args, backoff, timeout, retries,
                                                      down_retries, flap_window, confirm,
                                                      down_slices, full_sweep, tz_offset),
                                   tz_offset)
                else:
                    notice('FAILED TO START LOGGING', 3)
            else:
                answer = key_confirm_dialog(' RESET LOGGING ',
                    ['[Y] clear this file   [N] start a fresh file (old kept)',
                     '[ESC]/[ENTER] cancel'], ('y', 'n'))
                if answer == 'y':
                    if reset_logfile(logfile_file_name):
                        notice('LOGGING RESET - ' + logfile_file_name + ' CLEARED', 2)
                        write_log_info(args.disable_logging, logfile_file_name,
                                       build_cli_snapshot(args, backoff, timeout, retries,
                                                          down_retries, flap_window, confirm,
                                                          down_slices, full_sweep, tz_offset),
                                       tz_offset)
                    else:
                        notice('FAILED TO RESET LOGFILE', 3)
                elif answer == 'n':
                    # 'start a fresh file' also offers an optional custom name -
                    # blank keeps the default rotation-chain-style naming
                    custom = input_dialog(' NEW LOGFILE NAME ',
                        'optional file name (blank = auto-generated), .csv added automatically:')
                    new_name = validate_custom_logfile_name(custom) if custom else new_logfile_name(tz_offset)
                    if new_name is None:
                        notice('NAME ALREADY EXISTS OR INVALID - NEW LOGFILE NOT CREATED', 3)
                    elif reset_logfile(new_name):
                        logfile_file_name  = new_name
                        _logfile_file_name = new_name   # keep sigint_handler() in sync
                        notice('NEW LOGFILE: ' + logfile_file_name, 2)
                        write_log_info(args.disable_logging, logfile_file_name,
                                       build_cli_snapshot(args, backoff, timeout, retries,
                                                          down_retries, flap_window, confirm,
                                                          down_slices, full_sweep, tz_offset),
                                       tz_offset)
                    else:
                        notice('FAILED TO CREATE NEW LOGFILE', 3)
                else:
                    notice('RESET CANCELLED', 3)
        elif cmd == 'EXIT':
            # same as the web GUI's own EXIT button - tell a --web_view browser
            # mirror right away, BEFORE maybe_run_epinga() below can block on its
            # "[y/N]" prompt for as long as the user takes to answer it.
            with web_lock:
                web_state['stopped'] = True
                web_state['message'] = 'stopped'
            time.sleep(1.5)   # guarantee the browser's next poll sees it even if
                               # maybe_run_epinga() below has nothing to prompt for
            curses.endwin()
            print(f'THX for using eping.py v{VERSION} - www.jeitler.cc')
            if is_newer_version(remote_version, VERSION):
                print_update_notice(remote_version)
            maybe_run_epinga(logfile_file_name, args.disable_logging)
            sys.stdout.flush()
            # os._exit(), not sys.exit(): see sigint_handler() for why.
            ssh_shutdown()
            os._exit(0)

        # a command only changes what is shown - repaint at once instead of making
        # the user wait for the next scan round to finish
        if cmd and have_data:
            rebuild_display()
            draw_screen()
            screen.refresh()
        if cli_message is not None:
            web_sync(cli_message, bump=True)
            cli_message = None
        elif cmd and have_data:
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
                if args.set_reference:
                    # -setref: same as pressing [S]/SET REFERENCE once learning ends
                    _up_list = sorted(up_seen, key=lambda h: (
                        int(ipaddress.ip_address(h)) if is_ip_host(h) else float('inf')
                    ))
                    _up_list = (apply_prefer_ip(_up_list, int(args.dns_ttl)) if prefer_ip
                                else apply_prefer_hostname(_up_list, int(args.dns_ttl))
                                if prefer_hostname else _up_list)
                    _keep = set(_up_list)   # once, not per element (was O(n^2))
                    prune_dropped_hosts([h for h in original_hosts_list if h not in _keep],
                                        host_state, up_seen, down_streak)
                    original_hosts_list = list(_up_list)
                    active_hosts_list   = _up_list
                    filter_mode = 0
                else:
                    filter_mode = 1    # UP view (display filter), every host is still pinged
                screen.clear()
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
        if args.disable_logging:
            _new_lf = rotate_log_if_needed(logfile_file_name, int(args.log_max_size),
                                           int(args.log_max_files), tz_offset)
            if _new_lf != logfile_file_name:
                logfile_file_name  = _new_lf
                _logfile_file_name = _new_lf
                write_log_info(args.disable_logging, logfile_file_name,
                              build_cli_snapshot(args, backoff, timeout, retries,
                                                 down_retries, flap_window, confirm,
                                                 down_slices, full_sweep, tz_offset), tz_offset)
        if pending_add_hosts and pending_add_hosts <= set(host_state):
            pending_add_hosts.clear()
            web_sync('done', bump=True)
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
            deadline  = time.time() + max(remaining, 0.05)   # -w 0: never a hot loop
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