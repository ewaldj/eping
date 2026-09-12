#!/usr/bin/env python3

# - - - - - - - - - - - - - - - - - - - - - - - -
# eping.py by ewald@jeitler.cc 2024 https://www.jeitler.cc 
# - - - - - - - - - - - - - - - - - - - - - - - -
# When I wrote this code, only god and 
# I knew how it worked. 
# Now, only god knows it! 
# - - - - - - - - - - - - - - - - - - - - - - - -
VERSION = '2.83'
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
DNS_CACHE_TTL      = 300      # seconds a resolved hostname stays valid (0 = no caching)
DNS_FAIL_TTL       = 30       # negative cache: retry unresolvable names sooner
DNS_RESOLVERS      = 16       # parallel name lookups
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

# [U] cycles through these views. Like before, the filter also shrinks what is pinged,
# which is what makes UP-ONLY shorten the cycle. Hosts filtered away are not probed and
# therefore cannot come back until the view is switched to ALL again.
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
    ('EVER-UP',        'E-UP',  'EUP'),
]

# web gui only: unifies the previously independent PREFER HOSTNAME / IP ONLY
# toggles into one mutually-exclusive dropdown (see the 'addr_mode' web command).
# 0/1/2 are non-destructive display filters (recomputed from original_hosts_list
# each time); 3 renames hosts to their address in place (apply_ip_only_on/off).
ADDR_MODE_LABELS = ['provided ip/name', 'prefer hostname', 'prefer ip address', 'ip only']

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
import shlex
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

def error_handler(message):
    print ('\n ' + str(message) + '\n')
    sys.exit(0)

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
    with _dns_lock:
        _dns_cache[name] = (ip, time.time() + (ttl if ip else min(ttl, DNS_FAIL_TTL)))
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
    if old in up_seen:
        up_seen.discard(old)
        up_seen.add(new)
    if old in down_streak:
        down_streak[new] = down_streak.pop(old)
    forget_names([new])   # force a fresh forward lookup for the new identity

def _forward_confirms(name, ip):
    """True if 'name' has a forward record (A for an IPv4 ip, AAAA for an IPv6 ip)
    that resolves back to exactly this ip. Guards GET NAMES: a PTR record with no
    matching forward record must not be used to rename a host, or pinging it
    afterwards by name would fail (NO-DNS) or silently hit a different address."""
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
            if is_ip_host(h):
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
        if is_ip_host(h):
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
            # slot 4 carries the pinged IP - overwritten with the display name later
            # in run_ping_round(), so we stash it here before that happens
            fping_result_data.append([hostname, state, timestamp, rtt, hostname, no_of_changes, '', 0])

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

def apply_match_filter(rows, pattern):
    """Pure display filter: keep only rows whose display name (rows[i][0]) or
    resolved/pinged IP (rows[i][8], when present) matches 'pattern' (an already-
    compiled regex). This is applied after build_display(), on the rows about to be
    shown - it never touches active_hosts_list, so every host keeps being pinged on
    every round regardless of what the filter currently hides. Pass pattern=None for
    no-op (filter off)."""
    if pattern is None:
        return rows
    return [r for r in rows
           if pattern.search(r[0]) or (len(r) > 8 and r[8] and pattern.search(r[8]))]

def filter_hosts(mode, original_hosts_list, host_state, tz_offset,
                 flap_window=FLAP_WINDOW_DEF, up_seen=None):
    """Host list for the given view mode - a snapshot, taken when the view switches.
    Modes 0-2 (ALL/UP/UP+FLAPPING) are also used by the CLI's [U] key and its web
    gui keyboard-shortcut equivalent; modes 3-9 are reachable only through the web
    gui's view dropdown (set_filter) - see WEB_VIEW_MODES.
    'changes' (entry[5], the CH NO column) is 0 while a host has never left the state
    it was first observed in this run - that is what ALWAYS-UP/ALWAYS-DOWN mean here;
    it is a live-session fact, not the full-log uptime% epinga.py's report computes.
    Mode 9 (EVER-UP) needs up_seen (the same set update_host_state() feeds and that
    survives state changes for the whole run, unlike host_state's single-prior-state
    'changes' counter) - a host can flip DOWN<->NO-DNS with changes>0 and still have
    never been UP, so 'changes' alone cannot stand in for 'ever up'."""
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
        elif mode == 9 and up_seen is not None and h in up_seen:
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

def apply_prefer_hostname(hosts_list, dns_ttl):
    """[P] toggle: drop raw-IP entries whose address is also covered by a hostname
    entry in the same list. The hostname gets pinged anyway, so pinging the bare IP a
    second time is redundant - a raw IP with no hostname counterpart is kept as-is.
    A hostname with several A-records (e.g. anycast siblings) covers all of them, not
    just the one resolve_name() currently has cached. dns_ttl controls how long a
    hostname's resolved addresses are cached for this check - see _cached_all_ips()."""
    hostname_ips = set()
    for h in hosts_list:
        if not is_ip_host(h):
            hostname_ips.update(_cached_all_ips(h, dns_ttl))
    return [h for h in hosts_list
            if not (is_ip_host(h) and h in hostname_ips)]

def apply_prefer_ip(hosts_list, dns_ttl):
    """Web-gui-only mirror of apply_prefer_hostname: drop a hostname entry when its
    resolved address is already covered by a raw-IP entry in the same list (the
    opposite redundancy check - IP wins, hostname is dropped). dns_ttl controls how
    long a hostname's resolved addresses are cached for this check - see
    _cached_all_ips()."""
    raw_ips = set(h for h in hosts_list if is_ip_host(h))
    if not raw_ips:
        return list(hosts_list)
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
    error_handler(f'THX for using eping.py v{VERSION}  –  www.jeitler.cc')

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
    # tell a --web_view browser mirror right away, BEFORE maybe_run_epinga() below
    # can block on its "[y/N]" input() prompt for as long as the user takes to
    # answer it - same notice the web GUI's own EXIT button already gives.
    with web_lock:
        web_state['stopped'] = True
        web_state['message'] = 'stopped'
    time.sleep(1.5)   # guarantee the browser's next poll sees it even if
                       # maybe_run_epinga() below has nothing to prompt for
    screen=curses.initscr()
    curses.endwin()
    print(f'THX for using eping.py v{VERSION}  –  www.jeitler.cc')
    if _remote_version and _remote_version > VERSION:
        print_update_notice(_remote_version)
    maybe_run_epinga(_logfile_file_name, _logging_enabled)
    sys.stdout.flush()
    # os._exit(), not sys.exit(): a running [G] GET NAMES background lookup uses a
    # ThreadPoolExecutor whose worker threads are not daemons, so sys.exit() would
    # block here until every in-flight PTR lookup finishes (or times out) instead of
    # stopping right away.
    os._exit(0)

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

        host_state[hostname] = [hostname, new_state, timestamp, rtt, old_state, changes, change_ts, tbd, resolved_ip]

        # up_seen tracks "seen UP at least once" for the whole run (used by the
        # web gui's EVER-UP view, see filter_hosts()) - not gated on learning_done:
        # with the default -up 0, learning_done is True from run 1, so gating this
        # on it would leave up_seen permanently empty and EVER-UP would never match
        # anything. The one-time learning-phase seeding read (active_hosts_list =
        # sorted(up_seen, ...) below) only happens while up_check_runs > 0 and
        # fires once, so up_seen continuing to grow afterward does not affect it.
        if 'UP' in new_state:
            up_seen.add(hostname)

        # logging
        if logging_enabled and learning_phase:
            logdata = ([timestamp] + [hostname] + [old_state.replace(" ", "")] + [new_state.replace(" ", "")] + [rtt] + [changes] + [change_ts] + [tbd] + [resolved_ip])
            with open(logfile_file_name, 'a', encoding='UTF8') as f:
                writer = csv.writer(f)
                writer.writerow(logdata)

def write_log_comment(logging_enabled, logfile_file_name, comment_text, tz_offset=0):
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
    now_str = get_date_time()
    ts = datetime.datetime.strptime(now_str, "%d/%m/%Y %H:%M:%S")
    if tz_offset:
        ts = ts + datetime.timedelta(hours=tz_offset)
    logdata = [ts, '#COMMENT#', '', '', '', '', '', '', comment_text]
    with open(logfile_file_name, 'a', encoding='UTF8') as f:
        writer = csv.writer(f)
        writer.writerow(logdata)
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
    with open(logfile_file_name, 'a', encoding='UTF8') as f:
        writer = csv.writer(f)
        writer.writerow(logdata)
    return True

def reset_logfile(logfile_file_name):
    """(Re)write the CSV log with just its header row - used by RESET LOGGING / L,
    both for clearing the current file and for creating a fresh one.

    Same header as the initial file creation at startup. Returns True on success,
    False if the file could not be (re)written (e.g. permission denied).
    """
    header = ['TIMESTAMP','HOSTNAME','PREVIOUS_STATE','CURRENT_STATE','RTT',
              'NO_OF_CHANGES','CHANGE_TIMESTAMP','TBD','IP']
    try:
        with open(logfile_file_name, 'w', encoding='UTF8') as f:
            writer = csv.writer(f)
            writer.writerow(header)
        return True
    except OSError:
        return False

def new_logfile_name(tz_offset=0):
    """Fresh 'eping-log_<timestamp>.csv' name, same format used at startup."""
    now = datetime.datetime.now() + datetime.timedelta(hours=tz_offset)
    return 'eping-log_' + now.strftime('%Y-%m-%d_%H:%M:%S') + '.csv'

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

    # fping cannot mix v4 and v6 targets in one invocation, so every retry-class
    # group above is split again by address family. In the common single-family
    # case this yields exactly one subgroup per group, same as before IPv6 support.
    subgroups = []   # (targets, retries, label, family)
    for grp_targets, grp_retries, grp_name in groups:
        by_fam = {'4': [], '6': []}
        for t in grp_targets:
            fam = ip_version_str(t)
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
    'host_list_shown'  : [],   # DOWNLOAD > SHOWN HOSTS - currently displayed hosts
    'host_list_all'    : [],   # DOWNLOAD > ALL HOSTS - the full reference list
    'hosts'            : 0,
    'hosts_up'         : 0,
    'hosts_down'       : 0,
    'hosts_shown'      : 0,   # after the [M] display filter narrows the view
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
  .fsbox{display:flex;align-items:center;gap:4px;margin-left:auto;color:var(--dim)}
  .fsbox button{padding:4px 9px}
  input[type=text]{background:var(--panel);color:var(--fg);border:1px solid var(--ctrl-line);
                   padding:4px 8px;font:inherit;border-radius:3px;min-width:200px}
  select{background:var(--panel);color:var(--fg);border:1px solid var(--ctrl-line);
         padding:4px 8px;font:inherit;border-radius:3px}
  select:hover{border-color:var(--acc)}
  select.on{border-color:var(--up);color:var(--up)}
  input[type=text]:focus{outline:none;border-color:var(--acc)}
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

  /* ---- confirmation modal (RESET LOGGING) ---- */
  .modal-overlay{position:fixed;inset:0;background:rgba(0,0,0,.55);
                 display:flex;align-items:center;justify-content:center;z-index:50}
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
<div class="layout">
  <div id="banner" class="banner" style="display:none"></div>
  <div id="resetLogModal" class="modal-overlay" style="display:none">
    <div class="modal-box">
      <h3>RESET LOGGING</h3>
      <p>Delete ALL entries in the current CSV log, or start a new file?<br>
         Keys also work: <b>Y</b>=clear, <b>N</b>=new file, <b>ESC</b>/<b>ENTER</b>=cancel.</p>
      <div class="modal-buttons">
        <button id="modalBtnClearLog" class="danger">CLEAR LOGGING (Y)</button>
        <button id="modalBtnNewLog">NEW FILE (N)</button>
        <button id="modalBtnCancelLog">CANCEL (ESC)</button>
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
    <span class="ctrls-row">
     <span id="ctrlsMain">
      <select id="selFilter" title="choose which hosts are shown and pinged - a host outside the current view is not checked until a view including it is selected again">
        <option value="0">ALL HOSTS</option>
        <option value="1">CURRENTLY-UP</option>
        <option value="3">ALWAYS-UP</option>
        <option value="9">EVER-UP</option>
        <option value="2">UP+FLAPPING</option>
        <option value="4">FLAPPING-ONLY</option>
        <option value="5">ALWAYS-DOWN</option>
        <option value="6">CURRENTLY-DOWN</option>
        <option value="7">DOWN+FLAPPING</option>
        <option value="8">NO-DNS</option>
      </select>
      <select id="sortSel" title="sort order - a flapping host is grouped as FLAP regardless of its current state">
        <option value="0">SORT: ADDRESS</option>
        <option value="1">SORT: UP/FLAP/DOWN</option>
        <option value="2">SORT: DOWN/FLAP/UP</option>
        <option value="3">SORT: FLAP/UP/DOWN</option>
        <option value="4">SORT: FLAP/DOWN/UP</option>
      </select>
      <button id="btnSetRef" title="use the hosts currently shown as the new reference list">SET REFERENCE</button>
      <button id="btnZero" title="reset CH-TIME and CH NO for all hosts">ZERO CHANGES</button>
      <button id="btnClear" class="danger" title="remove every host from the list, resets all state">CLEAR ALL</button>
      <select id="selAddrMode" title="prefer hostname: skip a raw IP already covered by a hostname | prefer ip address: skip a hostname already covered by a raw IP | ip only: resolve every hostname to its IP and ping/track it by address">
        <option value="0">PROVIDED IP/NAME</option>
        <option value="1">PREFER HOSTNAME</option>
        <option value="2">PREFER IP ADDRESS</option>
        <option value="3">SWITCH TO IP ONLY</option>
      </select>
      <button id="btnGetNames" title="reverse-DNS resolve IP hosts and rename them to their hostname">GET NAMES</button>
      <button id="btnAdvOptions" title="adjust fping/timer/timezone options live">ADV OPTIONS</button>
      <button id="btnResetLog" class="danger" title="Y=clear this file, N=start a fresh file (old kept), ESC/ENTER=cancel">RESET LOG</button>
      <select id="selDownload" title="download the full reference list, only the currently shown hosts, or the active logfile">
        <option value="" selected>DOWNLOAD</option>
        <option value="hosts_all">ALL HOSTS</option>
        <option value="hosts_shown">SHOWN HOSTS</option>
        <option value="logfile">LOGFILE</option>
      </select>
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
     </span>
     <span class="sep">&nbsp;|&nbsp;</span>
     <span class="grp">
      <input type="text" id="addInput" placeholder="IPv4/IPv6, host, IPv4 CIDR, IPv6 /128, ip1-ip2">
      <button id="btnAdd" title="add the given host(s) to the list - same input as DELETE">ADD</button>
      <button id="btnDel" title="remove the given host(s) - same input as ADD">DELETE</button>
     </span>
     <span class="sep">&nbsp;|&nbsp;</span>
     <span class="grp">
      <input type="text" id="commentInput" title="free text, logged with a timestamp to the CSV (only while logging is on)" placeholder="comment for the log">
      <button id="btnComment" title="append a timestamped comment row to the CSV log">COMMENT</button>
     </span>
     <span class="sep">&nbsp;|&nbsp;</span>
     <button id="btnUpload" title="load hosts from a text/CSV file">ADD FILE</button>
     <input type="file" id="fileInput" accept=".txt,.csv,.list,text/plain" style="display:none">
     <button id="btnGenReport" title="analyse the active logfile with epinga.py and open the report in a new tab">GENERATE REPORT</button>
    </span>
   </span>
  </div>

  <div class="stats">
    <span>HOSTS: <b id="sHosts">0</b></span>
    <span>RUNTIME: <b id="sRuntime">0.00</b><b>s</b></span>
    <span>RUNS: <b id="sRuns">0</b></span>
    <span class="u">HOSTS-UP: <b id="sUp">0</b></span>
    <span class="d">HOSTS-DOWN: <b id="sDown">0</b></span>
    <span title="hosts matching the display filter, out of the totals above"
          id="sShownWrap">HOSTS-SHOWN: <b id="sShown">0</b></span>
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

/* ---------------- commands ---------------- */
var PENDING = {up_only:'switching view ...', set_filter:'switching view ...', sort:'sorting ...', add:'adding host(s) ...',
               del:'removing host(s) ...', set_ref:'setting reference ...',
               clear:'clearing all hosts ...', zero:'resetting change counters ...',
               addr_mode:'switching address mode ...',
               get_names:'resolving names ...',
               match_filter:'applying filter ...',
               add_comment:'logging comment ...',
               reset_log:'resetting log ...',
               set_option:'applying option ...',
               reset_options:'resetting options ...',
               run_report:'generating report ...',
               exit:'stopping eping ...'};
var pending = false, lastMsgSeq = null;
var pendingAddrMode   = null;   // see selAddrMode onchange / poll() below
var pendingFilterMode = null;   // same problem/fix as pendingAddrMode, for selFilter
var pendingSortMode   = null;   // same problem/fix as pendingAddrMode, for sortSel
var lastOptions       = {};    // ADV OPTIONS - latest snapshot from the server, see poll()

function note(text, isPending){
  var m = document.getElementById('msg');
  m.textContent = text || '';
  m.className   = isPending ? 'msg pending' : 'msg';
  pending       = !!isPending;
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
var resetLogModal = document.getElementById('resetLogModal');
var loggingOn = false;   // kept in sync from every status poll, see render()
var reportWindow = null; // blank tab opened by GENERATE REPORT, filled in once ready - see poll()
function resetLogOpen(){ return resetLogModal.style.display !== 'none'; }
function openResetLog(){ resetLogModal.style.display = 'flex'; }
function closeResetLog(){ resetLogModal.style.display = 'none'; }

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
    'timestamp offset']
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

var stoppedModal    = document.getElementById('stoppedModal');
var stoppedMsg       = document.getElementById('stoppedMsg');
var stoppedDismissed = false;   // user closed it - don't keep popping it back up
function openStoppedModal(text){
  if(stoppedDismissed) return;
  stoppedMsg.textContent = text;
  stoppedModal.style.display = 'flex';
}
document.getElementById('modalBtnReload').onclick = function(){ location.reload(); };
document.getElementById('modalBtnCloseStopped').onclick = function(){
  // browsers only allow script to close a tab it opened itself (window.open()) -
  // a normally navigated-to tab silently ignores window.close(), with no way to
  // detect that it was ignored, so this is a best-effort attempt, not a guarantee.
  window.close();
  stoppedDismissed = true;
  stoppedModal.style.display = 'none';
};
document.getElementById('btnResetLog').onclick = function(){
  if(loggingOn){ openResetLog(); }
  else{ post('reset_log'); }   // logging is off - start it right away, no confirmation
};
document.getElementById('modalBtnClearLog').onclick = function(){ closeResetLog(); post('reset_log', 'y'); };
document.getElementById('modalBtnNewLog').onclick   = function(){ closeResetLog(); post('reset_log', 'new'); };
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
document.getElementById('btnGenReport').onclick = function(){
  // window.open() must happen synchronously in the click handler or browsers
  // treat it as a popup and block it - open a blank tab now, fill it in once
  // poll() sees the report become ready (or close it again on error).
  reportWindow = window.open('', '_blank');
  if(reportWindow){
    reportWindow.document.write(REPORT_WAIT_HTML);
    reportWindow.document.close();
  }
  post('run_report', '');
};
document.getElementById('selDownload').onchange = function(){
  var what  = this.value;
  var label = this.options[this.selectedIndex].text;
  this.value = '';                              // reset - a select, not a toggle
  if(!what) return;
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
    var f = document.createElement('iframe');
    f.style.display = 'none';
    f.src = 'api/download/logfile';
    document.body.appendChild(f);
    setTimeout(function(){ if(f.parentNode) document.body.removeChild(f); }, 60000);
    note('downloading ' + label + ' ...', true);
    return;
  }
  note('downloading ' + label + ' ...', true);
  fetch('api/download/' + what).then(function(r){
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
    });
  }).catch(function(){ note(label + ': download failed', false); });
};
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
   where the CLI opens an input dialog (ADD, DEL, MATCH FILTER, COMMENT) the
   matching field is focused instead, since the web field is persistent, not
   a one-shot dialog. R has no curses screen to redraw, so it forces an
   immediate status refresh. Disabled entirely while the page is read-only,
   and while a text field has focus, so normal typing and Ctrl+C keep working. */
document.addEventListener('keydown', function(e){
  if(resetLogOpen()){
    var rk = e.key.toLowerCase();
    if(rk === 'y'){ closeResetLog(); post('reset_log', 'y'); e.preventDefault(); }
    else if(rk === 'n'){ closeResetLog(); post('reset_log', 'new'); e.preventDefault(); }
    else if(rk === 'escape' || e.key === 'Enter'){ closeResetLog(); e.preventDefault(); }
    return;   // any other key is ignored, the modal stays open
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
    case 'o': cycleSortMode(); break;
    case 'a': setMode('add'); document.getElementById('addInput').focus(); break;
    case 'd': setMode('del'); document.getElementById('addInput').focus(); break;
    case 'f': document.getElementById('btnUpload').click(); break;
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

var rz;
window.addEventListener('resize', function(){
  clearTimeout(rz); rz = setTimeout(function(){ render(lastRows); }, 80); });

/* ---------------- polling ---------------- */
var pollSeq = 0, lastAppliedSeq = 0;
function poll(){
  if(stopped) return;
  var mySeq = ++pollSeq;
  fetch('api/status').then(function(r){return r.json();}).then(function(s){
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
    document.getElementById('clock').textContent = s.datetime;
    document.getElementById('sHosts').textContent   = s.hosts;
    document.getElementById('sRuntime').textContent = s.run_time;
    document.getElementById('sRuns').textContent    = s.run_counter;
    document.getElementById('sUp').textContent      = s.hosts_up;
    document.getElementById('sDown').textContent    = s.hosts_down;
    var swrap = document.getElementById('sShownWrap');
    swrap.style.display = s.match_filter ? '' : 'none';
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
    if(s.msg_seq !== lastMsgSeq){ lastMsgSeq = s.msg_seq; note(s.message || '', false); }

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
    render(s.rows);

    document.body.classList.remove('off');   // reachable again - undo a previous catch()
    if(s.stopped){ stopped = true;
      document.body.classList.add('off');
      openStoppedModal('eping.py stopped - THX for using eping.py');
    }
  }).catch(function(){
    // covers every way the process can go away without telling us first (kill -9,
    // a crash, the terminal closing) - the graceful exits (Ctrl+C, [E], EXIT button)
    // already set s.stopped above before the socket disappears, this is the backstop
    document.body.classList.add('off');
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

def run_epinga_report():
    """GENERATE REPORT (web gui): analyse the active logfile with epinga.py and
    make the resulting HTML available at /api/report.

    Runs in its own thread - epinga.py can take a while on large logfiles, and
    must never block run_web_mode()'s fping loop or the HTTP request thread.
    """
    global _report_file_path, _report_running
    with web_lock:
        logpath = web_state.get('logfile') or ''
    try:
        if not logpath or not os.path.exists(logpath) or os.path.getsize(logpath) == 0:
            raise RuntimeError('no active logfile with data yet')
        epinga_path = find_epinga_path()
        if not epinga_path:
            raise RuntimeError('epinga.py not found next to eping.py or in PATH')
        report_path = os.path.splitext(logpath)[0] + '_report.html'
        # stdin=DEVNULL: epinga.py's end-of-run "open in browser?" prompt then
        # fails fast with EOFError instead of blocking - harmless, the report
        # is already written to disk by that point. --no-version-check avoids
        # an unnecessary network call from a headless/background run.
        subprocess.run([sys.executable, epinga_path, '-f', logpath, '-q',
                        '--html', report_path, '--no-version-check'],
                       stdin=subprocess.DEVNULL,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if not os.path.exists(report_path) or os.path.getsize(report_path) == 0:
            raise RuntimeError('epinga.py did not produce a report')
        with _report_lock:
            _report_file_path = report_path
        with web_lock:
            web_state['report'] = {'status': 'ready', 'error': ''}
    except Exception as e:
        with web_lock:
            web_state['report'] = {'status': 'error', 'error': str(e)}
    finally:
        _report_running = False


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
        try:
            self.send_response(code)
            self.send_header('Content-Type', ctype)
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            if filename:
                self.send_header('Content-Disposition',
                                 'attachment; filename="' + filename + '"')
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
        elif path in ('/api/download/hosts_shown', 'api/download/hosts_shown',
                      '/api/download/hosts_all', 'api/download/hosts_all'):
            # DOWNLOAD > SHOWN HOSTS / ALL HOSTS - one host per line, same
            # plain-text format ADD FILE/upload accept.
            key = 'host_list_shown' if 'hosts_shown' in path else 'host_list_all'
            with web_lock:
                hosts = list(web_state.get(key) or [])
            body = ''.join(h + chr(10) for h in hosts)
            tag   = 'shown' if key == 'host_list_shown' else 'all'
            fname = ('eping-hosts_' + tag + '_'
                    + datetime.datetime.now().strftime('%Y-%m-%d_%H%M%S') + '.txt')
            self._respond(200, 'text/plain; charset=utf-8', body, fname)
        elif path in ('/api/download/logfile', 'api/download/logfile'):
            # DOWNLOAD > LOGFILE - the currently active CSV log, read fresh from
            # disk (not cached) so the download always reflects the latest rows.
            # Streamed in chunks (not read() into one big bytes object) - the log
            # can grow into the GB range and a single in-memory read/write nearly
            # doubles peak RSS and can fail or stall on large files.
            with web_lock:
                logpath = web_state.get('logfile') or ''
            if not logpath or not os.path.exists(logpath):
                self._respond(404, 'text/plain; charset=utf-8', 'no active logfile')
                return
            try:
                size = os.path.getsize(logpath)
                f = open(logpath, 'rb')
            except OSError:
                self._respond(404, 'text/plain; charset=utf-8', 'logfile not readable')
                return
            try:
                with f:
                    self.send_response(200)
                    self.send_header('Content-Type', 'text/csv; charset=utf-8')
                    self.send_header('Content-Length', str(size))
                    self.send_header('Cache-Control', 'no-store')
                    self.send_header('Content-Disposition',
                                     'attachment; filename="' + os.path.basename(logpath) + '"')
                    self.end_headers()
                    shutil.copyfileobj(f, self.wfile, length=1024 * 1024)
            except (BrokenPipeError, ConnectionResetError, OSError):
                pass
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
        if cmd not in ('up_only', 'set_filter', 'add', 'del', 'set_ref', 'clear', 'zero', 'sort', 'exit', 'addr_mode', 'get_names', 'match_filter', 'add_comment', 'reset_log', 'set_option', 'reset_options', 'run_report'):
            self._respond(400, 'application/json; charset=utf-8', json.dumps({'ok': False}))
            return
        if cmd == 'run_report':
            # GENERATE REPORT - runs in its own background thread (epinga.py can
            # take a while on a large logfile), not via web_commands/run_web_mode -
            # it needs no access to that loop's locals, only web_state['logfile'].
            global _report_running
            with web_lock:
                already_running = _report_running
                if not already_running:
                    _report_running = True
                    web_state['report'] = {'status': 'running', 'error': ''}
            if not already_running:
                threading.Thread(target=run_epinga_report, daemon=True).start()
            self._respond(200, 'application/json; charset=utf-8', json.dumps({'ok': True}))
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
                scan_info='', sort_mode=0, addr_mode=0,
                match_filter='', original_hosts_list=None, hosts_shown=None, options=None):
    now  = now_local(tz_offset)
    rows = web_rows(display_list)
    with web_lock:
        web_state.update({
            'datetime'        : now.strftime("%d/%m/%Y %H:%M:%S"),
            'rows'            : rows,
            'hosts'           : len(rows),
            # DOWNLOAD - SHOWN HOSTS: only what's currently displayed (view, address
            # mode and display filter already applied via display_list/rows above);
            # ALL HOSTS: the full reference list, unfiltered.
            'host_list_shown' : [r['host'] for r in rows],
            'host_list_all'   : list(original_hosts_list) if original_hosts_list is not None else [],
            'hosts_up'        : hosts_up,
            'hosts_down'      : hosts_down,
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
]
ADV_OPTION_KEYS = set(o[0] for o in ADV_OPTIONS)

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
    if args.no_check_source:
        parts.append('-ncs')
    if args.web:
        parts.append('-web')
    if args.web_view:
        parts.append('-wv')
    parts.append('-port ' + str(args.web_port))
    parts.append('-bind ' + args.web_bind)
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
        print(' no hosts yet - use ADD or ADD FILE in the web gui')
    print(' press CTRL-C to stop\n')

    with web_lock:
        web_state['wait_time'] = float(args.waittime)

    tz_offset         = int(args.time_zone_adjust)
    # ADV OPTIONS: snapshot of every startup value, for RESET TO DEFAULT
    start_option_values = adv_option_values(args, down_retries, flap_window,
                                            confirm, down_slices, full_sweep, tz_offset)
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
                    active_hosts_list = apply_addr_mode(next_list)
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
                        active_hosts_list = apply_addr_mode(target_list)
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
                        base_list = filter_hosts(filter_mode, original_hosts_list,
                                                 host_state, tz_offset, flap_window, up_seen)
                        active_hosts_list = apply_addr_mode(base_list)
                        message = 'address mode: ' + ADDR_MODE_LABELS[addr_mode]
            elif cmd == 'get_names':
                if gn_thread is not None and gn_thread.is_alive():
                    message = 'get names: already running'
                else:
                    gn_thread, gn_result, gn_candidates = get_names_start(
                        original_hosts_list, int(args.dns_ttl))
                    if gn_thread is None:
                        message = 'get names: no eligible IP host(s)'
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
                        message = 'display filter enabled'
                    except re.error as e:
                        message = 'match filter: invalid regex - ' + str(e)
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
                    added, err = add_hosts_to(new_hosts, active_hosts_list, original_hosts_list)
                    message = err if err else 'added ' + str(added) + ' host(s)'
                    if not err and added:
                        write_log_info(args.disable_logging, logfile_file_name,
                                       host_spec_cli('ADD', value), tz_offset)
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
                        if added:
                            write_log_info(args.disable_logging, logfile_file_name,
                                           'ADD -f (uploaded, ' + str(added) + ' host(s))', tz_offset)
            elif cmd == 'set_ref':
                # what is displayed right now becomes the new reference list
                dropped = [h for h in original_hosts_list if h not in set(active_hosts_list)]
                prune_dropped_hosts(dropped, host_state, up_seen, down_streak)
                original_hosts_list[:] = list(active_hosts_list)
                filter_mode = 0
                message = 'reference set to the ' + str(len(active_hosts_list)) + ' host(s) shown'
                write_log_info(args.disable_logging, logfile_file_name, '-setref', tz_offset)
            elif cmd == 'zero':
                for _entry in host_state.values():
                    _entry[5] = 0
                    _entry[6] = ''
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
                if not args.disable_logging:
                    # logging is currently OFF - START LOG turns it on right away,
                    # no confirmation needed (there is nothing to lose yet)
                    new_name = new_logfile_name(tz_offset)
                    if reset_logfile(new_name):
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
                    choice = value.strip().lower()
                    if choice == 'y':
                        if reset_logfile(logfile_file_name):
                            message = 'logging reset - ' + logfile_file_name + ' cleared'
                            write_log_info(args.disable_logging, logfile_file_name,
                                           build_cli_snapshot(args, backoff, timeout, retries,
                                                              down_retries, flap_window, confirm,
                                                              down_slices, full_sweep, tz_offset),
                                           tz_offset)
                        else:
                            message = 'failed to reset log file'
                    elif choice == 'new':
                        new_name = new_logfile_name(tz_offset)
                        if reset_logfile(new_name):
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
                print(f'THX for using eping.py v{VERSION}  –  www.jeitler.cc')
                if _remote_version and _remote_version > VERSION:
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
            quick    = build_display(active_hosts_list, host_state, sort_mode,
                                     tz_offset, flap_window)
            quick_up = sum(1 for e in quick if 'UP' in e[1])
            quick_total = len(quick)
            if match_filter_re is not None:
                quick = apply_match_filter(quick, match_filter_re)
            with web_lock:
                web_state['message']      = message
                web_state['msg_seq']      = web_state.get('msg_seq', 0) + 1
                quick_rows                = web_rows(quick)
                web_state['rows']         = quick_rows
                # DOWNLOAD - SHOWN/ALL HOSTS, see web_publish()
                web_state['host_list_shown'] = [r['host'] for r in quick_rows]
                web_state['host_list_all']   = list(original_hosts_list)
                web_state['hosts']        = len(quick)
                web_state['hosts_up']     = quick_up
                web_state['hosts_down']   = quick_total - quick_up
                web_state['hosts_shown']  = len(quick)
                web_state['filter_mode']  = filter_mode
                web_state['filter_label'] = WEB_VIEW_MODES[filter_mode][0]
                web_state['addr_mode'] = addr_mode
                web_state['sort_mode']    = sort_mode
                web_state['match_filter'] = match_filter_text
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
                active_hosts_list = sorted(up_seen, key=lambda h: (
                    int(ipaddress.ip_address(h)) if is_ip_host(h) else float('inf')))
                active_hosts_list = apply_addr_mode(active_hosts_list)
                if args.set_reference:
                    # -setref: same as the 'set_ref' web command, once learning ends
                    prune_dropped_hosts([h for h in original_hosts_list if h not in set(active_hosts_list)],
                                        host_state, up_seen, down_streak)
                    original_hosts_list = list(active_hosts_list)
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
        # HOSTS/HOSTS-UP/HOSTS-DOWN are the totals for the whole current view - a
        # [M] display filter narrows what's SHOWN, not what's actually being pinged,
        # so it must not make these look like only 2 hosts exist. hosts_count_shown
        # is the post-filter count, reported separately (HOSTS-SHOWN in the web GUI).
        hosts_count_up   = sum(1 for e in display_list if 'UP' in e[1])
        hosts_count_down = len(display_list) - hosts_count_up
        if match_filter_re is not None:
            display_list = apply_match_filter(display_list, match_filter_re)
        hosts_count_shown = len(display_list)
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
                    tz_offset, message, scan_info, sort_mode, addr_mode,
                    match_filter_text, original_hosts_list, hosts_shown=hosts_count_shown,
                    options=adv_option_values(args, down_retries, flap_window, confirm,
                                              down_slices, full_sweep, tz_offset))

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
    parser.add_argument('-cl', '--clean', action="store_true", dest='delete_files', help="delete all files start with \'eping-l*\'' ")
    parser.add_argument('-up', '--up', default='0', dest='up_hosts_check', help="display and check only host the are up x runs" )
    parser.add_argument('-setref', '--set_reference', action="store_true", dest='set_reference', help="with -up: once the learning phase ends, use the hosts found UP as the new reference list (same as pressing [S]/SET REFERENCE)" )
    parser.add_argument('-p', '--threads', default='auto', dest='num_of_threads', help="fping processes per retry group, range 0-" + str(THREADS_MANUAL_MAX) + " (default: auto = " + str(PROCS_PER_GROUP) + "; 0 is an alias for auto; higher values cost accuracy)" )
    parser.add_argument('-tz', '--timezone', default='0', dest='time_zone_adjust', help="default is 0 range from -24 to 24" )
    parser.add_argument('-w', '--wait', default ='0.5', dest='waittime', help="wait time between rounds in seconds, range 0-" + str(WAITTIME_MAX) )   
    parser.add_argument('-du', '--disable_versioncheck', action="store_true", help="disable online versioncheck")
    parser.add_argument('-ra', '--rate', default=str(DEFAULT_RATE_PPS), dest='rate_pps', help="ICMP packets per second, range " + str(MIN_RATE_PPS) + "-" + str(MAX_RATE_PPS) + " (default: " + str(DEFAULT_RATE_PPS) + "; -i cannot go below 1ms, so one process per group tops out near 1000 - higher values have no effect. Use -i 0 to remove the limit entirely)")
    parser.add_argument('-dns', '--dns_ttl', default=str(DNS_CACHE_TTL), dest='dns_ttl', help="seconds a resolved hostname is cached, range 0-" + str(DNS_TTL_MAX) + " (default: " + str(DNS_CACHE_TTL) + ", 0 = let fping resolve every run)")
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
    parser.add_argument('-ncs', '--no_check_source', action="store_true", dest='no_check_source', help="do not pass --check-source to fping (only needed for hosts replying from a different address)")
    parser.add_argument('-web', '--web', action="store_true", dest='web', help="start the web gui instead of the terminal (CLI) output")
    parser.add_argument('-wv', '--web_view', action="store_true", dest='web_view', help="CLI mode plus a read-only web view on --port (browser shows the same data, no controls)")
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
    args = parser.parse_args()
    backoff = args.backoff
    timeout = args.timeout
    retries = args.retries
    interval = args.interval
    use_check_source = not args.no_check_source
    dns_family = '4' if args.force_ipv4 else ('6' if args.force_ipv6 else 'auto')

    # check online current version
    if not args.disable_versioncheck: 
           url = "https://raw.githubusercontent.com/ewaldj/eping/refs/heads/main/eversions"
           toolname = "eping.py"
           remote_version = check_version_online(url, toolname)
    else: 
        remote_version = version

    _remote_version = remote_version

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

    # -setref only makes sense together with a learning phase
    try:
        up_hosts_check_int = int(args.up_hosts_check)
    except ValueError:
        error_handler("ERROR: --up: must be a whole number")
    if args.set_reference and up_hosts_check_int <= 0:
        error_handler("ERROR: --set_reference requires --up N (N > 0)")

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
                "# opt: -web                         # start the web gui instead of the CLI\n",
                "# opt: -wv                          # CLI mode plus a read-only web view\n",
                "# opt: -port 8080                   # http port for -web / -wv\n",
                "# opt: -bind 0.0.0.0                # bind address for -web / -wv\n",
                ]
        try:
            create_file_if_not_exists(default_hostfile,data)
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
            for entry in parse_hosts_from_text(hostfile_text, file_stats):
                if is_ip_host(entry):
                    hosts_list_ipv4.append(entry)
                else:
                    hosts_list_fqdn.append(entry)
            if file_stats.get('skipped'):
                hostfile_skipped.extend(hostfile_path + ': ' + s for s in file_stats['skipped'])
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
        header = ['TIMESTAMP','HOSTNAME','PREVIOUS_STATE','CURRENT_STATE','RTT','NO_OF_CHANGES','CHANGE_TIMESTAMP','TBD','IP']
        try:
            with open(logfile_file_name, 'w', encoding='UTF8') as f:
                writer = csv.writer(f)
                writer.writerow(header)
        except:
            error_handler('ERROR: failed to create logfile: ' + logfile_file_name )
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
        _update_available = bool(remote_version) and (remote_version > version)
        with web_lock:
            web_state['version'] = version
        def _web_sigint(sig, frame):
            # same as the web GUI's own EXIT button - tell the browser right away
            with web_lock:
                web_state['stopped'] = True
                web_state['message'] = 'stopped'
            time.sleep(1.5)   # guarantee the browser's next poll sees the status
            print(f'\nTHX for using eping.py v{VERSION}  –  www.jeitler.cc')
            if _remote_version and _remote_version > VERSION:
                print_update_notice(_remote_version)
            # no maybe_run_epinga() prompt in web mode - see the 'exit' cmd handler
            sys.stdout.flush()
            # os._exit(), not sys.exit(): see sigint_handler() for why.
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
        global run_counter
        while not stop_event.is_set():
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
            run_counter += 1
            remaining = float(args.waittime) - (datetime.datetime.now() - t0).total_seconds()
            if remaining > 0:
                stop_event.wait(remaining)

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
    prefer_hostname = bool(args.prefer_hostname)
    ip_only_mode   = False
    ip_only_map    = {}
    sort_mode      = 0
    display_list   = []
    hosts_count_up = 0
    hosts_count_down = 0
    run_time       = '0.00'
    phase          = {}
    used_scan      = ''
    learning_phase = True
    update_available_cli = bool(remote_version) and (remote_version > version)
    gn_thread      = None   # [G] background PTR lookup - see get_names_start/finish
    gn_result      = None
    gn_candidates  = []
    match_filter_re   = None   # [M] display-only regex filter - active_hosts_list unaffected
    match_filter_text = ''

    # -gn / -ph: applied once, before the first ping round - by then original/active
    # host list, host_state, up_seen and down_streak all exist in this scope
    if args.get_names:
        apply_get_names(original_hosts_list, active_hosts_list, host_state,
                        up_seen, down_streak, int(args.dns_ttl))
    if args.ip_only:
        ip_only_map, _ = apply_ip_only_on(original_hosts_list, active_hosts_list,
                                          host_state, up_seen, down_streak, int(args.dns_ttl))
        ip_only_mode = True
    active_hosts_list = (apply_prefer_hostname(active_hosts_list, int(args.dns_ttl))
                         if prefer_hostname else active_hosts_list)

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
        # mirror the same fix as run_web_mode(): HOSTS-UP/DOWN in the web view should
        # be the totals for the current view, not narrowed by the [M] display filter
        # the way the curses screen's own hosts_count_up/down are (left untouched here).
        total_list = build_display(active_hosts_list, host_state, sort_mode,
                                   tz_offset, flap_window)
        total_up   = sum(1 for e in total_list if 'UP' in e[1])
        total_down = len(total_list) - total_up
        web_publish(display_list, run_counter, run_time, total_up, total_down,
                    filter_mode, learning_phase, run_counter, up_check_runs,
                    args.disable_logging, logfile_file_name, update_available_cli,
                    tz_offset, msg, used_scan, sort_mode,
                    (3 if ip_only_mode else (1 if prefer_hostname else 0)),
                    match_filter_text, original_hosts_list, hosts_shown=len(display_list))


    def rebuild_display():
        """Recompute the visible list straight from host_state - no ping needed.

        UP-ONLY, SET REFERENCE, DEL HOST and ZERO CHANGES are pure display operations,
        so they can take effect at once instead of after the next scan round.
        """
        global display_list, hosts_count_up, hosts_count_down
        display_list = build_display(active_hosts_list, host_state, sort_mode,
                                     tz_offset, flap_window)
        if match_filter_re is not None:
            display_list = apply_match_filter(display_list, match_filter_re)
        hosts_count_up   = sum(1 for e in display_list if 'UP' in e[1])
        hosts_count_down = len(display_list) - hosts_count_up

    def draw_screen():
        """Paint the whole screen from the data of the last completed round.

        Decoupled from the scan on purpose: it can be called any time, also while
        fping is still running, so a resize or a filter change shows immediately.
        """
        rows, cols = screen.getmaxyx()
        if remote_version and remote_version > version:
            screen_print_center_top('Update available - please visit https://www.jeitler.cc', 3)
        elif gn_thread is not None and gn_thread.is_alive():
            screen_print_center_top(
                'GET NAMES running in background (%d host(s))...' % len(gn_candidates), 2)
        elif match_filter_re is not None:
            screen_print_center_top(
                "MATCH FILTER '%s' active (%d of %d hosts shown, all still pinged)"
                % (match_filter_text, len(display_list), len(active_hosts_list)), 2)
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
        screen_output(rows - 1, 14, 'RUNTIME: ' + str(run_time) + 's', 1, 1)
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
        # order: U, M, A, D, F, O, T, S, Z, C, P, I, G, R, E - grouped by how often
        # each is used, rather than the historical add-order
        l_full  = ' [L]=RESET LOGGING ' if args.disable_logging else ' [L]=START LOG '
        l_short = ' [L]=RESET LOG '     if args.disable_logging else ' [L]=START LOG '
        l_tiny  = ' [L]RSTLOG '         if args.disable_logging else ' [L]STARTLOG '
        keys_full  = [' [U]=' + fm[0] + ' ', ' [M]=MATCH FILTER ', ' [A]=ADD ', ' [D]=DELETE ', ' [F]=ADD FILE ',
                      ' [O]=SORT ' + sm[0] + ' ', ' [T]=COMMENT ', ' [S]=SET REFERENCE ', ' [Z]=ZERO CHANGES ',
                      ' [C]=CLEAR ALL ', ' [P]=PREFER HOST ', ' [I]=IP ONLY ', ' [G]=GET NAMES ',
                      ' [R]=SCREEN REFRESH ', l_full, ' [E]=EXIT ']
        keys_short = [' [U]=' + fm[1] + ' ', ' [M]=FILTER ', ' [A]=ADD ', ' [D]=DEL ', ' [F]=FILE ',
                      ' [O]=' + sm[1] + ' ', ' [T]=COMMENT ', ' [S]=SET REF ', ' [Z]=ZERO ',
                      ' [C]=CLEAR ', ' [P]=PREFER ', ' [I]=IP ONLY ', ' [G]=NAMES ',
                      ' [R]=REFRESH ', l_short, ' [E]=EXIT ']
        keys_tiny  = [' [U]' + fm[2] + ' ', ' [M]FLT ', ' [A]ADD ', ' [D]DEL ', ' [F]FILE ',
                      ' [O]' + sm[1] + ' ', ' [T]CMT ', ' [S]REF ', ' [Z]ZERO ',
                      ' [C]CLR ', ' [P]PREF ', ' [I]IP ', ' [G]NAME ',
                      ' [R]RFR ', l_tiny, ' [E]EXIT ']
        keys_micro = [' U ', ' M ', ' A ', ' D ', ' F ', ' O ', ' T ', ' S ', ' Z ', ' C ', ' P ', ' I ', ' G ', ' R ', ' L ', ' E ']
        for keys in (keys_full, keys_short, keys_tiny, keys_micro):
            if sum(len(k) for k in keys) + 2 <= cols:
                break
        key_col = 2
        for idx, label in enumerate(keys):
            highlight = ((idx == 0 and filter_mode != 0) or (idx == 1 and match_filter_re is not None)
                        or (idx == 5 and sort_mode != 0) or (idx == 10 and prefer_hostname)
                        or (idx == 11 and ip_only_mode))
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
            elif k in (ord('p'), ord('P')):
                cmd = 'PREFER_HOSTNAME'
            elif k in (ord('i'), ord('I')):
                cmd = 'IP_ONLY'
            elif k in (ord('g'), ord('G')):
                cmd = 'GET_NAMES'
            elif k in (ord('m'), ord('M')):
                cmd = 'MATCH_FILTER'
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
            # the currently displayed host list becomes the new reference list
            dropped = [h for h in original_hosts_list if h not in set(active_hosts_list)]
            prune_dropped_hosts(dropped, host_state, up_seen, down_streak)
            original_hosts_list = list(active_hosts_list)
            filter_mode = 0            # active == reference, so no filter is active
            screen.clear()
            write_log_info(args.disable_logging, logfile_file_name, '-setref', tz_offset)
        elif cmd == 'CLEAR':
            active_hosts_list   = []
            original_hosts_list = []
            host_state.clear()
            up_seen.clear()
            down_streak.clear()
            _dns_cache.clear()
            _addr_redundancy_cache.clear()
            filter_mode = 0
            screen.clear()
            write_log_info(args.disable_logging, logfile_file_name, 'CLEAR', tz_offset)
        elif cmd == 'UP_ONLY':
            next_mode = (filter_mode + 1) % len(FILTER_MODES)
            next_list = filter_hosts(next_mode, original_hosts_list, host_state,
                                     tz_offset, flap_window, up_seen)
            if next_list or next_mode == 0:
                filter_mode       = next_mode
                active_hosts_list = (apply_prefer_hostname(next_list, int(args.dns_ttl))
                                     if prefer_hostname else next_list)
                screen.clear()
                write_log_info(args.disable_logging, logfile_file_name,
                               'FILTER ' + FILTER_MODES[filter_mode][0], tz_offset)
            else:
                notice('NO HOSTS MATCH ' + FILTER_MODES[next_mode][0], 3)
        elif cmd == 'PREFER_HOSTNAME':
            prefer_hostname = not prefer_hostname
            base_list = filter_hosts(filter_mode, original_hosts_list, host_state,
                                     tz_offset, flap_window, up_seen)
            active_hosts_list = (apply_prefer_hostname(base_list, int(args.dns_ttl))
                                 if prefer_hostname else base_list)
            notice('PREFER HOSTNAME: ' + ('ON' if prefer_hostname else 'OFF'), 2)
        elif cmd == 'IP_ONLY':
            if not ip_only_mode:
                ip_only_map, io_msg = apply_ip_only_on(
                    original_hosts_list, active_hosts_list, host_state,
                    up_seen, down_streak, int(args.dns_ttl))
                ip_only_mode = True
            else:
                io_msg = apply_ip_only_off(ip_only_map, original_hosts_list,
                                           active_hosts_list, host_state,
                                           up_seen, down_streak)
                ip_only_map = {}
                ip_only_mode = False
            notice(io_msg.upper(), 2)
        elif cmd == 'GET_NAMES':
            if gn_thread is not None and gn_thread.is_alive():
                notice('GET NAMES: ALREADY RUNNING', 3)
            else:
                gn_thread, gn_result, gn_candidates = get_names_start(
                    original_hosts_list, int(args.dns_ttl))
                if gn_thread is None:
                    notice('GET NAMES: NO ELIGIBLE IP HOST(S)', 2, 3)
                else:
                    notice('GET NAMES: RUNNING IN BACKGROUND (%d HOST(S))'
                          % len(gn_candidates), 2)
                    write_log_info(args.disable_logging, logfile_file_name, '-gn', tz_offset)
        elif cmd == 'MATCH_FILTER':
            value = input_dialog(' MATCH FILTER ',
                                 ' regex to match hostname/IP, case-insensitive - empty to disable:')
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
                    notice('MATCH FILTER: ON (%d OF %d SHOWN)'
                          % (len(display_list), len(active_hosts_list)), 2)
            elif match_filter_re is not None:
                match_filter_re, match_filter_text = None, ''
                rebuild_display()
                draw_screen()
                screen.refresh()
                notice('MATCH FILTER: OFF', 2)
        elif cmd == 'ORDER':
            sort_mode = (sort_mode + 1) % len(SORT_MODES)
            screen.clear()
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
                    added, err = add_hosts_to(new_hosts, active_hosts_list, original_hosts_list)
                    if err:
                        notice(err.upper(), 3)
                    elif added:
                        write_log_info(args.disable_logging, logfile_file_name,
                                       host_spec_cli('ADD', value), tz_offset)
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
                        if added:
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
                # logging is currently OFF - [L]/START LOG turns it on right away,
                # no confirmation needed (there is nothing to lose yet)
                new_name = new_logfile_name(tz_offset)
                if reset_logfile(new_name):
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
                    new_name = new_logfile_name(tz_offset)
                    if reset_logfile(new_name):
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
            print(f'THX for using eping.py v{VERSION}  –  www.jeitler.cc')
            if remote_version and remote_version > version:
                print_update_notice(remote_version)
            maybe_run_epinga(logfile_file_name, args.disable_logging)
            sys.stdout.flush()
            # os._exit(), not sys.exit(): see sigint_handler() for why.
            os._exit(0)

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
                    int(ipaddress.ip_address(h)) if is_ip_host(h) else float('inf')
                ))
                active_hosts_list = (apply_prefer_hostname(active_hosts_list, int(args.dns_ttl))
                                     if prefer_hostname else active_hosts_list)
                if args.set_reference:
                    # -setref: same as pressing [S]/SET REFERENCE once learning ends
                    prune_dropped_hosts([h for h in original_hosts_list if h not in set(active_hosts_list)],
                                        host_state, up_seen, down_streak)
                    original_hosts_list = list(active_hosts_list)
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