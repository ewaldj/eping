#!/usr/bin/env python3

# - - - - - - - - - - - - - - - - - - - - - - - -
# epinga.py by ewald@jeitler.cc 2024 https://www.jeitler.cc
# Large-file-capable analyser for eping.py CSV logfiles
# Streams the CSV row-by-row – RAM usage stays flat even for GB-sized logs
# - - - - - - - - - - - - - - - - - - - - - - - -

version = '1.99'

import re
import os
import csv
import sys
import json
import signal
import argparse
import datetime
import ipaddress
import html as html_lib

# ── optional modules ──────────────────────────────────────────────────────────
try:
    import urllib.request, socket as _socket
except Exception:
    urllib = None
    _socket = None

# ── colour helpers ────────────────────────────────────────────────────────────
CRED    = '\033[91m'
CGREEN  = '\033[92m'
CORANGE = '\033[33m'
CCYAN   = '\033[96m'
CBOLD   = '\033[1m'
CDIM    = '\033[2m'
CEND    = '\033[0m'

W = 100   # output width

def col(text, colour): return colour + text + CEND
def hr(ch='─'): print(ch * W)
def header_line(title, ch='─'):
    t = f' {title} '
    print(t.center(W, ch))

# ── signal / error helpers ────────────────────────────────────────────────────
def sigint_handler(sig, frame):
    print(f'\n{col("Interrupted.", CORANGE)}  epinga.py v{version}  – www.jeitler.cc\n')
    sys.exit(0)

def die(msg):
    print(f'\n {col("ERROR:", CRED)} {msg}\n')
    sys.exit(1)

# ── regex ─────────────────────────────────────────────────────────────────────
ip_re   = re.compile(r'^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}'
                     r'([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$')
fqdn_re = re.compile(r'(?=^.{4,253}$)(^((?!-)[a-zA-Z0-9-äöüÄÖÜ]{1,63}(?<!-)'
                     r'([\.]?))+[a-zA-ZäöüÄÖÜ]{0,63}$)')

def sort_hosts(hosts):
    ips, fqdns = [], []
    for h in hosts:
        (ips if ip_re.match(h) else fqdns).append(h)
    ips.sort(key=lambda x: int(ipaddress.ip_address(x)))
    fqdns.sort()
    return ips + fqdns

# ── version check ─────────────────────────────────────────────────────────────
def check_version_online(url, tool_name, timeout=2.0):
    if not urllib or not _socket:
        return None
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            for line in r.read().decode().splitlines():
                if line.startswith(tool_name + ' '):
                    return line.split()[1]
    except Exception:
        pass
    return None

# ── timestamp parsing ─────────────────────────────────────────────────────────
TS_FMT = '%Y-%m-%d %H:%M:%S'

def parse_ts(s):
    try:
        return datetime.datetime.strptime(s.strip(), TS_FMT)
    except ValueError:
        return None

# ── byte-tracking file wrapper (tell() fails with next(), so we count ourselves) ──
class _ByteTracker:
    """Wraps a text file and counts bytes via readline() so tell() is never needed."""
    def __init__(self, fh, encoding='utf-8'):
        self._fh       = fh
        self._enc      = encoding
        self.bytes_read = 0

    def readline(self):
        line = self._fh.readline()
        self.bytes_read += len(line.encode(self._enc, errors='replace'))
        return line

    def __iter__(self):
        return self

    def __next__(self):
        line = self.readline()
        if line == '':
            raise StopIteration
        return line

    def __getattr__(self, name):        # proxy everything else (fieldnames etc.)
        return getattr(self._fh, name)


# ── progress bar (bytes) ──────────────────────────────────────────────────────
def fmt_bytes(n):
    for unit in ('B', 'KB', 'MB', 'GB'):
        if n < 1024:
            return f'{n:.1f} {unit}'
        n /= 1024
    return f'{n:.1f} TB'

class Progress:
    def __init__(self, total_bytes, width=40):
        self.total   = total_bytes
        self.width   = width
        self.last_pct = -1

    def update(self, done_bytes):
        if self.total <= 0:
            return
        pct = int(done_bytes * 100 / self.total)
        if pct == self.last_pct:
            return
        self.last_pct = pct
        filled = int(self.width * pct / 100)
        bar = '█' * filled + '░' * (self.width - filled)
        print(f'\r  [{bar}] {pct:3d}%  {fmt_bytes(done_bytes)}/{fmt_bytes(self.total)} ',
              end='', flush=True)

    def done(self):
        if self.total > 0:
            print()   # newline after progress bar

# ── per-host data class ───────────────────────────────────────────────────────
class HostStats:
    __slots__ = ('first_ts', 'last_ts', 'current_state', 'prev_ts',
                 'rtt_min', 'rtt_max', 'rtt_sum', 'rtt_cnt',
                 'time_up', 'time_down', 'time_nodns',
                 'changes', 'no_of_changes', 'ip')

    def __init__(self, ts, state, ip=''):
        self.first_ts      = ts
        self.last_ts       = ts
        self.prev_ts       = ts
        self.current_state = state
        self.rtt_min       = float('inf')
        self.rtt_max       = float('-inf')
        self.rtt_sum       = 0.0
        self.rtt_cnt       = 0
        self.time_up       = datetime.timedelta(0)
        self.time_down     = datetime.timedelta(0)
        self.time_nodns    = datetime.timedelta(0)
        self.changes       = []          # [(ts, prev_state, new_state)]
        self.no_of_changes = 0
        self.ip             = ip or ''   # last known pinged IP (from the CSV's IP column)

    # ── feed one CSV row ──────────────────────────────────────────────────────
    def feed(self, ts, prev_state, cur_state, rtt_raw, no_of_changes_raw, ip_raw=''):
        # RTT
        try:
            rtt = float(rtt_raw)
            if rtt < self.rtt_min: self.rtt_min = rtt
            if rtt > self.rtt_max: self.rtt_max = rtt
            self.rtt_sum += rtt
            self.rtt_cnt += 1
        except (ValueError, TypeError):
            pass

        # state change
        if prev_state != cur_state:
            delta = ts - self.prev_ts if ts and self.prev_ts else datetime.timedelta(0)
            self._add_time(prev_state, delta)
            self.changes.append((ts, prev_state, cur_state))
            self.prev_ts       = ts
            self.current_state = cur_state

        self.last_ts = ts

        try:
            self.no_of_changes = int(no_of_changes_raw)
        except (ValueError, TypeError):
            pass

        if ip_raw:
            self.ip = ip_raw

    def _add_time(self, state, delta):
        if state == 'UP':
            self.time_up    += delta
        elif state == 'DOWN':
            self.time_down  += delta
        elif state == 'NO-DNS':
            self.time_nodns += delta

    # ── finalise: add last open interval ─────────────────────────────────────
    def finalise(self):
        if self.last_ts and self.prev_ts:
            delta = self.last_ts - self.prev_ts
            self._add_time(self.current_state, delta)

    # ── helpers ───────────────────────────────────────────────────────────────
    @property
    def has_rtt(self):
        return self.rtt_cnt > 0

    @property
    def rtt_avg(self):
        return round(self.rtt_sum / self.rtt_cnt, 2) if self.rtt_cnt else 0

    @property
    def total_span(self):
        if self.first_ts and self.last_ts:
            return self.last_ts - self.first_ts
        return datetime.timedelta(0)

    @property
    def uptime_pct(self):
        span = self.total_span.total_seconds()
        if span <= 0:
            return 0.0
        return round(self.time_up.total_seconds() * 100 / span, 2)

    @property
    def real_changes(self):
        # Actual UP/DOWN/NO-DNS transitions observed in this log, derived from
        # PREVIOUS_STATE/CURRENT_STATE per row. Independent of the device-side
        # NO_OF_CHANGES counter, which eping.py's 'zero' command can reset
        # mid-log, making the raw counter unreliable for classification.
        return len(self.changes)


# ── stream-parse the CSV ──────────────────────────────────────────────────────
def analyse(filename, filter_hosts=None, ts_start=None, ts_end=None, quiet=False):
    try:
        file_size = os.path.getsize(filename)
    except OSError as e:
        die(str(e))

    hosts      = {}   # hostname -> HostStats
    host_order = []   # insertion order
    comments   = []   # [{'ts': datetime, 'text': str}, ...] - from '#COMMENT#' sentinel rows
    rows_read  = 0

    progress = Progress(file_size) if not quiet else None

    try:
        fh = open(filename, 'r', encoding='UTF-8', newline='')
    except OSError as e:
        die(str(e))

    with fh:
        tracker = _ByteTracker(fh)
        reader  = csv.DictReader(tracker)

        # validate header
        required = {'HOSTNAME', 'TIMESTAMP', 'PREVIOUS_STATE', 'CURRENT_STATE',
                    'RTT', 'NO_OF_CHANGES'}
        if reader.fieldnames is None or not required.issubset(set(reader.fieldnames)):
            die(f'"{filename}" does not look like an eping logfile (wrong header).')

        for row in reader:
            rows_read += 1

            hostname = row['HOSTNAME']

            if hostname == '#COMMENT#':
                ts = parse_ts(row['TIMESTAMP'])
                if ts is None:
                    continue
                if ts_start and ts < ts_start:
                    continue
                if ts_end   and ts > ts_end:
                    continue
                text = row.get('IP', '').strip()
                if text:
                    comments.append({'ts': ts, 'text': text})
                continue

            if filter_hosts and hostname not in filter_hosts:
                continue

            ts = parse_ts(row['TIMESTAMP'])
            if ts is None:
                continue
            if ts_start and ts < ts_start:
                continue
            if ts_end   and ts > ts_end:
                continue

            prev_state = row['PREVIOUS_STATE']
            cur_state  = row['CURRENT_STATE']
            rtt_raw    = row['RTT']
            noc        = row['NO_OF_CHANGES']
            ip_raw     = row.get('IP', '')   # absent on older logfiles - fine, defaults to ''

            if hostname not in hosts:
                hosts[hostname] = HostStats(ts, cur_state, ip_raw)
                host_order.append(hostname)
            else:
                hosts[hostname].feed(ts, prev_state, cur_state, rtt_raw, noc, ip_raw)

            if progress and rows_read % 5000 == 0:
                progress.update(tracker.bytes_read)

    if progress:
        progress.update(tracker.bytes_read)
        progress.done()

    for h in hosts.values():
        h.finalise()

    comments.sort(key=lambda c: c['ts'])
    return hosts, host_order, rows_read, comments


# ── state colour ──────────────────────────────────────────────────────────────
def state_col(state):
    if state == 'UP':      return col(state.center(6), CGREEN)
    if state == 'DOWN':    return col(state.center(6), CRED)
    if state == 'NO-DNS':  return col(state.center(6), CRED)
    return state.center(6)

def fmt_td(td):
    total = int(td.total_seconds())
    h, rem = divmod(total, 3600)
    m, s   = divmod(rem, 60)
    if h:   return f'{h}h {m:02d}m {s:02d}s'
    if m:   return f'{m}m {s:02d}s'
    return  f'{s}s'

# ── print per-host detail ─────────────────────────────────────────────────────
def print_host(hostname, s, show_changes, comments=None):
    header_line(hostname)

    if show_changes and (s.changes or comments):
        # comments are a global timeline - only show ones logged while this host
        # was actually being observed (its first_ts..last_ts window), merged
        # chronologically with its own UP/DOWN transitions (same as the HTML report)
        relevant_comments = [
            c for c in (comments or [])
            if (not s.first_ts or c['ts'] >= s.first_ts) and (not s.last_ts or c['ts'] <= s.last_ts)
        ]
        timeline = (
            [('change', ts, frm, to) for ts, frm, to in s.changes]
            + [('comment', c['ts'], c['text'], None) for c in relevant_comments]
        )
        timeline.sort(key=lambda e: e[1] or datetime.datetime.min)
        for kind, ts, a, b in timeline:
            ts_str = ts.strftime(TS_FMT) if ts else '?'
            if kind == 'comment':
                print(f'  {ts_str}  {col("COMMENT: " + a, CORANGE)}')
            else:
                arrow = f'{state_col(a)} → {state_col(b)}'
                print(f'  {ts_str}  {arrow}')
        print()

    # RTT line
    if s.has_rtt:
        rtt_line = (f'  RTT  min: {col(str(round(s.rtt_min,2))+" ms", CCYAN)}'
                    f'  max: {col(str(round(s.rtt_max,2))+" ms", CCYAN)}'
                    f'  avg: {col(str(s.rtt_avg)+" ms", CCYAN)}'
                    f'  samples: {s.rtt_cnt}')
        print(rtt_line)
    else:
        print(f'  RTT  {col("no data", CDIM)}')

    # uptime line
    span_s    = s.total_span.total_seconds()
    up_pct    = s.uptime_pct
    pct_colour = CGREEN if up_pct >= 99 else (CORANGE if up_pct >= 90 else CRED)
    up_bar_len = 40
    filled     = int(up_bar_len * up_pct / 100) if span_s > 0 else 0
    up_bar     = col('█' * filled, CGREEN) + col('░' * (up_bar_len - filled), CRED)

    print(f'  Uptime  [{up_bar}] {col(f"{up_pct:.1f} %", pct_colour)}'
          f'  ↑ {fmt_td(s.time_up)}  ↓ {fmt_td(s.time_down + s.time_nodns)}'
          f'  span: {fmt_td(s.total_span)}')

    final_state = s.current_state
    print(f'  State changes: {s.real_changes}'
          f'  │  Final state: {state_col(final_state)}'
          f'  │  Log: {s.first_ts.strftime(TS_FMT) if s.first_ts else "?"}'
          f' → {s.last_ts.strftime(TS_FMT)  if s.last_ts  else "?"}')
    print()


# ── grid printer for host lists ───────────────────────────────────────────────
def print_host_grid(lst, indent=2, pad=2):
    """Print a list of hostnames in a tidy multi-column grid.
    col_width is derived from the longest hostname so names never break mid-word.
    cell_w = indent + col_width per cell (indent is prepended to every cell)."""
    if not lst:
        print(' ' * indent + col('–', CDIM))
        return
    try:
        term_w = os.get_terminal_size().columns
    except OSError:
        term_w = W
    col_width = max(len(h) for h in lst) + pad
    cell_w    = indent + col_width          # every cell carries its own indent
    cols      = max(1, term_w // cell_w)
    for i, h in enumerate(lst):
        end_char = '\n' if (i + 1) % cols == 0 or i == len(lst) - 1 else ''
        print(' ' * indent + h.ljust(col_width), end=end_char)
    if len(lst) % cols != 0:
        print()   # ensure final newline


# ── summary table ─────────────────────────────────────────────────────────────
def print_summary(hosts, host_order, sort_by='name'):
    # ── categorise ────────────────────────────────────────────────────────────
    always_up, always_down, always_nodns, flapping = [], [], [], []
    for h in host_order:
        s = hosts[h]
        if s.real_changes == 0:
            if   s.current_state == 'UP':     always_up.append(h)
            elif s.current_state == 'DOWN':   always_down.append(h)
            elif s.current_state == 'NO-DNS': always_nodns.append(h)
        else:
            flapping.append(h)

    # ── sort host_order for the detail table ──────────────────────────────────
    if sort_by == 'flapping':
        ordered = sorted(host_order, key=lambda h: hosts[h].real_changes, reverse=True)
    elif sort_by == 'uptime':
        ordered = sorted(host_order, key=lambda h: hosts[h].uptime_pct)
    elif sort_by == 'rtt':
        ordered = sorted(host_order, key=lambda h: hosts[h].rtt_avg)
    else:
        ordered = host_order   # insertion / log order

    # ── table ─────────────────────────────────────────────────────────────────
    print()
    hr('═')
    sort_note = f'  sorted by: {sort_by}' if sort_by != 'name' else ''
    header_line(f'SUMMARY{sort_note}', '═')
    hr('═')

    col_h  = 32
    col_st =  8
    col_up = 10
    col_rt = 10
    col_ch =  8

    hdr = (f'  {"HOST":<{col_h}} {"STATE":^{col_st}} {"UPTIME %":>{col_up}}'
           f'  {"MIN RTT":>{col_rt}}  {"AVG RTT":>{col_rt}}  {"MAX RTT":>{col_rt}}'
           f'  {"CHANGES":>{col_ch}}')
    print(col(hdr, CBOLD))
    hr()

    prev_cat = None
    for h in ordered:
        s = hosts[h]

        # category separator when sorting by flapping
        if sort_by == 'flapping':
            cat = 'flap' if s.real_changes > 0 else s.current_state
            if cat != prev_cat:
                if prev_cat is not None:
                    hr('·')
                prev_cat = cat

        up_pct     = s.uptime_pct
        pct_colour = CGREEN if up_pct >= 99 else (CORANGE if up_pct >= 90 else CRED)
        min_rtt    = f'{s.rtt_min} ms' if s.has_rtt else '-'
        avg_rtt    = f'{s.rtt_avg} ms' if s.has_rtt else '-'
        max_rtt    = f'{s.rtt_max} ms' if s.has_rtt else '-'
        noc        = str(s.real_changes)
        noc_col    = CORANGE if s.real_changes > 0 else CDIM

        line = (f'  {h:<{col_h}} {state_col(s.current_state):^{col_st}}'
                f' {col(f"{up_pct:6.1f} %", pct_colour)}'
                f'  {min_rtt:>{col_rt}}  {avg_rtt:>{col_rt}}  {max_rtt:>{col_rt}}'
                f'  {col(noc.rjust(col_ch), noc_col)}')
        print(line)

    hr()

    # ── bucket sections ───────────────────────────────────────────────────────
    def bucket(label, colour, lst, sort_fn=sort_hosts):
        hr()
        label_str = col(f'  {label}', colour + CBOLD)
        cnt_str   = col(f'{len(lst):>5}', CBOLD)
        print(f'{label_str}  {cnt_str}')
        hr('·')
        print_host_grid(sort_fn(lst))
        print()

    bucket('Always UP   ', CGREEN,  always_up)
    bucket('Flapping    ', CORANGE, flapping,
           sort_fn=lambda l: sorted(l, key=lambda h: hosts[h].real_changes, reverse=True))
    bucket('Always DOWN ', CRED,    always_down)
    bucket('No DNS      ', CRED,    always_nodns)
    hr()


# ── HTML export ───────────────────────────────────────────────────────────────
def build_report_data(hosts, host_order, filename, rows_read, base='', comments=None):
    """Serialize all analysis data to a plain dict for JSON embedding."""
    rows = []
    for h in host_order:
        s = hosts[h]
        initial_state = s.changes[0][1] if s.changes else s.current_state
        rows.append({
            'name':          h,
            'state':         s.current_state,
            'initial_state': initial_state,
            'uptime':        round(s.uptime_pct, 2),
            'rtt_min':       round(s.rtt_min, 2) if s.has_rtt else None,
            'rtt_max':       round(s.rtt_max, 2) if s.has_rtt else None,
            'rtt_avg':       s.rtt_avg           if s.has_rtt else None,
            'rtt_cnt':       s.rtt_cnt,
            'changes':       s.real_changes,
            'ip':            s.ip,
            'time_up':       fmt_td(s.time_up),
            'time_down':     fmt_td(s.time_down + s.time_nodns),
            'span':          fmt_td(s.total_span),
            'first_ts':      s.first_ts.strftime(TS_FMT) if s.first_ts else '',
            'last_ts':       s.last_ts.strftime(TS_FMT)  if s.last_ts  else '',
            'events': [
                {'ts': (ts.strftime(TS_FMT) if ts else ''), 'frm': frm, 'to': to}
                for ts, frm, to in s.changes
            ],
        })

    all_first = [r['first_ts'] for r in rows if r['first_ts']]
    all_last  = [r['last_ts']  for r in rows if r['last_ts']]
    comment_rows = [
        {'ts': c['ts'].strftime(TS_FMT), 'text': c['text']}
        for c in (comments or [])
    ]
    return {
        'filename':     filename,
        'base':         base,
        'generated':    datetime.datetime.now().strftime(TS_FMT),
        'rows_read':    rows_read,
        'global_start': min(all_first) if all_first else '',
        'global_end':   max(all_last)  if all_last  else '',
        'hosts':        rows,
        'comments':     comment_rows,
    }


def generate_html(data, out_path):
    json_data = json.dumps(data, ensure_ascii=False).replace('</script', '<\\/script')
    comments  = data.get('comments') or []
    if comments:
        comment_rows_html = '\n'.join(
            f'<div class="comment-row"><span class="comment-ts">{html_lib.escape(c["ts"])}</span>'
            f'<span class="comment-text">{html_lib.escape(c["text"])}</span></div>'
            for c in comments
        )
    else:
        comment_rows_html = '<div class="comment-row comment-empty">No comments logged.</div>'
    n_total   = len(data['hosts'])
    n_up      = sum(1 for h in data['hosts'] if h['changes'] == 0 and h['state'] == 'UP')
    n_flap    = sum(1 for h in data['hosts'] if h['changes'] > 0)
    n_down    = sum(1 for h in data['hosts'] if h['changes'] == 0 and h['state'] == 'DOWN')
    n_nodns   = sum(1 for h in data['hosts'] if h['changes'] == 0 and h['state'] == 'NO-DNS')

    html = f"""<!DOCTYPE html>
<html lang="de">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>epinga – {data['filename']}</title>
<link rel="icon" type="image/svg+xml" href="data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0iIzRhM2IzNCI+CiAgPGVsbGlwc2UgY3g9IjEyIiBjeT0iMTYuNSIgcng9IjUuNCIgcnk9IjQuMyIvPgogIDxlbGxpcHNlIGN4PSI1LjIiIGN5PSIxMC41IiByeD0iMi41IiByeT0iMy4xIi8+CiAgPGVsbGlwc2UgY3g9IjE4LjgiIGN5PSIxMC41IiByeD0iMi41IiByeT0iMy4xIi8+CiAgPGVsbGlwc2UgY3g9IjguOSIgY3k9IjUuNiIgcng9IjIuNCIgcnk9IjMuMSIvPgogIDxlbGxpcHNlIGN4PSIxNS4xIiBjeT0iNS42IiByeD0iMi40IiByeT0iMy4xIi8+Cjwvc3ZnPg==">
<style>
:root {{
  --bg:      #0d1117;
  --bg2:     #161b22;
  --bg3:     #21262d;
  --border:  #30363d;
  --text:    #c9d1d9;
  --dim:     #8b949e;
  --green:   #3fb950;
  --red:     #f85149;
  --orange:  #d29922;
  --cyan:    #58a6ff;
  --font:    'Fira Code','Cascadia Code','Consolas',monospace;
}}
:root.light {{
  --bg:      #f6f8fa;
  --bg2:     #ffffff;
  --bg3:     #eaeef2;
  --border:  #d0d7de;
  --text:    #1f2328;
  --dim:     #656d76;
  --green:   #1a7f37;
  --red:     #d1242f;
  --orange:  #9a6700;
  --cyan:    #0969da;
}}
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{ background: var(--bg); color: var(--text); font-family: var(--font);
       font-size: 13px; line-height: 1.5; }}
a {{ color: var(--cyan); text-decoration: none; }}

/* ── header ── */
.hdr {{ background: var(--bg2); border-bottom: 1px solid var(--border);
        padding: 16px 24px; display: flex; align-items: center; justify-content: space-between; gap: 16px; }}
.hdr-left {{ display: flex; flex-direction: column; }}
.hdr h1 {{ font-size: 18px; color: var(--text); letter-spacing: .5px; }}
.hdr .meta {{ color: var(--dim); font-size: 11px; margin-top: 4px; }}

/* ── stat cards ── */
.cards {{ display: flex; gap: 12px; padding: 16px 24px; flex-wrap: wrap; }}
.card {{ background: var(--bg2); border: 1px solid var(--border); border-radius: 6px;
         padding: 12px 20px; min-width: 120px; text-align: center; }}
.card .num {{ font-size: 28px; font-weight: 700; }}
.card .lbl {{ font-size: 11px; color: var(--dim); margin-top: 2px; }}
.card.up    .num {{ color: var(--green);  }}
.card.flap  .num {{ color: var(--orange); }}
.card.down  .num {{ color: var(--red);    }}
.card.nodns .num {{ color: var(--red);    }}
.cards {{ align-items: center; }}
.side-widget {{ margin-left: auto; width: 190px; display: flex; justify-content: center; }}
.cat-link {{ display: block; line-height: 0; }}
.cat {{ height: 90px; width: auto; display: block; filter: drop-shadow(0 4px 10px rgba(0,0,0,.25)); }}
.cat .tail {{ transform-origin: 152px 300px; animation: wag 2.6s ease-in-out infinite; }}
.cat .lid  {{ transform-origin: center; animation: blink 5s infinite; }}
@keyframes wag {{ 0%,100%{{ transform: rotate(0deg); }} 50%{{ transform: rotate(-11deg); }} }}
@keyframes blink {{ 0%,94%,100%{{ transform: scaleY(0); }} 96%,98%{{ transform: scaleY(1); }} }}
@media (prefers-reduced-motion: reduce) {{ .cat .tail, .cat .lid {{ animation: none; }} }}
.paw-title {{ color: var(--dim); vertical-align: -2px; margin-right: 4px; }}

/* ── toolbar ── */
.toolbar {{ display: flex; gap: 10px; padding: 0 24px 12px; flex-wrap: wrap;
            align-items: center; }}
.toolbar input, .toolbar select, .toolbar button {{
  background: var(--bg2); border: 1px solid var(--border); border-radius: 6px;
  color: var(--text); font-family: var(--font); font-size: 12px;
  padding: 6px 10px; outline: none; }}
.toolbar input {{ width: 260px; }}
.toolbar input:focus, .toolbar select:focus {{ border-color: var(--cyan); }}
.toolbar input.invalid {{ border-color: var(--red); }}
.toolbar label {{ color: var(--dim); font-size: 12px; }}
.toolbar button {{ cursor: pointer; }}
.toolbar button:hover {{ border-color: var(--cyan); }}
.toolbar button.active {{ background: var(--orange); border-color: var(--orange); color: var(--bg); font-weight: 600; }}
#btnShowIp.active {{ background: var(--green); border-color: var(--green); color: var(--bg); font-weight: 600; }}
.toolbar .site-link {{ display: flex; align-items: center; gap: 6px;
  color: var(--dim); text-decoration: none; font-size: 12px;
  padding: 4px 10px; border-radius: 999px; border: 1px solid var(--border); }}
.toolbar .site-link:hover {{ color: var(--cyan); border-color: var(--cyan); }}
.toolbar .site-link svg {{ flex: none; }}

/* ── table ── */
.tbl-wrap {{ padding: 0 24px 24px; overflow-x: auto; }}
/* comments + hostlist are static buckets outside #buckets (which supplies its
   own 24px via .buckets padding for the dynamically-generated buckets) - give
   both the same horizontal margin so all bucket boxes line up */
.bucket.hostlist, .bucket.comments {{ margin: 0 24px 20px; }}
.bucket.hostlist .tbl-wrap {{ padding: 0; }}
.bucket.comments .bucket-body {{ padding: 10px 16px; }}
.comment-row {{ display: flex; gap: 14px; padding: 5px 0; border-bottom: 1px solid var(--border); font-size: 13px; }}
.comment-row:last-child {{ border-bottom: none; }}
.comment-ts {{ color: var(--dim); white-space: nowrap; font-variant-numeric: tabular-nums; }}
.comment-text {{ color: var(--text); word-break: break-word; }}
.comment-row.comment-empty {{ color: var(--dim); font-style: italic; }}
.bucket.collapsed.hostlist .tbl-wrap {{ display: none; }}
table {{ width: 100%; border-collapse: collapse; }}
thead th {{
  background: var(--bg3); border: 1px solid var(--border); padding: 8px 12px;
  text-align: left; cursor: pointer; user-select: none; white-space: nowrap;
  color: var(--dim); font-size: 11px; letter-spacing: .6px;
  position: sticky; top: 0; z-index: 2; }}
thead th:hover {{ color: var(--text); }}
thead th.sort-asc::after  {{ content: ' ▲'; color: var(--cyan); }}
thead th.sort-desc::after {{ content: ' ▼'; color: var(--cyan); }}
thead th .sort-num {{ font-size: 9px; color: var(--cyan); font-weight: 700;
                       margin-left: 3px; vertical-align: super; }}
tbody tr {{
  border-bottom: 1px solid var(--border); cursor: pointer;
  transition: background .1s; }}
tbody tr:hover {{ background: var(--bg2); }}
tbody tr.expanded {{ background: var(--bg2); }}
tbody tr.detail-row {{ cursor: default; background: var(--bg3); }}
tbody tr.detail-row:hover {{ background: var(--bg3); }}
td {{ padding: 7px 12px; white-space: nowrap; }}
td.host {{ font-weight: 600; color: var(--text); }}
.host-ip {{ font-weight: 400; color: var(--dim); font-size: 12px; margin-left: 6px; }}

/* state badge */
.badge {{
  display: inline-block; width: 72px; padding: 2px 0; border-radius: 12px;
  font-size: 11px; font-weight: 700; letter-spacing: .4px;
  text-align: center; }}
.badge.UP      {{ background: rgba(63,185,80,.12);  color: var(--green);  border: 1px solid var(--green); }}
.badge.DOWN    {{ background: rgba(248,81,73,.12);  color: var(--red);    border: 1px solid var(--red); }}
.badge.NO-DNS  {{ background: rgba(248,81,73,.12);  color: var(--red);    border: 1px solid var(--red); }}
.badge.FLAPPING{{ background: rgba(210,153,34,.12); color: var(--orange); border: 1px solid var(--orange); }}

/* uptime bar */
.bar-wrap {{ width: 120px; height: 8px; background: rgba(248,81,73,.2);
             border-radius: 4px; overflow: hidden; display: inline-block;
             vertical-align: middle; margin-right: 6px; }}
.bar-fill {{ display: block; height: 100%; border-radius: 4px; }}
.pct-green  {{ color: var(--green);  }}
.pct-orange {{ color: var(--orange); }}
.pct-red    {{ color: var(--red);    }}

/* detail row */
.detail-inner {{ padding: 12px 16px; }}
.detail-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 16px;
                max-width: 900px; }}
.detail-section h4 {{ color: var(--dim); font-size: 11px; margin-bottom: 8px;
                       letter-spacing: .5px; }}
.events {{ display: flex; flex-direction: column; gap: 4px; }}
.event.comment-event {{ color: var(--orange); }}
.event.comment-event .comment-marker {{ margin-right: 2px; }}
.event.comment-event .comment-event-text {{ font-style: italic; word-break: break-word; }}
.event {{ display: flex; align-items: center; gap: 10px; font-size: 12px; }}
.event .ts  {{ color: var(--dim); width: 155px; flex-shrink: 0; }}
.arrow {{ color: var(--dim); }}
.stat-list {{ display: flex; flex-direction: column; gap: 4px; font-size: 12px; }}
.stat-list .kv {{ display: flex; gap: 8px; }}
.stat-list .k {{ color: var(--dim); width: 90px; }}
.stat-list .v {{ color: var(--text); }}
.chevron {{ float: right; color: var(--dim); transition: transform .2s; }}
.expanded .chevron {{ transform: rotate(180deg); }}
tr.hidden {{ display: none; }}

/* ── buckets ── */
.buckets {{ padding: 0 24px 40px; }}
.bucket {{ margin-bottom: 20px; }}
.bucket h3 {{
  font-size: 12px; letter-spacing: .6px; padding: 6px 12px;
  background: var(--bg2); border: 1px solid var(--border);
  border-radius: 6px 6px 0 0; display: flex; justify-content: space-between;
  align-items: center; cursor: default; }}
.bucket-toggle {{ display: flex; align-items: center; gap: 8px; cursor: pointer;
                   flex: 1; user-select: none; }}
.bucket-chevron {{ color: var(--dim); transition: transform .2s; display: inline-block; }}
.bucket.collapsed .bucket-chevron {{ transform: rotate(-90deg); }}
.sort-btn {{ color: var(--dim); font-size: 11px; cursor: pointer; user-select: none;
             letter-spacing: 0; }}
.sort-btn:hover {{ color: var(--text); }}
.bucket.collapsed .bucket-body {{ display: none; }}
.bucket-actions {{ display: flex; align-items: center; gap: 10px; }}
.dl-btn {{
  background: none; border: 1px solid var(--border); border-radius: 4px;
  color: var(--dim); cursor: pointer; font-size: 12px; line-height: 1;
  padding: 3px 7px; font-family: var(--font);
  display: inline-flex; align-items: center; gap: 4px; }}
.dl-btn:hover {{ color: var(--text); border-color: var(--cyan); }}
.bucket-body {{ border: 1px solid var(--border); border-top: none;
                border-radius: 0 0 6px 6px; padding: 12px; }}
.tag-list {{ display: flex; flex-wrap: wrap; gap: 6px; }}
.tag {{
  padding: 2px 10px; border-radius: 4px; font-size: 12px;
  border: 1px solid; cursor: default; }}
.tag.up    {{ background:rgba(63,185,80,.1);  color:var(--green);  border-color:var(--green); }}
.tag.flap  {{ background:rgba(210,153,34,.1); color:var(--orange); border-color:var(--orange); }}
.tag.down  {{ background:rgba(248,81,73,.1);  color:var(--red);    border-color:var(--red); }}
.tag.nodns {{ background:rgba(248,81,73,.1);  color:var(--red);    border-color:var(--red); }}
.tag.flap .chg {{ font-size:10px; opacity:.7; }}

/* ── theme toggle ── */
.theme-btn {{
  background: var(--bg3); border: 1px solid var(--border); border-radius: 6px;
  color: var(--text); font-family: var(--font); font-size: 12px;
  padding: 5px 12px; cursor: pointer; transition: background .15s;
  white-space: nowrap; flex-shrink: 0; }}
.theme-btn:hover {{ background: var(--border); }}

/* ── footer ── */
footer {{ display:flex; align-items:center; justify-content:center; gap:8px;
          padding:16px; color:var(--dim); font-size:11px;
          border-top:1px solid var(--border); }}
footer svg {{ flex:none; }}
footer a {{ color: inherit; text-decoration: underline; text-decoration-color: var(--border); }}
footer a:hover {{ color: var(--text); text-decoration-color: currentColor; }}
</style>
</head>
<body>

<div class="hdr">
  <div class="hdr-left">
    <h1><svg class="paw-title" width="16" height="16" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
      <ellipse cx="12" cy="16.5" rx="5.4" ry="4.3"/>
      <ellipse cx="5.2" cy="10.5" rx="2.5" ry="3.1"/>
      <ellipse cx="18.8" cy="10.5" rx="2.5" ry="3.1"/>
      <ellipse cx="8.9" cy="5.6" rx="2.4" ry="3.1"/>
      <ellipse cx="15.1" cy="5.6" rx="2.4" ry="3.1"/>
    </svg>epinga &nbsp;·&nbsp; Analysis Report</h1>
    <div class="meta">
      File: <strong>{data['filename']}</strong> &nbsp;|&nbsp;
      Generated: {data['generated']} &nbsp;|&nbsp;
      {data['rows_read']:,} rows &nbsp;|&nbsp;
      {n_total} hosts &nbsp;|&nbsp;
      <span id="shownHosts">{n_total} shown</span>
    </div>
  </div>
  <button class="theme-btn" onclick="toggleTheme()" id="themeBtn">☀ Light</button>
</div>

<div class="cards">
  <div class="card"><div class="num">{n_total}</div><div class="lbl">TOTAL HOSTS</div></div>
  <div class="card up">  <div class="num">{n_up}</div>   <div class="lbl">ALWAYS UP</div></div>
  <div class="card flap"><div class="num">{n_flap}</div> <div class="lbl">FLAPPING</div></div>
  <div class="card down"><div class="num">{n_down}</div> <div class="lbl">ALWAYS DOWN</div></div>
  <div class="card nodns"><div class="num">{n_nodns}</div><div class="lbl">NO-DNS</div></div>
  <div class="side-widget">
  <a href="https://jeitler.cc/nelly/" class="cat-link" target="_blank" rel="noopener" aria-label="More about Nelly">
  <svg class="cat" viewBox="0 0 320 340" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Cute cartoon cat">
    <g class="tail">
      <path d="M152 300 C 220 312, 268 286, 262 236 C 259 208, 232 200, 222 220 C 214 236, 232 244, 240 232"
            pathLength="100" fill="none" stroke="#fdfaf6" stroke-width="17" stroke-linecap="round"/>
      <path d="M152 300 C 220 312, 268 286, 262 236 C 259 208, 232 200, 222 220 C 214 236, 232 244, 240 232"
            pathLength="100" fill="none" stroke="#3f3733" stroke-width="17" stroke-linecap="round"
            stroke-dasharray="24 100" stroke-dashoffset="-6"/>
      <path d="M152 300 C 220 312, 268 286, 262 236 C 259 208, 232 200, 222 220 C 214 236, 232 244, 240 232"
            pathLength="100" fill="none" stroke="#f0a049" stroke-width="17" stroke-linecap="round"
            stroke-dasharray="26 100" stroke-dashoffset="-40"/>
      <path d="M152 300 C 220 312, 268 286, 262 236 C 259 208, 232 200, 222 220 C 214 236, 232 244, 240 232"
            pathLength="100" fill="none" stroke="#3f3733" stroke-width="17" stroke-linecap="round"
            stroke-dasharray="20 100" stroke-dashoffset="-76"/>
    </g>
    <ellipse cx="160" cy="252" rx="86" ry="66" fill="#fdfaf6"/>
    <path d="M92 216 C 108 200, 138 198, 150 214 C 160 228, 140 246, 118 244 C 100 242, 86 230, 92 216 Z" fill="#f0a049"/>
    <path d="M206 288 C 226 280, 240 262, 238 244 C 226 268, 208 276, 192 278 Z" fill="#3f3733"/>
    <ellipse cx="126" cy="308" rx="26" ry="15" fill="#fdfaf6" stroke="#e8ded4" stroke-width="2"/>
    <ellipse cx="194" cy="308" rx="26" ry="15" fill="#fdfaf6" stroke="#e8ded4" stroke-width="2"/>
    <path d="M118 306v7M126 304v9M134 306v7" stroke="#e0d3c7" stroke-width="2.5" stroke-linecap="round"/>
    <path d="M186 306v7M194 304v9M202 306v7" stroke="#e0d3c7" stroke-width="2.5" stroke-linecap="round"/>
    <path d="M84 108 L 82 46 L 132 82 Z" fill="#f0a049"/>
    <path d="M92 100 L 91 64 L 122 86 Z" fill="#ffc0cb"/>
    <path d="M236 108 L 238 46 L 188 82 Z" fill="#3f3733"/>
    <path d="M228 100 L 229 64 L 198 86 Z" fill="#ffc0cb"/>
    <ellipse cx="160" cy="146" rx="88" ry="78" fill="#fdfaf6"/>
    <path d="M160 68 C 200 68, 234 92, 242 128 C 226 140, 200 132, 186 112 C 176 96, 168 78, 160 68 Z" fill="#3f3733"/>
    <path d="M160 68 C 122 70, 92 92, 82 122 C 100 130, 122 120, 134 102 C 143 88, 152 76, 160 68 Z" fill="#f0a049"/>
    <path d="M232 176 C 224 196, 208 210, 190 216 C 200 196, 214 182, 232 176 Z" fill="#f0a049"/>
    <ellipse cx="128" cy="150" rx="15" ry="17" fill="#3f3733"/>
    <ellipse cx="192" cy="150" rx="15" ry="17" fill="#3f3733"/>
    <circle cx="133" cy="144" r="5.5" fill="#fff"/>
    <circle cx="197" cy="144" r="5.5" fill="#fff"/>
    <circle cx="124" cy="157" r="2.5" fill="#fff" opacity=".8"/>
    <circle cx="188" cy="157" r="2.5" fill="#fff" opacity=".8"/>
    <ellipse class="lid" cx="128" cy="150" rx="16" ry="18" fill="#fdfaf6"/>
    <ellipse class="lid" cx="192" cy="150" rx="16" ry="18" fill="#fdfaf6"/>
    <ellipse cx="104" cy="176" rx="15" ry="10" fill="#ffb7c5" opacity=".65"/>
    <ellipse cx="216" cy="176" rx="15" ry="10" fill="#ffb7c5" opacity=".65"/>
    <path d="M152 176 L 168 176 L 160 186 Z" fill="#ff9aa8"/>
    <path d="M160 186 C 160 196, 150 198, 145 192 M160 186 C 160 196, 170 198, 175 192"
          fill="none" stroke="#3f3733" stroke-width="3" stroke-linecap="round"/>
    <path d="M96 166 L 60 158 M96 176 L 58 178 M96 186 L 62 196" stroke="#c9b8ab" stroke-width="3" stroke-linecap="round"/>
    <path d="M224 166 L 260 158 M224 176 L 262 178 M224 186 L 258 196" stroke="#c9b8ab" stroke-width="3" stroke-linecap="round"/>
  </svg>
  </a>
  </div>
</div>

<div class="toolbar">
  <label>Filter:</label>
  <input id="search" type="text" placeholder="hostname/IP or /regex/ …" title="plain text or a regex (case-insensitive), matched against hostname and IP" oninput="applyFilter()">
  <label>Show:</label>
  <select id="stateFilter" onchange="applyFilter()">
    <option value="">All states</option>
    <option value="UP">UP</option>
    <option value="FLAP">Flapping</option>
    <option value="DOWN">DOWN</option>
    <option value="NO-DNS">NO-DNS</option>
  </select>
  <label>Sort:</label>
  <select id="sortSel" onchange="sortBySelect()">
    <option value="">– log order –</option>
    <option value="name">Name</option>
    <option value="uptime">Uptime %</option>
    <option value="rtt_avg">Avg RTT</option>
    <option value="changes">Changes</option>
  </select>
  <button id="btnShowIp" onclick="toggleShowIp()"
          title="Switch every host's displayed label between hostname and IP">IP View</button>
  <select id="dedupSel" onchange="onDedupSelectChange()" title="Deduplication mode for hosts monitored under both a hostname and an IP">
    <option value="" selected>No Deduplication</option>
    <option value="name">Hostname</option>
    <option value="ip">IP</option>
  </select>
  <div class="side-widget">
  <a class="site-link" href="https://www.jeitler.cc" target="_blank" rel="noopener">
    <svg width="13" height="13" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
      <ellipse cx="12" cy="16.5" rx="5.4" ry="4.3"/>
      <ellipse cx="5.2" cy="10.5" rx="2.5" ry="3.1"/>
      <ellipse cx="18.8" cy="10.5" rx="2.5" ry="3.1"/>
      <ellipse cx="8.9" cy="5.6" rx="2.4" ry="3.1"/>
      <ellipse cx="15.1" cy="5.6" rx="2.4" ry="3.1"/>
    </svg>
    www.jeitler.cc
    <svg width="13" height="13" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
      <ellipse cx="12" cy="16.5" rx="5.4" ry="4.3"/>
      <ellipse cx="5.2" cy="10.5" rx="2.5" ry="3.1"/>
      <ellipse cx="18.8" cy="10.5" rx="2.5" ry="3.1"/>
      <ellipse cx="8.9" cy="5.6" rx="2.4" ry="3.1"/>
      <ellipse cx="15.1" cy="5.6" rx="2.4" ry="3.1"/>
    </svg>
  </a>
  </div>
</div>

<div class="bucket comments collapsed" id="bucket-comments">
  <h3>
    <span class="bucket-toggle" onclick="toggleBucket('comments')">
      <span class="bucket-chevron">&#9662;</span><span>Comments ({len(comments)})</span>
    </span>
  </h3>
  <div class="bucket-body">
    {comment_rows_html}
  </div>
</div>

<div class="bucket hostlist" id="bucket-hostlist">
  <h3>
    <span class="bucket-toggle" onclick="toggleBucket('hostlist')">
      <span class="bucket-chevron">&#9662;</span><span>Host List</span>
    </span>
  </h3>
  <div class="bucket-body">
    <div class="tbl-wrap">
    <table id="mainTable">
    <thead>
    <tr>
      <th onclick="sortBy('name', event)"    data-col="name"
          title="Click to sort - Shift+click to add as secondary/tertiary sort criterion">HOST</th>
      <th onclick="sortBy('state', event)"   data-col="state" style="text-align:center;width:1px;white-space:nowrap"
          title="Click to sort - Shift+click to add as secondary/tertiary sort criterion">STATE</th>
      <th style="width:220px">TIMELINE</th>
      <th onclick="sortBy('uptime', event)"  data-col="uptime" style="text-align:right"
          title="Click to sort - Shift+click to add as secondary/tertiary sort criterion">UPTIME</th>
      <th onclick="sortBy('rtt_avg', event)" data-col="rtt_avg" style="text-align:right"
          title="Click to sort - Shift+click to add as secondary/tertiary sort criterion">AVG RTT</th>
      <th onclick="sortBy('rtt_min', event)" data-col="rtt_min" style="text-align:right"
          title="Click to sort - Shift+click to add as secondary/tertiary sort criterion">MIN RTT</th>
      <th onclick="sortBy('rtt_max', event)" data-col="rtt_max" style="text-align:right"
          title="Click to sort - Shift+click to add as secondary/tertiary sort criterion">MAX RTT</th>
      <th onclick="sortBy('changes', event)" data-col="changes" style="text-align:center"
          title="Click to sort - Shift+click to add as secondary/tertiary sort criterion">CHANGES</th>
    </tr>
    </thead>
    <tbody id="tbody"></tbody>
    </table>
    </div>
  </div>
</div>

<div class="buckets" id="buckets"></div>

<footer>
  <svg width="12" height="12" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
    <ellipse cx="12" cy="16.5" rx="5.4" ry="4.3"/>
    <ellipse cx="5.2" cy="10.5" rx="2.5" ry="3.1"/>
    <ellipse cx="18.8" cy="10.5" rx="2.5" ry="3.1"/>
    <ellipse cx="8.9" cy="5.6" rx="2.4" ry="3.1"/>
    <ellipse cx="15.1" cy="5.6" rx="2.4" ry="3.1"/>
  </svg>
  <span>epinga.py v{version} &nbsp;·&nbsp;
  &copy; Ewald Jeitler &nbsp;·&nbsp;
  supervised by <a href="https://jeitler.cc/nelly/" target="_blank" rel="noopener">Nelly</a> &nbsp;·&nbsp;
  <a href="https://tools.jeitler.cc" target="_blank" rel="noopener">tools.jeitler.cc</a> &nbsp;·&nbsp;
  <a href="https://www.jeitler.cc" target="_blank" rel="noopener">www.jeitler.cc</a></span>
  <svg width="12" height="12" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
    <ellipse cx="12" cy="16.5" rx="5.4" ry="4.3"/>
    <ellipse cx="5.2" cy="10.5" rx="2.5" ry="3.1"/>
    <ellipse cx="18.8" cy="10.5" rx="2.5" ry="3.1"/>
    <ellipse cx="8.9" cy="5.6" rx="2.4" ry="3.1"/>
    <ellipse cx="15.1" cy="5.6" rx="2.4" ry="3.1"/>
  </svg>
</footer>

<script>
const RAW = {json_data};

// IP-named hosts that are ALSO monitored under a hostname pointing at the same IP -
// these are the duplicates hidden in 'Hostnames' dedup mode. A raw-IP host with no
// hostname counterpart stays visible in either mode.
const REDUNDANT_IPS = new Set(
  RAW.hosts.filter(h => !isIpHost(h.name) && h.ip).map(h => h.ip)
);
// hostnames that are ALSO monitored as a raw IP host pointing at the same address -
// these are the duplicates hidden in 'IPs' dedup mode.
const IP_HOSTS_PRESENT = new Set(RAW.hosts.filter(h => isIpHost(h.name)).map(h => h.name));
const REDUNDANT_NAMES = new Set(
  RAW.hosts.filter(h => !isIpHost(h.name) && h.ip && IP_HOSTS_PRESENT.has(h.ip)).map(h => h.name)
);

// ── theme ──────────────────────────────────────────────────────────────────
(function() {{
  const saved = localStorage.getItem('epinga-theme');
  if (saved === 'light') document.documentElement.classList.add('light');
}})();
function toggleTheme() {{
  const isLight = document.documentElement.classList.toggle('light');
  localStorage.setItem('epinga-theme', isLight ? 'light' : 'dark');
  document.getElementById('themeBtn').textContent = isLight ? '🌙 Dark' : '☀ Light';
}}
// set button label on load
document.addEventListener('DOMContentLoaded', function() {{
  const isLight = document.documentElement.classList.contains('light');
  document.getElementById('themeBtn').textContent = isLight ? '🌙 Dark' : '☀ Light';
}});

let sortChain = [];   // [{{col, asc}}, ...] - earlier entries take priority, Shift+click appends
let rows = [...RAW.hosts];

const G_START = RAW.global_start ? new Date(RAW.global_start.replace(' ','T')).getTime() : 0;
const G_END   = RAW.global_end   ? new Date(RAW.global_end.replace(' ','T')).getTime()   : 1;
const G_SPAN  = G_END - G_START || 1;

function buildTimeline(h) {{
  const hStart = new Date(h.first_ts.replace(' ','T')).getTime();
  const hEnd   = new Date(h.last_ts.replace(' ','T')).getTime();

  // build state segments
  const segs = [];
  let t     = hStart;
  let state = h.initial_state;
  for (const ev of h.events) {{
    const evT = new Date(ev.ts.replace(' ','T')).getTime();
    if (evT > t) segs.push({{start: t, end: evT, state}});
    state = ev.to;
    t = evT;
  }}
  if (hEnd > t) segs.push({{start: t, end: hEnd, state}});

  // blank prefix/suffix (host not yet / no longer monitored)
  const preW  = ((hStart - G_START) / G_SPAN * 100).toFixed(3);
  const postW = ((G_END   - hEnd)   / G_SPAN * 100).toFixed(3);

  const segHtml = segs.map(seg => {{
    const l = ((seg.start - G_START) / G_SPAN * 100).toFixed(3);
    const w = ((seg.end   - seg.start) / G_SPAN * 100).toFixed(3);
    const c = seg.state === 'UP' ? '#3fb950'
            : seg.state === 'NO-DNS' ? '#d29922' : '#f85149';
    return `<div style="position:absolute;left:${{l}}%;width:${{w}}%;height:100%;background:${{c}}"></div>`;
  }}).join('');

  return `<div style="position:relative;width:100%;height:10px;background:var(--bg3);
    border-radius:4px;overflow:hidden" title="${{h.first_ts}} → ${{h.last_ts}}">${{segHtml}}</div>`;
}}

function stateBadge(s, changes) {{
  const label = changes > 0 ? 'FLAPPING' : s;
  return `<span class="badge ${{label}}">${{label}}</span>`;
}}

function uptimeBar(pct, flapping) {{
  const cls = flapping ? 'pct-orange' : pct >= 99 ? 'pct-green' : pct >= 90 ? 'pct-orange' : 'pct-red';
  return `<span class="${{cls}}">${{pct.toFixed(1)}} %</span>`;
}}

function rttCell(v) {{
  return v !== null ? v.toFixed(2) + ' ms' : '<span style="color:var(--dim)">–</span>';
}}

function renderTable(data) {{
  const tbody = document.getElementById('tbody');
  tbody.innerHTML = '';
  data.forEach((h, idx) => {{
    const noc_col = h.changes > 0 ? 'color:var(--orange)' : 'color:var(--dim)';
    const tr = document.createElement('tr');
    tr.id = 'r' + idx;
    tr.dataset.idx = idx;
    tr.innerHTML = `
      <td class="host">${{hostLabel(h)}}${{ secondaryLabel(h) ? ` <span class="host-ip">| ${{secondaryLabel(h)}}</span>` : '' }} <span class="chevron">&#8964;</span></td>
      <td style="text-align:center;white-space:nowrap">${{stateBadge(h.state, h.changes)}}</td>
      <td style="padding:0 12px"><div style="width:200px">${{buildTimeline(h)}}</div></td>
      <td style="text-align:right">${{uptimeBar(h.uptime, h.changes > 0)}}</td>
      <td style="text-align:right">${{rttCell(h.rtt_avg)}}</td>
      <td style="text-align:right">${{rttCell(h.rtt_min)}}</td>
      <td style="text-align:right">${{rttCell(h.rtt_max)}}</td>
      <td style="${{noc_col}};text-align:center">${{h.changes}}</td>`;
    tr.onclick = () => toggleDetail(tr, h);
    tbody.appendChild(tr);

    const dtr = document.createElement('tr');
    dtr.className = 'detail-row hidden';
    dtr.id = 'd' + idx;
    dtr.innerHTML = `<td colspan="8"><div class="detail-inner">${{buildDetail(h)}}</div></td>`;
    tbody.appendChild(dtr);
  }});
}}

function escHtml(s) {{
  return String(s).replace(/[&<>"']/g, c => ({{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}})[c]);
}}

function buildDetail(h) {{
  // comments are a global timeline, not per-host - only show ones logged while
  // this host was actually being observed (its first_ts..last_ts window)
  const relevantComments = (RAW.comments || []).filter(c =>
    (!h.first_ts || c.ts >= h.first_ts) && (!h.last_ts || c.ts <= h.last_ts)
  );
  const timeline = [
    ...h.events.map(e => ({{ts: e.ts, kind: 'change', frm: e.frm, to: e.to}})),
    ...relevantComments.map(c => ({{ts: c.ts, kind: 'comment', text: c.text}})),
  ].sort((a, b) => a.ts < b.ts ? -1 : (a.ts > b.ts ? 1 : 0));

  const eventsHtml = timeline.length === 0
    ? '<span style="color:var(--dim)">no state changes</span>'
    : timeline.map(e => {{
        if (e.kind === 'comment') {{
          return `<div class="event comment-event">
            <span class="ts">${{e.ts}}</span>
            <span class="comment-marker">&#128172;</span>
            <span class="comment-event-text">${{escHtml(e.text)}}</span>
          </div>`;
        }}
        const fc = e.frm === 'UP' ? 'var(--green)' : 'var(--red)';
        const tc = e.to  === 'UP' ? 'var(--green)' : 'var(--red)';
        return `<div class="event">
          <span class="ts">${{e.ts}}</span>
          <span style="color:${{fc}}">${{e.frm}}</span>
          <span class="arrow">→</span>
          <span style="color:${{tc}}">${{e.to}}</span>
        </div>`;
      }}).join('');

  const rttHtml = h.rtt_avg !== null
    ? `<div class="kv"><span class="k">Min</span><span class="v">${{h.rtt_min.toFixed(2)}} ms</span></div>
       <div class="kv"><span class="k">Max</span><span class="v">${{h.rtt_max.toFixed(2)}} ms</span></div>
       <div class="kv"><span class="k">Avg</span><span class="v">${{h.rtt_avg.toFixed(2)}} ms</span></div>
       <div class="kv"><span class="k">Samples</span><span class="v">${{h.rtt_cnt}}</span></div>`
    : '<span style="color:var(--dim)">no RTT data</span>';

  return `<div class="detail-grid">
    <div class="detail-section">
      <h4>STATE CHANGES</h4>
      <div class="events">${{eventsHtml}}</div>
    </div>
    <div class="detail-section">
      <h4>STATISTICS</h4>
      <div class="stat-list">
        <div class="kv"><span class="k">Ip</span><span class="v">${{h.ip || h.name}}</span></div>
        <div class="kv"><span class="k">Uptime</span><span class="v">${{h.time_up}}</span></div>
        <div class="kv"><span class="k">Downtime</span><span class="v">${{h.time_down}}</span></div>
        <div class="kv"><span class="k">Total span</span><span class="v">${{h.span}}</span></div>
        <div class="kv"><span class="k">First seen</span><span class="v">${{h.first_ts}}</span></div>
        <div class="kv"><span class="k">Last seen</span><span class="v">${{h.last_ts}}</span></div>
        ${{rttHtml}}
      </div>
    </div>
  </div>`;
}}

function toggleDetail(tr, h) {{
  const idx = tr.dataset.idx;
  const dtr = document.getElementById('d' + idx);
  const expanded = !dtr.classList.contains('hidden');
  // close all
  document.querySelectorAll('.detail-row').forEach(r => r.classList.add('hidden'));
  document.querySelectorAll('tbody tr:not(.detail-row)').forEach(r => r.classList.remove('expanded'));
  if (!expanded) {{
    dtr.classList.remove('hidden');
    tr.classList.add('expanded');
  }}
}}

// updates header arrows/order badges to match the current sortChain
function updateSortHeaders() {{
  document.querySelectorAll('thead th[data-col]').forEach(th => {{
    th.classList.remove('sort-asc','sort-desc');
    const old = th.querySelector('.sort-num');
    if (old) old.remove();
    const idx = sortChain.findIndex(s => s.col === th.dataset.col);
    if (idx !== -1) {{
      th.classList.add(sortChain[idx].asc ? 'sort-asc' : 'sort-desc');
      if (sortChain.length > 1) {{
        const badge = document.createElement('span');
        badge.className = 'sort-num';
        badge.textContent = String(idx + 1);
        th.appendChild(badge);
      }}
    }}
  }});
  const sel = document.getElementById('sortSel');
  sel.value = (sortChain.length === 1) ? sortChain[0].col : '';
  sel.title = sortChain.length > 1
    ? 'Multi-column sort active - see column headers (Shift+click a header to add/remove it)'
    : '';
}}

// plain click: sort by only this column (toggles direction if it's already the
// sole criterion). Shift+click: append this column as an additional tie-breaker,
// or toggle its direction if it's already part of the chain
function sortBy(col, ev) {{
  const shift = !!(ev && ev.shiftKey);
  const idx = sortChain.findIndex(s => s.col === col);
  if (shift) {{
    if (idx !== -1) {{
      sortChain[idx].asc = !sortChain[idx].asc;
    }} else {{
      sortChain.push({{col, asc: true}});
    }}
  }} else {{
    if (idx === 0 && sortChain.length === 1) {{
      sortChain[0].asc = !sortChain[0].asc;
    }} else {{
      sortChain = [{{col, asc: true}}];
    }}
  }}
  updateSortHeaders();
  applyFilter();
}}

function sortBySelect() {{
  const v = document.getElementById('sortSel').value;
  sortChain = v ? [{{col: v, asc: true}}] : [];
  updateSortHeaders();
  applyFilter();
}}

let dedupMode = '';   // '': off (default), 'name': show hostname (hide its IP counterpart), 'ip': show IP (hide its hostname counterpart)
let showIp     = false;   // display toggle only - which of name/ip is the primary label, independent of dedupMode

function isIpHost(name) {{
  if (/^(\\d{{1,3}}\\.){{3}}\\d{{1,3}}$/.test(name)) return true;
  return name.indexOf(':') !== -1 && /^[0-9a-fA-F:]+$/.test(name);   // IPv6 literal
}}

// true if 'h' is the duplicate side that the current dedup mode should hide -
// applied to both the table filter and the bucket sections below
function isDeduped(h) {{
  if (dedupMode === 'name') return isIpHost(h.name) && REDUNDANT_IPS.has(h.name);
  if (dedupMode === 'ip')   return !isIpHost(h.name) && REDUNDANT_NAMES.has(h.name);
  return false;   // '' = no deduplication
}}

// primary label for a host row/tag - IP when 'IP View' is on and an ip is known,
// hostname otherwise; applied everywhere a host is displayed (table + all buckets)
function hostLabel(h) {{
  return (showIp && h.ip) ? h.ip : h.name;
}}

// the "other" value next to the primary label (e.g. the small "| 1.2.3.4" suffix),
// or null when there is none / it equals the primary
function secondaryLabel(h) {{
  const primary = hostLabel(h);
  if (h.ip && h.ip !== primary) return h.ip;
  if (h.name !== primary) return h.name;
  return null;
}}

// display-only toggle: switches every host's primary label between name and IP
function toggleShowIp() {{
  showIp = !showIp;
  document.getElementById('btnShowIp').classList.toggle('active', showIp);
  applyFilter();
  renderBuckets();
}}

function onDedupSelectChange() {{
  dedupMode = document.getElementById('dedupSel').value;
  applyFilter();
  renderBuckets();
}}

// single-column comparator used by the sortChain - 'state' groups by the
// UP/FLAPPING/DOWN/NO-DNS badge order (not the raw state string, which has no
// FLAPPING value); missing values (null) always sort last regardless of direction
function compareOneColumn(col, asc, a, b) {{
  if (col === 'state') {{
    const od = stateOrder(a) - stateOrder(b);
    if (od !== 0) return asc ? od : -od;
    return asc ? a.name.localeCompare(b.name) : b.name.localeCompare(a.name);
  }}
  const av = a[col], bv = b[col];
  const aNull = av === null, bNull = bv === null;
  if (aNull || bNull) {{
    if (aNull && bNull) return 0;
    return aNull ? 1 : -1;
  }}
  if (typeof av === 'string') return asc ? av.localeCompare(bv) : bv.localeCompare(av);
  return asc ? av - bv : bv - av;
}}

function applyFilter() {{
  const qRaw  = document.getElementById('search').value;
  const state = document.getElementById('stateFilter').value;
  const searchEl = document.getElementById('search');
  // plain text is used as a substring match (old behaviour, unaffected); anything
  // that does not parse as valid regex syntax just falls back to substring too, so
  // typing a literal '(' or similar never surprises a user who didn't mean regex -
  // only used when the text actually compiles as a RegExp
  let qRe = null, qInvalid = false;
  if (qRaw) {{
    try {{ qRe = new RegExp(qRaw, 'i'); }}
    catch (e) {{ qInvalid = true; }}
  }}
  searchEl.classList.toggle('invalid', qInvalid);
  let filtered = RAW.hosts.filter(h => {{
    if (qRaw) {{
      if (qInvalid) {{
        const q = qRaw.toLowerCase();
        if (!h.name.toLowerCase().includes(q) && !(h.ip && h.ip.toLowerCase().includes(q))) return false;
      }} else if (!qRe.test(h.name) && !(h.ip && qRe.test(h.ip))) {{
        return false;
      }}
    }}
    if (state === 'FLAP' && h.changes === 0) return false;
    // UP/DOWN/NO-DNS filters must exclude flapping hosts, same as the buckets
    if (state && state !== 'FLAP' && (h.state !== state || h.changes > 0)) return false;
    if (isDeduped(h)) return false;
    return true;
  }});
  filtered.sort((a, b) => {{
    for (const {{col, asc}} of sortChain) {{
      const c = compareOneColumn(col, asc, a, b);
      if (c !== 0) return c;
    }}
    if (sortChain.length === 0) {{
      // default: UP → FLAPPING → DOWN → NO-DNS, then by name
      const od = stateOrder(a) - stateOrder(b);
      return od !== 0 ? od : a.name.localeCompare(b.name);
    }}
    return 0;   // every criterion in the chain tied
  }});
  document.getElementById('shownHosts').textContent = filtered.length + ' shown';
  renderTable(filtered);
}}

// ── buckets ────────────────────────────────────────────────────────────────
// download this bucket's hostnames/IPs as a .txt file, one per line - named after
// the source logfile so it lines up with eping-log_<ts>[.csv], e.g.
// eping-log_2026-09-05_16:50:05-up-hosts.txt
function downloadBucketList(list, suffix) {{
  const names = list.map(h => hostLabel(h));
  const blob  = new Blob([names.join('\\n') + (names.length ? '\\n' : '')], {{type: 'text/plain'}});
  const url   = URL.createObjectURL(blob);
  const a     = document.createElement('a');
  a.href      = url;
  a.download  = (RAW.base || 'epinga-export') + '-' + suffix + '-hosts.txt';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}}

function fallbackCopy(text, done) {{
  // execCommand fallback: works on file:// pages where the async Clipboard API may be unavailable
  const ta = document.createElement('textarea');
  ta.value = text;
  ta.style.position = 'fixed';
  ta.style.opacity  = '0';
  document.body.appendChild(ta);
  ta.select();
  let ok = false;
  try {{ ok = document.execCommand('copy'); }} catch (e) {{ ok = false; }}
  document.body.removeChild(ta);
  done(ok);
}}

function copyBucketList(list, btn) {{
  const names = list.map(h => hostLabel(h));
  const text  = names.join('\\n') + (names.length ? '\\n' : '');
  function done(ok) {{
    if (!btn) return;
    const orig = btn.textContent;
    btn.textContent = ok ? 'Copied!' : 'Copy failed';
    setTimeout(() => {{ btn.textContent = orig; }}, 1200);
  }}
  if (navigator.clipboard && navigator.clipboard.writeText) {{
    navigator.clipboard.writeText(text).then(() => done(true)).catch(() => fallbackCopy(text, done));
  }} else {{
    fallbackCopy(text, done);
  }}
}}

let BUCKET_LISTS = {{}};
// per-bucket sort direction ('asc'/'desc'), keyed by suffix - survives re-renders
// (showIp toggle, dedup change, collapse) since it lives outside renderBuckets().
let BUCKET_SORT = {{}};
function bucketSortDir(suffix) {{
  return BUCKET_SORT[suffix] || (suffix === 'flap' ? 'desc' : 'asc');
}}
function toggleBucketSort(suffix, evt) {{
  if (evt) evt.stopPropagation();   // don't also collapse the bucket
  BUCKET_SORT[suffix] = bucketSortDir(suffix) === 'asc' ? 'desc' : 'asc';
  renderBuckets();
}}
function downloadBucket(suffix) {{
  downloadBucketList(BUCKET_LISTS[suffix] || [], suffix);
}}
function copyBucket(suffix, btn) {{
  copyBucketList(BUCKET_LISTS[suffix] || [], btn);
}}

function renderBuckets() {{
  const pool = RAW.hosts.filter(h => !isDeduped(h));

  // 'up'/'down'/'nodns' sort alphabetically by the currently shown label;
  // 'flap' sorts by change count (most flappy first by default) - same criterion
  // as before, just reversible now.
  function byName(lst, suffix) {{
    const dir = bucketSortDir(suffix);
    const s   = [...lst].sort((a, b) => hostLabel(a).localeCompare(hostLabel(b)));
    return dir === 'desc' ? s.reverse() : s;
  }}
  function byChanges(lst, suffix) {{
    const dir = bucketSortDir(suffix);
    const s   = [...lst].sort((a, b) => a.changes - b.changes);
    return dir === 'desc' ? s.reverse() : s;
  }}

  const up    = byName(pool.filter(h => h.changes === 0 && h.state === 'UP'), 'up');
  const flap  = byChanges(pool.filter(h => h.changes > 0), 'flap');
  const down  = byName(pool.filter(h => h.changes === 0 && h.state === 'DOWN'), 'down');
  const nodns = byName(pool.filter(h => h.changes === 0 && h.state === 'NO-DNS'), 'nodns');

  function tags(lst, cls, labelFn) {{
    if (!lst.length) return '<span style="color:var(--dim)">–</span>';
    return lst.map(h => `<span class="tag ${{cls}}">${{labelFn(h)}}</span>`).join('');
  }}

  const bkts = [
    {{ title:'Always UP',    cls:'up',    list:up,    suffix:'up',
       fn: h=>`${{hostLabel(h)}}` }},
    {{ title:'Flapping',     cls:'flap',  list:flap,  suffix:'flap',
       fn: h=>`${{hostLabel(h)}} <span class="chg">(${{h.changes}})</span>` }},
    {{ title:'Always DOWN',  cls:'down',  list:down,  suffix:'down',
       fn: h=>`${{hostLabel(h)}}` }},
    {{ title:'No-DNS',       cls:'nodns', list:nodns, suffix:'nodns',
       fn: h=>`${{hostLabel(h)}}` }},
  ];
  BUCKET_LISTS = {{}};
  bkts.forEach(b => {{ BUCKET_LISTS[b.suffix] = b.list; }});
  const wasCollapsed = new Set(
    bkts.map(b => b.suffix).filter(s => {{
      const el = document.getElementById('bucket-' + s);
      return el && el.classList.contains('collapsed');
    }})
  );
  document.getElementById('buckets').innerHTML = bkts.map(b => `
    <div class="bucket" id="bucket-${{b.suffix}}">
      <h3>
        <span class="bucket-toggle" onclick="toggleBucket('${{b.suffix}}')">
          <span class="bucket-chevron">&#9662;</span><span>${{b.title}}</span>
          <span class="sort-btn" onclick="toggleBucketSort('${{b.suffix}}', event)"
                title="click to reverse sort order">${{bucketSortDir(b.suffix) === 'asc' ? '&#9650;' : '&#9660;'}}</span>
        </span>
        <span class="bucket-actions"><span>${{b.list.length}}</span>
        <button class="dl-btn" onclick="downloadBucket('${{b.suffix}}')"
                title="download hostnames/IPs of this list as .txt"
                ${{b.list.length ? '' : 'disabled'}}>&#8681; Download</button>
        <button class="dl-btn" onclick="copyBucket('${{b.suffix}}', this)"
                title="copy hostnames/IPs of this list to clipboard"
                ${{b.list.length ? '' : 'disabled'}}>Copy</button></span>
      </h3>
      <div class="bucket-body">
        <div class="tag-list">${{tags(b.list, b.cls, b.fn)}}</div>
      </div>
    </div>`).join('');
  wasCollapsed.forEach(s => {{
    const el = document.getElementById('bucket-' + s);
    if (el) el.classList.add('collapsed');
  }});
}}

function toggleBucket(suffix) {{
  const el = document.getElementById('bucket-' + suffix);
  if (el) el.classList.toggle('collapsed');
}}

function stateOrder(h) {{
  if (h.changes > 0)          return 1;  // FLAPPING
  if (h.state === 'UP')       return 0;  // always UP
  if (h.state === 'DOWN')     return 2;  // always DOWN
  return 3;                              // NO-DNS
}}
const defaultSorted = [...RAW.hosts].sort((a, b) => {{
  const od = stateOrder(a) - stateOrder(b);
  if (od !== 0) return od;
  return a.name.localeCompare(b.name);
}});
renderTable(defaultSorted);
renderBuckets();
</script>
</body>
</html>"""
    with open(out_path, 'w', encoding='utf-8') as fh:
        fh.write(html)


# ── output capture helpers ────────────────────────────────────────────────────
import io as _io

ANSI_ESCAPE = re.compile(r'\x1b\[[0-9;]*[mKJ]|\r')

def strip_ansi(s):
    return ANSI_ESCAPE.sub('', s)

class _Tee:
    """Write to both the real stdout and a StringIO buffer."""
    def __init__(self, real, buf):
        self._real = real
        self._buf  = buf
    def write(self, s):
        self._real.write(s)
        self._buf.write(s)
        return len(s)
    def flush(self):
        self._real.flush()
    def __getattr__(self, name):
        return getattr(self._real, name)


def getch_prompt(html_path):
    """Print an Enter/Esc prompt and return True if Enter was pressed."""
    print(f'\n  Open HTML report?  '
          f'{col("[Enter]", CGREEN)} open   {col("[Esc]", CDIM)} skip  ',
          end='', flush=True)
    try:
        import tty, termios
        fd  = sys.stdin.fileno()
        old = termios.tcgetattr(fd)
        try:
            tty.setraw(fd)
            ch = sys.stdin.buffer.read(1)
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old)
        print()
        return ch in (b'\r', b'\n')
    except Exception:
        ans = input()
        return ans.strip() == ''


# ── file selection menu ───────────────────────────────────────────────────────
def fmt_size(n):
    """Human-readable file size with 2 decimal places (KB/MB/GB)."""
    if n < 1024:
        return f'{n} B'
    for unit in ('KB', 'MB', 'GB', 'TB'):
        n /= 1024
        if n < 1024:
            return f'{n:.2f} {unit}'
    return f'{n:.2f} TB'


def file_menu(ext='.csv'):
    entries = sorted(
        (f.name, f.stat().st_size)
        for f in os.scandir()
        if f.is_file() and f.name.endswith(ext)
    )
    if not entries:
        die(f'No *{ext} files found in current directory.')
    size_w = max(len(fmt_size(sz)) for _, sz in entries)
    hr()
    print(f'  {"NO":>4}  {"SIZE":>{size_w}}  FILENAME')
    hr()
    for i, (name, sz) in enumerate(entries, 1):
        print(f'  {i:>4}  {fmt_size(sz):>{size_w}}  {name}')
    hr()
    files = [name for name, _ in entries]
    while True:
        choice = input(f'  Select file number (or "e" to exit): ').strip()
        if choice.lower() == 'e':
            sys.exit(0)
        if choice.isdigit() and 1 <= int(choice) <= len(files):
            return files[int(choice) - 1]
        print(f'  Invalid – enter 1..{len(files)} or e')


# ── argument parsing ──────────────────────────────────────────────────────────
def build_parser():
    p = argparse.ArgumentParser(
        description=f'epinga.py v{version} – eping logfile analyser (large-file capable)',
        formatter_class=argparse.RawTextHelpFormatter
    )
    p.add_argument('-f', '--logfile',  dest='filename', default='',
                   help='CSV logfile (omit for interactive menu)')
    p.add_argument('-H', '--host',     dest='hosts', action='append', default=[],
                   metavar='HOST',
                   help='Filter: only show this host (repeatable)')
    p.add_argument('-s', '--start',    dest='ts_start', default='',
                   metavar='YYYY-MM-DD HH:MM:SS',
                   help='Only include rows from this timestamp onwards')
    p.add_argument('-e', '--end',      dest='ts_end',   default='',
                   metavar='YYYY-MM-DD HH:MM:SS',
                   help='Only include rows up to this timestamp')
    p.add_argument('-S', '--sort',      dest='sort', default='name',
                   choices=['name', 'flapping', 'uptime', 'rtt'],
                   help='Sort summary table: name | flapping | uptime | rtt  (default: name)')
    p.add_argument('--no-detail',      dest='no_detail', action='store_true',
                   help='Skip per-host detail, show summary only')
    p.add_argument('--no-changes',     dest='no_changes', action='store_true',
                   help='Omit state-change event list per host')
    p.add_argument('--html',           dest='html_out', default='', metavar='FILE',
                   help='Custom filename for HTML report (default: auto-named)')
    p.add_argument('--open',           dest='open_browser', action='store_true',
                   help='Open HTML report automatically without asking')
    p.add_argument('-q', '--quiet',    dest='quiet', action='store_true',
                   help='Suppress progress bar')
    p.add_argument('--no-version-check', dest='no_version_check', action='store_true',
                   help='Skip the online update check (e.g. for headless/scripted runs)')
    p.add_argument('--version',        action='version', version=f'epinga.py {version}')
    return p


# ── main ──────────────────────────────────────────────────────────────────────
def main():
    signal.signal(signal.SIGINT, sigint_handler)

    if sys.version_info < (3, 8):
        die('Python 3.8 or later required.')

    args = build_parser().parse_args()

    # resolve filename
    filename = args.filename or file_menu()

    # parse optional filters
    filter_hosts = set(args.hosts) if args.hosts else None

    ts_start = parse_ts(args.ts_start) if args.ts_start else None
    ts_end   = parse_ts(args.ts_end)   if args.ts_end   else None

    # ── output paths (always auto-generated) ──
    base      = os.path.splitext(os.path.basename(filename))[0]
    html_path = args.html_out if args.html_out else base + '_report.html'
    txt_path  = base + '_report.txt'

    # ── banner (printed directly, not captured) ──
    print()
    hr('═')
    header_line(f'epinga.py  v{version}  –  eping logfile analyser  –  www.jeitler.cc', '═')
    hr('═')
    print(f'  File : {filename}  ({fmt_bytes(os.path.getsize(filename))})')
    if filter_hosts:
        print(f'  Hosts: {", ".join(sorted(filter_hosts))}')
    if ts_start or ts_end:
        print(f'  Range: {ts_start or "start"} → {ts_end or "end"}')
    print()

    # ── stream & analyse ──
    print('  Analysing…')
    hosts, host_order, rows_read, comments = analyse(
        filename,
        filter_hosts=filter_hosts,
        ts_start=ts_start,
        ts_end=ts_end,
        quiet=args.quiet,
    )
    print(f'  {rows_read:,} rows processed  │  {len(hosts)} host(s) found\n')

    if not hosts:
        die('No matching data found.')

    # ── start capturing output for text file ──
    _buf        = _io.StringIO()
    sys.stdout  = _Tee(sys.__stdout__, _buf)

    # ── comments (global timeline, shown once before the per-host detail - like
    # the HTML report's Comments section, placed above its Host List) ──
    hr('═')
    header_line(f'COMMENTS ({len(comments)})', '═')
    hr('═')
    print()
    if comments:
        for c in comments:
            ts_str = c['ts'].strftime(TS_FMT) if c['ts'] else '?'
            print(f'  {ts_str}  {col(c["text"], CORANGE)}')
    else:
        print(f'  {col("No comments logged.", CDIM)}')
    print()

    # ── per-host detail ──
    if not args.no_detail:
        hr('═')
        header_line('PER-HOST DETAIL', '═')
        hr('═')
        print()
        for h in host_order:
            print_host(h, hosts[h], show_changes=not args.no_changes, comments=comments)

    # ── summary ──
    print_summary(hosts, host_order, sort_by=args.sort)

    # ── restore stdout ──
    sys.stdout = sys.__stdout__

    # ── save text report ──
    with open(txt_path, 'w', encoding='utf-8') as fh:
        fh.write(strip_ansi(_buf.getvalue()))

    # ── save HTML report ──
    report_data = build_report_data(hosts, host_order, filename, rows_read, base, comments)
    generate_html(report_data, html_path)

    # ── version check ──
    if not args.no_version_check:
        url    = 'https://raw.githubusercontent.com/ewaldj/eping/refs/heads/main/eversions'
        remote = check_version_online(url, 'epinga.py')
        if remote and remote > version:
            print(col(f'  !! Update available (v{remote}) – https://www.jeitler.cc !!', CRED))
        else:
            print(f'  THX for using epinga.py v{version}  –  www.jeitler.cc')
    else:
        print(f'  THX for using epinga.py v{version}  –  www.jeitler.cc')

    print()
    print(col(f'  Text saved → {txt_path}', CCYAN))
    print(col(f'  HTML saved → {html_path}', CCYAN))

    # ── open HTML ──
    import subprocess, platform, shutil
    open_cmd = 'open' if platform.system() == 'Darwin' else 'xdg-open'
    can_open = shutil.which(open_cmd) is not None
    if can_open:
        if args.open_browser:
            subprocess.Popen([open_cmd, html_path])
        else:
            if getch_prompt(html_path):
                subprocess.Popen([open_cmd, html_path])
    print()


if __name__ == '__main__':
    main()
