# eping.py 2.70

Continuous ICMP reachability monitor built on top of `fping`. Scans a host list in a
loop and reports each host as UP, DOWN or NO-DNS, counting state changes over time.
Output is either a curses terminal UI (default) or a self-hosted web GUI.

Written by Ewald Jeitler — <https://www.jeitler.cc>

## Requirements

- Python 3.6 or newer
- `fping` in `$PATH` (`apt install fping`, `brew install fping`)
- A terminal supporting `curs_set()` for CLI mode

`--check-source` is used automatically if the installed fping supports it (5.0+).

## Installation / Update

Installs and updates `eping.py`, `epinga.py` and `esplit.py`:

```sh
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/ewaldj/eping/refs/heads/main/e-install.sh)"
```

## Quick start

```sh
./eping-1.60.py                             # CLI, uses/creates eping-hosts.txt
./eping-1.60.py -n 172.17.16.0/20           # scan a network
./eping-1.60.py -web                        # web GUI on http://<host>:8080
./eping-1.60.py -web -port 9000 -bind 127.0.0.1   # different port, local only
./eping-1.60.py -wv                         # CLI plus a read-only web view
```

Without arguments a sample `eping-hosts.txt` is created. Starting with no hosts at all
(`-df`) is valid — hosts can be added at runtime.

### Running unattended (screen / tmux)

CLI mode needs a live terminal, so to keep it running after you log out, run it inside
`screen` or `tmux` and detach. Quick guide:
<https://github.com/ewaldj/microups/blob/main/SCREEN_AND_TMUX-QUICK_GUIDE.md>

## Host sources

Combinable in one invocation:

| Source | Option |
|---|---|
| Host file | `-f FILE[,FILE...]`, one or more, comma and/or space separated (quote if space separated), disable with `-df` |
| CIDR network | `-n` (mask /13 … /32), one or more, comma separated |
| IP range | `-r`, one or more `start-end` ranges, comma separated |

`-n`: `-n 172.17.17.0/24,10.0.0.0/30`.

`-r`: `-r 10.0.0.0-10.0.0.10,172.19.0.0-1.13,172.20.2.0-15`. The end of a range may be
shortened to its last 1-3 octets, borrowed from that range's start address — so
`172.19.0.0-1.13` means `172.19.0.0-172.19.1.13` and `172.20.2.0-15` means
`172.20.2.0-172.20.2.15`.

Limits: 512000 hosts total, 524288 addresses per range. Duplicates are removed.
CIDR expansion includes network and broadcast addresses. With several `-f` files,
entries from all of them are combined before deduplication - a host in more than
one file is only pinged once.

### Host file format

The same parser is used for `-f`, for `F` (ADD FILE) in the CLI and for uploads in the
web GUI, so all three accept:

```
# comments start with a hash and run to the end of the line
127.0.0.1                 # single IPv4 address
192.168.99.0/29           # CIDR network - expanded to every address in it
10.131.0.0/19             # 8192 addresses
www.google.com            # hostname or FQDN
8.8.8.8, 9.9.9.9; 1.1.1.1 # comma and semicolon separate like blanks
2606:4700:4700::1111       # IPv6 address - same wherever an IPv4 address is accepted
2606:4700:4700::1111/128   # IPv6 address with /128 - accepted as that single host
```

Networks use the same mask range as `-n` (/13 … /32) everywhere — host file, ADD FILE,
web upload and the ADD HOST / DEL HOST input. A network outside that range is rejected
with a message naming the allowed range; `-f` prints a warning and ignores it. IPv6 has
no network expansion — `/128` (a single host) is accepted, any other IPv6 mask is
rejected with a message. Anything else that matches none of the forms is silently
ignored.

### Options embedded in the host file (`opt:` / `OPT:`)

A line starting with exactly `opt:` or `OPT:` (leading blanks are fine) carries CLI
options instead of hosts — handy for a per-site file that should always run the same
way, without retyping the flags every time:

```
opt: -ph -du -w 2
opt: -web -port 9000
1.1.1.1
8.8.8.8
```

Several `opt:` lines are allowed and are joined together in file order. `#` works
exactly like it does for a host line — it comments out the rest of the line, or the
whole line if it's right at the start (`# opt: -w 2` is ignored, not applied). Quote a
value that contains spaces, e.g. `opt: -f "my hosts.txt"`. An option actually typed on
the command line always wins over the same option from the file.

This only applies to the initial `-f` host file read at startup (including the default
`eping-hosts.txt`, and every file when `-f` names more than one, comma separated) —
`F` / ADD FILE in the CLI and a web GUI upload only ever add hosts, an `opt:` line in
one of those is left alone as ordinary (harmless) text.

The generated default `eping-hosts.txt` is laid out in three parts, in this order:
the sample hosts, this section explained with a few `opt:` examples, and then every
available CLI option as a commented-out `opt:` line with its default value (remove
the leading `# ` to activate one).

## CLI mode

Sorted table (IPv4 numerically, then hostnames), laid out in as many 64-column blocks
as the terminal width allows; a column header is only drawn above a block that actually
holds hosts. Green = UP, red = DOWN. Columns: hostname/IP, state, RTT
in ms, timestamp of the last state change, number of changes.

| Key | Action |
|---|---|
| `U` | cycle the view: ALL HOSTS → UP → UP+FLAPPING → ALL HOSTS |
| `M` | match filter — regex on hostname/IP (case-insensitive); only matching hosts are shown, every host keeps being pinged regardless; empty input turns it off (see *Match filter*) |
| `A` | add host — IP, hostname, CIDR (/13 … /32) or `ip1-ip2` (max 524288 addresses) |
| `D` | delete host — same input formats and limits as add |
| `F` | add hosts from a file |
| `O` | cycle the sort order (see *Views and sort orders*) |
| `T` | add comment — free text, logged with a timestamp to the CSV (only while logging is on) |
| `S` | set reference — the list currently shown becomes the new base list |
| `Z` | zero changes — reset CH-TIME and CH NO for every host, states are kept |
| `C` | clear all hosts and their state |
| `P` | toggle prefer hostnames — skip a raw IP host when the same address is already covered by a hostname entry (also shrinks what gets pinged) |
| `I` | toggle IP ONLY — resolve every hostname to its address (v4 or v6, whichever resolves, not distinguished) and ping/track it by IP instead of by name; a hostname whose address duplicates one already in the list is dropped instead of kept redundantly |
| `G` | get names — reverse-DNS every raw IP host without a hostname counterpart and rename it in place if a PTR record is found and confirmed by a matching forward A/AAAA record (history/uptime carry over; one-shot, not a toggle; runs in the background, a status line shows while it is resolving) |
| `R` | redraw the screen |
| `L` | logging on: reset logging — single keypress: `Y` deletes ALL entries in the CSV log file and restarts logging into it, `N` starts a fresh `eping-log_<timestamp>.csv` and keeps the old file untouched, `ESC`/`ENTER` cancels. Logging off: label switches to `START LOG` and starts logging into a new `eping-log_<timestamp>.csv` immediately, no confirmation |
| `E` | exit — terminates immediately (`os._exit()`), even with a [G] GET NAMES lookup still running in the background; it does not wait for it to finish |

Dialogs are confirmed with ENTER, cancelled with ESC or empty input. The key bar
switches to shorter labels on narrow terminals. A `PLEASE WAIT` box with an elapsed
counter is shown until the first round has produced results.

**Ping checks keep running while a dialog is open** (`A`, `D`, `F`, `M`, `T` all open
one). Typing a hostname or a comment can take a while; without this, the whole scan
would sit idle for that long, delaying detection of a real outage and skewing its
retry timing and CSV timestamp. A background round uses the exact same retry-class,
state-update and logging logic as the main loop - only the screen is not repainted
until the dialog closes (curses itself stays main-thread-only), at which point the
host table is refreshed at once to show everything that happened in the meantime.

**The display is decoupled from the scan.** The screen is repainted about seven times a
second, also while fping is still running, so the clock keeps ticking and a terminal
resize takes effect immediately. `UP`, `SET REFERENCE`, `DEL HOST` and `ZERO
CHANGES` only change what is shown and are applied at once, without waiting for the
running round.

Keys that change the host list cut the current round short, so the next round already
uses the new list — the UI reacts in about 0.15 s instead of after the full cycle.
Aborting is safe: a host with no fping output keeps its previous state and is never
reported DOWN. A resize or `R` only repaints and lets the measurement finish.

## Read-only web view (`-wv`)

`--web_view` keeps the terminal UI as the only driver and serves the same data over HTTP
on `--port` / `--bind`. The page has no controls, `POST /api/command` and
`POST /api/upload` answer `403`, and everything is operated from the terminal — view,
sort order and host list follow along in the browser within a second.

This exists because running two eping processes against the same hosts is a bad idea:
two fping groups on one machine double the packet rate and steal each other's replies
(measured on a /20: 244 instead of 866 reachable hosts). One process, one scan, two ways
to look at it.

Client-side column sorting still works in the browser and affects only that view.

## Web GUI (`-web`)

Serves a single self-contained page; no external resources are loaded.

- Table in CLI-style columns, filled top to bottom, then the next column to the right.
  The number of rows per column is derived from the measured row height and the window
  size, so shrinking the font shows more hosts. Horizontal scrolling if it does not fit,
  with a "SCROLL RIGHT FOR MORE" hint shown right-aligned in the HOSTS/RUNTIME/... stats
  bar (only while it's actually needed) - the footer stays hidden otherwise, leaving
  the full window height for the host grid.
- Font size 6–28 px via slider, the `A−`/`A+` buttons or the `+`/`−` keys; stored in
  `localStorage`. The font control sits right-aligned at the end of row 1 (see
  below) and stays visible even in the read-only web view, since it's a local
  display preference, not a control over eping.py itself.
- Column headers sort the whole list (IPv4-aware).
- Toolbar is fixed at two rows (wraps to more if the window is narrow, never
  fewer): row 1 - view select (10 views, picked directly from a dropdown - web
  gui only, see *Views and sort orders*; the CLI still cycles the original 3
  with `U`), sort order select, SET REFERENCE, ZERO CHANGES, CLEAR ALL, the
  address mode select (web gui only - see PREFER HOSTNAMES / IP ONLY below),
  GET NAMES, ADV OPTIONS (web gui only - see *ADV OPTIONS* below), RESET LOG
  (reads `START LOG` while logging is off), the DOWNLOAD
  select (web gui only - three targets: ALL HOSTS saves the full reference list;
  SHOWN HOSTS saves only what the table currently shows (view, address mode and
  display filter all apply, same as the table); both are plain text, same format
  ADD FILE/upload accept. LOGFILE saves the active CSV log, disabled while logging
  is off), EXIT, font size (right-aligned); row 2,
  in order and separated by `|`: the match filter field with SET / CLEAR, the
  host field with ADD / DELETE, the comment field with COMMENT, then ADD FILE and
  GENERATE REPORT (web gui only - see *GENERATE REPORT* below) at the end. All work
  exactly as the matching CLI keys (`U`, `P`, `I`, `G`, `O`, `T`, `A`, `D`, `F`, `L`,
  `E`), except the address mode select, DOWNLOAD and GENERATE REPORT, which are web
  gui only and have no matching CLI key (see below for the address mode select).
  The host field feeds both ADD and DELETE — type a value and press the matching
  button; ENTER triggers the button used last (ADD by default), ESC clears the field.
- **Keyboard shortcuts mirror the CLI keys**, without a modifier key and only
  while no text field has focus (so `Ctrl+C`, text selection and normal typing
  behave as expected): `U` cycles the view dropdown (same order as the CLI: ALL
  HOSTS → UP → UP+FLAPPING → ALL HOSTS); `P`, `I`, `G`, `S`, `Z`, `C`, `L`, `E`
  click the matching button (`E`/`C`/`L` still ask for confirmation, same as
  clicking them); `O` cycles the sort order; `A`/`D` focus the host field in
  ADD/DELETE mode; `M`/`T` focus the match filter / comment field; `F` opens
  the file picker; `R` forces an immediate status refresh (there's no curses
  screen to redraw). `+`/`−` (font size) work everywhere, including while
  typing.
- Host files can be uploaded via the button or dropped anywhere on the page
  (max 16 MB, same format as `-f`, see *Host file format*).
- Commands are acknowledged immediately, and a click aborts the running round.

### Views and sort orders

A host counts as **flapping** while its last state change lies within `-fw` minutes
(default: the max, 72000 = 50 days - effectively off unless lowered). Only the timestamp of the last change is kept, so this means *recently
unstable*, not a measured change rate. The change counter in the `CH NO` column shows
how often a host has changed; `Z` resets it.

`U` cycles the original three views (CLI, and as a web gui keyboard shortcut: ALL
HOSTS → UP → UP+FLAPPING → ALL HOSTS). The web gui's view dropdown additionally
offers 7 more views that only it can reach - the CLI has no way to select them and `U`
skips over them (cycling in from one of them resets to ALL HOSTS first). Either way,
the view also shrinks what is probed, which is what makes UP (and the other
non-ALL views) shorten the round - hosts filtered away are not probed and cannot come
back until the view is `ALL HOSTS` again. The host list is a snapshot taken when the
view is switched. Picking a view with no matching hosts is rejected (a notice/message
is shown) and the previous view stays active.

`ALWAYS-UP`/`ALWAYS-DOWN` mean "never left that state during this run" (`CH NO` / the
change counter is still 0) - a live-session fact, not the full-log uptime% epinga.py's
report computes from the CSV. `EVER-UP` is a different, separately tracked fact: it
stays true for the rest of the run once a host has been seen UP even once, no matter
how many times it has changed state since - `CH NO` alone cannot express this, since a
host that only ever toggled between DOWN and NO-DNS also has `CH NO` > 0 without ever
having been UP. `NO-DNS` counts as DOWN for `CURRENTLY-DOWN`/`ALWAYS-DOWN`/
`DOWN+FLAPPING` (same convention used for sorting, see below), so it overlaps with the
dedicated `NO-DNS` view by design - the views are meant to overlap where useful, the
same way `UP+FLAPPING` and `FLAPPING-ONLY` already do.

The web gui dropdown lists the views in this order (independent of their internal
index, which stays stable for scripting against `/api/status`'s `filter_mode`):
ALL HOSTS, CURRENTLY-UP, ALWAYS-UP, EVER-UP, UP+FLAPPING, FLAPPING-ONLY, ALWAYS-DOWN,
CURRENTLY-DOWN, DOWN+FLAPPING, NO-DNS.

| View | Contains | Where |
|---|---|---|
| ALL HOSTS | everything in the reference list | CLI + web gui |
| CURRENTLY-UP | hosts currently UP (shown as `UP` in the CLI/status text) | CLI + web gui |
| ALWAYS-UP | hosts currently UP that have never changed state this run | web gui only |
| EVER-UP | hosts that have been UP at least once this run, regardless of current state | web gui only |
| UP+FLAPPING | hosts currently UP plus flapping hosts, even if they are DOWN now | CLI + web gui |
| FLAPPING-ONLY | hosts currently flapping, regardless of UP/DOWN | web gui only |
| ALWAYS-DOWN | hosts currently DOWN/NO-DNS that have never changed state this run | web gui only |
| CURRENTLY-DOWN | hosts currently DOWN or NO-DNS (shown as `DOWN` in the status text), flapping or not | web gui only |
| DOWN+FLAPPING | hosts currently DOWN/NO-DNS plus flapping hosts, even if UP now | web gui only |
| NO-DNS | hosts currently unresolvable (no A/AAAA record) | web gui only |

`O` cycles five sort orders. A flapping host is also UP or DOWN right now, so the FLAP
group wins over its current state and therefore contains both green and red rows;
NO-DNS counts as DOWN. Inside the UP and DOWN group the normal order applies (IPv4
numerically, hostnames after that). Inside FLAP the order is: **state first, in the
direction of the mode** (`FLAP/UP/DOWN` puts the flapping UP hosts before the flapping
DOWN ones), then the **change count, highest first**, then the address. That keeps the
DOWN rows together instead of scattering them between the UP ones.

```
UP/FLAP/DOWN   1:U0 | 7:U9 3:U2 4:U2 6:U2  8:D9 5:D2 | 2:D0
               ^stable UP    ^FLAP: UP by count, then DOWN by count    ^stable DOWN
```

`ADDRESS` (default) · `UP/FLAP/DOWN` · `DOWN/FLAP/UP` · `FLAP/UP/DOWN` · `FLAP/DOWN/UP`

The active view and order are shown in the key bar and highlighted while not at the
default. Both are pure display operations and take effect immediately, without waiting
for the running scan round. The order is re-evaluated every round, so a host that
changes state moves to its new group right away.

### ADV OPTIONS

Web gui only. Opens a modal with every timer/fping/timezone option as a slider plus a
synced text field, applied live (no restart) while eping.py keeps running. RESET TO
DEFAULT restores the values the process was started with; APPLY re-sends every field's
current value as a catch-all in case a single change event was missed.

| Option | Range | 0/-1 means |
|---|---|---|
| BACKOFF | 1 – 2 | — |
| TIMEOUT | 10 – 5000 ms | — |
| RETRIES | 0 – 5 | — |
| DOWN RETRIES | 0 – 5 | `0` = disabled, every host gets full RETRIES |
| INTERVAL | -1 – 250 ms | `-1` = auto (unset, use RATE instead), `0` = no pacing |
| THREADS | 0 – 32 | `0` = auto |
| WAIT TIME | 0 – 600 s | — |
| CONFIRM | 1 – 10 | — |
| RATE | 10 – 25000 pps | — |
| FLAP WINDOW | 1 – 72000 min | — |
| DOWN SLICES | 1 – 20 | — |
| FULL SWEEP | 0 – 50 | `0` = disabled, never sweeps |
| DNS TTL | 0 – 3600 s | — |
| TIMEZONE | -24 – +24 h | — |

These are the same bounds enforced at CLI startup for the matching flags (see
*Probing*/*Output* above) - one set of limits, hard-enforced on both ends.

### HTTP API

| Method | Path | Body | Purpose |
|---|---|---|---|
| GET | `/` | — | the page |
| GET | `/api/status` | — | JSON: rows, counters, scan and phase info |
| GET | `/api/download/hosts_all` | — | the full reference list as a `.txt` download (DOWNLOAD > ALL HOSTS) |
| GET | `/api/download/hosts_shown` | — | the currently displayed hosts as a `.txt` download (DOWNLOAD > SHOWN HOSTS) |
| GET | `/api/download/logfile` | — | the active CSV log as a download (DOWNLOAD > LOGFILE); `404` while logging is off |
| GET | `/api/report` | — | the last `GENERATE REPORT` HTML result, served inline; `404` until one has completed |
| POST | `/api/command` | `{"cmd":"up_only\|set_filter\|addr_mode\|get_names\|match_filter\|sort\|add\|del\|set_ref\|zero\|add_comment\|reset_log\|clear\|set_option\|reset_options\|run_report\|exit","value":"..."}` | control; `set_option` value is `"key=value"` (see *ADV OPTIONS*); `run_report` starts a background `GENERATE REPORT` run (see below) |
| POST | `/api/upload` | `text/plain` host list | add hosts |

There is no authentication. The default bind address is `0.0.0.0` — use
`-bind 127.0.0.1` outside trusted networks.

## How a scan round works

1. **Name resolution.** Hostnames are resolved once (16 parallel lookups), cached for
   `-dns` seconds and handed to fping as addresses; the display keeps the original name.
   Names resolving to the same address share one probe. Unresolvable names are reported
   NO-DNS without invoking fping. `-dns 0` restores fping-side resolution.
2. **Retry classes.** Hosts currently UP and hosts never probed before get the full
   `-re` retry budget. Hosts confirmed DOWN get `-dr` retries, since retries only guard
   against wrongly declaring an UP host DOWN, while a single reply already proves a host
   is UP. Every `-fs`-th round probes everything with full retries.
3. **DOWN slicing.** Only 1/`-ds` of the DOWN hosts are probed per round, strided across
   the address range. This shortens the cycle considerably at the cost of a longer
   recheck interval per DOWN host. Accuracy is unaffected — a probed host always gets
   the full treatment.
4. **Pacing.** Both classes run at the same time, each in **one** fping process, and
   share the `--rate` budget in proportion to how many hosts they probe this round.
   `-i` is derived from that share.
5. **State update.** With `-cf` > 1 a host leaves UP only after that many consecutive
   non-UP observations; the opposite direction is never damped. The suppressed count is
   written to the TBD column of the log.

### Why only one fping process per group

Every raw ICMP socket receives a copy of every incoming ICMP packet and filters by id,
so N concurrent fping processes give each of them N times the receive load. Measured on
a /20 with 4109 hosts: **9 processes reported 244 hosts UP, one process reported 866** —
about 70 % of the reachable hosts were lost as false DOWN. Extra processes also gain
nothing, because a round takes `hosts / rate` seconds regardless of how it is split.
`-p` still accepts higher values (max 32) for diagnostics.

### Rate ceiling

`-i` cannot go below 1 ms, so one process tops out near 1000 packets/s nominally;
measured against a real /20, fping only reached about 1.8 ms, i.e. roughly 550
packets/s. A `--rate` above that has no effect and is reported as such in the scan info.
`-i 0` removes the pacing entirely but needs the privileges fping was installed with and
sends one hard burst.

## Options

### Host selection
`-f` hostfile(s), comma and/or space separated (e.g. `-f hosts1.txt,hosts2.txt` or `-f "hosts1.txt hosts2.txt"`) · `-df` disable hostfile · `-n` CIDR (comma separated) · `-r` IP range (comma separated, shortened end)

### Probing
| Option | Range | Default | Meaning |
|---|---|---|---|
| `-B` | 1 – 2 | 1.5 | backoff factor applied to `-t` on each retry |
| `-t` | 10 – 5000 | 250 | initial per-target timeout in ms |
| `-re` | 0 – 5 | 3 | retries for UP and unknown hosts |
| `-dr` | 0 – 5 | 1 | retries for confirmed DOWN hosts (`0` = same as everything else) |
| `-i` | -1 – 250 | auto | fixed send interval in ms, overrides `-ra`; `-1` = auto (unset), `0` = unpaced |
| `-p` | 0 – 32 | auto | fping processes per group (`0`/`auto` = 1) |
| `-w` | 0 – 600 | 0.5 | pause between rounds in seconds |
| `-cf` | 1 – 10 | 2 | consecutive DOWN observations before leaving UP (`1` = off) |
| `-ra` | 10 – 25000 | 1000 | ICMP packets per second |
| `-fw` | 1 – 72000 | 72000 (max, 50 days) | minutes since the last state change for a host to count as flapping |
| `-ds` | 1 – 20 | 4 | spread DOWN hosts over N rounds (`1` = all every round) |
| `-fs` | 0 – 50 | 10 | every Nth round probes everything fully (`0` = never) |
| `-dns` | 0 – 3600 | 300 | hostname cache TTL in seconds (`0` = off) |
| `-4` / `-6` | — | auto | prefer IPv4 (`-4`) or IPv6 (`-6`); if the preferred family has no record for a name, the other family is used instead of failing. Mutually exclusive. |
| `-ph` | — | off | start with PREFER HOSTNAMES active (see `P` key) |
| `-ipo` | — | off | start with IP ONLY active (see `I` key) |
| `-gn` | — | off | run GET NAMES once before the first ping round (see `G` key) |
| `-ncs` | — | off | do not pass `--check-source` to fping |
| `-up` | — | 0 | learning phase: after N rounds keep only hosts seen UP |
| `-setref` | — | off | with `-up`: once the learning phase ends, use the hosts found UP as the new reference list (same as pressing `S`/SET REFERENCE); requires `-up N` with N > 0 |

All ranges above are hard-enforced both at CLI startup and, in `-web` mode, live via the
ADV OPTIONS button in the web GUI - same bounds either way. See
[ADV OPTIONS](#adv-options) below.

### Output
| Option | Range | Default | Meaning |
|---|---|---|---|
| `-o` | — | auto | CSV log file name |
| `-dl` | — | — | disable logging |
| `-cl` | — | — | delete all `eping-*` files and exit |
| `-tz` | -24 – +24 | 0 | timezone offset in hours |
| `-dg` | — | off | show cycle time breakdown per phase and retry group |
| `-du` | — | — | disable the online version check |
| `-web` | — | off | web GUI instead of CLI |
| `-wv` | — | off | CLI plus a read-only web view |
| `-port` | — | 8080 | http port for `-web` and `-wv` |
| `-bind` | — | 0.0.0.0 | bind address for `-web` and `-wv` |

## Logging

Unless `-dl` is given, every round appends to `eping-log_YYYY-MM-DD_HH:MM:SS.csv`
(or `-o FILE`):

```
TIMESTAMP,HOSTNAME,PREVIOUS_STATE,CURRENT_STATE,RTT,NO_OF_CHANGES,CHANGE_TIMESTAMP,TBD,IP
```

`TBD` holds the number of currently suppressed DOWN observations (see `-cf`). `IP` is
the address actually pinged for that row — the same as `HOSTNAME` for a raw-IP host, or
the resolved address for a hostname entry (empty for `NO-DNS`).

`ZERO CHANGES` / `Z` resets `NO_OF_CHANGES` and `CHANGE_TIMESTAMP` for all hosts in the
running instance; the log file keeps everything already written.

`ADD COMMENT` / `T` (CLI: input dialog, Web GUI: text field + button) appends a
free-text, timestamped row to the CSV log while logging is on - useful to mark
events (maintenance, an outage ticket, ...) on the same timeline as the ping data.
The row uses the sentinel `#COMMENT#` in the `HOSTNAME` column and carries the
comment text in the `IP` column; `csv.writer` quotes it like any other field, so
Excel/Numbers import is unaffected. If logging is off (`-dl`), the command shows
a notice and nothing is written. epinga.py recognizes these rows automatically
(see below).

`RESET LOGGING` / `L` behaves differently depending on whether logging is currently on:
- Logging on: opens a confirmation before doing anything - CLI: a message box waiting
  for a single keypress; Web GUI: a modal with three buttons (CLEAR LOGGING / NEW FILE /
  CANCEL) that also responds to the same keys while it's open, no typing needed either
  way. `Y`/`N` decide, `ESC`/`ENTER` cancel, any other key is ignored and the
  dialog/modal keeps waiting:
  - `Y` - deletes ALL entries from the current CSV log file and restarts logging into
    the same file (the header row is rewritten, everything after it is gone) - keeps
    the existing filename/timestamp, e.g. if something else already references it.
  - `N` - starts a fresh `eping-log_<timestamp>.csv` (same naming as at startup) and
    switches logging to it; the old file is left exactly as it was.
- Logging off (`-dl`): the key/button reads `START LOG` instead and starts logging
  immediately into a fresh `eping-log_<timestamp>.csv` - no confirmation, since there
  is nothing to lose yet. `ADD COMMENT` / `T` works normally right after.

## Web GUI header

The Web GUI's header shows `eping.py vX.XX · © Ewald Jeitler · supervised by
Nelly · tools.jeitler.cc · www.jeitler.cc`, framed by two small paw icons -
matching epinga.py's HTML report footer. The CLI (curses) header is unaffected
and still reads `eping.py version X.XX by Ewald Jeitler`, since a terminal can't
render the SVG icons. The browser tab
also shows the same paw favicon as epinga.py's HTML report.

## Update notice (CLI)

If a newer eping.py is available online (see `-dv`/`--disable_versioncheck`),
the CLI shows a short one-line hint in its top bar while running, same as
before. On exit (`[E]` / Ctrl-C) a full notice is printed once, with the
install command and links:

```
  A new version of eping.py is available! (installed: vX.XX, latest: vY.YY)

  Install it with:
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/ewaldj/eping/refs/heads/main/e-install.sh)"

  Or visit:
    https://www.jeitler.cc
    https://github.com/ewaldj/eping
```

This appears whenever the eping.py process itself is stopped from a terminal -
plain CLI mode (`[E]` / Ctrl-C) and `--web` mode alike (its `EXIT` command and
Ctrl-C in the terminal running it) - since both print to a real terminal. Only
the Web GUI's own in-browser banner is a separate, shorter notice.

## Run analysis on exit

When eping.py stops (`[E]` / Ctrl-C in the CLI, or the `EXIT` command / Ctrl-C
in the terminal running `--web` mode) and logging was on (no `-dl`) and the
logfile exists and is non-empty, eping.py asks:

```
Run an analysis of this logfile with epinga.py now? [y/N]:
```

Typing `y` (case-insensitive) runs `epinga.py -f <logfile>` in-process before
exiting; Enter or any other input skips it. If no interactive input is
available (e.g. stdin closed), the prompt is skipped silently. No prompt is
shown if logging is disabled or the logfile doesn't exist/is empty.

Both this and `GENERATE REPORT` below resolve `epinga.py` the same way: the copy
next to `eping.py` is preferred, falling back to `epinga.py` in `PATH` if there
isn't one.

## GENERATE REPORT (web gui)

`GENERATE REPORT`, next to `ADD FILE`, runs `epinga.py` on the active CSV log and
opens the resulting HTML report in a new browser tab - without leaving eping.py or
touching a terminal. It needs logging to be on and the logfile to be non-empty;
otherwise the tab opens and immediately closes with an error in the footer.

epinga.py runs in a background thread (`stdin` closed, `--no-version-check`, `-q`,
`--html <logfile-base>_report.html`), so a large logfile doesn't block the fping
loop or the rest of the web gui - the new tab opens blank right away and is
navigated to the report once analysis finishes; poll interval is the same 1s as
the rest of the page. Only one run at a time; a click while one is already running
is a no-op until it completes.

`PREFER HOSTNAMES` / `P` (`-ph` to start with it on) drops a raw-IP host from what gets
pinged as soon as another entry in the list is a hostname resolving to that same
address — the hostname is already being probed, so the bare IP would just be a
duplicate. A raw IP with no hostname counterpart is always kept. Toggling back off
restores the full list. The redundancy check (which hostname resolves to which
address) is cached for `-dns` seconds, same as the DNS cache used for pinging - an
earlier uncached, always-fresh lookup made repeated switching between
`PREFER HOSTNAMES` and `PREFER IP ADDRESS` (web GUI) unreliable on any transient DNS
hiccup, since a single failed lookup silently dropped that one host from the
redundancy check for that switch only.

`IP ONLY` / `I` (`-ipo` to start with it on) resolves every hostname entry to its
address — v4 or v6, whichever resolve_name() returns (see `-4`/`-6` to prefer a
family; without either, A is preferred, AAAA only if there is no A record — either
way, the other family is used if the preferred one has no record) — and
renames it to that address in place, same rename-not-delete pattern as `GET NAMES`,
so history and uptime carry over. From then on that host is pinged and tracked by
IP, not by name. Toggling back off restores the original hostname for every entry
that was renamed. A hostname whose address collides with another host already in
the list is dropped entirely and not restored on toggling off - that is the CLI's
`I` key behaviour only. The web GUI's `SWITCH TO IP ONLY` mode never drops anything:
a hostname that does not resolve at all (`NO-DNS`), or whose resolved address
collides with another entry, is simply left alone (not renamed) and hidden from
the list and not pinged while that mode stays active - `original_hosts_list` is
untouched either way, so it reappears under its original name as soon as a
different address mode is selected.

The CLI only ever has these two independent toggles (`P`/`I`, each on or off on its
own). The web GUI instead offers one address mode dropdown with four, mutually
exclusive entries: `AS PROVIDED`, `PREFER HOSTNAME` (as above), `PREFER IP ADDRESS`
(the mirror image - drops a hostname entry as soon as its resolved address is
already covered by a raw-IP entry in the same list; non-destructive, exactly like
`PREFER HOSTNAME`) and `SWITCH TO IP ONLY` (as above). Switching away from
`SWITCH TO IP ONLY` to any other entry restores the renamed hostnames first, then
applies the newly selected mode - so the dropdown never leaves the destructive
IP-only rename half-applied underneath a display filter.

`GET NAMES` / `G` (`-gn` to run it once at startup) reverse-DNS resolves every raw-IP
host that has no hostname counterpart and, if a PTR record is found, renames it to that
hostname in place — `NO_OF_CHANGES`, uptime and the change history all carry over,
nothing is reset. A host is left as an IP when it has no PTR record, when the resolved
name collides with a host already in the list, or when the same PTR name is shared by
more than one candidate IP (e.g. anycast siblings such as 1.1.1.1/1.0.0.1 both
resolving to `one.one.one.one`) — renaming only one of them would make `PREFER
HOSTNAMES` treat the other as a redundant duplicate and drop it, so both are kept as
plain IPs instead. A PTR name is also rejected, and the host stays as an IP, if it has
no matching forward A (IPv4) / AAAA (IPv6) record pointing back to the same IP - a
stale or one-sided PTR record would otherwise rename the host to a name that fping
cannot resolve (or that resolves to a different address), breaking monitoring for it.
Unlike `PREFER HOSTNAMES` this is a one-shot action, not a toggle: hosts added
afterwards need `G` again.

Triggered interactively (`G` key / GET NAMES button), the reverse-DNS lookups run on a
background thread so the CLI/web loop keeps pinging and stays responsive while a large
host list resolves — only `-gn` at startup blocks, since there is nothing to stay
responsive for yet. While it runs, the CLI header shows "GET NAMES running in
background (N host(s))..." and the web GUI's status line shows the same; the result
message replaces it for 3 seconds once done. Pressing `G` again while one is still
running shows "already running" instead of starting a second one.

## Match filter

`M` (CLI) / the match filter field (web GUI) applies a case-insensitive regex to the
host list for display only - it is matched against both the shown name and the
resolved/pinged IP, so a filter on an IP also finds a host currently displayed by
hostname and vice versa. It never touches the ping targets: every host keeps being
pinged and its state/history keeps being tracked exactly as before, only the rows
that do not match are hidden from the table (and, in the CLI, the column layout
shrinks to fit just the matches). Submitting an empty value turns the filter off
again. In the CLI, an active filter replaces the version banner with
`MATCH FILTER '<regex>' active (N of M hosts shown, all still pinged)`; the web GUI
highlights the filter button the same way the address mode select does when it is
not `AS PROVIDED`. An invalid regex is rejected with an error message and the
previous filter (if any) is left unchanged.

## IPv6

IPv4 and IPv6 hosts can be mixed freely in one host list. A hostname is resolved
according to `-4`/`-6` (a preference, not a restriction — the other family is used
if the preferred one has no record for that name; default: A record first). An
IPv4-mapped IPv6 address (`::ffff:a.b.c.d`), which some resolvers synthesize for a
v4-only name instead of failing the AAAA query, is not treated as a real AAAA record
either — it is not a pingable native IPv6 destination — so that case falls back to
plain IPv4 the same way. `PREFER HOSTNAMES`, `PREFER IP ADDRESS` (web gui only) and
`GET NAMES` consider every resolved address of a hostname, not just one. Internally, fping cannot ping v4 and v6 targets in the same invocation, so a
round with both families in play runs one fping process per family — this is
transparent, `-dg` just shows an extra `full`/`reduced` group suffixed `/v6`. CIDR
(`-n`) and IP-range (`-r`) expansion remain IPv4-only; a single IPv6 host can
be given with `/128` (e.g. `2001:db8::1/128`), any other IPv6 mask is rejected. However
entered — bare address, `/128`, host file, upload — an IPv6 address is always stored in
its shortest form (`2001:4860:4860:0000:...:8888` becomes `2001:4860:4860::8888`).

## Diagnostics (`-dg`)

```
FPING 11.46 [full 865(-r 3,-i 5ms) 4.31s  reduced 3242(-r 1,-i 1ms) 11.46s]
   || DNS 0.00 STATE 0.01 BUILD 0.00 WAIT 0.50 DRAW 0.11
```

`FPING` is the wall time of the round, followed by the per-group wall time — both groups
run in parallel, so the total is the maximum, not the sum. The remaining phases are
eping's own work; on 4109 hosts they add up to about 0.12 s.

## Notes

- Scans are ICMP echo requests. Use only on networks you are authorised to probe.
- `-p` values above 1 and `-i 0` both trade measurement accuracy for speed and were
  measured to produce false DOWN reports; the defaults avoid them deliberately.
- `-dr 0` looks safe on paper but produced flapping hosts in practice — keep the
  default of 1.

# epinga.py 1.99

Analyses an `eping.py` CSV log and produces a terminal summary plus a self-contained
HTML report (no server, no external assets) with per-host detail, state-change
timelines and always-UP/flapping/always-DOWN/no-DNS buckets.

## Quick start

```sh
./epinga.py                              # interactive menu - pick a *.csv from the current dir
./epinga.py -f eping-log_2026-09-05.csv  # analyse a specific logfile
./epinga.py -f FILE --open               # analyse and open the HTML report right away
```

Output filenames are always auto-generated from the logfile name unless overridden:
`<base>_report.txt` (terminal-style text) and `<base>_report.html` (`--html FILE` to
override the latter).

## Options

| Option | Effect |
|---|---|
| `-f FILE`, `--logfile FILE` | CSV logfile (omit for the interactive file-picker menu) |
| `-H HOST`, `--host HOST` | Only include this host (repeatable) |
| `-s`, `--start YYYY-MM-DD HH:MM:SS` | Only rows from this timestamp onwards |
| `-e`, `--end YYYY-MM-DD HH:MM:SS` | Only rows up to this timestamp |
| `-S`, `--sort {name,flapping,uptime,rtt}` | Sort order for the summary table (default: `name`) |
| `--no-detail` | Skip per-host detail, summary only |
| `--no-changes` | Omit the state-change event list per host |
| `--html FILE` | Custom HTML report filename |
| `--open` | Open the HTML report automatically, no prompt |
| `-q`, `--quiet` | Suppress the progress bar |
| `--no-version-check` | Skip the online update check (used by eping.py's `GENERATE REPORT`) |

## HTML report

Everything is inlined into one `.html` file (CSS, JS and the analysed data as JSON) - it
can be copied, emailed or opened offline, with no dependency on the log file it was
built from.

The top bar shows total/UP/flapping/DOWN/no-DNS counts, followed by a toolbar with:

- **Filter** - plain text or a regex (case-insensitive), matched against both hostname
  and IP; an invalid regex falls back to plain substring matching instead of showing
  zero results.
- **Show** - restrict to one state (flapping is its own entry, independent of
  UP/DOWN/NO-DNS).
- **Sort** - by name, uptime %, avg RTT or number of changes (click a column header for
  the same effect). Shift+click a column header to add it as a secondary/tertiary/…
  tie-breaker (any number of columns, up to all of them) instead of replacing the
  sort - a small ①②③… badge next to the arrow shows each column's position in the
  chain. Shift+click a column already in the chain to flip its direction without
  changing its position; a plain click always resets to sorting by that column
  alone.
- **IP View** button (green when on) - display toggle only: swaps every host's primary
  label between hostname and IP (table and all four buckets), the other value shown
  small next to it. Independent of deduplication below.
- **Deduplication** dropdown (`No Deduplication` / `Hostname` / `IP`, default: no
  deduplication) - for a host monitored under both a hostname and its own raw IP,
  hides the redundant side; `Hostname` keeps the name and drops the IP entry,
  `IP` keeps the IP and drops the name entry. Applies to the table and all four
  buckets.

A **Comments** section, populated from `#COMMENT#` rows written by eping.py's
`ADD COMMENT` / `T` (see above), is shown above the Host List - collapsed by
default, since it is only relevant when comments were actually logged. Each entry
shows its timestamp and free text, in log order.

Comments logged while a host was being observed also appear inline in that host's
**STATE CHANGES** timeline (row click to expand), merged chronologically with its
UP/DOWN transitions and shown in a distinct color (orange) with a 💬 marker - useful
to see an event (maintenance, an outage ticket, ...) in context of what a specific
host was doing at the time. Comment text is HTML-escaped before display, so it is
shown as plain text even if it contains `<`, `&`, or a literal `</script>`. The
same merge happens in the text output (`PER-HOST DETAIL`, both the terminal and
the `_report.txt` file) - orange there too (ANSI in the terminal, plain in the file),
with a `COMMENT: ` prefix instead of the 💬 marker (text output uses no emoji/icons -
plain ASCII/typographic characters only: →, ↑/↓, │, █/░, ═/─/·). A
standalone **COMMENTS (N)** block, listing every comment in log order (or
"No comments logged." when there are none), is also printed once before
`PER-HOST DETAIL` in the text output - the same placement as the HTML report's
Comments section above its Host List.

The **Host List** section (filterable/sortable table) and each of the four bucket
sections (**Always UP**, **Flapping**, **Always DOWN**, **No-DNS**) are independently
collapsible by clicking their title bar (expanded by default); a bucket's collapsed
state survives an IP View / Deduplication change since those re-render the bucket
content. Each bucket header also has **Download** (exports its hostnames/IPs as
`<base>-<up|down|flap|nodns>-hosts.txt`) and **Copy** (copies the same list to the
clipboard, with an `execCommand` fallback for `file://` pages where the async
Clipboard API may be unavailable).

Clicking a table row expands its detail: full state-change history with timestamps,
and per-host statistics (IP, uptime, downtime, span, first/last seen, RTT min/avg/max).

# esplit.py 1.14

Splits a large CSV logfile into smaller parts by size - useful before importing a big
`eping-log_*.csv` into Excel/Numbers or sharing it, since epinga.py and esplit.py have
no size limit of their own.

```sh
./esplit.py                                      # interactive menu - pick a *.csv from the current dir
./esplit.py -i eping-log_2026-09-05.csv -o parts -s 20   # split into ~20 MB parts
```

| Option | Effect |
|---|---|
| `-i`, `--input FILE` | CSV file to split (omit for the interactive file-picker menu) |
| `-o`, `--output DIR` | Output folder for the parts (created if missing) |
| `-s`, `--size MB` | Maximum size per part, in MB |

Each part is named `part_NNN.csv` and gets its own copy of the header row, so every
part stays independently importable. Rows are never split across parts and are not
otherwise inspected - a `#COMMENT#` row (see eping.py's `ADD COMMENT` / `T`) is just
another row and lands in whichever part it falls into.
