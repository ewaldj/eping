# eping.py 3.54

Continuous ICMP reachability monitor built on `fping`. Scans a host list in a loop,
reports each host UP/DOWN/NO-DNS, counts state changes. CLI (curses) or web GUI.

Written by Ewald Jeitler — <https://www.jeitler.cc>

## Requirements

- Python 3.6+
- `fping` in `$PATH`
- A terminal supporting `curs_set()` for CLI mode
- `--check-source` used automatically if fping supports it (5.0+)

## Installation / Update

Installs/updates `eping.py`, `epinga.py`, `esplit.py`:

```sh
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/ewaldj/eping/refs/heads/main/e-install.sh)"
```

## Quick start

```sh
./eping.py                             # CLI, uses/creates eping-hosts.txt
./eping.py -n 172.17.16.0/20           # scan a network
./eping.py -web                        # web GUI on http://<host>:8080
./eping.py -web -port 9000 -bind 127.0.0.1
./eping.py -wv                         # CLI + read-only web view
./eping.py -wvc                        # CLI + controllable web view
```

No args: creates a sample `eping-hosts.txt`. `-df`: start with no hosts, add at runtime.

### Running unattended (screen / tmux)

CLI mode needs a live terminal — run inside `screen`/`tmux` and detach:
<https://github.com/ewaldj/microups/blob/main/SCREEN_AND_TMUX-QUICK_GUIDE.md>

## Host sources

Combinable:

| Source | Option |
|---|---|
| Host file | `-f FILE[,FILE...]`, comma/space separated, disable with `-df` |
| CIDR network | `-n` (mask /13 … /32), comma separated |
| IP range | `-r`, `start-end`, comma separated |

`-n 172.17.17.0/24,10.0.0.0/30` · `-r 10.0.0.0-10.0.0.10,172.19.0.0-1.13,172.20.2.0-15`
(range end may shorten to its last 1-3 octets: `172.19.0.0-1.13` = `172.19.0.0-172.19.1.13`).

Limits: 512000 hosts total, 524288 addresses per range. Duplicates removed. CIDR
expansion includes network/broadcast. Several `-f` files are combined before dedup.

### Host file format

Same parser for `-f`, `F`/ADD FILE (CLI), and web GUI ADD FILE:

```
# comment to end of line
127.0.0.1                 # IPv4
192.168.99.0/29           # CIDR - expanded
10.131.0.0/19             # 8192 addresses
www.google.com            # hostname/FQDN
8.8.8.8, 9.9.9.9; 1.1.1.1 # comma/semicolon = blank
2606:4700:4700::1111      # IPv6
2606:4700:4700::1111/128  # IPv6 with /128 - single host
```

Network mask range /13…/32 everywhere (host file, ADD FILE, web upload, ADD/DELETE
host input); out of range is rejected (message names the allowed range; `-f` warns and
ignores). IPv6: only `/128` accepted, any other mask rejected. Anything else is ignored.

### `opt:` / `OPT:` lines

A line starting with `opt:`/`OPT:` carries CLI options instead of a host:

```
opt: -ph -du -w 2
opt: -web -port 9000
1.1.1.1
8.8.8.8
```

Multiple `opt:` lines join in file order. `#` comments out the rest of the line (or
the whole line at the start). Quote values with spaces: `opt: -f "my hosts.txt"`. A
flag typed on the command line wins over the same flag from a file. Only applies to
the initial `-f` read at startup — `F`/ADD FILE (CLI or web, FROM CLIENT/FROM SERVER)
never parse `opt:` lines, they're just text.

The default `eping-hosts.txt`: sample hosts, this section, then every CLI option as a
commented-out `opt:` line with its default (remove `# ` to activate).

## CLI mode

Sorted table (IPv4 numerically, then hostnames), 64-column blocks. Green = UP, red =
DOWN. Columns: hostname/IP, state, RTT (ms), last-change timestamp, change count.

| Key | Action |
|---|---|
| `U` | view picker — all 9 views (see *Views and sort orders*) |
| `M` | match filter — regex on hostname/IP, display only (see *Match filter*) |
| `A` | add host — IP, hostname, CIDR (/13…/32), or `ip1-ip2` (max 524288) |
| `D` | delete host — same formats/limits as add |
| `F` | add hosts from a file |
| `O` | sort order picker — 5 orders (see *Views and sort orders*) |
| `T` | add comment — timestamped CSV row (logging on only) |
| `S` | set reference — shown list becomes new base list |
| `Z` | zero changes — reset CH-TIME/CH NO, states kept |
| `C` | clear all hosts and state |
| `P` | address mode picker — 4 modes (see *Address modes*) |
| `X` | ADV OPTIONS — live option editing (see *ADV OPTIONS*) |
| `N` | ANALYSE NOW — run epinga.py against the active logfile in the background (see *GENERATE REPORT*) |
| `G` | GET NAMES — reverse-DNS raw IPs, one-shot, background |
| `R` | redraw screen |
| `L` | reset logging (logging on) / START LOG (logging off) |
| `E` | exit — `os._exit()` immediately |

`U`, `O` and `P` open a picker dialog (`↑`/`↓` select, ENTER confirms, ESC cancels) -
same option set as the matching web GUI dropdown.

Dialogs: ENTER confirms, ESC/empty cancels. Key bar shortens on narrow terminals.
`PLEASE WAIT` box with elapsed counter shown until the first round has results.

Ping checks keep running while a dialog (`A`/`D`/`F`/`M`/`T`) is open — same
retry/state/logging logic as the main loop; screen repaints once the dialog closes.

Screen repaints ~7×/s independent of fping. `UP`, `SET REFERENCE`, `DEL HOST`, `ZERO
CHANGES` apply immediately without waiting for the round. A list-changing key cuts the
round short (~0.15s reaction). Aborting is safe — no-output host keeps its prior state.

## Read-only web view (`-wv`)

`--web_view`: CLI drives, browser mirrors over HTTP (`--port`/`--bind`). No controls —
`POST /api/command` and `POST /api/upload` answer `403`. Client-side column sort still
works locally.

## Controllable web view (`-wvc`)

`--web_view_control`: like `-wv`, but the browser can drive too (`POST` endpoints not
`403`). Same buttons/keys as *Web GUI* below, curses stays usable simultaneously. A CLI
keypress result (e.g. `S`, `Z`, `O`, `U`, `A`/`D`/`F`) also shows in the browser.

## Web GUI (`-web`)

Single self-contained page, no external resources.

- Table: CLI-style columns, filled top-down then next column right. Horizontal scroll
  if needed ("SCROLL RIGHT FOR MORE" hint in the stats bar).
- Footer stats: RUNTIME, HOST UP/DOWN/FLAPPING, for the whole current view regardless
  of the match filter. RUNTIME shows `n/a` briefly during a background round.
- Adding many hosts (`ADD`, `ADD FILE`, upload) shows "added N host(s) - please wait,
  pinging ..." until they appear with a state, then `done`.
- Font size 6–28px (slider, `A−`/`A+`, `+`/`−` keys), stored in `localStorage`.
- Column headers sort the list (IPv4-aware).
- Toolbar, two rows (wraps if narrow):
  - Row 1: view select (9 views), sort order select, SET REFERENCE, ZERO CHANGES,
    CLEAR ALL, address mode select, GET NAMES, ADV OPTIONS, RESET LOG, FILE OPERATIONS
    select, EXIT, font size.
  - Row 2: match filter (SET/CLEAR), host field (ADD/DELETE), comment field (COMMENT),
    ADD FILE select, GENERATE REPORT select.
  - View select, sort order select, address mode select and ADV OPTIONS all match the
    CLI's `U`/`O`/`P`/`X` pickers exactly. FILE OPERATIONS and ADD FILE > FROM CLIENT/
    FROM SERVER are web-gui-only (no CLI key - CLI already runs on the server's own
    filesystem).
- **FILE OPERATIONS** dropdown, in this order:
  | Entry | Does |
  |---|---|
  | SAVE HOSTS FILE ON SERVER | confirmation, then overwrites the currently displayed hosts into the active `-f` hostfile (first one, if eping.py was started with one); no active hostfile → asks for a name, `.txt` appended once |
  | UPLOAD FILE TO SERVER | picks a local `.txt`/`.csv`, saves as-is server-side, no host parsing; never overwrites, appends `-1`/`-2`/... |
  | DOWNLOAD ALL HOSTS | full reference list, plain text |
  | DOWNLOAD ACTIVE HOSTS | currently displayed hosts (view/address mode/filter applied), plain text |
  | DOWNLOAD ACTIVE LOGFILE | active CSV log, zipped; disabled while logging off |
  | DOWNLOAD SELECTED FILES | picker: every `.csv`/`.txt`/`.html` in the working dir, table (name/size/date), extension filter, "select all", "no compression" checkbox (single-file selection only); multi-select bundles into one ZIP |
  | DELETE FILES FROM SERVER | same picker as DOWNLOAD SELECTED FILES, red DELETE button, confirms with file count; active logfile can't be deleted |
  | VIEW FILE FROM SERVER | picker: every `.csv`/`.txt` in the working dir, table (name/size/date), "select all"; opens each picked file read-only, raw content, COPY/DOWNLOAD buttons - see *VIEW FILE FROM SERVER* below |
- **ADD FILE** dropdown: `FROM CLIENT` (local file picker) / `FROM SERVER` (picks one
  or more `.txt` files already on the server, adds their hosts).
- Keyboard shortcuts (no modifier, only while no text field has focus; own quick
  variants, not the CLI's picker keys of the same letter): `U` cycles the original 3
  views (ALL HOSTS → CURRENTLY-UP → UP+FLAPPING → ALL HOSTS), the other 6 need the
  dropdown; `O` cycles all 5 sort orders one at a time; `P`/`I` toggle PREFER HOSTNAME /
  SWITCH TO IP ONLY directly, the address mode select reaches all 4 modes; `G`/`S`/`Z`/
  `C`/`L`/`E` click the matching button (`E`/`C`/`L` confirm); `A`/`D` focus host field;
  `M`/`T` focus their field; `F` opens the file picker; `R` forces a status refresh;
  `+`/`−` font size (works while typing). No keyboard shortcut for `X`/ADV OPTIONS or
  GENERATE REPORT - click required.
- Host field feeds both ADD/DELETE; ENTER triggers the button used last, ESC clears.
- Files can also be dropped anywhere on the page (max 16MB, see *Host file format*).
- Commands acknowledge immediately; a click aborts the running round.

### Views and sort orders

**Flapping**: last state change within `-fw` minutes (default 72000 = 50 days, off
unless lowered). `CH NO` counts changes; `Z` resets it.

CLI `U` and web GUI's view select/`U` picker (see *CLI mode*) reach the same 9 views.
The web GUI's own `U` keyboard shortcut only cycles ALL HOSTS → CURRENTLY-UP →
UP+FLAPPING → ALL HOSTS (see *Web GUI* keyboard shortcuts). A view also limits what's
probed — filtered hosts aren't probed until back to ALL HOSTS. Host list snapshotted at
switch time. A view with no matches is rejected, previous view stays active.

`ALWAYS-UP`/`ALWAYS-DOWN`: never changed state this run (`CH NO` = 0). `NO-DNS` counts
as DOWN for `CURRENTLY-DOWN`/`ALWAYS-DOWN`/`DOWN+FLAPPING`.

Picker/dropdown order: ALL HOSTS, CURRENTLY-UP, ALWAYS-UP, UP+FLAPPING, FLAPPING-ONLY,
ALWAYS-DOWN, CURRENTLY-DOWN, DOWN+FLAPPING, NO-DNS.

| View | Contains |
|---|---|
| ALL HOSTS | everything |
| CURRENTLY-UP | UP now |
| ALWAYS-UP | UP, never changed this run |
| UP+FLAPPING | UP now + flapping |
| FLAPPING-ONLY | flapping, regardless of state |
| ALWAYS-DOWN | DOWN/NO-DNS, never changed this run |
| CURRENTLY-DOWN | DOWN or NO-DNS now |
| DOWN+FLAPPING | DOWN/NO-DNS now + flapping |
| NO-DNS | unresolvable now |

CLI `O` and web GUI's sort select/`O` picker reach the same 5 sort orders directly; the
web GUI's own `O` keyboard shortcut cycles them one at a time. `ADDRESS` (default),
`UP/FLAP/DOWN`, `DOWN/FLAP/UP`, `FLAP/UP/DOWN`, `FLAP/DOWN/UP`. FLAP group contains both
UP and DOWN flapping hosts; NO-DNS counts as DOWN. Inside FLAP: state first (direction
per mode), then change count (highest first), then address. Both view and order apply
immediately, order re-evaluated every round.

### ADV OPTIONS

Web GUI (button) and CLI (`X` key). Web: modal, every option as slider + text field,
applied live; RESET TO DEFAULT restores startup values, APPLY re-sends every field. CLI:
same 16 options/ranges in a dialog - `↑`/`↓` select, `+`/`-` step, ENTER to type a value
directly, `D` resets the selected option to its default, `R` resets all, ESC/`X` closes.

| Option | Range | 0/-1 means |
|---|---|---|
| BACKOFF | 1 – 2 | — |
| TIMEOUT | 10 – 5000 ms | — |
| RETRIES | 0 – 5 | — |
| DOWN RETRIES | 0 – 5 | `0` = disabled, full RETRIES |
| INTERVAL | -1 – 250 ms | `-1` = auto (use RATE), `0` = no pacing |
| THREADS | 0 – 32 | `0` = auto |
| WAIT TIME | 0 – 600 s | — |
| CONFIRM | 1 – 10 | — |
| RATE | 10 – 25000 pps | — |
| FLAP WINDOW | 1 – 72000 min | — |
| DOWN SLICES | 1 – 20 | — |
| FULL SWEEP | 0 – 50 | `0` = disabled |
| DNS TTL | 0 – 3600 s | — |
| TIMEZONE | -24 – +24 h | — |
| MAX LOG SIZE | 0, 10 – 2500 MB | `0` = no rotation |
| MAX LOG FILES | 0 – 500 | `0` = unlimited |

Same bounds as the matching CLI flags (`-lms`/`-lmf` for the last two - see *Output*).

### HTTP API

| Method | Path | Body | Purpose |
|---|---|---|---|
| GET | `/` | — | the page |
| GET | `/api/status` | — | JSON: rows, counters, scan/phase info |
| GET | `/api/logfiles` | — | JSON list of `.csv`/`.txt`/`.html` files (FILE OPERATIONS, ADD FILE > FROM SERVER) |
| GET | `/api/download/hosts_all` | — | full reference list, `.txt` |
| GET | `/api/download/hosts_shown` | — | shown hosts, `.txt` |
| GET | `/api/download/logfile` | — | active CSV log, zipped; `404` if logging off |
| GET | `/api/download/choose_logfile?name=...&nozip=1` | — | one or more files, ZIP (or raw for a single file with `nozip=1`) |
| GET | `/api/view_file?name=...&queue=...` | — | server-rendered VIEW FILE viewer page for one `.csv`/`.txt` file; repeatable `queue=` params carry the rest of the selection for the page's own "OPEN NEXT FILE" link |
| POST | `/api/delete_logfile` | `{"names":[...]}` | delete files; active logfile refused |
| POST | `/api/upload_server_file?name=...` | raw file content | save `.txt`/`.csv` as-is; never overwrites |
| POST | `/api/add_from_server` | `{"names":[...]}` | add hosts from listed `.txt` files |
| GET | `/api/report` | — | last GENERATE REPORT HTML; `404` until done |
| POST | `/api/command` | `{"cmd":"...","value":"..."}` | control (see cmd list below) |
| POST | `/api/upload` | host list, text | add hosts |

`cmd` values: `up_only`, `set_filter`, `addr_mode`, `get_names`, `match_filter`,
`sort`, `add`, `del`, `set_ref`, `zero`, `add_comment`, `reset_log`, `clear`,
`set_option`, `reset_options`, `run_report`, `save_hosts_file`, `exit`. `set_option`
value: `key=value`. `reset_log` value: logging off - optional custom file name (blank =
auto-generated); logging on - `y` (clear) or `new`/`new=<name>` (new file, optional
custom name). `run_report`: `value` = empty (active logfile) or one `.csv` filename; or
JSON body field `values`: `[...]` to merge and analyse multiple `.csv` files as one
(max 25). `save_hosts_file` value: optional target file name (blank
= active `-f` hostfile, or `eping-hosts.txt` if none).

`-wv` answers `403` to `POST /api/command`/`/api/upload`; `-wvc`/`-web` allow both. No
authentication. Default bind `0.0.0.0` — use `-bind 127.0.0.1` outside trusted networks.

## How a scan round works

1. Hostnames resolved once (32 parallel), cached around `-dns` seconds (randomized a
   bit so a large batch resolved together doesn't all expire - and need re-resolving -
   in the same round later). Same-address names share one probe. Unresolvable → NO-DNS,
   no fping call. `-dns 0` = fping-side resolve.
2. UP/new hosts get full `-re` retries; confirmed-DOWN hosts get `-dr` retries. Every
   `-fs`-th round probes everything with full retries.
3. Only 1/`-ds` of DOWN hosts probed per round, strided.
4. Both classes run concurrently, one fping process each, sharing `--rate`; `-i`
   derived from that share.
5. With `-cf` > 1, a host leaves UP only after that many consecutive non-UP results;
   suppressed count written to the log's TBD column.

One fping process per group (`-p` still accepts up to 32 for diagnostics): measured on
a /20 with 4109 hosts, 9 processes reported 244 UP, one process reported 866.

`-i` floor is 1ms (~1000 pps nominal); measured ~1.8ms (~550 pps) on a real /20. `-i 0`
removes pacing (needs fping's install privileges), one hard burst.

## Options

### Host selection
`-f` hostfile(s) (comma/space separated) · `-df` disable hostfile · `-n` CIDR (comma
separated) · `-r` IP range (comma separated, shortened end)

### Probing
| Option | Range | Default | Meaning |
|---|---|---|---|
| `-B` | 1 – 2 | 1.5 | backoff factor per retry |
| `-t` | 10 – 5000 | 250 | initial timeout (ms) |
| `-re` | 0 – 5 | 3 | retries, UP/unknown hosts |
| `-dr` | 0 – 5 | 1 | retries, confirmed DOWN (`0` = same as others) |
| `-i` | -1 – 250 | auto | send interval (ms), overrides `-ra`; `-1` auto, `0` unpaced |
| `-p` | 0 – 32 | auto | fping processes per group |
| `-w` | 0 – 600 | 0.5 | pause between rounds (s) |
| `-cf` | 1 – 10 | 2 | consecutive DOWN before leaving UP (`1` = off) |
| `-ra` | 10 – 25000 | 1000 | ICMP packets/s |
| `-fw` | 1 – 72000 | 72000 | minutes to count as flapping |
| `-ds` | 1 – 20 | 4 | spread DOWN hosts over N rounds |
| `-fs` | 0 – 50 | 10 | every Nth round: full sweep (`0` = never) |
| `-dns` | 0 – 3600 | 300 | hostname cache TTL (s, `0` off) |
| `-4` / `-6` | — | auto | prefer IPv4/IPv6, mutually exclusive |
| `-ph` | — | off | start with PREFER HOSTNAMES |
| `-ipo` | — | off | start with IP ONLY |
| `-gn` | — | off | GET NAMES once at startup |
| `-ncs` | — | off | skip `--check-source` |
| `-up` | — | 0 | learning phase: after N rounds keep only hosts seen UP |
| `-setref` | — | off | with `-up`: hosts seen UP become new reference list |

Hard-enforced at startup and live via ADV OPTIONS (`-web` only), same bounds.

### Output
| Option | Range | Default | Meaning |
|---|---|---|---|
| `-o` | — | auto | CSV log file name |
| `-dl` | — | — | disable logging |
| `-cl` | — | — | delete all `eping-*` files and exit |
| `-tz` | -24 – +24 | 0 | timezone offset (h) |
| `-dg` | — | off | cycle time breakdown |
| `-du` | — | — | disable online version check |
| `-lms` | 0, 10 – 2500 | 0 | max CSV log size (MB) before rotating; `0` = no rotation |
| `-lmf` | 0 – 500 | 0 | max `eping-log_*.csv` files kept, oldest deleted first; `0` = unlimited |
| `-web` | — | off | web GUI instead of CLI |
| `-wv` | — | off | CLI + read-only web view |
| `-port` | — | 8080 | http port |
| `-bind` | — | 0.0.0.0 | bind address |

## Logging

Unless `-dl`, every round appends to `eping-log_YYYY-MM-DD_HH:MM:SS.csv` (or `-o FILE`):

```
TIMESTAMP,HOSTNAME,PREVIOUS_STATE,CURRENT_STATE,RTT,NO_OF_CHANGES,CHANGE_TIMESTAMP,TBD,IP
```

`TBD`: suppressed DOWN observations (`-cf`). `IP`: address actually pinged (empty for
NO-DNS). Log rotates to a new file once it reaches `-lms` MB; a single round's data is
always written in full to one file, rotation only starts the next round in a new file.
`-lmf` prunes the oldest files once exceeded. A size-rotated file reuses the chain's
original timestamp with an incrementing `-1`/`-2`/... suffix
(`eping-log_<original-timestamp>-N.csv`); starting a new file manually (`RESET
LOGGING`/`L`) always gets the current time instead and begins a fresh chain.

`ZERO CHANGES`/`Z`: resets `NO_OF_CHANGES`/`CHANGE_TIMESTAMP` for the running instance;
log file keeps everything already written.

`ADD COMMENT`/`T`: appends a timestamped row while logging is on, `#COMMENT#` sentinel
in `HOSTNAME`, text in `IP`. No-op with a notice if logging is off. epinga.py detects
these rows automatically.

`RESET LOGGING`/`L`:
- Logging on: confirmation first (CLI keypress / web modal). `Y` clears all entries,
  restarts logging into the same file. `N` starts a fresh file, old file untouched -
  optional custom name (blank = auto-generated `eping-log_<timestamp>.csv`); a name
  that already exists is rejected, nothing is created. `ESC`/`ENTER` cancels.
- Logging off: same dialog, no clear option - `START LOGGING` starts a fresh file
  right away, same optional custom name.

## Web GUI header

Header: `eping.py vX.XX · © Ewald Jeitler · supervised by Nelly · tools.jeitler.cc ·
www.jeitler.cc`, paw icons, matching epinga.py's report footer/favicon. CLI header:
`eping.py version X.XX by Ewald Jeitler` (no SVG support).

## Update notice (CLI)

If a newer version is available (see `-du`), a one-line hint shows in the top bar. On
exit, a full notice prints once:

```
  A new version of eping.py is available! (installed: vX.XX, latest: vY.YY)

  Install it with:
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/ewaldj/eping/refs/heads/main/e-install.sh)"

  Or visit:
    https://www.jeitler.cc
    https://github.com/ewaldj/eping
```

Shown on any terminal-driven exit (CLI `[E]`/Ctrl-C, `-web`'s EXIT/Ctrl-C in its
terminal). The web GUI's in-browser banner is separate and shorter.

## Run analysis on exit

On stop, with logging on and a non-empty logfile, eping.py asks:

```
Run an analysis of this logfile with epinga.py now? [y/N]:
```

`y` (case-insensitive) runs `epinga.py -f <logfile>` before exit; anything else skips
it. Only asked on a terminal-driven exit (CLI `[E]`/Ctrl-C, or `-wv`/`-wvc`'s own
keyboard `[E]`/Ctrl-C); exiting via a browser's EXIT button never asks. No prompt if
logging is off or the logfile is empty/missing.

## GENERATE REPORT (web gui) / ANALYSE NOW (CLI `N`)

Runs epinga.py against one or more logfiles in the background while eping.py keeps
running - not just at exit. Web: GENERATE REPORT dropdown, two entries - `ACTIVE
LOGFILE` analyses the active CSV log (needs logging on, non-empty logfile, else the tab
closes and a footer error is shown), `CHOOSE LOGFILE` picks one or more `.csv` files in
the working dir - table (name/size/date), "select all" checkbox, nothing preselected;
up to 25 files per report, checking a 26th is refused.
More than one selected file is merged chronologically (by mtime) into one temporary
CSV, analysed as a single logfile, then the temp file is removed. Result opens in a new
tab; if a selected file was invalid or has meanwhile been removed (e.g. by log rotation
pruning it between picking and clicking GENERATE), the tab closes and a footer error is
shown instead of sitting on "please wait" forever. CLI: `N` always analyses the active
logfile only (needs logging on, non-empty logfile, else a notice is shown); result
path/error shown once done. Only one run at a time either way. See *epinga.py* below for
the report, and *Called from eping.py* under epinga.py for the invocation.

## VIEW FILE FROM SERVER (web gui only)

Read-only viewer for one or more `.csv`/`.txt` files in the working dir - FILE
OPERATIONS > VIEW FILE FROM SERVER, table picker (name/size/date), "select all". Each
selected file opens in its own tab: raw content, COPY (clipboard) and DOWNLOAD buttons,
no editing. Selecting more than one file opens the first tab right away; that tab shows
a centered "N more file(s) selected / OPEN NEXT FILE" box to open the next one, and so
on (browsers only allow one new tab per click, so the rest open one click at a time).
Max 200MB per file - larger files are refused with a message pointing at DOWNLOAD
instead, and the picker greys those files out, labeled "TOO LARGE", with the current
limit shown in the modal text.

## Address modes (PREFER HOSTNAME / SWITCH TO IP ONLY / GET NAMES)

`PREFER HOSTNAME` (`-ph`): drops a raw-IP host from pinging when another entry resolves
to the same address. Redundancy check cached `-dns` seconds. `PREFER IP ADDRESS`: the
mirror - drops a hostname entry once its resolved address is already covered by a
raw-IP entry. Both non-destructive, restored by switching to another mode.

`SWITCH TO IP ONLY` (`-ipo`): resolves every hostname to its address (v4/v6 per
`-4`/`-6`, A preferred by default) and renames it in place (history/uptime carry over).
CLI: a hostname whose address collides with another host is dropped and not restored.
Web GUI: colliding/unresolvable hosts are hidden (not pinged) while active, restored
automatically when switching away.

CLI `P` and the web GUI's address mode select/`P` picker reach the same 4 exclusive
modes: `HOSTNAME & IP` (default, no dedup), `PREFER HOSTNAME`, `PREFER IP ADDRESS`,
`SWITCH TO IP ONLY`. The web GUI additionally has its own `P`/`I` keyboard shortcuts
that toggle PREFER HOSTNAME / SWITCH TO IP ONLY directly (see *Web GUI*). Leaving
`SWITCH TO IP ONLY` restores hostnames before applying the new mode.

`GET NAMES`/`G` (`-gn`): reverse-DNS every raw IP with no hostname counterpart, renames
on a PTR match (history/uptime carry over). Stays an IP if: no PTR record, name
collides with an existing host, PTR name shared by more than one candidate IP, or no
matching forward A/AAAA record back to the same IP. One-shot, not a toggle.

Runs on a background thread (only `-gn` at startup blocks). While running: CLI
header/web status line show "GET NAMES running in background (N host(s))..."; result
message shows for 3s after. Re-triggering while running shows "already running".

## Match filter

`M` (CLI) / match filter field (web): case-insensitive regex, display only, matched
against shown name and resolved IP. Every host keeps being pinged regardless. Empty
value turns it off. CLI: replaces the version banner with `MATCH FILTER '<regex>'
active (N of M hosts shown, all still pinged)`. Invalid regex: error shown, previous
filter unchanged.

## IPv6

IPv4/IPv6 mixed freely. Resolution follows `-4`/`-6` (preference, not restriction; A
preferred by default). IPv4-mapped IPv6 (`::ffff:a.b.c.d`) falls back to plain IPv4.
`PREFER HOSTNAMES`/`PREFER IP ADDRESS`/`GET NAMES` consider every resolved address.
fping runs one process per family when both are present (`-dg` shows a `/v6` group).
CIDR/IP-range expansion IPv4-only; IPv6 needs `/128` (e.g. `2001:db8::1/128`), any
other mask rejected. IPv6 addresses are always stored in shortest form.

## Diagnostics (`-dg`)

```
FPING 11.46 [full 865(-r 3,-i 5ms) 4.31s  reduced 3242(-r 1,-i 1ms) 11.46s]
   || DNS 0.00 STATE 0.01 BUILD 0.00 WAIT 0.50 DRAW 0.11
```

`FPING`: round wall time, then per-group wall time (parallel, max not sum). Remaining
phases: eping's own work (~0.12s on 4109 hosts).

## Notes

- ICMP echo requests only. Use only on authorised networks.
- `-p` > 1 and `-i 0` reduce accuracy (false DOWN) — defaults avoid both.
- `-dr 0` produces flapping hosts in practice — keep the default of 1.

# epinga.py 2.27

Analyses an eping.py CSV log: terminal summary + self-contained HTML report (no
server, no external assets) with per-host detail, state-change timelines, and
always-UP/flapping/always-DOWN/no-DNS buckets.

## Quick start

```sh
./epinga.py                              # interactive menu - pick a *.csv
./epinga.py -f eping-log_2026-09-05.csv  # analyse a specific logfile
./epinga.py -f FILE --open               # analyse and open the report
```

Output: `<base>_report.txt` and `<base>_report.html` (`--html FILE` overrides).

## Options

| Option | Effect |
|---|---|
| `-f FILE`, `--logfile FILE` | CSV logfile (omit for interactive picker) |
| `-H HOST`, `--host HOST` | only this host (repeatable) |
| `-s`, `--start YYYY-MM-DD HH:MM:SS` | rows from this timestamp on |
| `-e`, `--end YYYY-MM-DD HH:MM:SS` | rows up to this timestamp |
| `-S`, `--sort {name,flapping,uptime,rtt}` | summary sort order (default `name`) |
| `--no-detail` | summary only |
| `--no-changes` | omit state-change list |
| `--html FILE` | custom HTML filename |
| `--open` | open HTML report automatically |
| `-q`, `--quiet` | suppress progress bar |
| `--no-version-check` | skip online update check |

## Called from eping.py

`GENERATE REPORT` (web gui) and `N`/ANALYSE NOW (CLI) both run epinga.py in a
background thread: `stdin` closed, `--no-version-check -q --html
<logfile-base>_report.html`. Web: a blank tab opens right away, navigates to the report
once done (1s poll). CLI: result path/error shown via a notice once done. Either way,
one run at a time, never overwrites - repeat run for the same logfile gets
`_report-1.html`, `_report-2.html`, etc. Also used by *Run analysis on exit*
(`epinga.py -f <logfile>`, in-process, no thread).

## HTML report

Everything inlined into one `.html` (CSS/JS/data as JSON) - portable, works offline.

Top bar: total/UP/flapping/DOWN/no-DNS/duplicate-host counts. Toolbar:

| Control | Does |
|---|---|
| Filter | text or regex (case-insensitive), hostname + IP; invalid regex falls back to substring |
| Show | restrict to one state (flapping independent of UP/DOWN/NO-DNS) |
| Sort | name / uptime% / avg RTT / changes; click a header, shift+click adds a tie-breaker (①②③ badge), shift+click again flips direction |
| IP View | toggle primary label hostname↔IP (table + buckets); independent of dedup |
| Deduplication | No dedup / Prefer IP / Prefer hostname - hides the redundant side across table, buckets, top-bar cards; DUPLICATES card is `0` once a mode is active |
| Download | saves the report exactly as shown (theme/dedup/sort/filter/collapsed state) as a standalone `.html`, client-side; hidden on `file://` |

**Comments**: section above Host List from `#COMMENT#` rows, collapsed by default,
timestamp + text in log order. Also appear inline in a host's STATE CHANGES timeline
(orange, 💬 marker), HTML-escaped. Same merge in text output (`PER-HOST DETAIL`,
`COMMENT:` prefix, no emoji). Standalone `COMMENTS (N)` block before `PER-HOST DETAIL`
in text output.

**Host List** (filterable/sortable table) + six buckets (Always UP, UP+FLAPPING,
Flapping, Always DOWN, DOWN+FLAPPING, No-DNS), independently collapsible. Host List and
DOWN+FLAPPING start expanded, the rest collapsed; state survives IP View/Dedup changes.
Each bucket: Download (`<base>-<up|down|flap|nodns>-hosts.txt`) + Copy (clipboard, with
`execCommand` fallback). Host List itself: Download (CSV) + Copy.

Row click expands: state-change history with timestamps, per-host stats (IP, uptime,
downtime, span, first/last seen, RTT min/avg/max).

# esplit.py 1.14

Splits a large CSV logfile into smaller parts by size.

```sh
./esplit.py                                      # interactive menu
./esplit.py -i eping-log_2026-09-05.csv -o parts -s 20   # ~20MB parts
```

| Option | Effect |
|---|---|
| `-i`, `--input FILE` | CSV file to split (omit for interactive picker) |
| `-o`, `--output DIR` | output folder (created if missing) |
| `-s`, `--size MB` | max size per part |

Each part: `part_NNN.csv`, own header row. Rows never split across parts; a
`#COMMENT#` row lands in whichever part it falls into.
