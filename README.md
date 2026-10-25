# eping.py 3.84

Continuous ICMP reachability monitor built on `fping`. Scans a host list in a loop,
reports each host UP/DOWN/NO-DNS, counts state changes. CLI (curses) or web GUI.

Written by Ewald Jeitler — <https://www.jeitler.cc>

## Requirements

- Python 3.6+ (eping.py and epinga.py)
- `fping` in `$PATH`
- A terminal supporting `curs_set()` for CLI mode
- `--check-source` used automatically if fping supports it (5.0+)
- Non-UTF-8 terminal locale (e.g. `LANG=C`): works, but box-drawing characters are shown as ASCII/`?`; `LC_ALL=C.UTF-8` gives the full look

## Installation / Update

Installs/updates `eping.py`, `epinga.py`, `esplit.py`:

```sh
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/ewaldj/eping/refs/heads/main/e-install.sh)"
```

## Windows

Web GUI version for Windows 10/11 (x64), no terminal mode. Python and fping are included.
Details: [Windows_Version](https://github.com/ewaldj/eping/tree/main/Windows_Version/)

- Installer: [`eping-installer.exe`](https://github.com/ewaldj/eping/raw/main/Windows_Version/eping-installer.exe)
  downloads the package and installs it (current user or all users, Start menu / desktop shortcut, uninstaller).
- Portable: unpack [`eping-windows.zip`](https://github.com/ewaldj/eping/raw/main/Windows_Version/eping-windows.zip)
  and start `eping.exe`.
- `eping.exe` is a small launcher window (web port, Start / Stop / Restart, open web GUI, console log, update).
  The browser opens as soon as eping answers (default `http://127.0.0.1:8080`). The port is read from the
  hosts file (`opt: -port 9000`); a port already in use is reported and can be changed in the window.
- Update: `eping.exe` checks `eversions` at start and every 6 hours; an Update button replaces `eping.py` /
  `epinga.py`, or the whole package if the `eping-windows` line in `eversions` is newer.
- No `-wv`/`-wvc` on Windows; log file names use `-` instead of `:`.
- Extra options: put them in `eping-args.txt` next to `eping.exe`. Details: `README-WINDOWS.txt` in the zip.

## macOS

Web GUI version for macOS 10.13+ (Apple Silicon and Intel). Python 3.11 and fping 5.5 are included.
Details: [OSX_Version](https://github.com/ewaldj/eping/tree/main/OSX_Version/)

- Installer: unzip [`eping-installer-mac.zip`](https://github.com/ewaldj/eping/raw/main/OSX_Version/eping-installer-mac.zip)
  and open `eping-installer.app` (current user or all users, uninstall).
- Portable: unpack [`eping-mac.zip`](https://github.com/ewaldj/eping/raw/main/OSX_Version/eping-mac.zip)
  and open `eping.app`.
- The apps are not notarized: use right-click / Open, or `xattr -dr com.apple.quarantine <folder>` once.
- `eping.app` shows the same window as the Windows launcher; the update check uses the `eping-mac` line in `eversions`.

## Quick start

```sh
./eping.py                             # CLI, uses/creates eping-hosts.txt
./eping.py -n 172.17.16.0/20           # scan a network
./eping.py -web                        # web GUI on http://<host>:8080
./eping.py -web -port 9000 -bind 127.0.0.1
./eping.py -wv                         # CLI + read-only web view
./eping.py -wvc                        # CLI + controllable web view
```

No args: creates a sample `eping-hosts.txt` and `eping-hosts-sample.csv` (same hosts with invented inventory values, a template for the *Inventory CSV import*; never loaded by eping). `-df`: start with no hosts, add at runtime.

### Running unattended (screen / tmux)

CLI mode needs a live terminal — run inside `screen`/`tmux` and detach:
<https://github.com/ewaldj/microups/blob/main/SCREEN_AND_TMUX-QUICK_GUIDE.md>

## Host sources

Combinable:

| Source | Option |
|---|---|
| Host file | `-f FILE[,FILE...]`, comma/space separated, disable with `-df`; `.txt` host list or inventory `.csv` (see *Inventory CSV import*) |
| CIDR network | `-n` (mask /13 … /32), comma separated |
| IP range | `-r`, `start-end`, comma separated |

`-n 172.17.17.0/24,10.0.0.0/30` · `-r 10.0.0.0-10.0.0.10,172.19.0.0-1.13,172.20.2.0-15`
(range end may shorten to its last 1-3 octets: `172.19.0.0-1.13` = `172.19.0.0-172.19.1.13`).

Limits: 512000 hosts total, 524288 addresses per range. Duplicates removed. CIDR
expansion includes network/broadcast. Several `-f` files are combined before dedup.

### Host file format

Same parser for `-f`, `F`/ADD FILE (CLI), and web GUI ADD HOSTS FILE:

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

Network mask range /13…/32 everywhere (host file, ADD HOSTS FILE, web upload, ADD/DELETE
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
the initial `-f` read at startup — `F`/ADD FILE (CLI) and ADD HOSTS FILE (web)
never parse `opt:` lines, they're just text.

`opt:` lines also work at the top of an inventory `.csv`. SAVE HOSTS FILE and DOWNLOAD ALL/ACTIVE HOSTS write every option that differs from the default there (start-up flags and live ADV OPTIONS changes; not `-f -df -n -r -o -up -setref -gn -cl`).

The default `eping-hosts.txt`: sample hosts, this section, then every CLI option as a
commented-out `opt:` line with its default (remove `# ` to activate).

## Inventory CSV import

A `.csv` inventory export (one device per row) can be used as host file: `-f FILE.csv`,
`F`/ADD FILE (CLI), web GUI FILE OPERATIONS > ADD HOSTS FILE (FROM CLIENT, FROM SERVER, drag and drop). Files
named `*.txt` are never treated as CSV - they keep the plain host file format above.

- **Detection**: first line that is not blank, a `#` comment or an `opt:` line is a header with the columns `IP Address` and
  `Hostname` (case-insensitive); the delimiter (`;`, `,` or tab) is detected.
- **Columns used**: `IP Address`, `Hostname`, `Serial Number`, `Model`, `Location`,
  `sysLocation`, `Type`, `Comment`. All other columns are ignored.
- **Host entry**: the `Hostname` (default; rows without an IP are pinged by name too,
  NO-DNS if it does not resolve). A name that is not a valid hostname falls back to the
  IP; rows without a usable entry are ignored. In the IP modes (`-ipo`, PREFER IP
  ADDRESS, also when active while the file is added) the entry is the IP address
  instead and rows without a valid IP are ignored. `-ph` is not needed for a CSV.
- **Duplicates**: one host per entry, the first row wins. The count of ignored and
  duplicate rows is reported when the file is added (startup message / web footer).
- **Log**: the six inventory values and the CSV hostname are written with every row
  of that host, see *Logging*. A `Hostname` that is not the host entry (IP mode) is
  only kept there as information.
- **Filters**: `M` matches the inventory values as text, `V` / ADV FILTER selects them
  (see *ADV FILTER*).
- **Save**: if the displayed hosts carry inventory values, `SAVE HOSTS FILE` writes an
  inventory `.csv` (see *Web GUI*); plain `.txt` hosts are saved as `.txt`.

Example (`;` delimited, extra columns are ignored):

```
Hostname;IP Address;Serial Number;Model;Location;sysLocation;Type;Comment
sw-core-01;10.0.0.1;FOC1234A1BC;C9300-48P;Vienna DC1;Rack A3;Switch;spare PSU missing
sw-core-02;10.0.0.2;FOC1234A1BD;C9300-48P;Vienna DC1;Rack A4;Switch;
ap-lobby-01;;FCW2528P5PSV;C9120AXI-E;Graz HQ;Lobby;AP;
rtr-edge-01;192.0.2.10;FTX9876B2CD;ISR4331;Linz POP;Rack B1;Router;uplink to ISP
sw-access-01;10.0.1.1;FOC5678C3DE;C9200L-24P;Vienna DC1;Rack C1;Switch;
fw-edge-01;192.0.2.1;JMX2345F6GH;ASA5516;Linz POP;Rack B2;Firewall;ASA 5516 - EoL 2027
```

This gives 6 hosts, named by `Hostname`. In an IP mode it gives 5 hosts (the IP
addresses); `ap-lobby-01` has no IP and is ignored.

## CLI mode

Sorted table (IPv4 numerically, then hostnames), 64-column blocks. Green = UP, red =
DOWN. Columns: hostname/IP, state, RTT (ms), last-change timestamp, change count.

| Key | Action |
|---|---|
| `U` | view picker — all 9 views (see *Views and sort orders*) |
| `M` | match filter — regex on hostname/IP and inventory fields, display only (see *Match filter*) |
| `V` | ADV FILTER — check/uncheck Model/Location/sysLocation/Type/Comment values (show only / hide), display only (see *ADV FILTER*) |
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

Ping checks keep running while a dialog (`A`/`D`/`F`/`M`/`V`/`T`) is open — same
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
- Footer stats: HOSTS, RUNTIME, HOST UP/DOWN/FLAPPING, for the whole current view regardless
  of the match filter and the ADV FILTER (HOSTS-SHOWN = shown count). The CLI footer counts the same way. RUNTIME shows `n/a` briefly during a background round.
- Adding many hosts (`ADD`, ADD HOSTS FILE, upload) shows "added N host(s) - please wait,
  pinging ..." until they appear with a state, then `done`.
- Font size 6–28px (slider, `A−`/`A+`, `+`/`−` keys), stored in `localStorage`.
- Column headers sort the list (IPv4-aware).
- Toolbar, two rows (wraps if narrow):
  - Row 1: view select (9 views), sort order select, SET REFERENCE, ZERO CHANGES,
    CLEAR ALL, address mode select, GET NAMES, ADV OPTIONS, RESET LOG, FILE OPERATIONS
    select, EXIT, font size.
  - Row 2: match filter (SET/CLEAR), ADV FILTER, host field (ADD/DELETE), comment
    field (COMMENT), GENERATE REPORT select.
  - View select, sort order select, address mode select and ADV OPTIONS all match the
    CLI's `U`/`O`/`P`/`X` pickers exactly. FILE OPERATIONS (incl. ADD HOSTS FILE FROM CLIENT/
    FROM SERVER) is web-gui-only (no CLI key - CLI already runs on the server's own
    filesystem).
- **FILE OPERATIONS** dropdown, in this order:
  | Entry | Does |
  |---|---|
  | ADD HOSTS FILE FROM SERVER | picks one or more `.txt` files or inventory `.csv` files already on the server, adds their hosts; a `.csv` without the inventory header, e.g. an eping log, is refused |
  | ADD HOSTS FILE FROM CLIENT | local file picker (`.txt`/`.csv`), adds the hosts; a file can also be dropped anywhere on the page |
  | SAVE HOSTS FILE ON SERVER | confirmation, then saves the currently displayed hosts; blank name overwrites the active `-f` hostfile (first one, if eping.py was started with one) or, with none active, the default `eping-hosts.txt`; a typed name always saves as that new file instead, `.txt` appended once, active hostfile left untouched. If the displayed hosts carry inventory values (CSV import) an inventory `.csv` is written instead (`;` delimited, columns as in *Inventory CSV import*); a `.txt` name or hostfile then becomes `.csv`, the default is `eping-hosts.csv`. The options that differ from the default are written first as `opt:` lines (see *Host file format*); for a `.csv` the checkboxes `include options (opt: lines)` (default on) and `save as .txt (hosts only, no inventory)` (default off) are offered |
  | UPLOAD FILE TO SERVER | picks a local `.txt`/`.csv`, saves as-is server-side, no host parsing; never overwrites, appends `-1`/`-2`/... |
  | DOWNLOAD ALL HOSTS | full reference list: inventory `.csv` if the hosts carry inventory values, else `.txt`; non-default options first as `opt:` lines (`.csv`: checkboxes `include options`, default on, and `save as .txt`, default off) |
  | DOWNLOAD ACTIVE HOSTS | currently displayed hosts (view/address mode/filter applied), same format and options as DOWNLOAD ALL HOSTS |
  | DOWNLOAD ACTIVE LOGFILE | active CSV log, zipped; disabled while logging off |
  | DOWNLOAD SELECTED FILES | picker: every `.csv`/`.txt`/`.html` in the working dir, table (name/size/date), extension filter, "select all", "no compression" checkbox (single-file selection only); multi-select bundles into one ZIP |
  | DELETE FILES FROM SERVER | same picker as DOWNLOAD SELECTED FILES, red DELETE button, confirms with file count; active logfile can't be deleted |
  | VIEW FILE FROM SERVER | picker: every `.csv`/`.txt` in the working dir, table (name/size/date), "select all"; opens each picked file read-only, raw content, COPY/DOWNLOAD buttons - see *VIEW FILE FROM SERVER* below |
- Keyboard shortcuts (no modifier, only while no text field has focus; own quick
  variants, not the CLI's picker keys of the same letter): `U` cycles the original 3
  views (ALL HOSTS → CURRENTLY-UP → UP+FLAPPING → ALL HOSTS), the other 6 need the
  dropdown; `O` cycles all 5 sort orders one at a time; `P`/`I` toggle PREFER HOSTNAME /
  SWITCH TO IP ONLY directly, the address mode select reaches all 4 modes; `G`/`S`/`Z`/
  `C`/`L`/`E` click the matching button (`E`/`C`/`L` confirm); `A`/`D` focus host field;
  `M`/`T` focus their field; `V` opens ADV FILTER; `F` opens the ADD HOSTS FILE FROM CLIENT picker; `R` forces a status refresh;
  `+`/`−` font size (works while typing). No keyboard shortcut for `X`/ADV OPTIONS or
  GENERATE REPORT - click required.
- Host field feeds both ADD/DELETE; ENTER triggers the button used last, ESC clears.
- Files can also be dropped anywhere on the page (max 16MB, see *Host file format*).
- Commands acknowledge immediately; a click aborts the running round.
- **Host popup**: hovering a host row (after ~350 ms) shows everything known about it:
  state, previous state, RTT, last check, changes, time in the current state, resolved/CSV
  IP, inventory values (Model, Location, sysLocation, Type, Comment, serial) and its
  history (last up to 50 state changes, newest first, merged with the log `COMMENT`s
  by time). The data is fetched per host on demand (`GET /api/host`), the polled status
  stays small. A click on the row pins the popup: the text can be selected, `COPY` copies
  all of it, `DELETE` removes the host immediately (no confirmation; not shown in `-wv`),
  `×`/ESC/click elsewhere closes it. The history lives in memory only; it is cleared by
  ZERO CHANGES and CLEAR ALL.

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
| GET | `/api/host?name=...` | — | JSON: all known data and history of one host (mouse-over popup) |
| GET | `/api/logfiles` | — | JSON list of `.csv`/`.txt`/`.html` files (FILE OPERATIONS > ADD HOSTS FILE FROM SERVER) |
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
| POST | `/api/advvalues` | `{"filter":{...}}` | ADV FILTER: values still selectable for a draft selection (same format as `adv_filter`) |
| POST | `/api/upload` | host list, text | add hosts |

`cmd` values: `up_only`, `set_filter`, `addr_mode`, `get_names`, `match_filter`,
`adv_filter`, `sort`, `add`, `del`, `set_ref`, `zero`, `add_comment`, `reset_log`, `clear`,
`set_option`, `reset_options`, `run_report`, `save_hosts_file`, `exit`. `adv_filter` value: JSON object `{"<field>":{"mode":"in|out","values":[...]}}` with the fields `model`,
`location`, `sysloc`, `type`, `comment`; `\u0001none` as value = hosts without a value; `{}` = off
(the old `{"<field>":"<value>"}` form is still accepted as `in` with one value). `set_option`
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
   no fping call. `-dns 0` = fping-side resolve. A command (filter, add, ...) cuts
   the name resolution short as well, so it applies at once even with thousands of
   hostnames.
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
TIMESTAMP,HOSTNAME,PREVIOUS_STATE,CURRENT_STATE,RTT,NO_OF_CHANGES,CHANGE_TIMESTAMP,TBD,IP,INV_HOSTNAME,SERIAL_NUMBER,MODEL,LOCATION,SYSLOCATION,TYPE,INV_COMMENT
```

`INV_HOSTNAME` … `INV_COMMENT`: the inventory values of a host added from an inventory CSV (see
*Inventory CSV import*), empty for all other hosts. Logs without these columns (older
versions) stay readable by epinga.py.

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
raw-IP entry. Both non-destructive, restored by switching to another mode. Starting
with `-ph` resolves every hostname first (in parallel): the CLI shows a PLEASE WAIT
box with an elapsed counter meanwhile, the web mode a line in the terminal.

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
against shown name, resolved IP and the inventory fields (CSV hostname, serial
number, model, location, sysLocation, type, comment). Every host keeps being pinged regardless. Empty
value turns it off. CLI: replaces the version banner with `MATCH FILTER '<regex>'
active (N of M hosts shown, all still pinged)`. Invalid regex: error shown, previous
filter unchanged.

## ADV FILTER

Excel-style display filter on the inventory values of a CSV import (*Inventory CSV
import*) for `Model`, `Location`, `sysLocation`, `Type` and `Comment`. Display only -
every host keeps being pinged. Needs hosts with inventory values; without them the
dialog says so.

- **Open**: CLI `V`, web GUI button `ADV FILTER` or key `V`. A separate window; the
  filter only changes when applied.
- **Per field**: check any number of values (with host count; `(empty)` = hosts without
  a value) and choose the mode: `SHOW ONLY CHECKED` (include) or `HIDE CHECKED`
  (exclude). Nothing checked = field not filtered.
- **Combination**: values within a field are ORed, fields are ANDed with each other, with
  the match filter (`M`) and the view. The lists narrow as you select: only values still
  possible with the other fields' selection are offered.
- **Web window**: one list per field with search box, `ALL`/`NONE` (act on the entries
  matching the search), the mode toggle, APPLY, RESET ALL, CLOSE. Lists show the first
  500 entries, the rest via search.
- **CLI window**: `↑`/`↓` field, ENTER opens the value list (`SPACE` check, `I` show-only/hide,
  `A` all, `N` none, ENTER ok, ESC cancel), then `A` APPLY, `R` RESET ALL, ESC CANCEL.
  No search in the CLI list.
- **Banner**: while active the CLI banner shows e.g. `ADV Type not in (Firewall, Switch)`.
- **Reset**: SET REFERENCE and CLEAR ALL turn the filter off. It is not saved
  with `SAVE HOSTS FILE`.

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

# epinga.py 2.35

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
| Filter | text or regex (case-insensitive), hostname + IP + inventory fields (CSV hostname, serial, model, location, sysLocation, type, comment); invalid regex falls back to substring |
| Show | restrict to one state (flapping independent of UP/DOWN/NO-DNS) |
| Sort | name / uptime% / avg RTT / changes; click a header, shift+click adds a tie-breaker (①②③ badge), shift+click again flips direction |
| IP View | toggle primary label hostname↔IP (table + buckets); independent of dedup |
| Deduplication | No dedup / Prefer IP / Prefer hostname - hides the redundant side across table, buckets, top-bar cards; DUPLICATES card is `0` once a mode is active |
| Reset | clears Filter, Show and the inventory drop-downs (sort, IP View and deduplication stay) |
| Download | saves the report exactly as shown (theme/dedup/sort/filter/collapsed state) as a standalone `.html`, client-side; hidden on `file://` |

**Inventory filters** (logs with inventory columns, see *Inventory CSV import*): to the
right of the top-bar counters, one drop-down each for Model, Location, sysLocation,
Type and Comment, listing the values found in the log with their host count (`(empty)` for hosts
without a value). They combine with each other and with Filter/Show and affect the
Host List only. A column without any value gets no drop-down; serial number and CSV
hostname are unique per device and searched via Filter instead. The drop-downs are
narrow; the one in use widens while it has focus and the others move aside. A host's detail shows
all inventory values, the Host List CSV download adds them as columns.

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
