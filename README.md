# eping.py 1.42

Continuous ICMP reachability monitor built on top of `fping`. Scans a host list in a
loop and reports each host as UP, DOWN or NO-DNS, counting state changes over time.
Output is either a curses terminal UI (default) or a self-hosted web GUI.

Written by Ewald Jeitler — <https://www.jeitler.guru>

## Requirements

- Python 3.6 or newer
- `fping` in `$PATH` (`apt install fping`, `brew install fping`)
- A terminal supporting `curs_set()` for CLI mode

`--check-source` is used automatically if the installed fping supports it (5.0+).

## Quick start

```sh
./eping.py                                  # CLI, uses/creates eping-hosts.txt
./eping.py -n 172.17.16.0/20                # scan a network
./eping.py -web                             # web GUI on http://<host>:8080
./eping.py -web -port 9000 -bind 127.0.0.1  # different port, local only
```

Without arguments a sample `eping-hosts.txt` is created. Starting with no hosts at all
(`-df`) is valid — hosts can be added at runtime.

## Host sources

Combinable in one invocation:

| Source | Option |
|---|---|
| Host file (IPs, hostnames, FQDNs) | `-f FILE`, disable with `-df` |
| CIDR network | `-n`, `-n1` … `-n4` (mask /13 … /32) |
| IP range | `-r`, `-r1` … `-r4` (`-r 10.0.0.1 10.0.0.99`) |

Limits: 512000 hosts total, 524288 addresses per range. Duplicates are removed.
CIDR expansion includes network and broadcast addresses.

## CLI mode

Sorted table (IPv4 numerically, then hostnames), laid out in as many 64-column blocks
as the terminal width allows. Green = UP, red = DOWN. Columns: hostname/IP, state, RTT
in ms, timestamp of the last state change, number of changes.

| Key | Action |
|---|---|
| `U` | UP-ONLY — show and probe only hosts currently UP; press again to restore |
| `A` | add host — IP, hostname, CIDR or `ip1-ip2` |
| `F` | add hosts from a file |
| `D` | delete host — same input formats as add |
| `S` | set reference — the list currently shown becomes the new base list |
| `C` | clear all hosts and their state |
| `R` | redraw the screen |
| `E` | exit |

Dialogs are confirmed with ENTER, cancelled with ESC or empty input. The key bar
switches to shorter labels on narrow terminals. A `PLEASE WAIT` box with an elapsed
counter is shown whenever the screen was cleared and no results are available yet.

Keys are handled while a scan is running: pressing one aborts the current round, so the
UI reacts in about 0.15 s instead of after the full cycle. Aborting is safe — a host
with no fping output keeps its previous state and is never reported DOWN.

## Web GUI (`-web`)

Serves a single self-contained page; no external resources are loaded.

- Table in CLI-style columns, filled top to bottom, then the next column to the right.
  The number of rows per column is derived from the measured row height and the window
  size, so shrinking the font shows more hosts. Horizontal scrolling if it does not fit.
- Font size 6–28 px via slider, `A−`/`A+` or the `+`/`−` keys; stored in `localStorage`.
- Column headers sort the whole list (IPv4-aware).
- Buttons: UP-ONLY, ADD HOST, DEL HOST, UPLOAD FILE, SET REFERENCE, CLEAR ALL, EXIT.
  Keys `U A D F S C` work as in CLI mode. The text field feeds both ADD and DEL; `A`/`D`
  preselect the mode.
- Host files can be uploaded via the button or dropped anywhere on the page
  (max 16 MB, `#` comments and comma/semicolon separators are understood).
- Commands are acknowledged immediately, and a click aborts the running round.

### HTTP API

| Method | Path | Body | Purpose |
|---|---|---|---|
| GET | `/` | — | the page |
| GET | `/api/status` | — | JSON: rows, counters, scan and phase info |
| POST | `/api/command` | `{"cmd":"up_only\|add\|del\|set_ref\|clear\|exit","value":"..."}` | control |
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
`-f` hostfile · `-df` disable hostfile · `-n`/`-n1..4` CIDR · `-r`/`-r1..4` IP range

### Probing
| Option | Default | Meaning |
|---|---|---|
| `-t` | 250 | initial per-target timeout in ms |
| `-B` | 1.5 | backoff factor applied to `-t` on each retry |
| `-re` | 3 | retries for UP and unknown hosts |
| `-dr` | 1 | retries for confirmed DOWN hosts (`-1` = same as everything else) |
| `-ds` | 4 | spread DOWN hosts over N rounds (`1` = all every round) |
| `-fs` | 10 | every Nth round probes everything fully (`0` = never) |
| `-cf` | 2 | consecutive DOWN observations before leaving UP (`1` = off) |
| `-ra` | 1000 | ICMP packets per second |
| `-i` | auto | fixed send interval in ms, overrides `-ra`; `0` = unpaced |
| `-p` | auto | fping processes per group (auto = 1, max 32) |
| `-dns` | 300 | hostname cache TTL in seconds (`0` = off) |
| `-ncs` | off | do not pass `--check-source` to fping |
| `-w` | 0.5 | pause between rounds in seconds |
| `-up` | 0 | learning phase: after N rounds keep only hosts seen UP |

### Output
| Option | Default | Meaning |
|---|---|---|
| `-o` | auto | CSV log file name |
| `-dl` | — | disable logging |
| `-cl` | — | delete all `eping-*` files and exit |
| `-tz` | 0 | timezone offset in hours (−24 … 24) |
| `-dg` | off | show cycle time breakdown per phase and retry group |
| `-du` | — | disable the online version check |
| `-web` | off | web GUI instead of CLI |
| `-port` | 8080 | web GUI port |
| `-bind` | 0.0.0.0 | web GUI bind address |

## Logging

Unless `-dl` is given, every round appends to `eping-log_YYYY-MM-DD_HH:MM:SS.csv`
(or `-o FILE`):

```
TIMESTAMP,HOSTNAME,PREVIOUS_STATE,CURRENT_STATE,RTT,NO_OF_CHANGES,CHANGE_TIMESTAMP,TBD
```

`TBD` holds the number of currently suppressed DOWN observations (see `-cf`).

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
