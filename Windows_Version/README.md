# eping for Windows

Web GUI version of [eping](https://github.com/ewaldj/eping) for Windows 10/11 (x64).
Python and fping are bundled, nothing else has to be installed.

## Download

| Variant | File | Use |
|---|---|---|
| Installer | [eping-installer.exe](https://github.com/ewaldj/eping/raw/main/Windows_Version/eping-installer.exe) | Downloads the package, installs it, creates Start menu / desktop shortcuts and an uninstaller |
| Portable | [eping-windows.zip](https://github.com/ewaldj/eping/raw/main/Windows_Version/eping-windows.zip) | Unzip anywhere and run `eping.exe` |

## Installer

1. Run `eping-installer.exe`.
2. Choose per user or all users (admin rights are requested for all users) and press Install.
3. Start eping from the Start menu. Uninstall via Windows Apps or `uninstall.exe`.

## Portable

1. Unzip `eping-windows.zip`.
2. Run `eping.exe`. The web GUI opens at http://127.0.0.1:8080.

Hosts files, logs and reports are stored in the eping folder.

## Update

`eping.exe` checks `eversions` on GitHub at start and every 6 hours. If a newer version
exists, an Update button appears: `eping.py` / `epinga.py` are replaced, or the whole
package if `eping-windows` is newer.

## Notes

- The web GUI listens on 127.0.0.1 only; add `-bind 0.0.0.0` to `eping-args.txt` to reach it from the network.
- Terminal (curses) mode and `-wv` / `-wvc` are not available on Windows.
- If no replies show up, check the firewall (ICMP echo) or start once as Administrator.
- Details: [README-WINDOWS.txt](README-WINDOWS.txt), main project: [eping](https://github.com/ewaldj/eping), <https://www.jeitler.cc>
