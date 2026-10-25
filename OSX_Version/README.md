# eping for macOS

Web GUI version of [eping](https://github.com/ewaldj/eping) for macOS 10.13+ (Apple Silicon and Intel).
A small launcher app (`eping.app`) starts eping in the background, opens the web GUI and offers
Start / Stop / Restart / Change port / Update in a dialog. Same functions as the Windows version.
Python 3.11 (for Apple Silicon and Intel) and fping 5.5 (universal) are included.

## Download

| Variant | File | Use |
|---|---|---|
| Installer | [eping-installer-mac.zip](https://github.com/ewaldj/eping/raw/main/OSX_Version/eping-installer-mac.zip) | Unzip, open `eping-installer.app`: downloads the package and installs it for the current user or all users |
| Portable | [eping-mac.zip](https://github.com/ewaldj/eping/raw/main/OSX_Version/eping-mac.zip) | Unzip anywhere and open `eping.app` |

## First start (apps are not notarized)

macOS blocks downloaded apps from unknown developers. Either right-click the app, choose Open
(macOS 15: System Settings / Privacy & Security / Open Anyway), or run once in Terminal:

```sh
xattr -dr com.apple.quarantine eping-installer.app   # or the eping-mac folder
```

The installer removes the flag from the installed eping files itself.

## Installer

1. Open `eping-installer.app`, press Install.
2. Choose Current user (`~/Applications/eping`) or All users (`/Applications/eping`, asks for the admin password).
3. Start eping from the last dialog. Uninstall: open the installer again and press Uninstall (hosts files and logs are kept).

## Requirements

macOS 10.13+. Nothing else has to be installed: the `python-aarch64` / `python-x86_64` folders and `fping` in the eping folder are used first (system `python3` and Homebrew `fping` are only a fallback).

## Update

The launcher checks `eversions` on GitHub at start and every 6 hours. If `eping.py` / `epinga.py` are
newer, "More... / Update now" replaces them; if `eping-mac` is newer, the whole package is replaced.

## Notes

- The web GUI listens on 127.0.0.1 only; add `-bind 0.0.0.0` to `eping-args.txt` to reach it from the network.
- Terminal (curses) mode: run `eping.py` directly in Terminal.
- Details: <https://www.jeitler.cc>
