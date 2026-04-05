# RNode_Halow_OTA_Flasher
GUI flasher for https://github.com/I-AM-ENGINEER/RNode_Halow_Firmware

# GitHub Actions build

This repository contains a manual GitHub Actions workflow in:

- `.github/workflows/build-manual.yml`

It expects these files to already exist in the repository root:

- `build_linux.sh`
- `build_win.bat`
- `requirements.txt`
- `rnode-halow-flasher-gui.py`

## What it does

1. Starts manually from the **Actions** tab.
2. Asks for a version, for example `1.4.0` or `1.4.0-beta1`.
3. Replaces `APP_VERSION` in `rnode-halow-flasher-gui.py` during the workflow run.
4. Builds Windows and Linux versions.
5. Uploads ready artifacts from `dist/`.

## Important

The version is injected only inside the workflow workspace.
The workflow does **not** commit that version back to the repository.

