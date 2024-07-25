# regscan

Windows registry file scanner for fast forensics

## Usage

Download latest Windows executable binary from [Releases](https://github.com/UltraForensic/regscan/releases) page and follow the usage below.

```
Usage: regscan.exe [OPTIONS] --target <TARGET> --outdir <OUTDIR>

Options:
  -t, --target <TARGET>  Target directory containing registry hive and transaction log files to process.
  -o, --outdir <OUTDIR>  Output directory to save TSV formatted timeline_results to.
  -n, --noisy            Disable automatic filter on some rule (eg. services) and output all timeline_results
  -r, --recover          Recover deleted entry and analyze (this option might need extra time to process).
  -h, --help             Print help
```

**This tool does not support non-Windows platform (such as macOS/Linux) because it uses Windows native API to decrypt some data inside SAM hive.**

## How to read the result

Following result files will be generated under the specified output directory (using `-o` or `--outdir`):

- `[TIMESTAMP]_[COMPUTERNAME]_ASEPs.tsv`
    - Check for possible malware ASEP entries
- `[TIMESTAMP]_[COMPUTERNAME]_LocalAccounts.tsv`
    - Check for local accounts information on target system
- `[TIMESTAMP]_[COMPUTERNAME]_SystemInfo.tsv`
    - Check for system information of target system
- `[TIMESTAMP]_[COMPUTERNAME]_Timeline.tsv`
    - Check for any suspicious or interesting indicator that has been detected in timeline format

## Contribution

Contribution is always welcome!
Please feel free to create a [pull request](https://github.com/UltraForensic/regscan/pulls) or [issue](https://github.com/UltraForensic/regscan/issues) to make this project better.

## Special Thanks

This software uses [notatin](https://github.com/strozfriedberg/notatin) to parse Windows registry file.
Thank you very much for making this amazing work.

## Copyright

Copyright 2024 Naoki Takayama. regscan is licensed under the Apache License, Version 2.0.
