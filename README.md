# regscan

Windows registry file scanner for fast forensics

## Usage

Download latest Windows executable binary from [Releases](https://github.com/UltraForensic/regscan/releases) page and follow the usage below.

```
Usage: regscan.exe [OPTIONS] --dir <TARGET> --tsv <TSV>

Options:
  -d, --dir <TARGET>  Target directory containing registry hive and transaction log files to process.
  -t, --tsv <TSV>     File name to save TSV formatted results to.
  -n, --noisy         Disable automatic filter on some rule (eg. services) and output all results
  -r, --recover       Recover deleted entry and analyze (this option might need extra time to process).
  -s, --stdout        Output the results also to the standard output.
  -h, --help          Print help
```

I have not tested if this tool works properly on Linux or macOS platform.
But you may try it out by running or building binary by your own.

## Contribution

Contribution is always welcome!
Please feel free to create a [pull request](https://github.com/UltraForensic/regscan/pulls) or [issue](https://github.com/UltraForensic/regscan/issues) to make this project better.

## Special Thanks

This software uses [notatin](https://github.com/strozfriedberg/notatin) to parse Windows registry file.
Thank you very much for making this amazing work.

## Copyright

Copyright 2024 Naoki Takayama. regscan is licensed under the Apache License, Version 2.0.
