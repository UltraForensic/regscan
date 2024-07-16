# regscan

Registry scanner for Windows forensic investigation

## Usage

Download latest Windows executable binary from [Releases](https://github.com/UltraForensic/regscan/releases) page and follow the usage below.

```
Usage: regscan.exe [OPTIONS] --dir <TARGET> --tsv <TSV>

Options:
  -d, --dir <TARGET>  Target directory containing registry hive and transaction log files to process.
  -t, --tsv <TSV>     File name to save TSV formatted results to.
  -r, --recover       Recover deleted entry and analyze (this option might need extra time to process).
  -s, --stdout        Output the results also to the standard output.
  -h, --help          Print help
```

I have not tested if this tool works properly on Linux or macOS platform.
But you may try it out by running or building binary by your own.

## Contribution

Contribution is always welcome!
This is almost my first project that uses Rust, and I guess my coding / design pattern is horrible.
Please feel free to send [PR](https://github.com/UltraForensic/regscan/pulls) or create an [issue](https://github.com/UltraForensic/regscan/issues) to make this project better.

## Special Thanks

This software uses [notatin](https://github.com/strozfriedberg/notatin) as Windows registry file parser.
Thank you very much for making this work and publishing.

## Copyright

Copyright 2024 Naoki Takayama. regscan is licensed under the Apache License, Version 2.0.
