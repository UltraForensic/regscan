# regscan

- Uses [notatin](https://github.com/strozfriedberg/notatin) as a Windows registry file parser

## Usage

Download built Windows binary from [Releases](https://github.com/UltraForensic/regscan/releases) page.

```
Usage: regscan.exe [OPTIONS] --dir <TARGET> --csv <CSV>

Options:
  -d, --dir <TARGET>  Target directory containing registry hive and transaction log files to process.
  -c, --csv <CSV>     File name to save CSV formatted results to.
  -r, --recover       Recover deleted entry and analyze (this option might need extra time to process).
  -s, --stdout        Output the results also to the standard output.
  -h, --help          Print help
```


## Copyright

Copyright 2024 Naoki Takayama. regscan is licensed under the Apache License, Version 2.0.
