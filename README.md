# iocgrep

Quick static triage for "does anything in this directory look obviously
bad." I use this as a first pass over downloaded scripts, extracted
archives, or a web shell someone found - before pulling out anything
heavier. It walks a file or directory, applies a small set of built-in
patterns, and prints every hit with the file and line number.

No external dependencies.

## What it flags out of the box

- IPv4 addresses and URLs
- Long base64-looking blobs (60+ chars) - common for encoded payloads
- PowerShell abuse patterns: `-enc`/`-encodedcommand`, `-nop -w hidden`,
  `DownloadString`/`DownloadFile`/`Net.WebClient`, `IEX`/`Invoke-Expression`
- `certutil -decode` (a known LOLBin trick for smuggling files past AV)
- PHP/JS decode-and-eval patterns (`eval(base64_decode(...))`, `atob(...)`)
- Reverse shell hints (`/dev/tcp/`, `nc -e`, `bash -i >&`)
- A short list of known malware-adjacent keywords (mimikatz, cobaltstrike,
  meterpreter, lsass.dmp, psexec.exe)

## Usage

```
python3 iocgrep.py ./suspicious_dir
python3 iocgrep.py webshell.php --csv hits.csv
python3 iocgrep.py ./suspicious_dir --category ipv4 --category url
```

Bring your own indicators (one per line, `#` for comments, plain strings
or regex both work):

```
python3 iocgrep.py ./suspicious_dir --iocs my_iocs.txt
```

```
[*] Scanned 2 file(s), 12 hit(s)

suspicious.ps1:2  [powershell_download]  DownloadString
suspicious.ps1:3  [base64_blob]  SGVsbG8gV29ybGQgdGhpcyBpcyBhIGZha2UgYmFzZTY0IGJsb2Igb2Yg...
suspicious.ps1:3  [powershell_encoded]  -enc
suspicious.ps1:4  [invoke_expression]  IEX (

[*] Summary:
  powershell_download    2
  ipv4                   3
  ...
```

## Limitations

This is pattern matching over text, not a signature engine or sandbox -
expect both false positives (a legitimate IP in a config file, a base64
image blob) and false negatives (anything obfuscated past these patterns).
Binary files are skipped by extension, not by content sniffing. Treat a
hit here as "worth a closer look," not a verdict.

## License

MIT, see LICENSE.
