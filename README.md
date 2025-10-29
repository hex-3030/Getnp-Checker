# getnp-checker

Retrieving Kerberos Tickets
hat will allow us to query ASReproastable accounts from the Key Distribution Center. The only thing that's necessary to query accounts is a valid set of usernames which we enumerated previously via Kerbrute.

> **WARNING / Legal:** This tool interacts with Active Directory and authentication services. Do **not** run it against systems you do not own or do not have explicit written permission to test. The author is not responsible for misuse.

## Goal
Run `GetNPUsers.py` against a list of accounts, stream output, and make success indicators obvious by printing them in color and saving findings to a local artifact file for later review.


## Features
- ANSI-colored results (choose green/red for success)
- Detects `$krb5asrep$23$`, "getting its TGT", `AS-REP`, `NTLM` and other patterns
- Takes users via embedded list or `--users-file`
- `--getnp`, `--domain`, `--extra-flags`, and `--timeout` options
- Logs per-run output to `logs/` and appends artifacts to `found_results.txt`

## Requirements
- Python 3 (for the Python runner)  
- `GetNPUsers.py` from Impacket (make sure it's installed and available)  
- Bash (for the Bash script)  
- Terminal that supports ANSI colors (for colored output)

## Usage examples

### Bash (quick)
```bash
# example with included Python script
./Check_GetNPUsers.py  --domain spookysec.local --success-color red

