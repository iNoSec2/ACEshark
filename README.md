# ACEshark
[![Python](https://img.shields.io/badge/Python-%E2%89%A5%203.12-yellow.svg)](https://www.python.org/) 
<img src="https://img.shields.io/badge/PowerShell-%E2%89%A5%20v3.0-blue">
<img src="https://img.shields.io/badge/Developed%20on-kali%20linux-blueviolet">
[![License](https://img.shields.io/badge/License-BSD-red.svg)](https://github.com/t3l3machus/ACEshark/blob/main/LICENSE)
<img src="https://img.shields.io/badge/Maintained%3F-Yes-96c40f">
<img src="https://img.shields.io/badge/Experimental-ff0000">

## What is it?
ACEshark is a utility designed for rapid extraction and analysis of Windows service configurations and Access Control Entries, eliminating the need for tools like `accesschk.exe` or other non-native binaries.

## Why?
- Efficiently identify and analyze service permissions to uncover potential privilege escalation vectors (changing the `binpath` of a service and restarting it).  
- Audit service permissions for specific users or across all groups and accounts.

## How it works
Running ACEshark starts an HTTP/HTTPS server to act as a listener for service configurations and Access Control Entries. It generates a small extractor script based on the specified options, which the user runs on the target machine. ACEshark then retrieves and processes the data, providing a detailed analysis.

ACEshark generates a log file for each extracted services configuration, allowing reports to be regenerated if needed.

## ❗Important
1. Even if a service is characterized as a great candidate for privilege escalation according to its ACEs and configuration, there are other Windows security features that may prevent you from actually abusing it.
2. This is probably not going to be particularly stealthy.
3. Using this tool against hosts that you do not have explicit permission to test is illegal. You are responsible for any trouble you may cause by using this tool.

## Overview
![image](https://github.com/user-attachments/assets/e292d618-1aa2-4431-953f-96c9a888e2a5)

![aceshark2](https://github.com/user-attachments/assets/09789877-665d-476a-8c2c-a86000380614)

## Installation
1. Clone the repository:
```
git clone https://github.com/t3l3machus/ACEshark
```

2. Install dependencies:
```
cd ACEshark  
pip3 install -r requirements.txt  
```
You’re all set.

**Note**: If automatic copy to clipboard of the extractor script fails, you may need to install a copy/paste mechanism, like `sudo apt-get install xclip` or `sudo apt-get install xselect`:

## Usage
```
ACEshark.py [-h] [-s SERVER_ADDRESS] [-p PORT] [-c CERTFILE] [-k KEYFILE] [-f FILE_INPUT] [-i] [-g] [-a] [-x CUSTOM_MODE] [-lg] [-gs] [-e] [-z CONFIG_FILENAME] [-d DELIMITER] [-q] [-v]

ACEshark is a utility designed for rapid extraction and analysis of Windows service configurations and Access Control Entries, eliminating the need for tools like accesschk.exe or other non-native binaries.

options:
  -h, --help            show this help message and exit

BASIC OPTIONS:
  -s SERVER_ADDRESS, --server-address SERVER_ADDRESS
                        Your server IP or domain name. This option cannot be used with -f.
  -p PORT, --port PORT  HTTP / HTTPS server port (default: 80 / 443).
  -c CERTFILE, --certfile CERTFILE
                        Optional: Path to the TLS certificate for enabling HTTPS.
  -k KEYFILE, --keyfile KEYFILE
                        Optional: Path to the private key for the TLS certificate.
  -f FILE_INPUT, --file-input FILE_INPUT
                        ACEshark creates log files every time you run the extractor script on a machine (stored in ~/.ACEshark). Use this option to regenerate a services config analysis from a log file. This
                        option cannot be used with -s.

MODES:
  -i, --interesting-only
                        List only those service ACEs that can potentially be abused by your user, based on their SID and group membership, with at least (WRITE_PROPERTY AND CONTROL_ACCESS) or GENERIC_ALL
                        privileges.
  -g, --great-candidates
                        Similar to --interesting-only but with stricter criteria. A service is labeled as a great candidate for privilege escalation if the service's START_TYPE == DEMAND_START AND TYPE ==
                        WIN32_OWN_PROCESS AND your user has (WRITE_PROPERTY AND CONTROL_ACCESS) OR GENERIC_ALL privileges.
  -a, --audit           Audit mode. Analyzes all service ACEs without searching for user-specific abusable services (Long output). This option also downgrades the extractor script, omitting the retrieval of
                        the current user's SID and group membership information. By default, the WRITE_PROPERTY and CONTROL_ACCESS rights are highlighted for simplicity when they are present.
  -x CUSTOM_MODE, --custom-mode CUSTOM_MODE
                        Provide a comma-separated list of integers representing the generic access rights to match. Only service ACEs that your user may be able to abuse, based on their SID and group
                        membership matching the provided rights, will be listed. Use -lg to list all predefined generic access rights.
  -lg, --list-generic   List all predefined generic access rights.

EXTRACTOR MODIFICATIONS:
  -gs, --get-service    This option modifies the extractor script to use Get-Service for listing available services. While cleaner, it may not work with a low-privileged account. The default Get-ChildItem
                        approach, though less elegant, is more likely to succeed in most cases.
  -e, --encode          Generate Base64-encoded services configuration extractor script instead of raw PowerShell.
  -z CONFIG_FILENAME, --config-filename CONFIG_FILENAME
                        Change the temporary filename used to store the extracted services configuration before transferring the data via HTTP (default: sc.txt).
  -d DELIMITER, --delimiter DELIMITER
                        Change the delimiter value used for service config serialization (default: #~). Use this option cautiously. It is rarely needed.

OUTPUT:
  -q, --quiet           Do not print the banner on startup.
  -v, --verbose         Print the user's SID and group membership info as well (not applicable in Audit mode).
```

## Special Thanks
[Pri3st](https://www.github.com/Pri3st), for helping test the tool!
