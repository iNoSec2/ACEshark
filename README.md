# ACEshark
[![Python](https://img.shields.io/badge/Python-%E2%89%A5%203.12-yellow.svg)](https://www.python.org/) 
<img src="https://img.shields.io/badge/PowerShell-%E2%89%A5%20v3.0-blue">
<img src="https://img.shields.io/badge/Developed%20on-kali%20linux-blueviolet">
[![License](https://img.shields.io/badge/License-BSD-red.svg)](https://github.com/t3l3machus/ACEshark/blob/main/LICENSE.md)
<img src="https://img.shields.io/badge/Maintained%3F-Yes-96c40f">
<img src="https://img.shields.io/badge/Experimental-ff0000">

## What is it?
ACEshark is a utility designed for rapid extraction and analysis of Windows service configurations and Access Control Entries, eliminating the need for tools like accesschk.exe or other non-native binaries.

## Why?
- Efficiently identify and analyze service permissions to uncover potential privilege escalation vectors (changing the `binpath` of a service and restarting it).  
- Audit service permissions for specific users or across all groups and accounts.

## How it works
Running ACEshark starts an HTTP server to act as a listener for service configurations and Access Control Entries. It generates a small extractor script based on the specified options, which the user runs on the target machine. ACEshark then retrieves and processes the data, providing a detailed analysis.

## ❗Important
- Even if a service is characterized as a great candidate for privilege escalation according to its ACEs and configuration, there are other Windows security features that may prevent you from actually abusing it.
- This is probably not going to be particularly stealthy.

## Overview
