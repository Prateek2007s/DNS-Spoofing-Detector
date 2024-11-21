# DNS Spoofing Detector

## Overview
DNS Spoofing Detector is a tool to detect DNS spoofing attempts by monitoring DNS queries and comparing the resolved IP addresses with the DNS response IPs. This helps identify potential mismatches indicating DNS spoofing, a common form of attack where attackers manipulate DNS responses to redirect traffic.

## Features
- Sniffs network traffic for DNS queries.
- Resolves DNS queries to the actual IP addresses.
- Compares the resolved IP with the DNS response IP to detect potential DNS spoofing.
- Alerts when a DNS spoofing attempt is detected.

## Requirements
- Python 3.x
- Dependencies:
  - scapy
  - dnspython

## Installation
To install the necessary dependencies, run the following command:

```bash
pip install -r requirements.txt
