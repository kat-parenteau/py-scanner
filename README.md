# py-scanner
py-scanner is a safety-first local network scanner built in Python using Nmap. 

It is designed to only scan localhost or private IP ranges, with optional support for user-defined whitelisted IPs. This ensures the tool cannot be used to scan public networks or unknown systems, reinforcing responsible and ethical use.

## Additional Context
After building the first version of py-scanner, I wrote an academic impact statement analyzing how tools like this can support security awareness and safer home-network practices. That work helped guide further improvements to the project’s safety-first design.

Impact Statement: https://docs.google.com/document/d/1Z-YsRTCljWrwD90i1FW1ljNz6bU8bqjRm-VVcqLKLXI/edit?usp=sharing 

## Supported Private Ranges
This tool will **only** scan:
- `127.0.0.0/8` (IPv4 localhost)
- `10.0.0.0/8`
- `172.16.0.0/12`
- `192.168.0.0/16`
- `::1/128` (IPv6 localhost)
- `fc00::/7` (IPv6 unique local addresses)
- plus any IPs listed in an optional whitelist file

Any public IP will stop execution with an error.

## Requirements
- Python 3.x  
- Nmap installed on the system  
- `python-nmap` (or equivalent binding)

### Install dependencies:
- Python package: `pip install python-nmap`
- Install Nmap: `sudo apt-get install nmap` or download from https://nmap.org/download.html

## Usage:
- Default scan on localhost: `python py-scanner-safe.py`
- Private IP: `python py-scanner-safe.py 192.168.1.10`
