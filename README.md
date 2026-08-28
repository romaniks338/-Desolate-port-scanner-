# -Desolate-port-scanner-
High-performance multi-threaded TCP/UDP port scanner written in modern C++17. Supports DNS resolution, Nmap-style CLI flags, version detection and custom thread pools.

High-performance multi-threaded TCP/UDP port scanner written in modern C++17.

## Features

- **TCP Connect** (`-sT`), **SYN Stealth** (`-sS`) and **UDP** (`-sU`) scanning
- **DNS resolution** — scan by domain or IP address
- **Version detection** (`-sV`) via banner grabbing
- **Full port range** support (`-p 1-65535` or `-p-`)
- **Multi-threaded** engine with adjustable thread pool (`-j`)
- **Nmap-style CLI** with familiar flags (`-p`, `-v`, `-oN`, `--show-all`)
- **Cross-platform** — Linux, macOS, Windows

## Build

```bash
mkdir build && cd build
cmake ..
cmake --build .
```

## Usage
./portscan <target> options

## Examples

# Scan specific ports on domain
./portscan scanme.nmap.org -p 22,80,443

# Scan all 65535 ports with 500 threads
./portscan 192.168.1.1 -p 1-65535 -j 500 --max-rtt-timeout 300

# SYN stealth scan (Linux + root)
sudo ./portscan 192.168.1.1 -sS -p 1-1000

# UDP scan with verbose output
./portscan 8.8.8.8 -sU -p 53,161 -v

# Version detection + save to file
./portscan example.com -p 22,80,443 -sV -oN results.txt

## Options

Flag	Description	
`-sT`	TCP connect scan (default)	
`-sS`	TCP SYN stealth scan	
`-sU`	UDP scan	
`-sV`	Version detection (banner grabbing)	
`-p <ports>`	Port selection: `80`, `1-1000`, `22,80,443`	
`-p-`	Scan all 65535 ports	
`-j <n>`	Thread count (default: 100)	
`--max-rtt-timeout <ms>`	Timeout per port (default: 1000)	
`-v`	Verbose mode	
`--show-all`	Show closed ports in output	
`-oN <file>`	Save results to file	
`-Pn`	Skip host discovery	

