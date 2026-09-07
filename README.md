# deeznetz

A lightweight network packet sniffer and ARP scanner written in Go, using
[gopacket](https://github.com/google/gopacket). It captures live traffic,
decodes DNS queries/responses and HTTP application payloads, saves captures
to `.pcap` files, and can discover hosts on a local network via ARP in both
active and passive modes (Netdiscover-style).

## Features

- Live packet capture on any network interface
- DNS query/response decoding (questions, answers, opcodes, response codes)
- HTTP application-layer payload inspection
- Hex/ASCII dumps of raw payloads
- BPF filter support
- Write captures to `.pcap` files
- Graceful shutdown on `Ctrl+C`
- **Active ARP scanning** of a CIDR range (sends ARP requests, collects replies)
- **Passive ARP listening** (silently discovers hosts from ARP traffic)
- MAC vendor (OUI) identification via the Wireshark `manuf` database

## Requirements

- Go 1.27+
- libpcap on Linux (or Npcap/WinPcap on Windows)
- Root/admin privileges to capture on a network interface
- `wget` and network access on first run to fetch the OUI database (optional —
  without it vendors display as "Unknown")

## Build

```sh
go build
```

## Usage

### ARP scanner

```sh
# Active scan of a subnet
sudo ./deeznetz arp -r 192.168.1.0/24

# Active scan with custom interface and timeout
sudo ./deeznetz arp -r 10.0.0.0/24 -i eth0 -timeout 5s

# Passive ARP listening (default when no -r given)
sudo ./deeznetz arp -p -i eth0

# Passive mode is the default
sudo ./deeznetz arp -i eth0
```

ARP subcommand flags:

| Flag | Description |
|------|-------------|
| `-r` | CIDR range to scan (enables active mode) |
| `-p` | Run in passive mode |
| `-i` | Network interface |
| `-timeout` | Response timeout for active scans (default: 3s) |
| `-delay` | Delay between ARP requests (default: 10ms) |

### OUI database

Vendor names are resolved from the Wireshark `manuf` database, which supports
24-, 28- and 36-bit MAC allocations. The database lives at `oui/manuf.txt`
inside the project.

On startup the tool checks for `oui/manuf.txt`; if it is missing it downloads
it automatically:

```sh
wget -O oui/manuf.txt 'https://www.wireshark.org/download/automated/data/manuf'
```

If the download fails (e.g. no network), the tool continues with vendors shown
as `Unknown` and retries on the next run. The `oui/` directory is gitignored.

Example ARP output:

```
Using interface: wlp1s0
Source IP: 192.168.0.109  MAC: dc:41:a9:e1:10:0e
OUI database: oui/manuf.txt

Mode: ACTIVE
======================================
Sending ARP requests to 253 host(s) in 192.168.0.0/24...
Listening for ARP replies (timeout 3s)...

IP               MAC                VENDOR               LAST SEEN
192.168.0.1      aa:bb:cc:dd:ee:ff  Cisco Systems, Inc   19:00:00
192.168.0.109    dc:41:a9:e1:10:0e  Intel Corporate      19:00:00

2 host(s) discovered.
```

### Packet capture

```sh
sudo ./deeznetz -i eth0 -f "tcp port 80" -o capture.pcap
```

Capture flags:

| Flag | Description |
|------|-------------|
| `-i` | Network interface to capture on (default: first non-loopback interface) |
| `-f` | BPF filter expression (e.g., `tcp port 80`) |
| `-o` | Output `.pcap` file path |
| `-s` | Snapshot length in bytes (default: 1600) |

### Example output

```
Sniffing on eth0...
--- [ DNS Query/Response (ID: 0xabcd) ] ---
  QR: false (IsResponse: false) | OpCode: 0 | RCode: 0
  [Question] Domain: example.com | Type: A | Class: IN
---------------------------------------
--- [ HTTP Payload ] ---
GET / HTTP/1.1
Host: example.com
------------------------
```

## License

[MIT](LICENSE)