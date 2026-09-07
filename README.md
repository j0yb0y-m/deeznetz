# deeznetz

A lightweight network packet sniffer written in Go, using
[gopacket](https://github.com/google/gopacket). It captures live traffic,
decodes DNS queries/responses and HTTP application payloads, and can save
captures to `.pcap` files.

## Features

- Live packet capture on any network interface
- DNS query/response decoding (questions, answers, opcodes, response codes)
- HTTP application-layer payload inspection
- Hex/ASCII dumps of raw payloads
- BPF filter support
- Write captures to `.pcap` files
- Graceful shutdown on `Ctrl+C`

## Requirements

- Go 1.27+
- libpcap on Linux (or Npcap/WinPcap on Windows)
- Root/admin privileges to capture on a network interface

## Build

```sh
go build
```

## Usage

```sh
sudo ./deeznetz -i eth0 -f "tcp port 80" -o capture.pcap
```

### Flags

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