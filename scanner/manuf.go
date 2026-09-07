package scanner

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
)

const (
	mask24 = uint32(0xFFFFFF)
	mask28 = uint32(0xFFFFFFF0)
	mask36 = uint64(0xFFFFFFFFF0)
)

const (
	ManufDir      = "oui"
	ManufFileName = "manuf.txt"
	manufFetchURL = "https://www.wireshark.org/download/automated/data/manuf"
)

var manuf = struct {
	sync.RWMutex
	oui  map[uint32]string
	ma28 map[uint32]string
	ma36 map[uint64]string
}{}

// ManufPath returns the path of the manuf database file inside the project's
// oui directory.
func ManufPath() string {
	return filepath.Join(ManufDir, ManufFileName)
}

// EnsureManuf returns the path to the manuf database, downloading it into the
// project's oui directory with wget if it does not exist yet.
func EnsureManuf() (string, error) {
	path := ManufPath()
	if fi, err := os.Stat(path); err == nil && !fi.IsDir() && fi.Size() > 0 {
		return path, nil
	}

	if err := os.MkdirAll(ManufDir, 0o755); err != nil {
		return "", fmt.Errorf("error creating oui directory: %v", err)
	}

	fmt.Printf("OUI database not found, downloading...\n")
	cmd := exec.Command("wget", "-O", path, manufFetchURL)
	if out, err := cmd.CombinedOutput(); err != nil {
		os.Remove(path)
		return "", fmt.Errorf("error downloading manuf database: %v: %s", err, out)
	}

	return path, nil
}

// LoadManuf reads a Wireshark manuf (OUI) database from the given path and
// replaces the active vendor table. It returns the number of entries loaded.
func LoadManuf(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	oui := make(map[uint32]string)
	ma28 := make(map[uint32]string)
	ma36 := make(map[uint64]string)

	count := 0
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	for scanner.Scan() {
		line := scanner.Text()
		if len(line) == 0 || line[0] == '#' {
			continue
		}

		fields := strings.Split(line, "\t")
		if len(fields) < 3 {
			continue
		}

		block := strings.TrimSpace(fields[0])
		vendor := strings.TrimSpace(fields[2])
		if block == "" || vendor == "" {
			continue
		}

		key, span, ok := parseMACBlock(block)
		if !ok {
			continue
		}
		switch span {
		case 24:
			oui[uint32(key)] = vendor
		case 28:
			ma28[uint32(key)] = vendor
		case 36:
			ma36[key] = vendor
		}
		count++
	}
	if err := scanner.Err(); err != nil {
		return count, err
	}

	manuf.Lock()
	manuf.oui = oui
	manuf.ma28 = ma28
	manuf.ma36 = ma36
	manuf.Unlock()

	return count, nil
}

func parseMACBlock(block string) (uint64, uint8, bool) {
	var span uint8 = 24
	addr, mask, hasMask := strings.Cut(block, "/")
	if hasMask {
		switch mask {
		case "28":
			span = 28
		case "36":
			span = 36
		default:
			return 0, 0, false
		}
	}

	parts := strings.Split(addr, ":")
	if len(parts) == 0 {
		return 0, 0, false
	}

	var base uint64
	for _, p := range parts {
		if len(p) != 2 {
			return 0, 0, false
		}
		var b byte
		for i := 0; i < 2; i++ {
			var d byte
			switch {
			case p[i] >= '0' && p[i] <= '9':
				d = p[i] - '0'
			case p[i] >= 'A' && p[i] <= 'F':
				d = p[i] - 'A' + 10
			case p[i] >= 'a' && p[i] <= 'f':
				d = p[i] - 'a' + 10
			default:
				return 0, 0, false
			}
			b = b<<4 | d
		}
		base = base<<8 | uint64(b)
	}

	switch span {
	case 24:
		return base & uint64(mask24), 24, true
	case 28:
		return base & uint64(mask28), 28, true
	default:
		return base & mask36, 36, true
	}
}

// LookupVendor resolves a MAC address to a vendor name using the loaded
// Wireshark manuf database. It prefers the most specific (longest) match:
// 36-bit before 28-bit before 24-bit OUI.
func LookupVendor(mac net.HardwareAddr) string {
	if len(mac) < 3 {
		return "Unknown"
	}

	mac36 := uint64(binary.BigEndian.Uint32(mac[:4]))<<8 | uint64(mac[4])
	mac28 := uint32(binary.BigEndian.Uint32(mac[:4]))
	mac24 := uint32(binary.BigEndian.Uint16(mac[:2]))<<8 | uint32(mac[2])

	manuf.RLock()
	if v, ok := manuf.ma36[mac36&mask36]; ok {
		manuf.RUnlock()
		return v
	}
	if v, ok := manuf.ma28[mac28&mask28]; ok {
		manuf.RUnlock()
		return v
	}
	if v, ok := manuf.oui[mac24&mask24]; ok {
		manuf.RUnlock()
		return v
	}
	manuf.RUnlock()

	return "Unknown"
}
