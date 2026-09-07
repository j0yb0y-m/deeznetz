package scanner

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

var commonPorts = []int{
	21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
	1433, 1723, 3306, 3389, 5432, 5900, 6379, 7001, 8000, 8008, 8080,
	8443, 8888, 9200, 27017,
}

var knownServices = map[int]string{
	20:    "ftp-data",
	21:    "ftp",
	22:    "ssh",
	23:    "telnet",
	25:    "smtp",
	53:    "domain",
	67:    "dhcp",
	68:    "dhcp",
	69:    "tftp",
	80:    "http",
	110:   "pop3",
	111:   "rpcbind",
	119:   "nntp",
	123:   "ntp",
	135:   "msrpc",
	137:   "netbios-ns",
	138:   "netbios-dgm",
	139:   "netbios-ssn",
	143:   "imap",
	161:   "snmp",
	162:   "snmptrap",
	389:   "ldap",
	443:   "https",
	445:   "microsoft-ds",
	465:   "smtps",
	514:   "syslog",
	587:   "submission",
	631:   "ipp",
	636:   "ldaps",
	873:   "rsync",
	993:   "imaps",
	995:   "pop3s",
	1080:  "socks",
	1433:  "ms-sql",
	1521:  "oracle",
	1723:  "pptp",
	3306:  "mysql",
	3389:  "rdp",
	5432:  "postgresql",
	5900:  "vnc",
	6379:  "redis",
	7001:  "weblogic",
	8000:  "http-alt",
	8008:  "http-alt",
	8080:  "http-proxy",
	8443:  "https-alt",
	8888:  "http-alt",
	9200:  "elasticsearch",
	27017: "mongodb",
}

func CommonPorts() []int {
	ports := make([]int, len(commonPorts))
	copy(ports, commonPorts)
	return ports
}

func parsePortRange(spec string) ([]int, error) {
	if loStr, hiStr, ok := strings.Cut(spec, "-"); ok {
		lo, err := strconv.Atoi(strings.TrimSpace(loStr))
		if err != nil {
			return nil, fmt.Errorf("invalid port range %q", spec)
		}
		hi, err := strconv.Atoi(strings.TrimSpace(hiStr))
		if err != nil {
			return nil, fmt.Errorf("invalid port range %q", spec)
		}
		if lo < 1 || hi > 65535 || lo > hi {
			return nil, fmt.Errorf("invalid port range %q", spec)
		}
		ports := make([]int, 0, hi-lo+1)
		for p := lo; p <= hi; p++ {
			ports = append(ports, p)
		}
		return ports, nil
	}

	port, err := strconv.Atoi(strings.TrimSpace(spec))
	if err != nil {
		return nil, fmt.Errorf("invalid port %q", spec)
	}
	if port < 1 || port > 65535 {
		return nil, fmt.Errorf("port out of range: %d", port)
	}
	return []int{port}, nil
}

func ParsePorts(spec string) ([]int, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return CommonPorts(), nil
	}

	seen := make(map[int]struct{})
	for _, part := range strings.Split(spec, ",") {
		ports, err := parsePortRange(part)
		if err != nil {
			return nil, err
		}
		for _, p := range ports {
			seen[p] = struct{}{}
		}
	}

	ports := make([]int, 0, len(seen))
	for p := range seen {
		ports = append(ports, p)
	}
	sort.Ints(ports)
	return ports, nil
}

func KnownService(port int) string {
	if svc, ok := knownServices[port]; ok {
		return svc
	}
	return ""
}

func ScanHost(ip net.IP, ports []int, timeout time.Duration, workers int) []int {
	if workers < 1 {
		workers = 1
	}
	if timeout <= 0 {
		timeout = 2 * time.Second
	}

	jobs := make(chan int)
	open := make(chan []int)
	var wg sync.WaitGroup

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for port := range jobs {
				conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip.String(), strconv.Itoa(port)), timeout)
				if err == nil {
					conn.Close()
					open <- []int{port}
				}
			}
		}()
	}

	go func() {
		for _, port := range ports {
			jobs <- port
		}
		close(jobs)
		wg.Wait()
		close(open)
	}()

	var openPorts []int
	for batch := range open {
		openPorts = append(openPorts, batch...)
	}
	sort.Ints(openPorts)
	return openPorts
}
