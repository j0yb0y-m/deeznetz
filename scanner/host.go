package scanner

import (
	"net"
	"sort"
	"sync"
	"time"
)

type Host struct {
	IP       net.IP
	MAC      net.HardwareAddr
	Vendor   string
	LastSeen time.Time
}

type HostTable struct {
	mu    sync.RWMutex
	hosts map[string]*Host
}

func NewHostTable() *HostTable {
	return &HostTable{
		hosts: make(map[string]*Host),
	}
}

func (t *HostTable) AddOrUpdate(ip net.IP, mac net.HardwareAddr) {
	if ip == nil || mac == nil {
		return
	}

	key := ip.String()
	now := time.Now()

	t.mu.Lock()
	defer t.mu.Unlock()

	if h, ok := t.hosts[key]; ok {
		if h.MAC.String() != mac.String() {
			h.MAC = mac
			h.Vendor = LookupVendor(mac)
		}
		h.LastSeen = now
		return
	}

	t.hosts[key] = &Host{
		IP:       ip,
		MAC:      mac,
		Vendor:   LookupVendor(mac),
		LastSeen: now,
	}
}

func (t *HostTable) Len() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.hosts)
}

func (t *HostTable) GetAll() []*Host {
	t.mu.RLock()
	defer t.mu.RUnlock()

	hosts := make([]*Host, 0, len(t.hosts))
	for _, h := range t.hosts {
		clone := *h
		hosts = append(hosts, &clone)
	}

	sort.Slice(hosts, func(i, j int) bool {
		return hosts[i].IP.String() < hosts[j].IP.String()
	})

	return hosts
}
