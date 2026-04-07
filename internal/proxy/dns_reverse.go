package proxy

import (
	"encoding/binary"
	"net"
	"sync"
	"time"
)

// ReverseDNSCache maps IP addresses to hostnames based on observed DNS
// responses. This enables the SOCKS5 handler to recover the original hostname
// when tun2proxy sends IP-only CONNECT requests (tun2proxy operates at the
// network level and only sees resolved IPs, not hostnames).
//
// Entries expire after 10 minutes. The cache is bounded to 10000 entries.
type ReverseDNSCache struct {
	mu      sync.RWMutex
	entries map[string]reverseDNSEntry
}

type reverseDNSEntry struct {
	hostname string
	addedAt  time.Time
}

const (
	reverseDNSTTL     = 10 * time.Minute
	reverseDNSMaxSize = 10000
)

// NewReverseDNSCache creates a new reverse DNS cache.
func NewReverseDNSCache() *ReverseDNSCache {
	return &ReverseDNSCache{
		entries: make(map[string]reverseDNSEntry, 256),
	}
}

// Store adds an IP -> hostname mapping to the cache.
func (c *ReverseDNSCache) Store(ip, hostname string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.entries) >= reverseDNSMaxSize {
		c.evictExpiredLocked()
	}
	if len(c.entries) >= reverseDNSMaxSize {
		return
	}

	c.entries[ip] = reverseDNSEntry{
		hostname: hostname,
		addedAt:  time.Now(),
	}
}

// Lookup returns the hostname for an IP, or empty string if not found or expired.
func (c *ReverseDNSCache) Lookup(ip string) string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, ok := c.entries[ip]
	if !ok {
		return ""
	}
	if time.Since(entry.addedAt) > reverseDNSTTL {
		return ""
	}
	return entry.hostname
}

// PopulateFromResponse parses a DNS response and extracts A/AAAA records,
// storing the IP -> hostname mappings.
func (c *ReverseDNSCache) PopulateFromResponse(hostname string, resp []byte) {
	if len(resp) < dnsHeaderLen {
		return
	}

	flags := binary.BigEndian.Uint16(resp[2:4])
	if flags&dnsFlagQR == 0 {
		return // not a response
	}
	if flags&0x000F != 0 {
		return // error response
	}

	qdcount := int(binary.BigEndian.Uint16(resp[4:6]))
	ancount := int(binary.BigEndian.Uint16(resp[6:8]))
	if ancount == 0 {
		return
	}

	// Skip question section.
	offset := dnsHeaderLen
	for i := 0; i < qdcount; i++ {
		_, newOffset, err := parseDNSName(resp, offset)
		if err != nil {
			return
		}
		offset = newOffset + 4
		if offset > len(resp) {
			return
		}
	}

	// Parse answer records.
	for i := 0; i < ancount; i++ {
		_, newOffset, err := parseDNSName(resp, offset)
		if err != nil {
			return
		}
		offset = newOffset
		if offset+10 > len(resp) {
			return
		}

		rrType := binary.BigEndian.Uint16(resp[offset : offset+2])
		rdLength := binary.BigEndian.Uint16(resp[offset+8 : offset+10])
		offset += 10

		if offset+int(rdLength) > len(resp) {
			return
		}

		switch rrType {
		case dnsTypeA:
			if rdLength == 4 {
				ip := net.IPv4(resp[offset], resp[offset+1], resp[offset+2], resp[offset+3])
				c.Store(ip.String(), hostname)
			}
		case dnsTypeAAAA:
			if rdLength == 16 {
				ip := net.IP(resp[offset : offset+16])
				c.Store(ip.String(), hostname)
			}
		}

		offset += int(rdLength)
	}
}

func (c *ReverseDNSCache) evictExpiredLocked() {
	now := time.Now()
	for ip, entry := range c.entries {
		if now.Sub(entry.addedAt) > reverseDNSTTL {
			delete(c.entries, ip)
		}
	}
}
