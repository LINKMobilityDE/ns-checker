package checker

import (
	"fmt"
	"strings"

	"github.com/LINKMobilityDE/ns-checker/zones"
	"github.com/miekg/dns"
)

// ErrWrongType shows the RR has a wrong type
var ErrWrongType error = fmt.Errorf("wrong RR type")

// cacheReversed contains the resolved part of record as keys. For example, for A/AAAA it would be a PTR record.
// And for PTR records it will be FQDN with trailing dot.
type cacheReversed map[string]dns.RR

// cache contains the record name as a key and cacheReversed as values.
type cache map[string]cacheReversed

// Checker is a helper to
type Checker struct {
	*zones.Records
	a    cache // [ptr]
	aaaa cache
	ptr  cache
}

func (c *Checker) prepare() (err error) {
	if err = c.prepareA(); err != nil {
		return err
	}
	if err = c.prepareAAAA(); err != nil {
		return err
	}
	if err = c.preparePTR(); err != nil {
		return err
	}
	return nil
}

func (c *Checker) prepareA() error {
	if c.a != nil {
		return nil
	}
	records := c.GetByType(dns.TypeA)
	c.a = make(cache, len(records))
	for _, r := range records {
		a := r.(*dns.A)
		ptr, err := dns.ReverseAddr(a.A.String())
		if err != nil {
			// It's highly unlikely, but we need to process it
			c.a = nil
			return fmt.Errorf("unable to reverse the A record: %v", a.A)
		}
		if cr, ok := c.a[a.Header().Name]; ok {
			cr[ptr] = r
		} else {
			cr = cacheReversed{ptr: r}
			c.a[a.Header().Name] = cr
		}
	}
	return nil
}

func (c *Checker) prepareAAAA() error {
	if c.aaaa != nil {
		return nil
	}
	records := c.GetByType(dns.TypeAAAA)
	c.aaaa = make(cache, len(records))
	for _, r := range records {
		aaaa := r.(*dns.AAAA)
		ptr, err := dns.ReverseAddr(aaaa.AAAA.String())
		if err != nil {
			// It's highly unlikely, but we need to process it
			c.aaaa = nil
			return fmt.Errorf("unable to reverse the AAAA record: %v", aaaa.AAAA)
		}
		if cr, ok := c.aaaa[aaaa.Header().Name]; ok {
			cr[ptr] = r
		} else {
			cr = cacheReversed{ptr: r}
			c.aaaa[aaaa.Header().Name] = cr
		}
	}
	return nil
}

func (c *Checker) preparePTR() error {
	if c.ptr != nil {
		return nil
	}
	records := c.GetByType(dns.TypePTR)
	c.ptr = make(cache, len(records))
	for _, r := range records {
		ptr := r.(*dns.PTR)
		if !(strings.HasSuffix(ptr.Hdr.Name, ".in-addr.arpa.") || strings.HasSuffix(ptr.Hdr.Name, ".ip6.arpa.")) {
			c.ptr = nil
			return fmt.Errorf("PTR record doesn't match IPv4 or IPv6: %v", ptr.Hdr.Name)
		}
		if cr, ok := c.ptr[ptr.Hdr.Name]; ok {
			cr[ptr.Ptr] = r
		} else {
			cr = cacheReversed{ptr.Ptr: r}
			c.ptr[ptr.Hdr.Name] = cr
		}
	}
	return nil
}

// CheckA checks if all A records in the object have according PTR record. If some records are not found
// in PTR, they will be returned with error.
func (c *Checker) CheckA() (failed []dns.RR, err error) {
	if err := c.prepare(); err != nil {
		return nil, err
	}
	// Check that for each A exists any PTR
	for _, cr := range c.a {
		success := false
		current := make([]dns.RR, 0, len(cr))
		for ptr := range cr {
			if _, success = c.ptr[ptr]; success {
				break
			}
			current = append(current, cr[ptr])
		}
		if !success {
			failed = append(failed, current...)
		}
	}
	return failed, err
}

// CheckAAAA checks if all AAAA records in the object have according PTR record. If some records are not found
// in PTR, they will be returned with error.
func (c *Checker) CheckAAAA() (failed []dns.RR, err error) {
	if err := c.prepare(); err != nil {
		return nil, err
	}
	// Check that for each A exists any PTR
	for _, cr := range c.aaaa {
		success := false
		current := make([]dns.RR, 0, len(cr))
		for ptr := range cr {
			if _, success = c.ptr[ptr]; success {
				break
			}
			current = append(current, cr[ptr])
		}
		if !success {
			failed = append(failed, current...)
		}
	}
	return failed, err
}

// CheckPTR checks if all PTR records in the object have according A/AAAA records. If some records are not found
// in PTR, they will be returned with error.
func (c *Checker) CheckPTR() (failed []dns.RR, err error) {
	if err := c.prepare(); err != nil {
		return nil, err
	}
	// Check that for each PTR exists proper A/AAAA
	for ptr, cr := range c.ptr {
		success := false
		current := make([]dns.RR, 0, len(cr))
		check := c.a
		if strings.HasSuffix(ptr, ".ip6.arpa.") {
			check = c.aaaa
		}
		for fqdn := range cr {
			if cr, firstSuccess := check[fqdn]; firstSuccess {
				if _, success = cr[ptr]; success {
					break
				}
			}
			current = append(current, cr[fqdn])
		}
		if !success {
			failed = append(failed, current...)
		}
	}
	return failed, err
}

func FormatFailed(failed []dns.RR, sep string) string {
	if len(failed) == 0 {
		return ""
	}
	seen := map[string]struct{}{}
	sb := new(strings.Builder)
	sb.WriteString(failed[0].Header().Name)
	for i := 1; i < len(failed); i++ {
		if _, ok := seen[failed[i].Header().Name]; ok {
			continue
		}
		seen[failed[i].Header().Name] = struct{}{}
		sb.WriteString(sep)
		sb.WriteString(failed[i].Header().Name)
	}
	return sb.String()
}
