package zones

import (
	"io/fs"
	"os"
	"path/filepath"

	"github.com/miekg/dns"
)

// Records represents the parsed DNS records. It contains a list of all records and grouped by types.
type Records struct {
	list  []dns.RR
	types map[uint16][]dns.RR
}

// ParseDirectory opens all files in dir. This functions assumes that all files in the directory are zone-files.
// includeAllowed is not implemented.
func ParseDirectory(dir string) (*Records, error) {
	rr := new(Records)
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, prevErr error) error {
		if prevErr != nil {
			return prevErr
		}
		if d.IsDir() {
			return nil
		}
		err := rr.parse(p)
		return err
	})

	if err != nil {
		return nil, err
	}

	return rr, nil
}

func (rr *Records) parse(filename string) error {
	r, err := os.OpenFile(filename, os.O_RDONLY, 0)
	if err != nil {
		return err
	}
	parser := dns.NewZoneParser(r, "", filename)
	if rr.types == nil {
		rr.types = make(map[uint16][]dns.RR)
	}
	for r, ok := parser.Next(); ok; r, ok = parser.Next() {
		rr.list = append(rr.list, r)
		if rt, ok := rr.types[r.Header().Rrtype]; ok {
			rr.types[r.Header().Rrtype] = append(rt, r)
		} else {
			rr.types[r.Header().Rrtype] = []dns.RR{r}
		}
	}
	if err := parser.Err(); err != nil {
		return err
	}
	return nil
}

// List returns copy of all records in the object. All records are still pointers, so
// you shouldn't change them.
func (rr *Records) List() []dns.RR {
	crr := make([]dns.RR, len(rr.list))
	copy(crr, rr.list)
	return crr
}

// Merge merges given records into existing
func (rr *Records) Merge(other *Records) {
	rr.list = append(rr.list, other.list...)
	if rr.types == nil {
		rr.types = make(map[uint16][]dns.RR)
	}
	for t, r := range other.types {
		if _, ok := rr.types[t]; ok {
			rr.types[t] = append(rr.types[t], r...)
		} else {
			rr.types[t] = make([]dns.RR, len(r))
			copy(rr.types[t], r)
		}
	}
}

// GetByType returns the records for particular dns.Type. All records are still pointers, so
// you shouldn't change them.
func (rr *Records) GetByType(t uint16) []dns.RR {
	if group, ok := rr.types[t]; ok {
		crr := make([]dns.RR, len(group))
		copy(crr, group)
		return crr
	}
	return nil
}

// Types returns all types in the instance
func (rr *Records) Types() []uint16 {
	types := make([]uint16, 0)
	for t := range rr.types {
		types = append(types, t)
	}
	return types
}

// TypesString returns string representation of all record types in the instance
func (rr *Records) TypesString() []string {
	types := make([]string, 0)
	for t := range rr.types {
		types = append(types, dns.Type(t).String())
	}
	return types
}
