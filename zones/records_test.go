package zones

import (
	"io/fs"
	"sort"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func prepareTest(t *testing.T) (*assert.Assertions, *Records) {
	assert := assert.New(t)
	rr := new(Records)
	err := rr.parse("tests/working/subzone.zone.tld.zone")
	assert.NoError(err)
	return assert, rr
}

func TestRecordsParse(t *testing.T) {
	assert, rr := prepareTest(t)
	assert.Len(rr.list, 25)
	assert.Len(rr.types[1], 16)
	assert.Len(rr.types[2], 3)
	assert.Len(rr.types[5], 4)
	assert.Len(rr.types[6], 1)
	assert.Len(rr.types[28], 1)
	err := rr.parse("tests/working/10.0.128.rev")
	assert.NoError(err)
	assert.Len(rr.list, 32)
	assert.Len(rr.types[1], 16)
	assert.Len(rr.types[2], 6)
	assert.Len(rr.types[5], 4)
	assert.Len(rr.types[6], 2)
	assert.Len(rr.types[28], 1)
	assert.Len(rr.types[12], 3)
}

func TestParseDirectory(t *testing.T) {
	assert := assert.New(t)
	rr, err := ParseDirectory("tests/working")
	assert.NoError(err)
	assert.Len(rr.list, 32)
	assert.Len(rr.types, 6)

	rr, err = ParseDirectory("tests/broken_open")
	assert.Error(err)
	var pathErr *fs.PathError
	assert.ErrorAs(err, &pathErr)

	rr, err = ParseDirectory("tests/broken_zone")
	assert.Error(err)
	var parseErr *dns.ParseError
	assert.ErrorAs(err, &parseErr)

	rr, err = ParseDirectory("tests/non_existent")
	assert.Error(err)
}

func TestRecordsList(t *testing.T) {
	assert, rr := prepareTest(t)
	result := rr.List()
	assert.Equal(rr.list, result)
	// Test result is actually copy
	rr.list = rr.list[:len(rr.list)-1]
	assert.NotEqual(rr.list, result)
	result = rr.List()
	assert.Equal(rr.list, result)
}

func TestRecordsGetByType(t *testing.T) {
	assert, rr := prepareTest(t)
	for _, t := range rr.Types() {
		result := rr.GetByType(t)
		assert.Equal(rr.types[t], result)
		rr.types[t] = rr.types[t][:len(rr.types[t])-1]
		assert.NotEqual(rr.types[t], result)
		result = rr.GetByType(t)
		assert.Equal(rr.types[t], result)
	}
}

func TestRecordsTypes(t *testing.T) {
	assert, rr := prepareTest(t)
	result := rr.Types()
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	assert.Equal([]uint16{1, 2, 5, 6, 28}, result)
}

func TestRecordsTypesString(t *testing.T) {
	assert, rr := prepareTest(t)
	result := rr.TypesString()
	sort.Strings(result)
	expected := []string{"A", "AAAA", "CNAME", "NS", "SOA"}
	assert.Equal(expected, result)
}
