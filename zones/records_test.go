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
	rr, err := ParseDirectory("tests/working", false)
	assert.NoError(err)
	assert.Len(rr.list, 32)
	assert.Len(rr.types, 6)

	var pathErr *fs.PathError
	rr, err = ParseDirectory("tests/broken_open", false)
	assert.Nil(rr)
	assert.Error(err)
	assert.ErrorAs(err, &pathErr)
	rr, err = ParseDirectory("tests/broken_open", true)
	assert.Nil(rr)
	assert.Error(err)
	assert.ErrorAs(err, &pathErr)

	rr, err = ParseDirectory("tests/non_existent", false)
	assert.Nil(rr)
	assert.Error(err)
	assert.ErrorAs(err, &pathErr)
	rr, err = ParseDirectory("tests/non_existent", true)
	assert.Nil(rr)
	assert.Error(err)
	assert.ErrorAs(err, &pathErr)

	var parseErr *dns.ParseError
	rr, err = ParseDirectory("tests/broken_zone", false)
	assert.Nil(rr)
	assert.Error(err)
	assert.ErrorAs(err, &parseErr)
	rr, err = ParseDirectory("tests/broken_zone", true)
	assert.NoError(err)
	// On parsing errors the whole content of file is ignored
	assert.Len(rr.list, 0)
	assert.Len(rr.types, 0)
}

func TestRecordsList(t *testing.T) {
	assert, rr := prepareTest(t)
	result := rr.List()
	assert.Equal(rr.list, result)
	// Test result is actually copy
	rr.list[0], rr.list[1] = rr.list[1], rr.list[0]
	assert.NotEqual(rr.list, result)
	result = rr.List()
	assert.Equal(rr.list, result)
}

func TestMerge(t *testing.T) {
	assert, rr := prepareTest(t)
	other := new(Records)
	err := other.parse("tests/working/10.0.128.rev")
	assert.NoError(err)
	rr.Merge(other)
	assert.Len(rr.list, 32)
	assert.Len(rr.types[1], 16)
	assert.Len(rr.types[2], 6)
	assert.Len(rr.types[5], 4)
	assert.Len(rr.types[6], 2)
	assert.Len(rr.types[28], 1)
	assert.Len(rr.types[12], 3)
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
