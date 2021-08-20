package checker

import (
	"testing"

	"github.com/LINKMobilityDE/ns-checker/zones"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func prepareRecords(t *testing.T) (*assert.Assertions, *Checker) {
	assert := assert.New(t)
	rr, err := zones.ParseDirectory("tests")
	assert.NoError(err)
	return assert, &Checker{Records: rr}
}

func spoilA(c *Checker) {
	spoiled := c.Records.GetByType(dns.TypeA)[0].(*dns.A)
	spoiled.A = []byte("a")
}

func spoilAAAA(c *Checker) {
	spoiled := c.Records.GetByType(dns.TypeAAAA)[0].(*dns.AAAA)
	spoiled.AAAA = []byte("a")
}

func spoilPTR(c *Checker) {
	spoiled := c.Records.GetByType(dns.TypePTR)[0].(*dns.PTR)
	spoiled.Hdr.Name = "blahblah"
}

func TestPrepare(t *testing.T) {
	assert, c := prepareRecords(t)
	assert.NoError(c.prepare())
	_, c = prepareRecords(t)
	spoilA(c)
	assert.Error(c.prepare())
	_, c = prepareRecords(t)
	spoilAAAA(c)
	assert.Error(c.prepare())
	_, c = prepareRecords(t)
	spoilPTR(c)
	assert.Error(c.prepare())
	_, err := c.CheckA()
	assert.Error(err)
	_, err = c.CheckAAAA()
	assert.Error(err)
	_, err = c.CheckPTR()
	assert.Error(err)
}

func TestPrepareA(t *testing.T) {
	assert, c := prepareRecords(t)
	assert.NoError(c.prepareA())
	assert.Len(c.a, 9)
	assert.Len(c.a["manager.subzone.zone.tld."], 8)
	spoilA(c)
	assert.NoError(c.prepareA())
	c.a = nil
	assert.Error(c.prepareA())
}

func TestPrepareAAAA(t *testing.T) {
	assert, c := prepareRecords(t)
	assert.NoError(c.prepareAAAA())
	assert.Len(c.aaaa, 3)
	assert.Len(c.aaaa["manager.subzone.zone.tld."], 2)
	spoilAAAA(c)
	assert.NoError(c.prepareAAAA())
	c.aaaa = nil
	assert.Error(c.prepareAAAA())
}

func TestPreparePTR(t *testing.T) {
	assert, c := prepareRecords(t)
	assert.NoError(c.preparePTR())
	assert.Len(c.ptr, 6)
	assert.Len(c.ptr["3.128.0.10.in-addr.arpa."], 2)
	spoilPTR(c)
	assert.NoError(c.preparePTR())
	c.ptr = nil
	assert.Error(c.preparePTR())
}

func TestCheckA(t *testing.T) {
	assert, c := prepareRecords(t)
	failed, err := c.CheckA()
	assert.NoError(err)
	assert.Len(failed, 5)
}

func TestCheckAAAA(t *testing.T) {
	assert, c := prepareRecords(t)
	failed, err := c.CheckAAAA()
	assert.NoError(err)
	assert.Len(failed, 1)
}

func TestCheckPTR(t *testing.T) {
	assert, c := prepareRecords(t)
	failed, err := c.CheckPTR()
	assert.NoError(err)
	assert.Len(failed, 2)
}
