package dhcpv6

import (
	"bytes"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestDUIDTypeString(t *testing.T) {
	tests := []struct {
		in  DUIDType
		out string
	}{
		{0, "Unknown"},
		{DUIDTypeLLT, "LinkLayerTime"},
		{DUIDTypeEN, "Enterprise Number"},
		{DUIDTypeLL, "LinkLayer"},
		{DUIDTypeUUID, "UUID"},
	}

	for _, test := range tests {
		if strings.Compare(test.in.String(), test.out) != 0 {
			t.Errorf("expected %s but got %s", test.out, test.in.String())
		}
	}
}

func TestDUIDDecode(t *testing.T) {
	// test decoding too few bytes
	if _, err := DecodeDUID([]byte{0}); err == nil {
		t.Error("expected error while decoding too short DUID")
	} else if err != errDUIDTooShort {
		t.Errorf("unexpected error: %s", err)
	}

	// test decoding unknown DUIDType
	if _, err := DecodeDUID([]byte{0, 255}); err == nil {
		t.Error("expected error while decoding unknown DUIDType")
	} else if err.Error() != "unhandled DUIDType Unknown" {
		t.Errorf("unexpected error: %s", err)
	}
}

func TestDuidLLT(t *testing.T) {
	// test decoding bytes to DUIDLLT
	fixtbyte := []byte{0, 1, 0, 1, 29, 205, 101, 0, 170, 187, 204, 221, 238, 255}
	duid, err := DecodeDUID(fixtbyte)
	if err != nil {
		t.Errorf("error decoding fixture: %s", err)
	}

	duidllt := duid.(*DUIDLLT)
	// check contents of duid
	if duidllt.Type() != DUIDTypeLLT {
		t.Errorf("expected duid type %d, got %d", DUIDTypeLLT, duidllt.Type())
	}
	fixthwtype := uint16(1)
	if duidllt.HardwareType != fixthwtype {
		t.Errorf("expected hw type %d, got %d", fixthwtype, duidllt.HardwareType)
	}
	// fixture with offset of 30 years
	fixttime := time.Unix(1446771200, 0)
	if !duidllt.Time.Equal(fixttime) {
		t.Errorf("expected time %s, got %s", fixttime, duidllt.Time)
	}
	fixtmac, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	if bytes.Compare(duidllt.LinkLayerAddress, fixtmac) != 0 {
		t.Errorf("expected lla %s, got %s", fixtmac, duidllt.LinkLayerAddress)
	}

	// test for error when decoding too small DUIDLLT
	if _, err := DecodeDUID(fixtbyte[:7]); err == nil {
		t.Error("expected error decoding too small DUIDLLT")
	} else if err != errDUIDTooShort {
		t.Errorf("unexpected error: %s", err)
	}

	// test matching output for String()
	fixtstr := "hwaddr/time type 1 time 500000000 aa:bb:cc:dd:ee:ff"
	if duidllt.String() != fixtstr {
		t.Errorf("unexpected String() output: %s", duidllt.String())
	}

	// test matching output for Len()
	fixtlen := uint16(14)
	if duidllt.Len() != fixtlen {
		t.Errorf("expected Len of %d, got %d", fixtlen, duidllt.Len())
	}

	// test if marshalled bytes match fixture
	if mshByte, err := duidllt.Marshal(); err != nil {
		t.Errorf("error marshalling DUID: %s", err)
	} else if bytes.Compare(fixtbyte, mshByte) != 0 {
		t.Errorf("marshalled DUID didn't match fixture!\nfixture: %v\nmarshal: %v", fixtbyte, mshByte)
	}

	// recreate same struct and see if its marshal matches fixture
	duidllt = &DUIDLLT{
		HardwareType:     fixthwtype,
		Time:             fixttime,
		LinkLayerAddress: fixtmac,
	}
	if mshByte, err := duidllt.Marshal(); err != nil {
		t.Errorf("error marshalling DUID: %s", err)
	} else if bytes.Compare(fixtbyte, mshByte) != 0 {
		t.Errorf("marshalled DUID didn't match fixture!\nfixture: %v\nmarshal: %v", fixtbyte, mshByte)
	}
}

func TestDuidLL(t *testing.T) {
	// test decoding bytes to DUIDLL
	fixtbyte := []byte{0, 3, 0, 1, 170, 187, 204, 221, 238, 255}
	duid, err := DecodeDUID(fixtbyte)
	if err != nil {
		t.Errorf("error decoding fixture: %s", err)
	}

	duidll := duid.(*DUIDLL)
	// check contents of duid
	if duidll.Type() != DUIDTypeLL {
		t.Errorf("expected duid type %d, got %d", DUIDTypeLL, duidll.Type())
	}
	fixthwtype := uint16(1)
	if duidll.HardwareType != fixthwtype {
		t.Errorf("expected hw type %d, got %d", fixthwtype, duidll.HardwareType)
	}
	fixtmac, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	if bytes.Compare(duidll.LinkLayerAddress, fixtmac) != 0 {
		t.Errorf("expected lla %s, got %s", fixtmac, duidll.LinkLayerAddress)
	}

	// test for error when decoding too small DUIDLL
	if _, err := DecodeDUID(fixtbyte[:3]); err == nil {
		t.Error("expected error decoding too small DUIDLL")
	} else if err != errDUIDTooShort {
		t.Errorf("unexpected error: %s", err)
	}

	// test matching output for String()
	fixtstr := "hwaddr type 3 aa:bb:cc:dd:ee:ff"
	if duidll.String() != fixtstr {
		t.Errorf("unexpected String() output: %s", duidll.String())
	}

	// test matching output for Len()
	fixtlen := uint16(10)
	if duidll.Len() != fixtlen {
		t.Errorf("expected Len of %d, got %d", fixtlen, duidll.Len())
	}

	// test if marshalled bytes match fixture
	if mshByte, err := duidll.Marshal(); err != nil {
		t.Errorf("error marshalling DUID: %s", err)
	} else if bytes.Compare(fixtbyte, mshByte) != 0 {
		t.Errorf("marshalled DUID didn't match fixture!\nfixture: %v\nmarshal: %v", fixtbyte, mshByte)
	}

	// recreate same struct and see if it's marshal matches fixture
	duidll = &DUIDLL{
		HardwareType:     fixthwtype,
		LinkLayerAddress: fixtmac,
	}
	if mshByte, err := duidll.Marshal(); err != nil {
		t.Errorf("error marshalling DUID: %s", err)
	} else if bytes.Compare(fixtbyte, mshByte) != 0 {
		t.Errorf("marshalled DUID didn't match fixture!\nfixture: %v\nmarshal: %v", fixtbyte, mshByte)
	}
}

func TestDuidUUID(t *testing.T) {
	// test decoding bytes to DUIDUUID
	fixtbyte := []byte{0, 4, 126, 102, 234, 162, 230, 221, 73, 123, 142, 33, 49, 148, 75, 40, 43, 67}
	duid, err := DecodeDUID(fixtbyte)
	if err != nil {
		t.Errorf("error decoding fixture: %s", err)
	}

	duiduuid := duid.(*DUIDUUID)
	// check contents of duid
	if duiduuid.Type() != DUIDTypeUUID {
		t.Errorf("expected duid type %d, got %d", DUIDTypeUUID, duiduuid.Type())
	}

	fixtuuid := "7e66eaa2-e6dd-497b-8e21-31944b282b43"
	if fixtuuid != duiduuid.UUID.String() {
		t.Errorf("expected UUID %s, got %s", fixtuuid, duiduuid.UUID.String())
	}

	// test for error when decoding too small DUIDUUID
	if _, err = DecodeDUID(fixtbyte[:17]); err == nil {
		t.Error("expected error decoding too small DUIDUUID")
	} else if err != errDUIDTooShort {
		t.Errorf("unexpected error: %s", err)
	}

	// test matching output for String()
	fixtstr := "type 4"
	if duiduuid.String() != fixtstr {
		t.Errorf("unexpected String() output: %s", duiduuid.String())
	}

	// test matching output for Len()
	fixtlen := uint16(18)
	if duiduuid.Len() != fixtlen {
		t.Errorf("expected Len of %d, got %d", fixtlen, duiduuid.Len())
	}

	// test if marshalled bytes match fixture
	if mshByte, merr := duiduuid.Marshal(); merr != nil {
		t.Errorf("error marshalling DUID: %s", merr)
	} else if bytes.Compare(fixtbyte, mshByte) != 0 {
		t.Errorf("marshalled DUID didn't match fixture!\nfixture: %v\nmarshal: %v", fixtbyte, mshByte)
	}

	// recreate same struct and see if it's marshal matches fixture
	duiduuid = &DUIDUUID{}
	if duiduuid.UUID, err = uuid.Parse(fixtuuid); err != nil {
		t.Errorf("error parsing UUID: %s", err)
	}
	if mshByte, err := duiduuid.Marshal(); err != nil {
		t.Errorf("error marshalling DUID: %s", err)
	} else if bytes.Compare(fixtbyte, mshByte) != 0 {
		t.Errorf("marshalled DUID didn't match fixture!\nfixture: %v\nmarshal: %v", fixtbyte, mshByte)
	}
}
