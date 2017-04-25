package dhcpv6

import (
	"bytes"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

func TestOptionTypeString(t *testing.T) {
	tests := []struct {
		in  OptionType
		out string
	}{
		{0, "Unknown (0)"},
		{OptionTypeClientID, "Client Identifier (1)"},
		{OptionTypeServerID, "Server Identifier (2)"},
		{OptionTypeIANA, "Identity Association for Non-temporary Addresses (3)"},
		{OptionTypeIATA, "Identity Association for Temporary Addresses (4)"},
		{OptionTypeIAAddress, "Identity Association Address (5)"},
		{OptionTypeOptionRequest, "Option Request (6)"},
		{OptionTypePreference, "Preference (7)"},
		{OptionTypeElapsedTime, "Elapsed Time (8)"},
		{OptionTypeRelayMessage, "Relay Message (9)"},
		{OptionTypeAuthentication, "Authentication (11)"},
		{OptionTypeServerUnicast, "Server Unicast (12)"},
		{OptionTypeStatusCode, "Status Code (13)"},
		{OptionTypeRapidCommit, "Rapid Commit (14)"},
		{OptionTypeUserClass, "User Class (15)"},
		{OptionTypeVendorClass, "Vendor Class (16)"},
		{OptionTypeVendorOption, "Vendor-specific Information (17)"},
		{OptionTypeInterfaceID, "Interface-ID (18)"},
		{OptionTypeReconfigureMessage, "Reconfigure Message (19)"},
		{OptionTypeReconfigureAccept, "Reconfigure Accept (20)"},
		{OptionTypeDNSServer, "DNS Server (23)"},
		{OptionTypeDNSSearchList, "DNS Search List (24)"},
	}

	for _, test := range tests {
		if strings.Compare(test.in.String(), test.out) != 0 {
			t.Errorf("expected %s but got %s", test.out, test.in.String())
		}
	}
}

// test OptionClientID
func TestOptionClientID(t *testing.T) {
	var opt *OptionClientID

	fixtbyte := []byte{0, 1, 0, 14, 0, 1, 0, 1, 29, 205, 101, 0, 170, 187, 204, 221, 238, 255}
	// test decoding bytes to []Option
	if list, err := ParseOptions(fixtbyte); err != nil {
		t.Errorf("could not parse fixture: %s", err)
	} else if len(list) != 1 {
		t.Errorf("expected exactly 1 option, got %d", len(list))
	} else {
		opt = list[0].(*OptionClientID)
	}

	// check contents of Option
	if opt.Type() != OptionTypeClientID {
		t.Errorf("unexpected type: %s", opt.Type())
	}
	// the DUID of this Option is tested separately
	// for now, just check the type of the DUID
	if opt.DUID.Type() != DUIDTypeLLT {
		t.Errorf("unexpected DUID type: %s", opt.DUID.Type())
	}

	// test matching output for String()
	fixtstr := "client-ID hwaddr/time type 1 time 500000000 aa:bb:cc:dd:ee:ff"
	if fixtstr != opt.String() {
		t.Errorf("unexpected String() output: %s", opt.String())
	}

	// test if marshalled bytes match fixture
	if mshByte, err := opt.Marshal(); err != nil {
		t.Errorf("error marshalling ClientID: %s", err)
	} else if bytes.Compare(fixtbyte, mshByte) != 0 {
		t.Errorf("marshalled ClientID didn't match fixture!\nfixture: %v\nmarshal: %v", fixtbyte, mshByte)
	}

	// create same OptionClientID and see if its marshal matches fixture
	opt = &OptionClientID{
		DUID: &DUIDLLT{
			DUIDBase: &DUIDBase{
				DUIDType: DUIDTypeLLT,
			},
			HardwareType: 1,
			Time:         time.Unix(1446771200, 0),
		},
	}
	opt.DUID.(*DUIDLLT).LinkLayerAddress, _ = net.ParseMAC("aa:bb:cc:dd:ee:ff")
	if mshByte, err := opt.Marshal(); err != nil {
		t.Errorf("error marshalling ClientID: %s", err)
	} else if bytes.Compare(mshByte, fixtbyte) != 0 {
		t.Errorf("marshalled ClientID didn't match fixture!\nfixture: %v\nmarshal: %v", fixtbyte, mshByte)
	}
}

// test OptionServerID
func TestOptionServerID(t *testing.T) {
	var opt *OptionServerID

	fixtbyte := []byte{0, 2, 0, 14, 0, 1, 0, 1, 29, 205, 101, 0, 170, 187, 204, 221, 238, 255}
	// test decoding bytes to []Option
	if list, err := ParseOptions(fixtbyte); err != nil {
		t.Errorf("could not parse fixture: %s", err)
	} else if len(list) != 1 {
		t.Errorf("expected exactly 1 option, got %d", len(list))
	} else {
		opt = list[0].(*OptionServerID)
	}

	// check contents of Option
	if opt.Type() != OptionTypeServerID {
		t.Errorf("unexpected type: %s", opt.Type())
	}
	// the DUID of this Option is tested separately
	// for now, just check the type of the DUID
	if opt.DUID.Type() != DUIDTypeLLT {
		t.Errorf("unexpected DUID type: %s", opt.DUID.Type())
	}

	// test matching output for String()
	fixtstr := "server-ID hwaddr/time type 1 time 500000000 aa:bb:cc:dd:ee:ff"
	if fixtstr != opt.String() {
		t.Errorf("unexpected String() output: %s", opt.String())
	}

	// test if marshalled bytes match fixture
	if mshByte, err := opt.Marshal(); err != nil {
		t.Errorf("error marshalling ServerID: %s", err)
	} else if bytes.Compare(fixtbyte, mshByte) != 0 {
		t.Errorf("marshalled ServerID didn't match fixture!\nfixture: %v\nmarshal: %v", fixtbyte, mshByte)
	}

	// create same OptionClientID and see if its marshal matches fixture
	opt = &OptionServerID{
		DUID: &DUIDLLT{
			DUIDBase: &DUIDBase{
				DUIDType: DUIDTypeLLT,
			},
			HardwareType: 1,
			Time:         time.Unix(1446771200, 0),
		},
	}
	opt.DUID.(*DUIDLLT).LinkLayerAddress, _ = net.ParseMAC("aa:bb:cc:dd:ee:ff")
	if mshByte, err := opt.Marshal(); err != nil {
		t.Errorf("error marshalling ServerID: %s", err)
	} else if bytes.Compare(mshByte, fixtbyte) != 0 {
		t.Errorf("marshalled ServerID didn't match fixture!\nfixture: %v\nmarshal: %v", fixtbyte, mshByte)
	}
}

func TestOptionIANA(t *testing.T) {
	var opt *OptionIANA

	// fixture of an IA_NA option containing no other options
	fixtbyte := []byte{0, 3, 0, 12, 0, 250, 153, 31, 0, 0, 1, 44, 0, 0, 1, 194}
	if list, err := ParseOptions(fixtbyte); err != nil {
		t.Errorf("could not parse fixture: %s", err)
	} else if len(list) != 1 {
		t.Errorf("expected exactly 1 option, got %d", len(list))
	} else {
		opt = list[0].(*OptionIANA)
	}

	// check contents of Option
	if opt.Type() != OptionTypeIANA {
		t.Errorf("unexpected type: %s", opt.Type())
	}
	// TODO: check IAID
	if opt.T1 != 300 {
		t.Errorf("expected T1 300, got %d", opt.T1)
	}
	if opt.T2 != 450 {
		t.Errorf("expected T2 450, got %d", opt.T2)
	}

	// test matching output for String()
	fixtstr := "IA_NA IAID:16423199 T1:300 T2:450"
	if fixtstr != opt.String() {
		t.Errorf("unexpected String() output: %s", opt.String())
	}

	// test if marshalled bytes match fixture
	if mshByte, err := opt.Marshal(); err != nil {
		t.Errorf("error marshalling IANA: %s", err)
	} else if bytes.Compare(mshByte, fixtbyte) != 0 {
		t.Errorf("marshalled IANA didn't match fixture!\nfixture: %v\nmarshal: %v", fixtbyte, mshByte)
	}

	// recreate same OptionIANA and see if its marshal matches fixture
	opt = &OptionIANA{
		IAID: 16423199,
		T1:   300,
		T2:   450,
	}

	if mshByte, err := opt.Marshal(); err != nil {
		t.Errorf("error marshalling IANA: %s", err)
	} else if bytes.Compare(mshByte, fixtbyte) != 0 {
		t.Errorf("marshalled IANA didn't match fixture!\nfixture: %v\nmarshal: %v", fixtbyte, mshByte)
	}

	// redo all checks with an IAAddress option in the IANA option
	fixtbyte = []byte{0, 3, 0, 40, 0, 250, 153, 31, 0, 0, 1, 44, 0, 0, 1, 194, 0, 5, 0, 24, 253, 212, 71, 50, 21, 217, 234, 106, 0, 0, 0, 0, 0, 0, 16, 0, 0, 0, 14, 16, 0, 0, 28, 32}
	if list, err := ParseOptions(fixtbyte); err != nil {
		t.Errorf("could not parse fixture: %s", err)
	} else if len(list) != 1 {
		t.Errorf("expected exactly 1 option, got %d", len(list))
	} else {
		opt = list[0].(*OptionIANA)
	}

	// check for 1 IAAddress option within the option
	if len(opt.Options) != 1 {
		t.Errorf("expected 1 option, got %d", len(opt.Options))
	}
	// check type of option
	if opt.Options[0].Type() != OptionTypeIAAddress {
		t.Errorf("expected OptionTypeIAAddress, got %s", opt.Options[0].Type())
	}

	// recreate same OptionIANA and see if its marshal matches fixture
	iaaddr := &OptionIAAddress{
		Address:           net.ParseIP("fdd4:4732:15d9:ea6a::1000"),
		PreferredLifetime: 3600,
		ValidLifetime:     7200,
	}

	opt = &OptionIANA{
		IAID:    16423199,
		T1:      300,
		T2:      450,
		Options: Options{iaaddr},
	}
	if mshByte, err := opt.Marshal(); err != nil {
		t.Errorf("error marshalling IANA: %s", err)
	} else if bytes.Compare(mshByte, fixtbyte) != 0 {
		t.Errorf("marshalled IANA didn't match fixture!\nfixture: %v\nmarshal: %v", fixtbyte, mshByte)
	}

	// do it again but now use the AddOption function of OptionIANA
	opt = &OptionIANA{
		IAID: 16423199,
		T1:   300,
		T2:   450,
	}
	opt.AddOption(iaaddr)
	if mshByte, err := opt.Marshal(); err != nil {
		t.Errorf("error marshalling IANA: %s", err)
	} else if bytes.Compare(mshByte, fixtbyte) != 0 {
		t.Errorf("marshalled IANA didn't match fixture!\nfixture: %v\nmarshal: %v", fixtbyte, mshByte)
	}

	// check if opt now has an IAAddress option
	if opt.HasOption(OptionTypeIAAddress) == nil {
		t.Errorf("IANA should have option OptionTypeIAAddress")
	}
	// check if opt has random other option
	if opt.HasOption(OptionTypeRapidCommit) != nil {
		t.Errorf("IANA shouldn't have option OptionTypeRapidCommit")
	}
}

func TestOptionIAAddress(t *testing.T) {
	var opt *OptionIAAddress

	fixtbyte := []byte{0, 5, 0, 24, 253, 212, 71, 50, 21, 217, 234, 106, 0, 0, 0, 0, 0, 0, 16, 0, 0, 0, 14, 16, 0, 0, 28, 32}
	// test decoding bytes to []Option
	if list, err := ParseOptions(fixtbyte); err != nil {
		t.Errorf("could not parse fixture: %s", err)
	} else if len(list) != 1 {
		t.Errorf("expected exactly 1 option, got %d", len(list))
	} else {
		opt = list[0].(*OptionIAAddress)
	}

	// check contents of Option
	if opt.Type() != OptionTypeIAAddress {
		t.Errorf("unexpected type: %s", opt.Type())
	}
	fixtaddr := net.ParseIP("fdd4:4732:15d9:ea6a::1000")
	if !fixtaddr.Equal(opt.Address) {
		t.Errorf("expected address %s, got %s", fixtaddr, opt.Address)
	}
	if opt.PreferredLifetime != 3600 {
		t.Errorf("expected preferred lifetime 3600, got %d", opt.PreferredLifetime)
	}
	if opt.ValidLifetime != 7200 {
		t.Errorf("expected valid lifetime 7200, got %d", opt.ValidLifetime)
	}

	// test matching output for String()
	fixtstr := "IA_ADDR fdd4:4732:15d9:ea6a::1000 pltime:3600 vltime:7200"
	if fixtstr != opt.String() {
		t.Errorf("unexpected String() output: %s", opt.String())
	}

	// test if marshalled bytes match fixture
	if mshByte, err := opt.Marshal(); err != nil {
		t.Errorf("error marshalling IAAddress: %s", err)
	} else if bytes.Compare(mshByte, fixtbyte) != 0 {
		t.Errorf("marshalled IAAddress didn't match fixture!\nfixture: %v\nmarshal: %v", fixtbyte, mshByte)
	}

	// create same OptionClientID and see if its marshal matches fixture
	opt = &OptionIAAddress{
		Address:           fixtaddr,
		PreferredLifetime: 3600,
		ValidLifetime:     7200,
	}

	if mshByte, err := opt.Marshal(); err != nil {
		t.Errorf("error marshalling IAAddress: %s", err)
	} else if bytes.Compare(mshByte, fixtbyte) != 0 {
		t.Errorf("marshalled IAAddress didn't match fixture!\nfixture: %v\nmarshal: %v", fixtbyte, mshByte)
	}
}

func TestOptionOptionRequest(t *testing.T) {
	var opt *OptionOptionRequest

	fixtbyte := []byte{0, 6, 0, 4, 0, 23, 0, 24}
	// test decoding bytes to []Option
	if list, err := ParseOptions(fixtbyte); err != nil {
		t.Errorf("could not parse fixture: %s", err)
	} else if len(list) != 1 {
		t.Errorf("expected exactly 1 option, got %d", len(list))
	} else {
		opt = list[0].(*OptionOptionRequest)
	}

	// check contents of Option
	if opt.Type() != OptionTypeOptionRequest {
		t.Errorf("unexpected type: %s", opt.Type())
	}
	if !opt.HasOption(OptionTypeDNSServer) {
		t.Errorf("OptionRequest should have OptionTypeDNSServer")
	}
	if !opt.HasOption(OptionTypeDNSSearchList) {
		t.Errorf("OptionRequest should have OptionTypeDNSSearchList")
	}
	if opt.HasOption(OptionTypeClientID) {
		t.Errorf("OptionRequest shouldn't have OptionTypeClientID")
	}

	// test matching output for String()
	fixtstr := "option-request DNS Server (23) DNS Search List (24)"
	if fixtstr != opt.String() {
		t.Errorf("unexpected String() output: %s", opt.String())
	}

	// test if marshalled bytes match fixture
	if mshByte, err := opt.Marshal(); err != nil {
		t.Errorf("error marshalling OptionRequest: %s", err)
	} else if bytes.Compare(mshByte, fixtbyte) != 0 {
		t.Errorf("marshalled OptionRequest didn't match fixture!\nfixture: %v\nmarshal: %v", fixtbyte, mshByte)
	}

	// create same struct and see if its marshal matches fixture
	opt = &OptionOptionRequest{
		Options: []OptionType{
			OptionTypeDNSServer,
			OptionTypeDNSSearchList,
		},
	}

	if mshByte, err := opt.Marshal(); err != nil {
		t.Errorf("error marshalling OptionRequest: %s", err)
	} else if bytes.Compare(mshByte, fixtbyte) != 0 {
		t.Errorf("marshalled OptionRequest didn't match fixture!\nfixture: %v\nmarshal: %v", fixtbyte, mshByte)
	}
}

func TestOptionElapsedTime(t *testing.T) {
	// option (option type Elapsed Time (8)): [0 8 0 2 0 0]
	var opt *OptionElapsedTime

	fixtbyte := []byte{0, 8, 0, 2, 0, 10}
	// test decoding bytes to []Option
	if list, err := ParseOptions(fixtbyte); err != nil {
		t.Errorf("could not parse fixture: %s", err)
	} else if len(list) != 1 {
		t.Errorf("expected exactly 1 option, got %d", len(list))
	} else {
		opt = list[0].(*OptionElapsedTime)
	}

	// check contents of Option
	if opt.Type() != OptionTypeElapsedTime {
		t.Errorf("unexpected type: %s", opt.Type())
	}
	fixttime := (time.Duration(100) * time.Millisecond)
	if opt.ElapsedTime != fixttime {
		t.Errorf("expected %s, got %s", fixttime, opt.ElapsedTime)
	}

	// test matching output for String()
	fixtstr := "elapsed-time 100ms"
	if fixtstr != opt.String() {
		t.Errorf("unexpected String() output: %s", opt.String())
	}

	// test if marshalled bytes match fixture
	if mshByte, err := opt.Marshal(); err != nil {
		t.Errorf("error marshalling OptionElapsedTime: %s", err)
	} else if bytes.Compare(mshByte, fixtbyte) != 0 {
		t.Errorf("marshalled OptionElapsedTime didn't match fixture!\nfixture: %v\nmarshal: %v", fixtbyte, mshByte)
	}

	// create same struct and see if its marshal matches fixture
	opt = &OptionElapsedTime{
		ElapsedTime: fixttime,
	}
	if mshByte, err := opt.Marshal(); err != nil {
		t.Errorf("error marshalling OptionElapsedTime: %s", err)
	} else if bytes.Compare(mshByte, fixtbyte) != 0 {
		t.Errorf("marshalled OptionElapsedTime didn't match fixture!\nfixture: %v\nmarshal: %v", fixtbyte, mshByte)
	}
}

func TestOptionStatusCode(t *testing.T) {
	var opt *OptionStatusCode

	fixtbyte := []byte{0, 13, 0, 40, 0, 4, 83, 111, 109, 101, 32, 111, 102, 32, 116, 104, 101, 32, 97, 100, 100, 114, 101, 115, 115, 101, 115, 32, 97, 114, 101, 32, 110, 111, 116, 32, 111, 110, 32, 108, 105, 110, 107, 46}
	// test decoding bytes to []Option
	if list, err := ParseOptions(fixtbyte); err != nil {
		t.Errorf("could not parse fixture: %s", err)
	} else if len(list) != 1 {
		t.Errorf("expected exactly 1 option, got %d", len(list))
	} else {
		opt = list[0].(*OptionStatusCode)
	}

	// check contents of Option
	if opt.Type() != OptionTypeStatusCode {
		t.Errorf("unexpected type: %s", opt.Type())
	}
	fixtcode := StatusCodeNotOnLink
	if opt.Code != fixtcode {
		t.Errorf("expected status code %s, got %s", fixtcode, opt.Code)
	}
	fixtmsg := "Some of the addresses are not on link."
	if opt.Message != fixtmsg {
		t.Errorf("expected status message %s, got %s", fixtmsg, opt.Message)
	}

	// test matching output for String()
	fixtstr := fmt.Sprintf("status-code %s: %s", opt.Code, opt.Message)
	if fixtstr != opt.String() {
		t.Errorf("unexpected String() output: %s", opt.String())
	}

	// test if marshalled bytes match fixture
	if mshByte, err := opt.Marshal(); err != nil {
		t.Errorf("error marshalling OptionStatusCode: %s", err)
	} else if bytes.Compare(mshByte, fixtbyte) != 0 {
		t.Errorf("marshalled OptionStatusCode didn't match fixture!\nfixture: %v\nmarshal: %v", fixtbyte, mshByte)
	}

	// create same struct and see if its marshal matches fixture
	opt = &OptionStatusCode{
		Code:    fixtcode,
		Message: fixtmsg,
	}
	if mshByte, err := opt.Marshal(); err != nil {
		t.Errorf("error marshalling OptionStatusCode: %s", err)
	} else if bytes.Compare(mshByte, fixtbyte) != 0 {
		t.Errorf("marshalled OptionStatusCode didn't match fixture!\nfixture: %v\nmarshal: %v", fixtbyte, mshByte)
	}
}

func TestStatusCodeString(t *testing.T) {
	tests := []struct {
		in  StatusCode
		out string
	}{
		{StatusCodeSuccess, "Success (0)"},
		{StatusCodeUnspecFail, "UnspecFail (1)"},
		{StatusCodeNoAddrsAvail, "NoAddrsAvail (2)"},
		{StatusCodeNoBinding, "NoBinding (3)"},
		{StatusCodeNotOnLink, "NotOnLink (4)"},
		{StatusCodeUseMulticast, "UseMulticast (5)"},
		{255, "Unknown (255)"},
	}

	for _, test := range tests {
		if strings.Compare(test.in.String(), test.out) != 0 {
			t.Errorf("expected %s but got %s", test.out, test.in.String())
		}
	}
}

func TestOptionRapidCommit(t *testing.T) {
	var opt *OptionRapidCommit

	fixtbyte := []byte{0, 14, 0, 0}
	// test decoding bytes to []Option
	if list, err := ParseOptions(fixtbyte); err != nil {
		t.Errorf("could not parse fixture: %s", err)
	} else if len(list) != 1 {
		t.Errorf("expected exactly 1 option, got %d", len(list))
	} else {
		opt = list[0].(*OptionRapidCommit)
	}

	// check contents of Option
	if opt.Type() != OptionTypeRapidCommit {
		t.Errorf("unexpected type: %s", opt.Type())
	}

	// check body length
	fixtlen := uint16(0)
	if opt.Len() != fixtlen {
		t.Errorf("expected length %d, got %d", fixtlen, opt.Len())
	}

	// test matching output for String()
	fixtstr := "rapid-commit"
	if fixtstr != opt.String() {
		t.Errorf("unexpected String() output: %s", opt.String())
	}

	// test if marshalled bytes match fixture
	if mshByte, err := opt.Marshal(); err != nil {
		t.Errorf("error marshalling OptionRapidCommit: %s", err)
	} else if bytes.Compare(mshByte, fixtbyte) != 0 {
		t.Errorf("marshalled OptionRapidCommit didn't match fixture!\nfixture: %v\nmarshal: %v", fixtbyte, mshByte)
	}

	// create same struct and see if its marshal matches fixture
	opt = &OptionRapidCommit{}
	if mshByte, err := opt.Marshal(); err != nil {
		t.Errorf("error marshalling OptionRapidCommit: %s", err)
	} else if bytes.Compare(mshByte, fixtbyte) != 0 {
		t.Errorf("marshalled OptionRapidCommit didn't match fixture!\nfixture: %v\nmarshal: %v", fixtbyte, mshByte)
	}
}
