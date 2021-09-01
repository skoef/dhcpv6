package dhcpv6

import (
	"bytes"
	"fmt"
	"net"
	"reflect"
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
		{OptionTypeBootFileURL, "Boot File URL (59)"},
		{OptionTypeBootFileParameters, "Boot File Parameters (60)"},
		{OptionTypeNextHop, "Next Hop (242)"},
		{OptionTypeRoutePrefix, "Route Prefix (243)"},
	}

	for _, test := range tests {
		if strings.Compare(test.in.String(), test.out) != 0 {
			t.Errorf("expected %s but got %s", test.out, test.in.String())
		}
	}
}

func TestAddOption(t *testing.T) {
	// simply add an option twice to another option and check if it occurs in the
	// option list twice

	// OptionIANA 'implements' optionContainer
	iana := &OptionIANA{}
	fixtlen := 0

	if len(iana.options) != fixtlen {
		t.Errorf("expected %d options, got %d", fixtlen, len(iana.options))
	}

	iana.AddOption(&OptionRapidCommit{})
	fixtlen++
	if len(iana.options) != fixtlen {
		t.Errorf("expected %d options, got %d", fixtlen, len(iana.options))
	}

	iana.AddOption(&OptionRapidCommit{})
	fixtlen++
	if len(iana.options) != fixtlen {
		t.Errorf("expected %d options, got %d", fixtlen, len(iana.options))
	}

	// check if both options have same type
	if iana.options[0].Type() != OptionTypeRapidCommit || iana.options[1].Type() != OptionTypeRapidCommit {
		t.Errorf("expected both options to have type OptionTypeRapidCommit, got %s/%s", iana.options[0].Type(), iana.options[1].Type())
	}
}

// test DecodeOptions
// each separate Option will be tested in their own test
// but some edges cases in DecodeOptions will be tested here
func TestDecodeOptions(t *testing.T) {
	var fixtbyte []byte

	// try to decode too few bytes and check for an error
	fixtbyte = []byte{0, 1, 0}
	if _, err := DecodeOptions(fixtbyte); err == nil {
		t.Error("expected error while trying to decode too few bytes")
	} else if err != errOptionTooShort {
		t.Errorf("unexpected error: %s", err)
	}

	// try to decode an option with an length set longer than bytes it carries
	fixtbyte = []byte{0, 1, 0, 4}
	if _, err := DecodeOptions(fixtbyte); err == nil {
		t.Error("expected error while trying to decode too few bytes")
	} else if err != errOptionTooShort {
		t.Errorf("unexpected error: %s", err)
	}

	// try to decode an unhandled option
	fixtbyte = make([]byte, 4)
	if list, err := DecodeOptions(fixtbyte); err != nil {
		t.Errorf("unexpected error while trying to decode unhandled option type: %s", err.Error())
	} else if len(list) != 0 {
		t.Errorf("expected empty list, got %d entries", len(list))
	}
}

// test OptionClientID
func TestOptionClientID(t *testing.T) {
	var opt *OptionClientID

	fixtbyte := []byte{0, 1, 0, 14, 0, 1, 0, 1, 29, 205, 101, 0, 170, 187, 204, 221, 238, 255}
	// test decoding bytes to []Option
	if list, err := DecodeOptions(fixtbyte); err != nil {
		t.Errorf("could not decode fixture: %s", err)
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

	// check body length
	fixtlen := uint16(14)
	if opt.Len() != fixtlen {
		t.Errorf("expected length %d, got %d", fixtlen, opt.Len())
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

	// try to decode a OptionClientID with too few bytes for DUID
	wrongbytes := []byte{0, 1, 0, 1, 0}
	if _, err := DecodeOptions(wrongbytes); err == nil {
		t.Error("expected error while trying to decode OptionClientID with too few bytes")
	} else if err != errDUIDTooShort {
		t.Errorf("unexpected error: %s", err)
	}
}

// test OptionServerID
func TestOptionServerID(t *testing.T) {
	var opt *OptionServerID

	fixtbyte := []byte{0, 2, 0, 14, 0, 1, 0, 1, 29, 205, 101, 0, 170, 187, 204, 221, 238, 255}
	// test decoding bytes to []Option
	if list, err := DecodeOptions(fixtbyte); err != nil {
		t.Errorf("could not decode fixture: %s", err)
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

	// check body length
	fixtlen := uint16(14)
	if opt.Len() != fixtlen {
		t.Errorf("expected length %d, got %d", fixtlen, opt.Len())
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

	// try to decode a OptionServerID with too few bytes for DUID
	wrongbytes := []byte{0, 2, 0, 1, 0}
	if _, err := DecodeOptions(wrongbytes); err == nil {
		t.Error("expected error while trying to decode OptionServerID with too few bytes")
	} else if err != errDUIDTooShort {
		t.Errorf("unexpected error: %s", err)
	}

	// test matching 2 OptionServerID's to eachother

	// should not be equal (different type)
	if opt.Equal(OptionClientID{}) {
		t.Error("ServerID should not be equal to ClientID")
	}

	// should not be equal (different content)
	noteql := OptionServerID{
		DUID: &DUIDLL{},
	}
	if opt.Equal(noteql) {
		t.Error("ServerID should not be equal to ServerID with different DUID")
	}

	// should be equal (similar content)
	eql := &OptionServerID{
		DUID: &DUIDLLT{
			HardwareType: 1,
			Time:         time.Unix(1446771200, 0),
		},
	}
	eql.DUID.(*DUIDLLT).LinkLayerAddress, _ = net.ParseMAC("aa:bb:cc:dd:ee:ff")
	if !opt.Equal(eql) {
		t.Error("ServerID should be equal to ServerID with similar content")
	}
}

func TestOptionIANA(t *testing.T) {
	var opt *OptionIANA

	// fixture of an IA_NA option containing no other options
	fixtbyte := []byte{0, 3, 0, 12, 0, 250, 153, 31, 0, 0, 1, 44, 0, 0, 1, 194}
	if list, err := DecodeOptions(fixtbyte); err != nil {
		t.Errorf("could not decode fixture: %s", err)
	} else if len(list) != 1 {
		t.Errorf("expected exactly 1 option, got %d", len(list))
	} else {
		opt = list[0].(*OptionIANA)
	}

	// check contents of Option
	if opt.Type() != OptionTypeIANA {
		t.Errorf("unexpected type: %s", opt.Type())
	}
	fixtiaid := uint32(16423199)
	if opt.IAID != fixtiaid {
		t.Errorf("expected IAID %d, got %d", fixtiaid, opt.IAID)
	}
	fixtt1 := 300 * time.Second
	if opt.T1 != fixtt1 {
		t.Errorf("expected T1 %d, got %d", fixtt1, opt.T1)
	}
	fixtt2 := 450 * time.Second
	if opt.T2 != fixtt2 {
		t.Errorf("expected T2 %d, got %d", fixtt2, opt.T2)
	}

	// check body length
	fixtlen := uint16(12)
	if opt.Len() != fixtlen {
		t.Errorf("expected length %d, got %d", fixtlen, opt.Len())
	}

	// test matching output for String()
	fixtstr := "IA_NA IAID:16423199 T1:5m0s T2:7m30s"
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
		IAID: fixtiaid,
		T1:   fixtt1,
		T2:   fixtt2,
	}

	if mshByte, err := opt.Marshal(); err != nil {
		t.Errorf("error marshalling IANA: %s", err)
	} else if bytes.Compare(mshByte, fixtbyte) != 0 {
		t.Errorf("marshalled IANA didn't match fixture!\nfixture: %v\nmarshal: %v", fixtbyte, mshByte)
	}

	// redo all checks with an IAAddress option in the IANA option
	fixtbyte = []byte{0, 3, 0, 40, 0, 250, 153, 31, 0, 0, 1, 44, 0, 0, 1, 194, 0, 5, 0, 24, 253, 212, 71, 50, 21, 217, 234, 106, 0, 0, 0, 0, 0, 0, 16, 0, 0, 0, 14, 16, 0, 0, 28, 32}
	if list, err := DecodeOptions(fixtbyte); err != nil {
		t.Errorf("could not decode fixture: %s", err)
	} else if len(list) != 1 {
		t.Errorf("expected exactly 1 option, got %d", len(list))
	} else {
		opt = list[0].(*OptionIANA)
	}

	// check for 1 IAAddress option within the option
	if len(opt.options) != 1 {
		t.Errorf("expected 1 option, got %d", len(opt.options))
	}
	// check type of option
	if opt.options[0].Type() != OptionTypeIAAddress {
		t.Errorf("expected OptionTypeIAAddress, got %s", opt.options[0].Type())
	}

	// recreate same OptionIANA including IAAddress option and see if its marshal
	// matches fixture
	opt = &OptionIANA{
		IAID: fixtiaid,
		T1:   fixtt1,
		T2:   fixtt2,
	}
	opt.SetOption(&OptionIAAddress{
		Address:           net.ParseIP("fdd4:4732:15d9:ea6a::1000"),
		PreferredLifetime: 3600 * time.Second,
		ValidLifetime:     7200 * time.Second,
	})
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

	// test matching output for String()
	fixtstr = "IA_NA IAID:16423199 T1:5m0s T2:7m30s [IA_ADDR fdd4:4732:15d9:ea6a::1000 pltime:1h0m0s vltime:2h0m0s]"
	if fixtstr != opt.String() {
		t.Errorf("unexpected String() output: %s", opt.String())
	}

	// override IAAddress option and test if it was replaced instead of added
	newiaddr := &OptionIAAddress{
		Address:           net.ParseIP("fdd4:4732:15d9:ea6a::1000"),
		PreferredLifetime: 1800 * time.Second,
		ValidLifetime:     7200 * time.Second,
	}
	opt.SetOption(newiaddr)

	if len(opt.options) != 1 {
		t.Errorf("expected 1 option, got %d options", len(opt.options))
	}

	// check if PreferredLifetime (which was 3600) is now 1800
	if opt.options[0].(*OptionIAAddress).PreferredLifetime != newiaddr.PreferredLifetime {
		t.Errorf("expected preferred lifetime of %d, got %d", newiaddr.PreferredLifetime, opt.options[0].(*OptionIAAddress).PreferredLifetime)
	}

	// use SetOption for an option that was not set before and see if it is added
	// anyway
	rc := &OptionRapidCommit{}
	opt.SetOption(rc)
	if len(opt.options) != 2 {
		t.Errorf("expected 2 options, got %d options", len(opt.options))
	}

	// try to decode fixture with too short option length
	fixtbyte[3] = 11
	// test decoding bytes to []Option
	if _, err := DecodeOptions(fixtbyte); err == nil {
		t.Error("expected error while decoding too short option")
	} else {
		fixterr := errOptionTooShort
		if err != fixterr {
			t.Errorf("expected option too short error, got %s", err)
		}
	}
}

func TestOptionIAAddress(t *testing.T) {
	var opt *OptionIAAddress

	fixtbyte := []byte{0, 5, 0, 36, 253, 212, 71, 50, 21, 217, 234, 106, 0, 0, 0, 0, 0, 0, 16, 0, 0, 0, 14, 16, 0, 0, 28, 32, 0, 13, 0, 8, 0, 0, 102, 111, 111, 98, 97, 114}
	// test decoding bytes to []Option
	if list, err := DecodeOptions(fixtbyte); err != nil {
		t.Errorf("could not decode fixture: %s", err)
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
	fixtpl := 3600 * time.Second
	if opt.PreferredLifetime != fixtpl {
		t.Errorf("expected preferred lifetime 3600, got %d", opt.PreferredLifetime)
	}
	fixtvl := 7200 * time.Second
	if opt.ValidLifetime != fixtvl {
		t.Errorf("expected valid lifetime 7200, got %d", opt.ValidLifetime)
	}
	if sc := opt.HasOption(OptionTypeStatusCode); sc == nil {
		t.Error("expected status code option")
	}

	// check body length
	fixtlen := uint16(36)
	if opt.Len() != fixtlen {
		t.Errorf("expected length %d, got %d", fixtlen, opt.Len())
	}

	// test matching output for String()
	fixtstr := "IA_ADDR fdd4:4732:15d9:ea6a::1000 pltime:1h0m0s vltime:2h0m0s [status-code Success (0): foobar]"
	if fixtstr != opt.String() {
		t.Errorf("unexpected String() output: %s", opt.String())
	}

	// test if marshalled bytes match fixture
	if mshByte, err := opt.Marshal(); err != nil {
		t.Errorf("error marshalling IAAddress: %s", err)
	} else if bytes.Compare(mshByte, fixtbyte) != 0 {
		t.Errorf("marshalled IAAddress didn't match fixture!\nfixture: %v\nmarshal: %v", fixtbyte, mshByte)
	}

	// create same OptionIAAddress and see if its marshal matches fixture
	opt = &OptionIAAddress{
		Address:           fixtaddr,
		PreferredLifetime: fixtpl,
		ValidLifetime:     fixtvl,
	}
	opt.AddOption(&OptionStatusCode{
		Code:    StatusCodeSuccess,
		Message: "foobar",
	})

	if mshByte, err := opt.Marshal(); err != nil {
		t.Errorf("error marshalling IAAddress: %s", err)
	} else if bytes.Compare(mshByte, fixtbyte) != 0 {
		t.Errorf("marshalled IAAddress didn't match fixture!\nfixture: %v\nmarshal: %v", fixtbyte, mshByte)
	}

	// try to decode fixture with too short option length
	fixtbyte[3] = 23
	// test decoding bytes to []Option
	if _, err := DecodeOptions(fixtbyte); err == nil {
		t.Error("expected error while decoding too short option")
	} else {
		fixterr := errOptionTooShort
		if err != fixterr {
			t.Errorf("expected option too short error, got %s", err)
		}
	}
}

func TestOptionOptionRequest(t *testing.T) {
	var opt *OptionOptionRequest

	fixtbyte := []byte{0, 6, 0, 4, 0, 23, 0, 24}
	// test decoding bytes to []Option
	if list, err := DecodeOptions(fixtbyte); err != nil {
		t.Errorf("could not decode fixture: %s", err)
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

	// check body length
	fixtlen := uint16(4)
	if opt.Len() != fixtlen {
		t.Errorf("expected length %d, got %d", fixtlen, opt.Len())
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
	if list, err := DecodeOptions(fixtbyte); err != nil {
		t.Errorf("could not decode fixture: %s", err)
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

	// check body length
	fixtlen := uint16(2)
	if opt.Len() != fixtlen {
		t.Errorf("expected length %d, got %d", fixtlen, opt.Len())
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

	// try to decode fixture with too short option length
	fixtbyte[3] = 1
	// test decoding bytes to []Option
	if _, err := DecodeOptions(fixtbyte); err == nil {
		t.Error("expected error while decoding too short option")
	} else {
		fixterr := errOptionTooShort
		if err != fixterr {
			t.Errorf("expected option too short error, got %s", err)
		}
	}

	// try to decode fixture with too long option length
	fixtbyte = []byte{0, 8, 0, 3, 0, 10, 1}
	// test decoding bytes to []Option
	if _, err := DecodeOptions(fixtbyte); err == nil {
		t.Error("expected error while decoding too short option")
	} else {
		fixterr := errOptionTooLong
		if err != fixterr {
			t.Errorf("expected option too long error, got %s", err)
		}
	}
}

func TestOptionStatusCode(t *testing.T) {
	var opt *OptionStatusCode

	fixtbyte := []byte{0, 13, 0, 40, 0, 4, 83, 111, 109, 101, 32, 111, 102, 32, 116, 104, 101, 32, 97, 100, 100, 114, 101, 115, 115, 101, 115, 32, 97, 114, 101, 32, 110, 111, 116, 32, 111, 110, 32, 108, 105, 110, 107, 46}
	// test decoding bytes to []Option
	if list, err := DecodeOptions(fixtbyte); err != nil {
		t.Errorf("could not decode fixture: %s", err)
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

	// check body length
	fixtlen := uint16(40)
	if opt.Len() != fixtlen {
		t.Errorf("expected length %d, got %d", fixtlen, opt.Len())
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

	// try to decode fixture with too short option length
	fixtbyte[3] = 1
	// test decoding bytes to []Option
	if _, err := DecodeOptions(fixtbyte); err == nil {
		t.Error("expected error while decoding too short option")
	} else {
		fixterr := errOptionTooShort
		if err != fixterr {
			t.Errorf("expected option too short error, got %s", err)
		}
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
	if list, err := DecodeOptions(fixtbyte); err != nil {
		t.Errorf("could not decode fixture: %s", err)
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

	// try to decode fixture with too long option length
	fixtbyte = []byte{0, 14, 0, 1, 1}
	// test decoding bytes to []Option
	if _, err := DecodeOptions(fixtbyte); err == nil {
		t.Error("expected error while decoding too short option")
	} else {
		fixterr := errOptionTooLong
		if err != fixterr {
			t.Errorf("expected option too long error, got %s", err)
		}
	}
}

func TestOptionUserClass(t *testing.T) {
	var opt *OptionUserClass

	fixtbyte := []byte{0, 15, 0, 6, 0, 4, 116, 101, 115, 116}
	// test decoding bytes to []Option
	if list, err := DecodeOptions(fixtbyte); err != nil {
		t.Errorf("could not decode fixture: %s", err)
	} else if len(list) != 1 {
		t.Errorf("expected exactly 1 option, got %d", len(list))
	} else {
		opt = list[0].(*OptionUserClass)
	}

	// check contents of Option
	if opt.Type() != OptionTypeUserClass {
		t.Errorf("unexpected type: %s", opt.Type())
	}

	// check body length
	fixtlen := uint16(6)
	if opt.Len() != fixtlen {
		t.Errorf("expected length %d, got %d", fixtlen, opt.Len())
	}

	// test matching output for String()
	fixtstr := "user-class test"
	if fixtstr != opt.String() {
		t.Errorf("unexpected String() output: %s", opt.String())
	}

	// test if marshalled bytes match fixture
	if mshByte, err := opt.Marshal(); err != nil {
		t.Errorf("error marshalling OptionUserClass: %s", err)
	} else if bytes.Compare(mshByte, fixtbyte) != 0 {
		t.Errorf("marshalled OptionUserClass didn't match fixture!\nfixture: %v\nmarshal: %v", fixtbyte, mshByte)
	}

	// create same struct and see if its marshal matches fixture
	opt = &OptionUserClass{}
	opt.ClassData = []string{"test"}
	if mshByte, err := opt.Marshal(); err != nil {
		t.Errorf("error marshalling OptionUserClass: %s", err)
	} else if bytes.Compare(mshByte, fixtbyte) != 0 {
		t.Errorf("marshalled OptionUserClass didn't match fixture!\nfixture: %v\nmarshal: %v", fixtbyte, mshByte)
	}

	// test parameter length checking in parsing class data
	// mess up the length of the first string so decoding breaks
	// and we end up with no class data
	fixtbyte[5] = 5
	opt.decodeClassData(fixtbyte[4:])
	if len(opt.ClassData) != 0 {
		t.Errorf("option should have 0 pieces of class data, but has %d", len(opt.ClassData))
	}
}

func TestOptionVendorClass(t *testing.T) {
	var opt *OptionVendorClass

	fixtbyte := []byte{0, 16, 0, 18, 0, 0, 0, 42, 0, 6, 102, 111, 111, 98, 97, 114, 0, 4, 116, 101, 115, 116}
	// test decoding bytes to []Option
	if list, err := DecodeOptions(fixtbyte); err != nil {
		t.Errorf("could not decode fixture: %s", err)
	} else if len(list) != 1 {
		t.Errorf("expected exactly 1 option, got %d", len(list))
	} else {
		opt = list[0].(*OptionVendorClass)
	}

	// check contents of Option
	if opt.Type() != OptionTypeVendorClass {
		t.Errorf("unexpected type: %s", opt.Type())
	}

	// check body length
	fixtlen := uint16(18)
	if opt.Len() != fixtlen {
		t.Errorf("expected length %d, got %d", fixtlen, opt.Len())
	}
	fixten := uint32(42)
	if opt.EnterpriseNumber != fixten {
		t.Errorf("expected enterprise number %d, got %d", fixten, opt.EnterpriseNumber)
	}

	// test matching output for String()
	fixtstr := "vendor-class foobar, test"
	if fixtstr != opt.String() {
		t.Errorf("unexpected String() output: %s", opt.String())
	}

	// test if marshalled bytes match fixture
	if mshByte, err := opt.Marshal(); err != nil {
		t.Errorf("error marshalling OptionVendorClass: %s", err)
	} else if bytes.Compare(mshByte, fixtbyte) != 0 {
		t.Errorf("marshalled OptionVendorClass didn't match fixture!\nfixture: %v\nmarshal: %v", fixtbyte, mshByte)
	}

	// create same struct and see if its marshal matches fixture
	opt = &OptionVendorClass{
		EnterpriseNumber: fixten,
	}
	opt.ClassData = []string{"foobar", "test"}
	if mshByte, err := opt.Marshal(); err != nil {
		t.Errorf("error marshalling OptionVendorClass: %s", err)
	} else if !bytes.Equal(fixtbyte, mshByte) {
		t.Errorf("marshalled OptionVendorClass didn't match fixture!\nfixture: %v\nmarshal: %v", fixtbyte, mshByte)
	}
}

func TestOptionDNSServer(t *testing.T) {
	opt := &OptionDNSServer{
		Servers: []net.IP{net.ParseIP("fe80::1"), net.ParseIP("fe80::2")},
	}

	// check body length
	fixtlen := uint16(32)
	if opt.Len() != fixtlen {
		t.Errorf("expected length %d, got %d", fixtlen, opt.Len())
	}

	// test matching output for String()
	fixtstr := "DNS-recursive-name-server fe80::1,fe80::2"
	if fixtstr != opt.String() {
		t.Errorf("unexpected String() output: %s", opt.String())
	}

	fixtbyte := []byte{0, 23, 0, 32, 254, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 254, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}
	// test if marshalled bytes match fixture
	if mshByte, err := opt.Marshal(); err != nil {
		t.Errorf("error marshalling OptionDNSServer: %s", err)
	} else if !bytes.Equal(mshByte, fixtbyte) {
		t.Errorf("marshalled OptionDNSServer didn't match fixture!\nfixture: %v\nmarshal: %v", fixtbyte, mshByte)
	}
}

func TestOptionBootFileURL(t *testing.T) {
	var opt *OptionBootFileURL

	fixtbyte := []byte{0, 59, 0, 29, 104, 116, 116, 112, 58, 47, 47, 101, 120, 97, 109, 112, 108, 101, 46, 111, 114, 103, 47, 112, 120, 101, 108, 105, 110, 117, 120, 46, 48}
	// test decoding bytes to []Option
	if list, err := DecodeOptions(fixtbyte); err != nil {
		t.Errorf("could not decode fixture: %s", err)
	} else if len(list) != 1 {
		t.Errorf("expected exactly 1 option, got %d", len(list))
	} else {
		opt = list[0].(*OptionBootFileURL)
	}

	// check contents of Option
	if opt.Type() != OptionTypeBootFileURL {
		t.Errorf("unexpected type: %s", opt.Type())
	}

	// check body length
	fixtlen := uint16(29)
	if opt.Len() != fixtlen {
		t.Errorf("expected length %d, got %d", fixtlen, opt.Len())
	}
	fixturl := "http://example.org/pxelinux.0"
	if opt.URL != fixturl {
		t.Errorf("expected url %s, got %s", fixturl, opt.URL)
	}

	// test matching output for String()
	fixtstr := fmt.Sprintf("boot-file-url %s", fixturl)
	if fixtstr != opt.String() {
		t.Errorf("unexpected String() output: %s", opt.String())
	}

	// test if marshalled bytes match fixture
	if mshByte, err := opt.Marshal(); err != nil {
		t.Errorf("error marshalling OptionBootFileURL: %s", err)
	} else if bytes.Compare(mshByte, fixtbyte) != 0 {
		t.Errorf("marshalled OptionBootFileURL didn't match fixture!\nfixture: %v\nmarshal: %v", fixtbyte, mshByte)
	}

	// create same struct and see if its marshal matches fixture
	opt = &OptionBootFileURL{
		URL: fixturl,
	}
	if mshByte, err := opt.Marshal(); err != nil {
		t.Errorf("error marshalling OptionBootFileURL: %s", err)
	} else if bytes.Compare(mshByte, fixtbyte) != 0 {
		t.Errorf("marshalled OptionBootFileURL didn't match fixture!\nfixture: %v\nmarshal: %v", fixtbyte, mshByte)
	}
}

func TestOptionBootFileParameters(t *testing.T) {
	var opt *OptionBootFileParameters

	fixtbyte := []byte{0, 60, 0, 18, 0, 3, 102, 111, 111, 0, 3, 98, 97, 114, 0, 6, 102, 111, 111, 98, 97, 114}

	// test decoding bytes to []Option
	if list, err := DecodeOptions(fixtbyte); err != nil {
		t.Errorf("could not decode fixture: %s", err)
	} else if len(list) != 1 {
		t.Errorf("expected exactly 1 option, got %d", len(list))
	} else {
		opt = list[0].(*OptionBootFileParameters)
	}

	// check contents of Option
	if opt.Type() != OptionTypeBootFileParameters {
		t.Errorf("unexpected type: %s", opt.Type())
	}

	// check body length
	fixtlen := uint16(18)
	if opt.Len() != fixtlen {
		t.Errorf("expected length %d, got %d", fixtlen, opt.Len())
	}
	fixtparam := []string{"foo", "bar", "foobar"}
	if !reflect.DeepEqual(fixtparam, opt.Parameters) {
		t.Errorf("expected params %s, got %s", fixtparam, opt.Parameters)
	}

	// test matching output for String()
	fixtstr := "boot-file-params foo bar foobar"
	if fixtstr != opt.String() {
		t.Errorf("unexpected String() output: %s", opt.String())
	}

	// test if marshalled bytes match fixture
	if mshByte, err := opt.Marshal(); err != nil {
		t.Errorf("error marshalling OptionBootFileParameters: %s", err)
	} else if bytes.Compare(mshByte, fixtbyte) != 0 {
		t.Errorf("marshalled OptionBootFileParameters didn't match fixture!\nfixture: %v\nmarshal: %v", fixtbyte, mshByte)
	}

	// create same struct and see if its marshal matches fixture
	opt = &OptionBootFileParameters{
		Parameters: fixtparam,
	}
	if mshByte, err := opt.Marshal(); err != nil {
		t.Errorf("error marshalling OptionBootFileParameters: %s", err)
	} else if bytes.Compare(mshByte, fixtbyte) != 0 {
		t.Errorf("marshalled OptionBootFileParameters didn't match fixture!\nfixture: %v\nmarshal: %v", fixtbyte, mshByte)
	}

	// test parameter length checking in parsing parameters
	// mess up the length of the first parameter so decoding breaks
	// and we end up with an empty set of parameters
	fixtbyte[5] = 17
	opt.decodeParameters(fixtbyte[4:])
	if len(opt.Parameters) != 0 {
		t.Errorf("option should have 0 parameters but has %d", len(opt.Parameters))
	}
}

func TestOptionClientSystemArchitectureType(t *testing.T) {
	var opt *OptionClientSystemArchitectureType

	fixtbyte := []byte{0, 61, 0, 2, 0, 0}

	// test decoding bytes to []Option
	if list, err := DecodeOptions(fixtbyte); err != nil {
		t.Errorf("could not decode fixture: %s", err)
	} else if len(list) != 1 {
		t.Errorf("expected exactly 1 option, got %d", len(list))
	} else {
		opt = list[0].(*OptionClientSystemArchitectureType)
	}

	// check contents of Option
	if opt.Type() != OptionTypeClientSystemArchitectureType {
		t.Errorf("unexpected type: %s", opt.Type())
	}

	// check body length
	fixtlen := uint16(2)
	if opt.Len() != fixtlen {
		t.Errorf("expected length %d, got %d", fixtlen, opt.Len())
	}
	if len(opt.Types) != 1 {
		t.Errorf("expected type length 1, got %d", len(opt.Types))
	}
	fixttype := ArchitectureTypeIntelx86PC
	if opt.Types[0] != fixttype {
		t.Errorf("expected type %s, got %s", fixttype, opt.Types[0])
	}

	// test matching output for String()
	fixtstr := "client-system-architecture-type [Intel x86PC (0)]"
	if fixtstr != opt.String() {
		t.Errorf("unexpected String() output: %s", opt.String())
	}

	// test if marshalled bytes match fixture
	if mshByte, err := opt.Marshal(); err != nil {
		t.Errorf("error marshalling OptionClientSystemArchitectureType: %s", err)
	} else if bytes.Compare(mshByte, fixtbyte) != 0 {
		t.Errorf("marshalled OptionClientSystemArchitectureType didn't match fixture!\nfixture: %v\nmarshal: %v", fixtbyte, mshByte)
	}

	// create same struct and see if its marshal matches fixture
	opt = &OptionClientSystemArchitectureType{
		Types: []ArchitectureType{fixttype},
	}
	if mshByte, err := opt.Marshal(); err != nil {
		t.Errorf("error marshalling OptionClientSystemArchitectureType: %s", err)
	} else if bytes.Compare(mshByte, fixtbyte) != 0 {
		t.Errorf("marshalled OptionClientSystemArchitectureType didn't match fixture!\nfixture: %v\nmarshal: %v", fixtbyte, mshByte)
	}
}

func TestArchitectureTypeString(t *testing.T) {
	tests := []struct {
		in  ArchitectureType
		out string
	}{
		{ArchitectureTypeIntelx86PC, "Intel x86PC (0)"},
		{ArchitectureTypeNECPC98, "NEC/PC98 (1)"},
		{ArchitectureTypeEFIItanium, "EFI Itanium (2)"},
		{ArchitectureTypeDECAlpha, "DEC Alpha (3)"},
		{ArchitectureTypeArcx86, "Arc x86 (4)"},
		{ArchitectureTypeIntelLeanClient, "Intel Lean Client (5)"},
		{ArchitectureTypeEFIIA32, "EFI IA32 (6)"},
		{ArchitectureTypeEFIBC, "EFI BC (7)"},
		{ArchitectureTypeEFIXscale, "EFI Xscale (8)"},
		{ArchitectureTypeEFIx8664, "EFI x86-64 (9)"},
		{255, "Unknown (255)"},
	}

	for _, test := range tests {
		if strings.Compare(test.in.String(), test.out) != 0 {
			t.Errorf("expected %s but got %s", test.out, test.in.String())
		}
	}
}

func TestOptionClientNetworkInterfaceIdentifier(t *testing.T) {
	var opt *OptionClientNetworkInterfaceIdentifier

	fixtbyte := []byte{0, 62, 0, 3, 1, 2, 1}

	// test decoding bytes to []Option
	if list, err := DecodeOptions(fixtbyte); err != nil {
		t.Errorf("could not decode fixture: %s", err)
	} else if len(list) != 1 {
		t.Errorf("expected exactly 1 option, got %d", len(list))
	} else {
		opt = list[0].(*OptionClientNetworkInterfaceIdentifier)
	}

	// check contents of Option
	if opt.Type() != OptionTypeClientNetworkInterfaceIdentifier {
		t.Errorf("unexpected type: %s", opt.Type())
	}

	// check body length
	fixtlen := uint16(3)
	if opt.Len() != fixtlen {
		t.Errorf("expected length %d, got %d", fixtlen, opt.Len())
	}
	fixttype := InterfaceTypeUNDI
	if opt.InterfaceType != fixttype {
		t.Errorf("expected type %d, got %d", fixttype, opt.InterfaceType)
	}
	fixtrevmaj := uint8(2)
	if opt.RevisionMajor != fixtrevmaj {
		t.Errorf("expected major revision %d, got %d", fixtrevmaj, opt.RevisionMajor)
	}
	fixtrevmin := uint8(1)
	if opt.RevisionMinor != fixtrevmin {
		t.Errorf("expected minor revision %d, got %d", fixtrevmin, opt.RevisionMinor)
	}

	// test matching output for String()
	fixtstr := "client-network-interface-identifier Universal Network Device Interface (UNDI) (1): 2.1"
	if fixtstr != opt.String() {
		t.Errorf("unexpected String() output: %s", opt.String())
	}

	// test if marshalled bytes match fixture
	if mshByte, err := opt.Marshal(); err != nil {
		t.Errorf("error marshalling OptionClientNetworkInterfaceIdentifier: %s", err)
	} else if bytes.Compare(mshByte, fixtbyte) != 0 {
		t.Errorf("marshalled OptionClientNetworkInterfaceIdentifier didn't match fixture!\nfixture: %v\nmarshal: %v", fixtbyte, mshByte)
	}

	// create same struct and see if its marshal matches fixture
	opt = &OptionClientNetworkInterfaceIdentifier{
		InterfaceType: fixttype,
		RevisionMajor: fixtrevmaj,
		RevisionMinor: fixtrevmin,
	}
	if mshByte, err := opt.Marshal(); err != nil {
		t.Errorf("error marshalling OptionClientNetworkInterfaceIdentifier: %s", err)
	} else if bytes.Compare(mshByte, fixtbyte) != 0 {
		t.Errorf("marshalled OptionClientNetworkInterfaceIdentifier didn't match fixture!\nfixture: %v\nmarshal: %v", fixtbyte, mshByte)
	}

	// try to decode fixture with too short option length
	fixtbyte[3] = 2
	// test decoding bytes to []Option
	if _, err := DecodeOptions(fixtbyte); err == nil {
		t.Error("expected error while decoding too short option")
	} else {
		fixterr := errOptionTooShort
		if err != fixterr {
			t.Errorf("expected option too short error, got %s", err)
		}
	}
}

func TestInterfaceTypeString(t *testing.T) {
	tests := []struct {
		in  InterfaceType
		out string
	}{
		{InterfaceTypeUNDI, "Universal Network Device Interface (UNDI) (1)"},
		{255, "Unknown (255)"},
	}

	for _, test := range tests {
		if strings.Compare(test.in.String(), test.out) != 0 {
			t.Errorf("expected %s but got %s", test.out, test.in.String())
		}
	}
}

func TestOptionNextHop(t *testing.T) {
	var opt *OptionNextHop

	fixtbyte := []byte{0, 242, 0, 16, 253, 212, 71, 50, 21, 217, 234, 106, 0, 0, 0, 0, 0, 0, 16, 0}
	// test decoding bytes to []Option
	if list, err := DecodeOptions(fixtbyte); err != nil {
		t.Errorf("could not decode fixture: %s", err)
	} else if len(list) != 1 {
		t.Errorf("expected exactly 1 option, got %d", len(list))
	} else {
		opt = list[0].(*OptionNextHop)
	}

	// check contents of Option
	if opt.Type() != OptionTypeNextHop {
		t.Errorf("unexpected type: %s", opt.Type())
	}
	fixtaddr := net.ParseIP("fdd4:4732:15d9:ea6a::1000")
	if !opt.Address.Equal(fixtaddr) {
		t.Errorf("expected address %s, got %s", fixtaddr, opt.Address)
	}

	// check body length
	fixtlen := uint16(16)
	if opt.Len() != fixtlen {
		t.Errorf("expected length %d, got %d", fixtlen, opt.Len())
	}

	// test matching output for String()
	fixtstr := "next-hop fdd4:4732:15d9:ea6a::1000"
	if fixtstr != opt.String() {
		t.Errorf("unexpected String() output: %s", opt.String())
	}

	// test if marshalled bytes match fixture
	if mshByte, err := opt.Marshal(); err != nil {
		t.Errorf("error marshalling OptionNextHop: %s", err)
	} else if bytes.Compare(mshByte, fixtbyte) != 0 {
		t.Errorf("marshalled OptionNextHop didn't match fixture!\nfixture: %v\nmarshal: %v", fixtbyte, mshByte)
	}

	// create same struct and see if its marshal matches fixture
	opt = &OptionNextHop{
		Address: fixtaddr,
	}
	if mshByte, err := opt.Marshal(); err != nil {
		t.Errorf("error marshalling OptionNextHop: %s", err)
	} else if bytes.Compare(mshByte, fixtbyte) != 0 {
		t.Errorf("marshalled OptionNextHop didn't match fixture!\nfixture: %v\nmarshal: %v", fixtbyte, mshByte)
	}

	// add route prefix option
	opt.SetOption(&OptionRoutePrefix{
		RouteLifetime: 3600,
		Metric:        10,
		Preference:    RoutePreferenceHigh,
		Prefix:        net.ParseIP("fdd4:4732:15d9:ea6a::"),
		PrefixLength:  64,
	})

	// test matching output for String()
	fixtstr = "next-hop fdd4:4732:15d9:ea6a::1000 [route-prefix fdd4:4732:15d9:ea6a::/64]"
	if fixtstr != opt.String() {
		t.Errorf("unexpected String() output: %s", opt.String())
	}

	fixtbyte = []byte{0, 242, 0, 42, 253, 212, 71, 50, 21, 217, 234, 106, 0, 0, 0, 0, 0, 0, 16, 0, 0, 243, 0, 22, 0, 0, 14, 16, 64, 24, 253, 212, 71, 50, 21, 217, 234, 106, 0, 0, 0, 0, 0, 0, 0, 0}
	// test decoding bytes to []Option
	if list, err := DecodeOptions(fixtbyte); err != nil {
		t.Errorf("could not decode fixture: %s", err)
	} else if len(list) != 1 {
		t.Errorf("expected exactly 1 option, got %d", len(list))
	} else {
		opt = list[0].(*OptionNextHop)
	}

	if mshByte, err := opt.Marshal(); err != nil {
		t.Errorf("error marshalling OptionNextHop: %s", err)
	} else if bytes.Compare(mshByte, fixtbyte) != 0 {
		t.Errorf("marshalled OptionNextHop didn't match fixture!\nfixture: %v\nmarshal: %v", fixtbyte, mshByte)
	}

	// try to decode fixture with too short option length
	fixtbyte[3] = 15
	// test decoding bytes to []Option
	if _, err := DecodeOptions(fixtbyte); err == nil {
		t.Error("expected error while decoding too short option")
	} else {
		fixterr := errOptionTooShort
		if err != fixterr {
			t.Errorf("expected option too short error, got %s", err)
		}
	}
}

func TestOptionRoutePrefix(t *testing.T) {
	var opt *OptionRoutePrefix

	fixtbyte := []byte{0, 243, 0, 34, 0, 0, 14, 16, 64, 24, 253, 212, 71, 50, 21, 217, 234, 106, 0, 0, 0, 0, 0, 0, 0, 0, 0, 13, 0, 8, 0, 0, 102, 111, 111, 98, 97, 114}
	// test decoding bytes to []Option
	if list, err := DecodeOptions(fixtbyte); err != nil {
		t.Errorf("could not decode fixture: %s", err)
	} else if len(list) != 1 {
		t.Errorf("expected exactly 1 option, got %d", len(list))
	} else {
		opt = list[0].(*OptionRoutePrefix)
	}

	// check contents of Option
	if opt.Type() != OptionTypeRoutePrefix {
		t.Errorf("unexpected type: %s", opt.Type())
	}
	fixtlt := uint32(3600)
	if opt.RouteLifetime != fixtlt {
		t.Errorf("expected router lifetime %d, got %d", fixtlt, opt.RouteLifetime)
	}
	fixtpl := uint8(64)
	if opt.PrefixLength != fixtpl {
		t.Errorf("expected prefix length %d, got %d", fixtpl, opt.PrefixLength)
	}
	fixtpref := RoutePreferenceLow
	if opt.Preference != fixtpref {
		t.Errorf("expected preference %s, got %s", fixtpref, opt.Preference)
	}
	fixtprefix := net.ParseIP("fdd4:4732:15d9:ea6a::")
	if !opt.Prefix.Equal(fixtprefix) {
		t.Errorf("expected prefix %s, got %s", fixtprefix, opt.Prefix)
	}
	if sc := opt.HasOption(OptionTypeStatusCode); sc == nil {
		t.Error("expected status code option")
	}

	// check body length
	fixtlen := uint16(34)
	if opt.Len() != fixtlen {
		t.Errorf("expected length %d, got %d", fixtlen, opt.Len())
	}

	// test matching output for String()
	fixtstr := fmt.Sprintf("route-prefix %s/%d [status-code Success (0): foobar]", fixtprefix, fixtpl)
	if fixtstr != opt.String() {
		t.Errorf("unexpected String() output: %s", opt.String())
	}

	// test if marshalled bytes match fixture
	if mshByte, err := opt.Marshal(); err != nil {
		t.Errorf("error marshalling OptionRoutePrefix: %s", err)
	} else if bytes.Compare(mshByte, fixtbyte) != 0 {
		t.Errorf("marshalled OptionRoutePrefix didn't match fixture!\nfixture: %v\nmarshal: %v", fixtbyte, mshByte)
	}

	// create same struct and see if its marshal matches fixture
	opt = &OptionRoutePrefix{
		RouteLifetime: fixtlt,
		PrefixLength:  fixtpl,
		Preference:    fixtpref,
		Metric:        10,
		Prefix:        fixtprefix,
	}
	opt.AddOption(&OptionStatusCode{
		Code:    StatusCodeSuccess,
		Message: "foobar",
	})
	if mshByte, err := opt.Marshal(); err != nil {
		t.Errorf("error marshalling OptionRoutePrefix: %s", err)
	} else if bytes.Compare(mshByte, fixtbyte) != 0 {
		t.Errorf("marshalled OptionRoutePrefix didn't match fixture!\nfixture: %v\nmarshal: %v", fixtbyte, mshByte)
	}

	// check if route preference is correctly parsed
	fixtbyte[9] = 8
	if list, err := DecodeOptions(fixtbyte); err != nil {
		t.Errorf("could not decode fixture: %s", err)
	} else if len(list) != 1 {
		t.Errorf("expected exactly 1 option, got %d", len(list))
	} else {
		opt = list[0].(*OptionRoutePrefix)
	}

	if opt.Preference != RoutePreferenceHigh {
		t.Errorf("expected router preference %s, got %s", RoutePreferenceHigh, opt.Preference)
	}

	if mshByte, err := opt.Marshal(); err != nil {
		t.Errorf("error marshalling OptionRoutePrefix: %s", err)
	} else if bytes.Compare(mshByte, fixtbyte) != 0 {
		t.Errorf("marshalled OptionRoutePrefix didn't match fixture!\nfixture: %v\nmarshal: %v", fixtbyte, mshByte)
	}

	// try to decode fixture with too short option length
	fixtbyte[3] = 14
	// test decoding bytes to []Option
	if _, err := DecodeOptions(fixtbyte); err == nil {
		t.Error("expected error while decoding too short option")
	} else {
		fixterr := errOptionTooShort
		if err != fixterr {
			t.Errorf("expected option too short error, got %s", err)
		}
	}
}

func TestRoutePreferenceString(t *testing.T) {
	tests := []struct {
		in  RoutePreference
		out string
	}{
		{RoutePreferenceMedium, "Medium (0)"},
		{RoutePreferenceHigh, "High (1)"},
		{RoutePreferenceLow, "Low (3)"},
		{255, "Unknown (255)"},
	}

	for _, test := range tests {
		if strings.Compare(test.in.String(), test.out) != 0 {
			t.Errorf("expected %s but got %s", test.out, test.in.String())
		}
	}
}
