package dhcpv6

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

var (
	errOptionTooShort = errors.New("option too short")
	errOptionTooLong  = errors.New("option too long")
)

// options that contain options themselves can use optionContainer for easy
// option management
type optionContainer struct {
	options Options
}

// HasOption returns first occurance of option with type t or nil if no options
// with that type are in Options
func (o optionContainer) HasOption(t OptionType) Option {
	for _, opt := range o.options {
		if opt.Type() == t {
			return opt
		}
	}
	return nil
}

// AddOption adds given Option to slice of Options, even if this type occurs in
// the list already. To prevent duplicate option types in the list, you will
// probably want to use SetOption instead
func (o *optionContainer) AddOption(opt Option) {
	o.options = append(o.options, opt)
}

// SetOption sets given Option to slice of Options, replacing first potential
// duplicate option of the same type
func (o *optionContainer) SetOption(newopt Option) {
	for i, opt := range o.options {
		if opt.Type() == newopt.Type() {
			o.options[i] = newopt
			return
		}
	}

	o.options = append(o.options, newopt)
}

// OptionType describes DHCPv6 option types
type OptionType uint8

// DHCPv6 option types as described in RFC's 3315, 3646, 5970 and a draft for
// Route Options
const (
	_ OptionType = iota
	// RFC3315
	OptionTypeClientID
	OptionTypeServerID
	OptionTypeIANA
	OptionTypeIATA
	OptionTypeIAAddress
	OptionTypeOptionRequest
	OptionTypePreference
	OptionTypeElapsedTime
	OptionTypeRelayMessage
	_
	OptionTypeAuthentication
	OptionTypeServerUnicast
	OptionTypeStatusCode
	OptionTypeRapidCommit
	OptionTypeUserClass
	OptionTypeVendorClass
	OptionTypeVendorOption
	OptionTypeInterfaceID
	OptionTypeReconfigureMessage
	OptionTypeReconfigureAccept
	_
	_
	// RFC3646
	OptionTypeDNSServer
	OptionTypeDNSSearchList
	// RFC5970
	OptionTypeBootFileURL                      OptionType = 59
	OptionTypeBootFileParameters               OptionType = 60
	OptionTypeClientSystemArchitectureType     OptionType = 61
	OptionTypeClientNetworkInterfaceIdentifier OptionType = 62
	// draft-ietf-mif-dhcpv6-route-option
	OptionTypeNextHop     OptionType = 242
	OptionTypeRoutePrefix OptionType = 243
)

func (t OptionType) String() string {
	name := func() string {
		switch t {
		case OptionTypeClientID:
			return "Client Identifier"
		case OptionTypeServerID:
			return "Server Identifier"
		case OptionTypeIANA:
			return "Identity Association for Non-temporary Addresses"
		case OptionTypeIATA:
			return "Identity Association for Temporary Addresses"
		case OptionTypeIAAddress:
			return "Identity Association Address"
		case OptionTypeOptionRequest:
			return "Option Request"
		case OptionTypePreference:
			return "Preference"
		case OptionTypeElapsedTime:
			return "Elapsed Time"
		case OptionTypeRelayMessage:
			return "Relay Message"
		case OptionTypeAuthentication:
			return "Authentication"
		case OptionTypeServerUnicast:
			return "Server Unicast"
		case OptionTypeStatusCode:
			return "Status Code"
		case OptionTypeRapidCommit:
			return "Rapid Commit"
		case OptionTypeUserClass:
			return "User Class"
		case OptionTypeVendorClass:
			return "Vendor Class"
		case OptionTypeVendorOption:
			return "Vendor-specific Information"
		case OptionTypeInterfaceID:
			return "Interface-ID"
		case OptionTypeReconfigureMessage:
			return "Reconfigure Message"
		case OptionTypeReconfigureAccept:
			return "Reconfigure Accept"
		case OptionTypeDNSServer:
			return "DNS Server"
		case OptionTypeDNSSearchList:
			return "DNS Search List"
		case OptionTypeBootFileURL:
			return "Boot File URL"
		case OptionTypeBootFileParameters:
			return "Boot File Parameters"
		case OptionTypeNextHop:
			return "Next Hop"
		case OptionTypeRoutePrefix:
			return "Route Prefix"
		default:
			return typeUnknown
		}
	}
	return fmt.Sprintf("%s (%d)", name(), t)
}

// Option -- interface to build various DHCPv6 options on
type Option interface {
	String() string
	Len() uint16
	Type() OptionType
	Marshal() ([]byte, error)
}

// Options is a type wrapper for a slice of Options
type Options []Option

// Marshal is a helper function of Options and returns marshalled results
// for all Options or error when there is one
func (o Options) Marshal() ([]byte, error) {
	b := []byte{}
	// loop over all options and append bytes to b
	// or abort when it throws an error
	for _, opt := range o {
		ob, err := opt.Marshal()
		if err != nil {
			return nil, err
		}

		b = append(b, ob...)
	}

	return b, nil
}

// Len returns combined length in bytes for all Options in slice
// this includes the option header (containing type and length)
func (o Options) Len() uint16 {
	l := uint16(0)
	// loop over all options and add length to l
	for _, opt := range o {
		// since this function is mostly used to calculate byte length for byte
		// slices containing these options, the 4 byte option header has to be
		// calculated as well for each option
		l += opt.Len() + 4
	}

	return l
}

// OptionClientID implements the Client Identifier option as described at
// https://tools.ietf.org/html/rfc3315#section-22.2
type OptionClientID struct {
	DUID DUID
}

func (o OptionClientID) String() string {
	return fmt.Sprintf("client-ID %s", o.DUID)
}

// Len returns the length in bytes of OptionClientID's body
func (o OptionClientID) Len() uint16 {
	return o.DUID.Len()
}

// Type returns OptionTypeClientID
func (o OptionClientID) Type() OptionType {
	return OptionTypeClientID
}

// Marshal returns byte slice representing this OptionClientID
func (o OptionClientID) Marshal() ([]byte, error) {
	// prepare byte slice of appropriate length
	// DUID will be appended later
	b := make([]byte, 4) // type (2 bytes), length (2 bytes)
	// set type
	binary.BigEndian.PutUint16(b[0:2], uint16(OptionTypeClientID))
	// set length
	binary.BigEndian.PutUint16(b[2:4], o.Len())
	// append DUID bytes
	duid, err := o.DUID.Marshal()
	if err != nil {
		return nil, fmt.Errorf("could not marshal DUID: %s", err)
	}
	b = append(b, duid...)

	return b, nil
}

// OptionServerID implements the Server Identifier option as described at
// https://tools.ietf.org/html/rfc3315#section-22.3
type OptionServerID struct {
	DUID DUID
}

func (o OptionServerID) String() string {
	return fmt.Sprintf("server-ID %s", o.DUID)
}

// Len returns the length in bytes of OptionServerID's body
func (o OptionServerID) Len() uint16 {
	return o.DUID.Len()
}

// Type returns OptionTypeServerID
func (o OptionServerID) Type() OptionType {
	return OptionTypeServerID
}

// Marshal returns byte slice representing this OptionServerID
func (o OptionServerID) Marshal() ([]byte, error) {
	// prepare byte slice of appropriate length
	// DUID will be appended later
	b := make([]byte, 4) // type (2 bytes), length (2 bytes)
	// set type
	binary.BigEndian.PutUint16(b[0:2], uint16(OptionTypeServerID))
	// set length
	binary.BigEndian.PutUint16(b[2:4], o.Len())
	// append DUID bytes
	duid, err := o.DUID.Marshal()
	if err != nil {
		return nil, fmt.Errorf("could not marshal DUID: %s", err)
	}
	b = append(b, duid...)

	return b, nil
}

// Equal returns true if given ServerID option is byte-wise identical or false
// otherwise
func (o OptionServerID) Equal(opt Option) bool {
	if opt.Type() != OptionTypeServerID {
		return false
	}

	optb, err := opt.Marshal()
	if err != nil {
		return false
	}
	myb, err := o.Marshal()
	if err != nil {
		return false
	}

	return bytes.Compare(optb, myb) == 0
}

// OptionIANA implements the Identity Association for Non-temporary Addresses
// option as described at https://tools.ietf.org/html/rfc3315#section-22.4
type OptionIANA struct {
	optionContainer
	IAID uint32
	T1   time.Duration // delay before Renew
	T2   time.Duration // delay before Rebind
}

func (o OptionIANA) String() string {
	output := fmt.Sprintf("IA_NA IAID:%d T1:%d T2:%d", o.IAID, o.T1, o.T2)
	if len(o.options) > 0 {
		output += fmt.Sprintf(" %s", o.options)
	}
	return output
}

// Len returns the length in bytes of OptionIANA's body
func (o OptionIANA) Len() uint16 {
	// iaid (4 bytes)
	// t1 (4 bytes)
	// t2 (4 bytes)
	// any additional options' length
	return 12 + o.options.Len()
}

// Type returns OptionIANA
func (o OptionIANA) Type() OptionType {
	return OptionTypeIANA
}

// Marshal returns byte slice representing this OptionIANA
func (o *OptionIANA) Marshal() ([]byte, error) {
	// prepare byte slice of appropriate length
	// any options will be appended later
	b := make([]byte, 16)
	// set type
	binary.BigEndian.PutUint16(b[0:2], uint16(OptionTypeIANA))
	// set length
	binary.BigEndian.PutUint16(b[2:4], o.Len())
	// set IAID
	binary.BigEndian.PutUint32(b[4:8], o.IAID)
	// set T1
	binary.BigEndian.PutUint32(b[8:12], uint32(o.T1))
	// set T2
	binary.BigEndian.PutUint32(b[12:16], uint32(o.T2))
	if len(o.options) > 0 {
		optMarshal, err := o.options.Marshal()
		if err != nil {
			return nil, err
		}
		b = append(b, optMarshal...)
	}
	return b, nil
}

// OptionIAAddress implements the IA Address option as described at
// https://tools.ietf.org/html/rfc3315#section-22.6
type OptionIAAddress struct {
	Address           net.IP
	PreferredLifetime time.Duration
	ValidLifetime     time.Duration
	// TODO: options
}

func (o OptionIAAddress) String() string {
	return fmt.Sprintf("IA_ADDR %s pltime:%d vltime:%d", o.Address, o.PreferredLifetime, o.ValidLifetime)
}

// Type returns OptionTypeIAAddress
func (o OptionIAAddress) Type() OptionType {
	return OptionTypeIAAddress
}

// Len returns the length in bytes of OptionIAAddress's body
func (o OptionIAAddress) Len() uint16 {
	// preferred lifetime (4 bytes)
	// valid lifetime (4 bytes)
	// address (16 bytes)
	// TODO: any additional options' length
	return 24
}

// Marshal returns byte slice representing this OptionIAAddress
func (o OptionIAAddress) Marshal() ([]byte, error) {
	// prepare byte slice of appropriate length
	// address, preferred and valid time and optional options are appended later
	b := make([]byte, 4)
	// set type
	binary.BigEndian.PutUint16(b[0:2], uint16(OptionTypeIAAddress))
	// set length
	binary.BigEndian.PutUint16(b[2:4], o.Len())
	// set address
	b = append(b, o.Address...)
	t := make([]byte, 8)
	// set preferred time
	binary.BigEndian.PutUint32(t[0:4], uint32(o.PreferredLifetime))
	// set valid time
	binary.BigEndian.PutUint32(t[4:8], uint32(o.ValidLifetime))
	b = append(b, t...)
	return b, nil
}

// OptionOptionRequest implements the Option Request option as described at
// https://tools.ietf.org/html/rfc3315#section-22.7
type OptionOptionRequest struct {
	Options []OptionType
}

func (o OptionOptionRequest) String() string {
	output := "option-request"
	for _, opt := range o.Options {
		output += fmt.Sprintf(" %s", opt)
	}
	return output
}

// Len returns the length in bytes of OptionOptionRequest's body
func (o OptionOptionRequest) Len() uint16 {
	return uint16(len(o.Options) * 2)
}

// Type returns OptionTypeOptionRequest
func (o OptionOptionRequest) Type() OptionType {
	return OptionTypeOptionRequest
}

// Marshal returns byte slice representing this OptionOptionRequest
func (o OptionOptionRequest) Marshal() ([]byte, error) {
	// prepare byte slice of appropriate length
	b := make([]byte, 4+o.Len())
	// set type
	binary.BigEndian.PutUint16(b[0:2], uint16(OptionTypeOptionRequest))
	// set length
	binary.BigEndian.PutUint16(b[2:4], o.Len())
	// fill in all options
	for i, opt := range o.Options {
		binary.BigEndian.PutUint16(b[4+(i*2):6+(i*2)], uint16(opt))
	}
	return b, nil
}

// HasOption returns Option if this IA_NA option has OptionType t as option or
// nil otherwise
func (o OptionOptionRequest) HasOption(t OptionType) bool {
	for _, opt := range o.Options {
		if opt == t {
			return true
		}
	}
	return false
}

// helper function to decode the DHCPv6 options requested in this specific option
// this is somewhat similar to DecodeOptions, but instead of the entire option
// here only the option types are decoded
func (o *OptionOptionRequest) decodeOptions(data []byte) error {
	var options []OptionType
	for {
		if len(data) < 2 {
			break
		}
		optionType := OptionType(binary.BigEndian.Uint16(data[:2]))
		options = append(options, optionType)
		data = data[2:]
	}

	o.Options = options
	return nil
}

// OptionElapsedTime implements the Elapsed Time option as described at
// https://tools.ietf.org/html/rfc3315#section-22.9
type OptionElapsedTime struct {
	ElapsedTime time.Duration
}

func (o OptionElapsedTime) String() string {
	return fmt.Sprintf("elapsed-time %v", o.ElapsedTime)
}

// Len returns the length in bytes of OptionElapsedTime's body
func (o OptionElapsedTime) Len() uint16 {
	return 2
}

// Type returns OptionTypeElapsedTime
func (o OptionElapsedTime) Type() OptionType {
	return OptionTypeElapsedTime
}

// Marshal returns byte slice representing this OptionElapsedTime
func (o OptionElapsedTime) Marshal() ([]byte, error) {
	// prepare byte slice of appropriate length
	b := make([]byte, 4+o.Len())
	// set type
	binary.BigEndian.PutUint16(b[0:2], uint16(OptionTypeElapsedTime))
	// set length
	binary.BigEndian.PutUint16(b[2:4], o.Len())
	// set time (divide by 10 to go from millisecond to hundredths of seconds again)
	binary.BigEndian.PutUint16(b[4:6], uint16(o.ElapsedTime/time.Millisecond/10))

	return b, nil
}

type StatusCode uint16

// Status codes as described at https://tools.ietf.org/html/rfc3315#section-24.4
const (
	StatusCodeSuccess StatusCode = iota
	StatusCodeUnspecFail
	StatusCodeNoAddrsAvail
	StatusCodeNoBinding
	StatusCodeNotOnLink
	StatusCodeUseMulticast
)

func (s StatusCode) String() string {
	name := func() string {
		switch s {
		case StatusCodeSuccess:
			return "Success"
		case StatusCodeUnspecFail:
			return "UnspecFail"
		case StatusCodeNoAddrsAvail:
			return "NoAddrsAvail"
		case StatusCodeNoBinding:
			return "NoBinding"
		case StatusCodeNotOnLink:
			return "NotOnLink"
		case StatusCodeUseMulticast:
			return "UseMulticast"
		default:
			return typeUnknown
		}
	}

	return fmt.Sprintf("%s (%d)", name(), s)
}

// OptionStatusCode implements the Status Code option as described at
// https://tools.ietf.org/html/rfc3315#section-22.13
type OptionStatusCode struct {
	Code    StatusCode
	Message string
}

func (o OptionStatusCode) String() string {
	return fmt.Sprintf("status-code %s: %s", o.Code, o.Message)
}

// Len returns the length in bytes of OptionStatusCode's body
func (o OptionStatusCode) Len() uint16 {
	return uint16(2 + len(o.Message))
}

// Type returns OptionTypeStatusCode
func (o OptionStatusCode) Type() OptionType {
	return OptionTypeStatusCode
}

// Marshal returns byte slice representing this OptionStatusCode
func (o OptionStatusCode) Marshal() ([]byte, error) {
	// prepare byte slice of appropriate length
	b := make([]byte, 6)
	// set type
	binary.BigEndian.PutUint16(b[0:2], uint16(OptionTypeStatusCode))
	// set length
	binary.BigEndian.PutUint16(b[2:4], o.Len())
	// set StatusCode
	binary.BigEndian.PutUint16(b[4:6], uint16(o.Code))
	// set message
	b = append(b, []byte(o.Message)...)

	return b, nil
}

// OptionRapidCommit implements the Rapid Commit option as described at
// https://tools.ietf.org/html/rfc3315#section-22.14
// this option acts basically as a flag for the message carrying it
// and has no further contents
type OptionRapidCommit struct{}

func (o OptionRapidCommit) String() string {
	return "rapid-commit"
}

// Len returns the length in bytes of OptionRapidCommit's body
func (o OptionRapidCommit) Len() uint16 {
	return 0
}

// Type returns OptionTypeRapidCommit
func (o OptionRapidCommit) Type() OptionType {
	return OptionTypeRapidCommit
}

// Marshal returns byte slice representing this OptionRapidCommit
func (o OptionRapidCommit) Marshal() ([]byte, error) {
	// prepare byte slice of appropriate length
	b := make([]byte, 4)
	// set type
	binary.BigEndian.PutUint16(b[0:2], uint16(OptionTypeRapidCommit))
	// setting length is not necessary, it's 0 already

	return b, nil
}

// options that contain class data can use optionContainer for easy
// encoding/decoding
type classDataContainer struct {
	ClassData []string
}

// helper function to decode the user class data
func (o *classDataContainer) decodeClassData(data []byte) error {
	opaque := []string{}
	for {
		if len(data) < 2 {
			// class data too short
			break
		}

		pl := binary.BigEndian.Uint16(data[0:2])
		if uint16(len(data)) < 2+pl {
			// class data body too short
			break
		}

		opaque = append(opaque, string(data[2:2+pl]))
		data = data[2+pl:]
	}

	o.ClassData = opaque
	return nil
}

func (o classDataContainer) encodeClassData() []byte {
	b := make([]byte, 0)
	for _, cd := range o.ClassData {
		pl := make([]byte, 2)
		binary.BigEndian.PutUint16(pl[0:2], uint16(len(cd)))
		// append class data length
		b = append(b, pl...)
		// append class data
		b = append(b, []byte(cd)...)
	}

	return b
}

func (o classDataContainer) classDataLen() uint16 {
	pl := 0
	for _, cd := range o.ClassData {
		pl += len(cd) + 2 // 2 additional bytes per parameter for parameter length
	}

	return uint16(pl)
}

// OptionUserClass implements the User Class option described in
// https://tools.ietf.org/html/rfc3315#section-22.15
type OptionUserClass struct {
	classDataContainer
}

func (o OptionUserClass) String() string {
	return fmt.Sprintf("user-class %s", strings.Join(o.ClassData, ", "))
}

// Len returns the length in bytes of OptionUserClass's body
func (o OptionUserClass) Len() uint16 {
	return uint16(o.classDataLen())
}

// Type returns OptionTypeUserClass
func (o OptionUserClass) Type() OptionType {
	return OptionTypeUserClass
}

// Marshal returns byte slice representing this OptionUserClass
func (o OptionUserClass) Marshal() ([]byte, error) {
	// prepare byte slice of appropriate length
	b := make([]byte, 4)
	// set type
	binary.BigEndian.PutUint16(b[0:2], uint16(OptionTypeUserClass))
	// set length
	binary.BigEndian.PutUint16(b[2:4], o.Len())
	// append user class data
	b = append(b, o.encodeClassData()...)

	return b, nil
}

// OptionVendorClass implements the Vendor Class option described in
// https://tools.ietf.org/html/rfc3315#section-22.16
type OptionVendorClass struct {
	classDataContainer
	EnterpriseNumber uint32
}

func (o OptionVendorClass) String() string {
	return fmt.Sprintf("vendor-class %s", strings.Join(o.ClassData, ", "))
}

// Len returns the length in bytes of OptionVendorClass's body
func (o OptionVendorClass) Len() uint16 {
	return uint16(o.classDataLen()) + 4 // for EnterpriseNumber
}

// Type returns OptionTypeVendorClass
func (o OptionVendorClass) Type() OptionType {
	return OptionTypeVendorClass
}

// Marshal returns byte slice representing this OptionVendorClass
func (o OptionVendorClass) Marshal() ([]byte, error) {
	// prepare byte slice of appropriate length
	b := make([]byte, 8)
	// set type
	binary.BigEndian.PutUint16(b[0:2], uint16(OptionTypeVendorClass))
	// set length
	binary.BigEndian.PutUint16(b[2:4], o.Len())
	// set enterprise number
	binary.BigEndian.PutUint32(b[4:8], o.EnterpriseNumber)
	// append user class data
	b = append(b, o.encodeClassData()...)

	return b, nil
}

// OptionBootFileURL implements the Boot File URL option described in
// https://tools.ietf.org/html/rfc5970#section-3.1
type OptionBootFileURL struct {
	URL string
}

func (o OptionBootFileURL) String() string {
	return fmt.Sprintf("boot-file-url %s", o.URL)
}

// Len returns the length in bytes of OptionBootFileURL's body
func (o OptionBootFileURL) Len() uint16 {
	return uint16(len(o.URL))
}

// Type returns OptionTypeBootFileURL
func (o OptionBootFileURL) Type() OptionType {
	return OptionTypeBootFileURL
}

// Marshal returns byte slice representing this OptionBootFileURL
func (o OptionBootFileURL) Marshal() ([]byte, error) {
	// prepare byte slice of appropriate length
	b := make([]byte, 4)
	// set type
	binary.BigEndian.PutUint16(b[0:2], uint16(OptionTypeBootFileURL))
	// set length
	binary.BigEndian.PutUint16(b[2:4], o.Len())
	// append string
	b = append(b, []byte(o.URL)...)

	return b, nil
}

// OptionBootFileParameters implements the Boot File URL option described in
// https://tools.ietf.org/html/rfc5970#section-3.2
type OptionBootFileParameters struct {
	Parameters []string
}

func (o OptionBootFileParameters) String() string {
	output := "boot-file-params"
	for _, p := range o.Parameters {
		output += fmt.Sprintf(" %s", p)
	}

	return output
}

// Len returns the length in bytes of OptionBootFileParameters's body
func (o OptionBootFileParameters) Len() uint16 {
	pl := 0
	for _, p := range o.Parameters {
		pl += len(p) + 2 // 2 additional bytes per parameter for parameter length
	}

	return uint16(pl)
}

// Type returns OptionTypeBootFileParameters
func (o OptionBootFileParameters) Type() OptionType {
	return OptionTypeBootFileParameters
}

// Marshal returns byte slice representing this OptionBootFileParameters
func (o OptionBootFileParameters) Marshal() ([]byte, error) {
	// prepare byte slice of appropriate length
	b := make([]byte, 4)
	// set type
	binary.BigEndian.PutUint16(b[0:2], uint16(OptionTypeBootFileParameters))
	// set length
	binary.BigEndian.PutUint16(b[2:4], o.Len())
	for _, p := range o.Parameters {
		pl := make([]byte, 2)
		binary.BigEndian.PutUint16(pl[0:2], uint16(len(p)))
		// append parameter length
		b = append(b, pl...)
		// append parameter
		b = append(b, []byte(p)...)
	}

	return b, nil
}

// helper function to decode the parameters
func (o *OptionBootFileParameters) decodeParameters(data []byte) error {
	params := []string{}
	for {
		if len(data) < 2 {
			// param data too short
			break
		}

		pl := binary.BigEndian.Uint16(data[0:2])
		if uint16(len(data)) < 2+pl {
			// param body too short
			break
		}

		params = append(params, string(data[2:2+pl]))
		data = data[2+pl:]
	}

	o.Parameters = params
	return nil
}

type ArchitectureType uint16

// Architecture types as described at https://tools.ietf.org/html/rfc4578#section-2.1
const (
	ArchitectureTypeIntelx86PC ArchitectureType = iota
	ArchitectureTypeNECPC98
	ArchitectureTypeEFIItanium
	ArchitectureTypeDECAlpha
	ArchitectureTypeArcx86
	ArchitectureTypeIntelLeanClient
	ArchitectureTypeEFIIA32
	ArchitectureTypeEFIBC
	ArchitectureTypeEFIXscale
	ArchitectureTypeEFIx8664
)

func (s ArchitectureType) String() string {
	name := func() string {
		switch s {
		case ArchitectureTypeIntelx86PC:
			return "Intel x86PC"
		case ArchitectureTypeNECPC98:
			return "NEC/PC98"
		case ArchitectureTypeEFIItanium:
			return "EFI Itanium"
		case ArchitectureTypeDECAlpha:
			return "DEC Alpha"
		case ArchitectureTypeArcx86:
			return "Arc x86"
		case ArchitectureTypeIntelLeanClient:
			return "Intel Lean Client"
		case ArchitectureTypeEFIIA32:
			return "EFI IA32"
		case ArchitectureTypeEFIBC:
			return "EFI BC"
		case ArchitectureTypeEFIXscale:
			return "EFI Xscale"
		case ArchitectureTypeEFIx8664:
			return "EFI x86-64"
		default:
			return typeUnknown
		}
	}

	return fmt.Sprintf("%s (%d)", name(), s)
}

// OptionClientSystemArchitectureType implements the Client System
// Architecture Type option as described in
// https://tools.ietf.org/html/rfc5970#section-3.3
type OptionClientSystemArchitectureType struct {
	Types []ArchitectureType
}

func (o OptionClientSystemArchitectureType) String() string {
	return fmt.Sprintf("client-system-architecture-type %s", o.Types)
}

// Len returns the length in bytes of OptionClientSystemArchitectureType's body
func (o OptionClientSystemArchitectureType) Len() uint16 {
	return uint16(2 * len(o.Types))
}

// Type returns OptionTypeClientSystemArchitectureType
func (o OptionClientSystemArchitectureType) Type() OptionType {
	return OptionTypeClientSystemArchitectureType
}

// Marshal returns byte slice representing this OptionClientSystemArchitectureType
func (o OptionClientSystemArchitectureType) Marshal() ([]byte, error) {
	// prepare byte slice of appropriate length
	b := make([]byte, 4)
	// set type
	binary.BigEndian.PutUint16(b[0:2], uint16(OptionTypeClientSystemArchitectureType))
	// set length
	binary.BigEndian.PutUint16(b[2:4], o.Len())
	// append types
	for _, t := range o.Types {
		tb := make([]byte, 2)
		binary.BigEndian.PutUint16(tb[0:2], uint16(t))
		b = append(b, tb...)
	}

	return b, nil
}

type InterfaceType uint8

// Interface types as described at https://tools.ietf.org/html/rfc4578#section-2.2
const (
	_ InterfaceType = iota
	InterfaceTypeUNDI
)

func (s InterfaceType) String() string {
	name := func() string {
		switch s {
		case InterfaceTypeUNDI:
			return "Universal Network Device Interface (UNDI)"
		default:
			return typeUnknown
		}
	}

	return fmt.Sprintf("%s (%d)", name(), s)
}

// OptionClientNetworkInterfaceIdentifier implements the Client Network
// Interface Identifier option as described in
// https://tools.ietf.org/html/rfc5970#section-3.4
type OptionClientNetworkInterfaceIdentifier struct {
	InterfaceType InterfaceType
	RevisionMajor uint8
	RevisionMinor uint8
}

func (o OptionClientNetworkInterfaceIdentifier) String() string {
	return fmt.Sprintf("client-network-interface-identifier %s: %d.%d",
		o.InterfaceType, o.RevisionMajor, o.RevisionMinor)
}

// Len returns the length in bytes of OptionClientNetworkInterfaceIdentifier's
// body
func (o OptionClientNetworkInterfaceIdentifier) Len() uint16 {
	return 3 // static length
}

// Type returns OptionTypeClientNetworkInterfaceIdentifier
func (o OptionClientNetworkInterfaceIdentifier) Type() OptionType {
	return OptionTypeClientNetworkInterfaceIdentifier
}

// Marshal returns byte slice representing this
// OptionTypeClientNetworkInterfaceIdentifier
func (o OptionClientNetworkInterfaceIdentifier) Marshal() ([]byte, error) {
	// prepare byte slice of appropriate length
	b := make([]byte, 7)
	// set type
	binary.BigEndian.PutUint16(b[0:2], uint16(OptionTypeClientNetworkInterfaceIdentifier))
	// set length
	binary.BigEndian.PutUint16(b[2:4], o.Len())
	// set type, major and minor revision
	b[4] = uint8(o.InterfaceType)
	b[5] = o.RevisionMajor
	b[6] = o.RevisionMinor

	return b, nil
}

// OptionNextHop implements the Next Hop option proposed in
// https://tools.ietf.org/html/draft-ietf-mif-dhcpv6-route-option-05#section-5.1
type OptionNextHop struct {
	optionContainer
	Address net.IP
}

func (o OptionNextHop) String() string {
	output := fmt.Sprintf("next-hop %s", o.Address)
	if len(o.options) > 0 {
		output += fmt.Sprintf(" %s", o.options)
	}

	return output
}

// Len returns the length in bytes of OptionNextHop's body
func (o OptionNextHop) Len() uint16 {
	return 16 + o.options.Len()
}

// Type returns OptionTypeNextHop
func (o OptionNextHop) Type() OptionType {
	return OptionTypeNextHop
}

// Marshal returns byte slice representing this OptionNextHop
func (o OptionNextHop) Marshal() ([]byte, error) {
	// prepare byte slice of appropriate length
	b := make([]byte, 4)
	// set type
	binary.BigEndian.PutUint16(b[0:2], uint16(OptionTypeNextHop))
	// set length
	binary.BigEndian.PutUint16(b[2:4], o.Len())
	// set address
	b = append(b, o.Address...)
	if len(o.options) > 0 {
		optMarshal, err := o.options.Marshal()
		if err != nil {
			return nil, err
		}
		b = append(b, optMarshal...)
	}
	return b, nil
}

type RoutePreference uint8

// Route preferences as described at https://tools.ietf.org/html/draft-ietf-mif-dhcpv6-route-option-05#section-5.2
const (
	RoutePreferenceMedium RoutePreference = iota
	RoutePreferenceHigh
	_
	RoutePreferenceLow
)

func (s RoutePreference) String() string {
	name := func() string {
		switch s {
		case RoutePreferenceMedium:
			return "Medium"
		case RoutePreferenceHigh:
			return "High"
		case RoutePreferenceLow:
			return "Low"
		default:
			return typeUnknown
		}
	}

	return fmt.Sprintf("%s (%d)", name(), s)
}

// OptionRoutePrefix implements the Next Hop option proposed in
// https://tools.ietf.org/html/draft-ietf-mif-dhcpv6-route-option-05#section-5.2
type OptionRoutePrefix struct {
	optionContainer
	RouteLifetime uint32
	PrefixLength  uint8
	Preference    RoutePreference
	Metric        uint8
	Prefix        net.IP
}

func (o OptionRoutePrefix) String() string {
	output := fmt.Sprintf("route-prefix %s/%d", o.Prefix, o.PrefixLength)
	if len(o.options) > 0 {
		output += fmt.Sprintf(" %s", o.options)
	}

	return output
}

// Len returns the length in bytes of OptionNextHop's body
func (o OptionRoutePrefix) Len() uint16 {
	return 22 + o.options.Len()
}

// Type returns OptionTypeNextHop
func (o OptionRoutePrefix) Type() OptionType {
	return OptionTypeRoutePrefix
}

// Marshal returns byte slice representing this OptionRoutePrefix
func (o OptionRoutePrefix) Marshal() ([]byte, error) {
	// prepare byte slice of appropriate length
	b := make([]byte, 10)
	// set type
	binary.BigEndian.PutUint16(b[0:2], uint16(OptionTypeRoutePrefix))
	// set length
	binary.BigEndian.PutUint16(b[2:4], o.Len())
	// set router lifetime
	binary.BigEndian.PutUint32(b[4:8], o.RouteLifetime)
	// set prefix length
	b[8] = o.PrefixLength
	// set router preference
	// medium is 00, which is default
	switch o.Preference {
	case RoutePreferenceLow:
		b[9] ^= 24 // 2^4 + 2^3
	case RoutePreferenceHigh:
		b[9] ^= 8 // 2^3
	}
	// append prefix
	b = append(b, o.Prefix...)
	// add options
	if len(o.options) > 0 {
		optMarshal, err := o.options.Marshal()
		if err != nil {
			return nil, err
		}
		b = append(b, optMarshal...)
	}

	return b, nil
}

// DecodeOptions takes DHCPv6 option bytes and tries to decode every handled
// option, looking at its type and the given length, and returns a slice
// containing all decoded structs
func DecodeOptions(data []byte) (Options, error) {
	// empty container
	list := Options{}

	for {
		// the first 4 bytes of a  option contain option type and data length
		// so that's the least amount of bytes expected
		if len(data) < 4 {
			return list, errOptionTooShort
		}

		optionType := OptionType(binary.BigEndian.Uint16(data[0:2]))
		optionLen := binary.BigEndian.Uint16(data[2:4])
		// check if we have at least the same amount of bytes this option's length
		// is prescribing
		if len(data) < int(optionLen+4) {
			return list, errOptionTooShort
		}

		var currentOption Option
		switch optionType {
		case OptionTypeClientID:
			currentOption = &OptionClientID{}
			duid, err := DecodeDUID(data[4 : 4+optionLen])
			if err != nil {
				return list, err
			}
			currentOption.(*OptionClientID).DUID = duid
		case OptionTypeServerID:
			currentOption = &OptionServerID{}
			duid, err := DecodeDUID(data[4 : 4+optionLen])
			if err != nil {
				return list, err
			}
			currentOption.(*OptionServerID).DUID = duid
		case OptionTypeIANA:
			if optionLen < 12 {
				return list, errOptionTooShort
			}
			currentOption = &OptionIANA{}
			currentOption.(*OptionIANA).IAID = binary.BigEndian.Uint32(data[4:8])
			currentOption.(*OptionIANA).T1 = time.Duration(binary.BigEndian.Uint32(data[8:12]))
			currentOption.(*OptionIANA).T2 = time.Duration(binary.BigEndian.Uint32(data[12:16]))
			if optionLen > 12 {
				var err error
				currentOption.(*OptionIANA).options, err = DecodeOptions(data[16 : optionLen+4])
				if err != nil {
					return list, err
				}
			}
		case OptionTypeIAAddress:
			if optionLen < 24 {
				return list, errOptionTooShort
			}
			currentOption = &OptionIAAddress{
				Address:           data[4:20],
				PreferredLifetime: time.Duration(binary.BigEndian.Uint32(data[20:24])),
				ValidLifetime:     time.Duration(binary.BigEndian.Uint32(data[24:28])),
			}
		case OptionTypeOptionRequest:
			currentOption = &OptionOptionRequest{}
			if optionLen > 0 {
				currentOption.(*OptionOptionRequest).decodeOptions(data[4 : 4+optionLen])
			}
		case OptionTypeElapsedTime:
			if optionLen < 2 {
				return list, errOptionTooShort
			}
			if optionLen > 2 {
				return list, errOptionTooLong
			}
			currentOption = &OptionElapsedTime{
				// RFC3315 describes elapsed time is expressed in hundredths of a second
				// hence the 10 * millisecond
				ElapsedTime: (time.Duration(binary.BigEndian.Uint16(data[4:4+optionLen])) * time.Millisecond * 10),
			}
		case OptionTypeStatusCode:
			if optionLen < 2 {
				return list, errOptionTooShort
			}
			currentOption = &OptionStatusCode{
				Code:    StatusCode(binary.BigEndian.Uint16(data[4:6])),
				Message: string(data[6 : optionLen+4]),
			}
		case OptionTypeRapidCommit:
			if optionLen != 0 {
				return list, errOptionTooLong
			}

			currentOption = &OptionRapidCommit{}
		case OptionTypeUserClass:
			currentOption = &OptionUserClass{}
			if optionLen > 0 {
				currentOption.(*OptionUserClass).decodeClassData(data[4 : 4+optionLen])
			}
		case OptionTypeVendorClass:
			currentOption = &OptionVendorClass{
				EnterpriseNumber: binary.BigEndian.Uint32(data[4:8]),
			}
			if optionLen > 4 {
				currentOption.(*OptionVendorClass).decodeClassData(data[8 : 4+optionLen])
			}
		case OptionTypeBootFileURL:
			currentOption = &OptionBootFileURL{}
			if optionLen > 0 {
				currentOption.(*OptionBootFileURL).URL = string(data[4 : 4+optionLen])
			}
		case OptionTypeBootFileParameters:
			currentOption = &OptionBootFileParameters{}
			if optionLen > 0 {
				currentOption.(*OptionBootFileParameters).decodeParameters(data[4 : 4+optionLen])
			}
		case OptionTypeClientSystemArchitectureType:
			currentOption = &OptionClientSystemArchitectureType{}
			if optionLen > 0 {
				at := make([]ArchitectureType, 0)
				for i := uint16(0); i < optionLen; i += 2 {
					at = append(at, ArchitectureType(binary.BigEndian.Uint16(data[4+i:6+i])))
				}
				currentOption.(*OptionClientSystemArchitectureType).Types = at
			}
		case OptionTypeClientNetworkInterfaceIdentifier:
			if optionLen != 3 {
				return list, errOptionTooShort
			}
			currentOption = &OptionClientNetworkInterfaceIdentifier{
				InterfaceType: InterfaceType(data[4]),
				RevisionMajor: data[5],
				RevisionMinor: data[6],
			}
		case OptionTypeNextHop:
			if optionLen < 16 {
				return list, errOptionTooShort
			}
			currentOption = &OptionNextHop{
				Address: data[4:20],
			}
			if optionLen > 16 {
				var err error
				currentOption.(*OptionNextHop).options, err = DecodeOptions(data[20 : optionLen+4])
				if err != nil {
					return list, err
				}
			}

		case OptionTypeRoutePrefix:
			if optionLen < 22 {
				return list, errOptionTooShort
			}
			currentOption = &OptionRoutePrefix{
				PrefixLength: data[8],
				Prefix:       data[10:26],
			}
			currentOption.(*OptionRoutePrefix).RouteLifetime = binary.BigEndian.Uint32(data[4:8])
			// parse preference
			if data[9]&16 > 0 && data[9]&8 > 0 { // 2^4 + 2^3
				currentOption.(*OptionRoutePrefix).Preference = RoutePreferenceLow
			} else if data[9]&8 > 0 { // 2^3
				currentOption.(*OptionRoutePrefix).Preference = RoutePreferenceHigh
			}
			if optionLen > 22 {
				var err error
				currentOption.(*OptionRoutePrefix).options, err = DecodeOptions(data[26 : optionLen+4])
				if err != nil {
					return list, err
				}
			}

		default:
			fmt.Printf("unhandled option type: %s\n", optionType)
		}

		// append last decoded option to list
		if currentOption != nil {
			list = append(list, currentOption)
		}

		// chop off bytes and go on to next option
		if len(data) <= int((4 + optionLen)) {
			break
		}

		data = data[4+optionLen:]
	}

	return list, nil
}
