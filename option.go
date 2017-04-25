package dhcpv6

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"
)

var (
	errOptionTooShort = errors.New("option too short")
	errOptionTooLong  = errors.New("option too long")
)

// DHCPv6 option type
type OptionType uint8

//  Option types as described in RFC3315 and RFC3646
const (
	_ OptionType = iota
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
	OptionTypeDNSServer
	OptionTypeDNSSearchList
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
		default:
			return "Unknown"
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

// OptionIANA implements the Identity Association for Non-temporary Addresses
// option as described at https://tools.ietf.org/html/rfc3315#section-22.4
type OptionIANA struct {
	IAID    uint32
	T1      time.Duration // delay before Renew
	T2      time.Duration // delay before Rebind
	Options Options
}

func (o OptionIANA) String() string {
	output := fmt.Sprintf("IA_NA IAID:%d T1:%d T2:%d", o.IAID, o.T1, o.T2)
	if len(o.Options) > 0 {
		output += fmt.Sprintf(" %s", o.Options)
	}
	return output
}

// Len returns the length in bytes of OptionIANA's body
func (o OptionIANA) Len() uint16 {
	// iaid (4 bytes)
	// t1 (4 bytes)
	// t2 (4 bytes)
	// any additional options' length
	return 12 + o.Options.Len()
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
	if len(o.Options) > 0 {
		optMarshal, err := o.Options.Marshal()
		if err != nil {
			return nil, err
		}
		b = append(b, optMarshal...)
	}
	return b, nil
}

// HasOption returns Option if this IA_NA option has OptionType t as option or
// nil otherwise
func (o OptionIANA) HasOption(t OptionType) Option {
	for _, opt := range o.Options {
		if opt.Type() == t {
			return opt
		}
	}
	return nil
}

// AddOption adds given Option to slice of Options
func (o *OptionIANA) AddOption(opt Option) {
	o.Options = append(o.Options, opt)
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
			return "Unknown"
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

// DecodeOptions takes DHCPv6 option bytes and tries to decode every handled
// option, looking at its type and the given length, and returns a slice
// containing all decoded structs
func DecodeOptions(data []byte) (Options, error) {
	// empty container
	list := Options{}

	// the first 4 bytes of a  option contain option type and data length
	// so that's the least amount of bytes expected
	if len(data) < 4 {
		return list, errOptionTooShort
	}

	for {
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
				return list, errOptionTooShort
			}
			currentOption.(*OptionClientID).DUID = duid
		case OptionTypeServerID:
			currentOption = &OptionServerID{}
			duid, err := DecodeDUID(data[4 : 4+optionLen])
			if err != nil {
				return list, errOptionTooShort
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
				currentOption.(*OptionIANA).Options, err = DecodeOptions(data[16 : optionLen+4])
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
			if optionLen != 2 {
				return list, errOptionTooShort
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
		default:
			fmt.Printf("unhandled option type: %s\n", optionType)
		}

		// append last decoded option to list
		list = append(list, currentOption)

		// chop off bytes and go on to next option
		if len(data) <= int((4 + optionLen)) {
			break
		}

		data = data[4+optionLen:]
	}

	return list, nil
}
