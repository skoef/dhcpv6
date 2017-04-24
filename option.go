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

// base struct to be embedded by all DHCPv6 options
type optionBase struct {
	OptionType OptionType
}

func (o optionBase) Type() OptionType {
	return o.OptionType
}

// Option -- interface to build various DHCPv6 options on
type Option interface {
	String() string
	Type() OptionType
	// uncomment once all Options have Marshal() implemented
	// Marshal() ([]byte, error)
}

// OptionClientID implements the Client Identifier option as described at
// https://tools.ietf.org/html/rfc3315#section-22.2
type OptionClientID struct {
	*optionBase
	DUID DUID
}

func (o OptionClientID) String() string {
	return fmt.Sprintf("client-ID %s", o.DUID)
}

// Type returns OptionTypeClientID
func (o OptionClientID) Type() OptionType {
	return OptionTypeClientID
}

// Marshal returns byte slice representing this OptionClientID
func (o OptionClientID) Marshal() ([]byte, error) {
	// prepare byte slice of appropriate length
	// DUID will be appended later
	lgth := 4 // type (2 bytes), length (2 bytes)
	b := make([]byte, lgth)
	// set type
	binary.BigEndian.PutUint16(b[0:2], uint16(OptionTypeClientID))
	//b[0] = uint8(OptionTypeClientID)
	// length depends on length of DUID
	duid, err := o.DUID.Marshal()
	if err != nil {
		return nil, fmt.Errorf("could not marshal DUID: %s", err)
	}
	// set length
	binary.BigEndian.PutUint16(b[2:4], uint16(len(duid)))
	// append DUID bytes
	b = append(b, duid...)
	return b, nil
}

// OptionServerID implements the Server Identifier option as described at
// https://tools.ietf.org/html/rfc3315#section-22.3
type OptionServerID struct {
	*optionBase
	DUID DUID
}

func (o OptionServerID) String() string {
	return fmt.Sprintf("server-ID %s", o.DUID)
}

// Type returns OptionTypeServerID
func (o OptionServerID) Type() OptionType {
	return OptionTypeServerID
}

// Marshal returns byte slice representing this OptionServerID
func (o OptionServerID) Marshal() ([]byte, error) {
	// prepare byte slice of appropriate length
	// DUID will be appended later
	lgth := 4 // type (2 bytes), length (2 bytes)
	b := make([]byte, lgth)
	// set type
	binary.BigEndian.PutUint16(b[0:2], uint16(OptionTypeServerID))
	//b[0] = uint8(OptionTypeClientID)
	// length depends on length of DUID
	duid, err := o.DUID.Marshal()
	if err != nil {
		return nil, fmt.Errorf("could not marshal DUID: %s", err)
	}
	// set length
	binary.BigEndian.PutUint16(b[2:4], uint16(len(duid)))
	// append DUID bytes
	b = append(b, duid...)
	return b, nil
}

// OptionIANA implements the Identity Association for Non-temporary Addresses
// option as described at https://tools.ietf.org/html/rfc3315#section-22.4
type OptionIANA struct {
	*optionBase
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

// OptionIAAddress implements the IA Address option as described at
// https://tools.ietf.org/html/rfc3315#section-22.6
type OptionIAAddress struct {
	*optionBase
	Address           net.IP
	PreferredLifetime time.Duration
	ValidLifetime     time.Duration
	// TODO: options
}

func (o OptionIAAddress) String() string {
	return fmt.Sprintf("IA_ADDR %s pltime:%d vltime:%d", o.Address, o.PreferredLifetime, o.ValidLifetime)
}

// OptionOptionRequest implements the Option Request option as described at
// https://tools.ietf.org/html/rfc3315#section-22.7
type OptionOptionRequest struct {
	*optionBase
	Options []OptionType
}

func (o OptionOptionRequest) String() string {
	output := "option-request"
	for _, opt := range o.Options {
		output += fmt.Sprintf(" %s", opt)
	}
	return output
}

// helper function to parse the DHCPv6 options requested in this specific option
func (o *OptionOptionRequest) parseOptions(data []byte) error {
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
	*optionBase
	ElapsedTime time.Duration
}

func (o OptionElapsedTime) String() string {
	return fmt.Sprintf("elapsed-time %v", o.ElapsedTime)
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
	*optionBase
	Code    StatusCode
	Message string
}

func (o OptionStatusCode) String() string {
	return fmt.Sprintf("status-code %s: %s", o.Code, o.Message)
}

// OptionRapidCommit implements the Rapid Commit option as described at
// https://tools.ietf.org/html/rfc3315#section-22.14
// this option acts basically as a flag for the message carrying it
// and has no further contents
type OptionRapidCommit struct {
	*optionBase
}

func (o OptionRapidCommit) String() string {
	return "rapid-commit"
}

// ParseOptions takes DHCPv6 option bytes and parses every handled option,
// looking at its type and the given length, and returns a slice containing all
// decoded structs
func ParseOptions(data []byte) (Options, error) {
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
			currentOption = &OptionClientID{
				optionBase: &optionBase{
					OptionType: optionType,
				},
			}
			duid, err := DecodeDUID(data[4 : 4+optionLen])
			if err != nil {
				return list, errOptionTooShort
			}
			currentOption.(*OptionClientID).DUID = duid
		case OptionTypeServerID:
			currentOption = &OptionServerID{
				optionBase: &optionBase{
					OptionType: optionType,
				},
			}
			duid, err := DecodeDUID(data[4 : 4+optionLen])
			if err != nil {
				return list, errOptionTooShort
			}
			currentOption.(*OptionServerID).DUID = duid
		case OptionTypeIANA:
			if optionLen < 12 {
				return list, errOptionTooShort
			}
			currentOption = &OptionIANA{
				optionBase: &optionBase{
					OptionType: optionType,
				},
			}
			currentOption.(*OptionIANA).IAID = binary.BigEndian.Uint32(data[4:8])
			currentOption.(*OptionIANA).T1 = time.Duration(binary.BigEndian.Uint32(data[8:12]))
			currentOption.(*OptionIANA).T2 = time.Duration(binary.BigEndian.Uint32(data[12:16]))
			if optionLen > 12 {
				var err error
				currentOption.(*OptionIANA).Options, err = ParseOptions(data[16 : optionLen+4])
				if err != nil {
					return list, err
				}
			}
		case OptionTypeIAAddress:
			if optionLen < 24 {
				return list, errOptionTooShort
			}
			currentOption = &OptionIAAddress{
				optionBase: &optionBase{
					OptionType: optionType,
				},
				Address:           data[4:20],
				PreferredLifetime: time.Duration(binary.BigEndian.Uint32(data[20:24])),
				ValidLifetime:     time.Duration(binary.BigEndian.Uint32(data[24:28])),
			}
		case OptionTypeOptionRequest:
			currentOption = &OptionOptionRequest{
				optionBase: &optionBase{
					OptionType: optionType,
				},
			}
			if optionLen > 0 {
				currentOption.(*OptionOptionRequest).parseOptions(data[4 : 4+optionLen])
			}
		case OptionTypeElapsedTime:
			if optionLen != 2 {
				return list, errOptionTooShort
			}
			currentOption = &OptionElapsedTime{
				optionBase: &optionBase{
					OptionType: optionType,
				},
				// elapsed time is expressed in hundredths of a second
				// hence the 10 * millisecond
				ElapsedTime: (time.Duration(binary.BigEndian.Uint16(data[4:4+optionLen])) * time.Millisecond * 10),
			}
		case OptionTypeStatusCode:
			if optionLen < 2 {
				return list, errOptionTooShort
			}
			fmt.Printf("status code bytes: %v\n", data)
			currentOption = &OptionStatusCode{
				optionBase: &optionBase{
					OptionType: optionType,
				},
				Code:    StatusCode(binary.BigEndian.Uint16(data[4:6])),
				Message: string(data[6 : optionLen+4]),
			}
		case OptionTypeRapidCommit:
			if optionLen != 0 {
				return list, errOptionTooLong
			}

			currentOption = &OptionRapidCommit{
				optionBase: &optionBase{
					OptionType: optionType,
				},
			}
		default:
			fmt.Printf("unhandled option type: %s\n", optionType)
		}

		// append last parsed option to list
		list = append(list, currentOption)

		// chop off bytes and go on to next option
		if len(data) <= int((4 + optionLen)) {
			break
		}
		data = data[4+optionLen:]
	}

	return list, nil
}
