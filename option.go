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

type OptionType uint8

//  Options types as described in RFC3315 and RFC3646
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
	return fmt.Sprintf("option type %s (%d)", name(), t)
}

// base struct to be embedded by all DHCPv6 options
type optionBase struct {
	OptionType OptionType
}

type Option interface {
	String() string
}

// https://tools.ietf.org/html/rfc3315#section-22.2
type OptionClientID struct {
	*optionBase
	DUID DUID
}

func (o OptionClientID) String() string {
	return fmt.Sprintf("client-ID %s", o.DUID)
}

// https://tools.ietf.org/html/rfc3315#section-22.3
type OptionServerID struct {
	*optionBase
	DUID DUID
}

func (o OptionServerID) String() string {
	return fmt.Sprintf("server-ID %s", o.DUID)
}

// https://tools.ietf.org/html/rfc3315#section-22.4
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

// https://tools.ietf.org/html/rfc3315#section-22.9
type OptionElapsedTime struct {
	*optionBase
	ElapsedTime time.Duration
}

func (o OptionElapsedTime) String() string {
	return fmt.Sprintf("elapsed-time %v", o.ElapsedTime)
}

// https://tools.ietf.org/html/rfc3315#section-22.14
type OptionRapidCommit struct {
	*optionBase
}

func (o OptionRapidCommit) String() string {
	return "rapid-commit"
}

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
			duid, err := parseDUID(data[4 : 4+optionLen])
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
			duid, err := parseDUID(data[4 : 4+optionLen])
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
