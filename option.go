package dhcpv6

import (
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

var (
	errOptionTooShort = errors.New("option too short")
	errOptionTooLong  = errors.New("option too long")
)

type DHCPv6OptionType uint8

// DHCPv6 Options types as described in RFC3315 and RFC3646
const (
	_ DHCPv6OptionType = iota
	DHCPv6OptionTypeClientID
	DHCPv6OptionTypeServerID
	DHCPv6OptionTypeIANA
	DHCPv6OptionTypeIATA
	DHCPv6OptionTypeIAAddress
	DHCPv6OptionTypeOptionRequest
	DHCPv6OptionTypePreference
	DHCPv6OptionTypeElapsedTime
	DHCPv6OptionTypeRelayMessage
	DHCPv6OptionTypeAuthentication
	DHCPv6OptionTypeServerUnicast
	DHCPv6OptionTypeStatusCode
	DHCPv6OptionTypeRapidCommit
	DHCPv6OptionTypeUserClass
	DHCPv6OptionTypeVendorClass
	DHCPv6OptionTypeVendorOption
	DHCPv6OptionTypeInterfaceID
	DHCPv6OptionTypeReconfigureMessage
	DHCPv6OptionTypeReconfigureAccept
	_
	_
	_
	DHCPv6OptionTypeDNSServer
	DHCPv6OptionTypeDNSSearchList
)

func (t DHCPv6OptionType) String() string {
	name := func() string {
		switch t {
		case DHCPv6OptionTypeClientID:
			return "Client Identifier"
		case DHCPv6OptionTypeServerID:
			return "Server Identifier"
		case DHCPv6OptionTypeIANA:
			return "Identity Association for Non-temporary Addresses"
		case DHCPv6OptionTypeIATA:
			return "Identity Association for Temporary Addresses"
		case DHCPv6OptionTypeIAAddress:
			return "Identity Association Address"
		case DHCPv6OptionTypeOptionRequest:
			return "Option Request"
		case DHCPv6OptionTypePreference:
			return "Preference"
		case DHCPv6OptionTypeElapsedTime:
			return "Elapsed Time"
		case DHCPv6OptionTypeRelayMessage:
			return "Relay Message"
		case DHCPv6OptionTypeAuthentication:
			return "Authentication"
		case DHCPv6OptionTypeServerUnicast:
			return "Server Unicast"
		case DHCPv6OptionTypeStatusCode:
			return "Status Code"
		case DHCPv6OptionTypeRapidCommit:
			return "Rapid Commit"
		case DHCPv6OptionTypeUserClass:
			return "User Class"
		case DHCPv6OptionTypeVendorClass:
			return "Vendor Class"
		case DHCPv6OptionTypeVendorOption:
			return "Vendor-specific Information"
		case DHCPv6OptionTypeInterfaceID:
			return "Interface-ID"
		case DHCPv6OptionTypeReconfigureMessage:
			return "Reconfigure Message"
		case DHCPv6OptionTypeReconfigureAccept:
			return "Reconfigure Accept"
		case DHCPv6OptionTypeDNSServer:
			return "DNS Server"
		case DHCPv6OptionTypeDNSSearchList:
			return "DNS Search List"
		default:
			return "Unknown"
		}
	}
	return fmt.Sprintf("option type %s (%d)", name(), t)
}

type DHCPv6OptionBase struct {
	OptionType DHCPv6OptionType
}

type DHCPv6Option interface {
	String() string
}

// https://tools.ietf.org/html/rfc3315#section-22.2
type DHCPv6OptionClientID struct {
	*DHCPv6OptionBase
	DUID DUID
}

func (o DHCPv6OptionClientID) String() string {
	return fmt.Sprintf("client-ID %s", o.DUID)
}

// https://tools.ietf.org/html/rfc3315#section-22.3
type DHCPv6OptionServerID struct {
	*DHCPv6OptionBase
	DUID DUID
}

func (o DHCPv6OptionServerID) String() string {
	return fmt.Sprintf("server-ID %s", o.DUID)
}

// https://tools.ietf.org/html/rfc3315#section-22.4
type DHCPv6OptionIANA struct {
	*DHCPv6OptionBase
	IAID uint32
	T1   time.Duration // delay before Renew
	T2   time.Duration // delay before Rebind
}

func (o DHCPv6OptionIANA) String() string {
	return fmt.Sprintf("IA_NA IAID:%d T1:%d T2:%d", o.IAID, o.T1, o.T2)
}

// https://tools.ietf.org/html/rfc3315#section-22.7
type DHCPv6OptionOptionRequest struct {
	*DHCPv6OptionBase
	Options []DHCPv6OptionType
}

func (o DHCPv6OptionOptionRequest) String() string {
	output := "option-request"
	for _, opt := range o.Options {
		output += fmt.Sprintf(" %s", opt)
	}
	return output
}

func (o *DHCPv6OptionOptionRequest) parseOptions(data []byte) error {
	var options []DHCPv6OptionType
	for {
		if len(data) < 2 {
			break
		}
		optionType := DHCPv6OptionType(binary.BigEndian.Uint16(data[:2]))
		options = append(options, optionType)
		data = data[2:]
	}

	o.Options = options
	return nil
}

// https://tools.ietf.org/html/rfc3315#section-22.9
type DHCPv6OptionElapsedTime struct {
	*DHCPv6OptionBase
	ElapsedTime time.Duration
}

func (o DHCPv6OptionElapsedTime) String() string {
	return fmt.Sprintf("elapsed-time %v", o.ElapsedTime)
}

// https://tools.ietf.org/html/rfc3315#section-22.14
type DHCPv6OptionRapidCommit struct {
	*DHCPv6OptionBase
}

func (o DHCPv6OptionRapidCommit) String() string {
	return "rapid-commit"
}

func ParseOptions(data []byte) (DHCPv6Options, error) {
	// empty container
	list := DHCPv6Options{}

	// the first 4 bytes of a DHCPv6 option contain option type and data length
	// so that's the least amount of bytes expected
	if len(data) < 4 {
		return list, errOptionTooShort
	}

	for {
		optionType := DHCPv6OptionType(binary.BigEndian.Uint16(data[0:2]))
		optionLen := binary.BigEndian.Uint16(data[2:4])
		// check if we have at least the same amount of bytes this option's length
		// is prescribing
		if len(data) < int(optionLen+4) {
			return list, errOptionTooShort
		}

		var currentOption DHCPv6Option
		switch optionType {
		case DHCPv6OptionTypeClientID:
			currentOption = &DHCPv6OptionClientID{
				DHCPv6OptionBase: &DHCPv6OptionBase{
					OptionType: optionType,
				},
			}
			duid, err := parseDUID(data[4 : 4+optionLen])
			if err != nil {
				return list, errOptionTooShort
			}
			currentOption.(*DHCPv6OptionClientID).DUID = duid
		case DHCPv6OptionTypeServerID:
			currentOption = &DHCPv6OptionServerID{
				DHCPv6OptionBase: &DHCPv6OptionBase{
					OptionType: optionType,
				},
			}
			duid, err := parseDUID(data[4 : 4+optionLen])
			if err != nil {
				return list, errOptionTooShort
			}
			currentOption.(*DHCPv6OptionServerID).DUID = duid
		case DHCPv6OptionTypeIANA:
			if optionLen < 12 {
				return list, errOptionTooShort
			}
			currentOption = &DHCPv6OptionIANA{
				DHCPv6OptionBase: &DHCPv6OptionBase{
					OptionType: optionType,
				},
			}
			currentOption.(*DHCPv6OptionIANA).IAID = binary.BigEndian.Uint32(data[4:8])
			currentOption.(*DHCPv6OptionIANA).T1 = time.Duration(binary.BigEndian.Uint32(data[8:12]))
			currentOption.(*DHCPv6OptionIANA).T2 = time.Duration(binary.BigEndian.Uint32(data[12:16]))
			//if optionLen > 12 {
			//	TODO: parse IANA options
			//}
		case DHCPv6OptionTypeOptionRequest:
			currentOption = &DHCPv6OptionOptionRequest{
				DHCPv6OptionBase: &DHCPv6OptionBase{
					OptionType: optionType,
				},
			}
			if optionLen > 0 {
				currentOption.(*DHCPv6OptionOptionRequest).parseOptions(data[4 : 4+optionLen])
			}
		case DHCPv6OptionTypeElapsedTime:
			if optionLen != 2 {
				return list, errOptionTooShort
			}
			currentOption = &DHCPv6OptionElapsedTime{
				DHCPv6OptionBase: &DHCPv6OptionBase{
					OptionType: optionType,
				},
				// elapsed time is expressed in hundredths of a second
				// hence the 10 * millisecond
				ElapsedTime: (time.Duration(binary.BigEndian.Uint16(data[4:4+optionLen])) * time.Millisecond * 10),
			}
		case DHCPv6OptionTypeRapidCommit:
			if optionLen != 0 {
				return list, errOptionTooLong
			}

			currentOption = &DHCPv6OptionRapidCommit{
				DHCPv6OptionBase: &DHCPv6OptionBase{
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
