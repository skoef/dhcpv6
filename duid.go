package dhcpv6

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"
)

var (
	errDUIDTooShort      = errors.New("duid too short")
	thirtyYearsInSeconds = uint32(946771200)
)

// DUIDType represents the type of DUID
type DUIDType uint8

func (d DUIDType) String() string {
	switch d {
	case DUIDTypeLLT:
		return "LinkLayerTime"
	case DUIDTypeEN:
		return "Enterprise Number"
	case DUIDTypeLL:
		return "LinkLayer"
	default:
		return "Unknown"
	}
}

// DUID types as described in https://tools.ietf.org/html/rfc3315#section-9.1
const (
	_ DUIDType = iota
	DUIDTypeLLT
	DUIDTypeEN
	DUIDTypeLL
)

type DUID interface {
	String() string
	Type() DUIDType
	Marshal() ([]byte, error)
}

type DUIDBase struct {
	DUIDType DUIDType
}

// DUIDLLT - as described in https://tools.ietf.org/html/rfc3315#section-9.2
type DUIDLLT struct {
	*DUIDBase
	HardwareType     uint16
	Time             time.Time
	LinkLayerAddress net.HardwareAddr
}

func (d DUIDLLT) String() string {
	output := fmt.Sprintf("hwaddr/time type %d", d.DUIDType)

	if !d.Time.IsZero() {
		// subtract 30 year offset from time
		output += fmt.Sprintf(" time %d", d.Time.Unix()-int64(thirtyYearsInSeconds))
	}

	output += fmt.Sprintf(" %v", d.LinkLayerAddress)
	return output
}

// Type returns DUIDTypeLLT
func (d DUIDLLT) Type() DUIDType {
	return DUIDTypeLLT
}

// Marshal returns byte slice representing this DUIDLLT
func (d DUIDLLT) Marshal() ([]byte, error) {
	// prepare byte slice of appropriate length
	// LinkLayerAddress will be appended later
	len := 4 + 4 // type, hwtype, time
	b := make([]byte, len)

	// set type
	binary.BigEndian.PutUint16(b[0:2], uint16(DUIDTypeLLT))
	// set hw type
	binary.BigEndian.PutUint16(b[2:4], uint16(d.HardwareType))
	// set time (subtract 30 years offset)
	binary.BigEndian.PutUint32(b[4:8], uint32(d.Time.Unix()-int64(thirtyYearsInSeconds)))
	// append LinkLayerAddress
	b = append(b, d.LinkLayerAddress...)
	return b, nil
}

// DUIDEN - as described in https://tools.ietf.org/html/rfc3315#section-9.3
// NOTE: currently not implemented
type DUIDEN struct {
	*DUIDBase
	EnterpriseNumber uint32
	ID               []byte
}

// DUIDLL - as described in https://tools.ietf.org/html/rfc3315#section-9.4
type DUIDLL struct {
	*DUIDBase
	HardwareType     uint16
	LinkLayerAddress net.HardwareAddr
}

func (d DUIDLL) String() string {
	return fmt.Sprintf("hwaddr type %d %v", d.DUIDType, d.LinkLayerAddress)
}

// Type returns DUIDTypeLL
func (d DUIDLL) Type() DUIDType {
	return DUIDTypeLL
}

// Marshal returns byte slice representing this DUIDLL
func (d DUIDLL) Marshal() ([]byte, error) {
	// prepare byte slice of appropriate length
	// LinkLayerAddress will be appended later
	len := 4 // type, hwtype
	b := make([]byte, len)

	// set type
	binary.BigEndian.PutUint16(b[0:2], uint16(DUIDTypeLL))
	// set hw type
	binary.BigEndian.PutUint16(b[2:4], uint16(d.HardwareType))
	// append LinkLayerAddress
	b = append(b, d.LinkLayerAddress...)
	return b, nil
}

// DecodeDUID tries to decode given byte slice to one of the defined
// DUIDTypes
func DecodeDUID(data []byte) (DUID, error) {
	var currentDUID DUID

	// type is defined in the first 2 bytes
	if len(data) < 2 {
		return currentDUID, errDUIDTooShort
	}

	duidType := DUIDType(binary.BigEndian.Uint16(data[0:2]))

	switch duidType {
	case DUIDTypeLLT:
		// DUID-LLT's should be at least 8 bytes
		// containing hardware type, time
		// the link layer address is variable in length, but here a regular MAC
		// address is assumed
		if len(data) < 8 {
			return currentDUID, errDUIDTooShort
		}
		currentDUID = &DUIDLLT{
			DUIDBase: &DUIDBase{
				DUIDType: duidType,
			},
			HardwareType: binary.BigEndian.Uint16(data[2:4]),
			// as stated in RFC3315, DUID epoch is at Jan 1st 2000 (UTC)
			// and golang Time works with an epoch at Jan 1st 1970 (UTC)
			// I'm adding 30 years of seconds to the uint32 we decode
			Time: time.Unix(int64(binary.BigEndian.Uint32(data[4:8])+thirtyYearsInSeconds), 0),
		}
		if len(data) > 8 {
			currentDUID.(*DUIDLLT).LinkLayerAddress = data[8:]
		}
	case DUIDTypeLL:
		// DUID-LL's should be at least 4 bytes
		// containing hardware type
		// the link layer address is variable in length, but here a regular MAC
		// address is assumed
		if len(data) < 4 {
			return currentDUID, errDUIDTooShort
		}
		currentDUID = &DUIDLL{
			DUIDBase: &DUIDBase{
				DUIDType: duidType,
			},
			HardwareType: binary.BigEndian.Uint16(data[2:4]),
		}
		if len(data) > 4 {
			currentDUID.(*DUIDLL).LinkLayerAddress = data[4:]
		}
	default:
		return currentDUID, fmt.Errorf("unhandled DUIDType %s", duidType)
	}

	return currentDUID, nil
}
