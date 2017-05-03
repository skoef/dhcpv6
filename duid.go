package dhcpv6

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/google/uuid"
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
	case DUIDTypeUUID:
		return "UUID"
	default:
		return typeUnknown
	}
}

// DUID types as described in https://tools.ietf.org/html/rfc3315#section-9.1 and
// https://tools.ietf.org/html/rfc6355#section-4
const (
	_ DUIDType = iota
	// RFC3315
	DUIDTypeLLT
	DUIDTypeEN
	DUIDTypeLL
	// RFC6355
	DUIDTypeUUID
)

// DUID acts as an interface of other DUIDs
type DUID interface {
	String() string
	Len() uint16
	Type() DUIDType
	Marshal() ([]byte, error)
}

// DUIDLLT - as described in https://tools.ietf.org/html/rfc3315#section-9.2
type DUIDLLT struct {
	HardwareType     uint16
	Time             time.Time
	LinkLayerAddress net.HardwareAddr
}

func (d DUIDLLT) String() string {
	output := fmt.Sprintf("hwaddr/time type %d", d.Type())

	if !d.Time.IsZero() {
		// subtract 30 year offset from time
		output += fmt.Sprintf(" time %d", d.Time.Unix()-int64(thirtyYearsInSeconds))
	}

	output += fmt.Sprintf(" %v", d.LinkLayerAddress)
	return output
}

// Len returns length in bytes for entire DUIDLLT
func (d DUIDLLT) Len() uint16 {
	// type, hwtype, time
	return uint16(8 + len(d.LinkLayerAddress))
}

// Type returns DUIDTypeLLT
func (d DUIDLLT) Type() DUIDType {
	return DUIDTypeLLT
}

// Marshal returns byte slice representing this DUIDLLT
func (d DUIDLLT) Marshal() ([]byte, error) {
	// prepare byte slice of appropriate length
	// LinkLayerAddress will be appended later
	b := make([]byte, 8) // type, hwtype, time

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
	EnterpriseNumber uint32
	ID               []byte
}

// DUIDLL - as described in https://tools.ietf.org/html/rfc3315#section-9.4
type DUIDLL struct {
	HardwareType     uint16
	LinkLayerAddress net.HardwareAddr
}

func (d DUIDLL) String() string {
	return fmt.Sprintf("hwaddr type %d %v", d.Type(), d.LinkLayerAddress)
}

// Len returns length in bytes for entire DUIDLL
func (d DUIDLL) Len() uint16 {
	return uint16(4 + len(d.LinkLayerAddress))
}

// Type returns DUIDTypeLL
func (d DUIDLL) Type() DUIDType {
	return DUIDTypeLL
}

// Marshal returns byte slice representing this DUIDLL
func (d DUIDLL) Marshal() ([]byte, error) {
	// prepare byte slice of appropriate length
	// LinkLayerAddress will be appended later
	b := make([]byte, 4) // type, hwtype

	// set type
	binary.BigEndian.PutUint16(b[0:2], uint16(DUIDTypeLL))
	// set hw type
	binary.BigEndian.PutUint16(b[2:4], uint16(d.HardwareType))
	// append LinkLayerAddress
	b = append(b, d.LinkLayerAddress...)
	return b, nil
}

// DUIDUUID as described in https://tools.ietf.org/html/rfc6355#section-4
type DUIDUUID struct {
	UUID uuid.UUID
}

func (d DUIDUUID) String() string {
	return fmt.Sprintf("type %d", d.Type())
}

// Len returns length in bytes for the entire DUIDUUID
func (d DUIDUUID) Len() uint16 {
	// static length
	return uint16(18)
}

// Type returns DUIDTypeUUID
func (d DUIDUUID) Type() DUIDType {
	return DUIDTypeUUID
}

// Marshal returns byte slice representing this DUIDLL
func (d DUIDUUID) Marshal() ([]byte, error) {
	// prepare byte slice of appropriate length
	b := make([]byte, 2)
	// set type
	binary.BigEndian.PutUint16(b[0:2], uint16(DUIDTypeUUID))
	// append UUID
	ub, err := d.UUID.MarshalBinary()
	if err != nil {
		return nil, err
	}
	b = append(b, ub...)

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
		// DUID-LLTs should be at least 8 bytes
		// containing hardware type, time
		// the link layer address is variable in length, but here a regular MAC
		// address is assumed
		if len(data) < 8 {
			return currentDUID, errDUIDTooShort
		}
		currentDUID = &DUIDLLT{
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
		// DUID-LLs should be at least 4 bytes
		// containing hardware type
		// the link layer address is variable in length, but here a regular MAC
		// address is assumed
		if len(data) < 4 {
			return currentDUID, errDUIDTooShort
		}
		currentDUID = &DUIDLL{
			HardwareType: binary.BigEndian.Uint16(data[2:4]),
		}
		if len(data) > 4 {
			currentDUID.(*DUIDLL).LinkLayerAddress = data[4:]
		}
	case DUIDTypeUUID:
		// DUID-UUIDs should be exactly 18 bytes
		// with the UUID being 128 bits / 16 bytes
		if len(data) != 18 {
			return currentDUID, errDUIDTooShort
		}
		currentDUID = &DUIDUUID{}
		if err := currentDUID.(*DUIDUUID).UUID.UnmarshalBinary(data[2:18]); err != nil {
			return currentDUID, err
		}
	default:
		return currentDUID, fmt.Errorf("unhandled DUIDType %s", duidType)
	}

	return currentDUID, nil
}
