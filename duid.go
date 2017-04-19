package dhcpv6

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

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
}

type DUIDBase struct {
	Type DUIDType
}

// DUIDLLT - as described in https://tools.ietf.org/html/rfc3315#section-9.2
type DUIDLLT struct {
	*DUIDBase
	HardwareType     uint16
	Time             time.Time
	LinkLayerAddress net.HardwareAddr
}

func (d DUIDLLT) String() string {
	// client-ID hwaddr/time type 1 time 545494311 525400fa991f
	//                                             52:54:00:fa:99:1f
	return fmt.Sprintf("hwaddr/time type 1 time %d %v", d.Time.Unix(), d.LinkLayerAddress)
}

// DUIDEN - as described in https://tools.ietf.org/html/rfc3315#section-9.3
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

func parseDUID(data []byte) (DUID, error) {
	duidType := DUIDType(binary.BigEndian.Uint16(data[0:2]))

	var currentDUID DUID
	switch duidType {
	case DUIDTypeLLT:
		currentDUID = &DUIDLLT{
			DUIDBase: &DUIDBase{
				Type: duidType,
			},
			HardwareType: binary.BigEndian.Uint16(data[2:4]),
			// as stated in RFC3315, DUID epoch is at Jan 1st 2000 (UTC)
			// and golang Time works with an epoch at Jan 1st 1970 (UTC)
			// I'm adding 30 years of seconds to the uint32 we decode
			Time:             time.Unix(int64(binary.BigEndian.Uint32(data[4:8])+946771200), 0),
			LinkLayerAddress: data[8:],
		}
	default:
		return currentDUID, fmt.Errorf("unhandled duidType %s", duidType)
	}

	return currentDUID, nil
}
