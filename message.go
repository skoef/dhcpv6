package dhcpv6

import (
	"encoding/binary"
	"errors"
	"fmt"
)

var (
	errMessageTooShort = errors.New("message too short")
)

type DHCPv6MsgType uint8

// add constants for all DHCPv6 message types from RFC3315
const (
	_ DHCPv6MsgType = iota
	DHCPv6MsgTypeSolicit
	DHCPv6MsgTypeAdvertise
	DHCPv6MsgTypeRequest
	DHCPv6MsgTypeConfirm
	DHCPv6MsgTypeRenew
	DHCPv6MsgTypeRebind
	DHCPv6MsgTypeReply
	DHCPv6MsgTypeRelease
	DHCPv6MsgTypeDecline
	DHCPv6MsgTypeReconfigure
	DHCPv6MsgTypeInformationRequest
	DHCPv6MsgTypeRelayForward
	DHCPv6MsgTypeRelayReply
)

func (t DHCPv6MsgType) String() string {
	name := func() string {
		switch t {
		case DHCPv6MsgTypeSolicit:
			return "Solicit"
		case DHCPv6MsgTypeAdvertise:
			return "Advertise"
		case DHCPv6MsgTypeRequest:
			return "Request"
		case DHCPv6MsgTypeConfirm:
			return "Confirm"
		case DHCPv6MsgTypeRenew:
			return "Renew"
		case DHCPv6MsgTypeRebind:
			return "Rebind"
		case DHCPv6MsgTypeReply:
			return "Reply"
		case DHCPv6MsgTypeRelease:
			return "Release"
		case DHCPv6MsgTypeDecline:
			return "Decline"
		case DHCPv6MsgTypeReconfigure:
			return "Reconfigure"
		case DHCPv6MsgTypeInformationRequest:
			return "Information Request"
		case DHCPv6MsgTypeRelayForward:
			return "Relay Forward"
		case DHCPv6MsgTypeRelayReply:
			return "Relay Reply"
		default:
			return "Unknown"
		}
	}
	return fmt.Sprintf("message type %s (%d)", name(), t)
}

type DHCPv6Options []DHCPv6Option

type DHCPv6 struct {
	MessageType DHCPv6MsgType
	Xid         uint32
	Options     DHCPv6Options
}

func ParseMessage(data []byte) (*DHCPv6, error) {
	// the first 4 bytes of a DHCPv6 message contain message type and transaction-id
	// so that's the least amount of bytes expected
	if len(data) < 4 {
		return nil, errMessageTooShort
	}

	d := &DHCPv6{
		MessageType: DHCPv6MsgType(data[0]),
	}
	data[0] = 0
	d.Xid = binary.BigEndian.Uint32(data[0:4])

	// additional options to parse
	if len(data) > 4 {
		options, err := ParseOptions(data[4:])
		if err != nil {
			return nil, fmt.Errorf("could not parse options: %s", err)
		}

		d.Options = options
	}

	return d, nil
}
