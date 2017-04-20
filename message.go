package dhcpv6

import (
	"encoding/binary"
	"errors"
	"fmt"
)

var (
	errMessageTooShort = errors.New("message too short")
)

type MessageType uint8

// add constants for all DHCPv6 message types from RFC3315
const (
	_ MessageType = iota
	MessageTypeSolicit
	MessageTypeAdvertise
	MessageTypeRequest
	MessageTypeConfirm
	MessageTypeRenew
	MessageTypeRebind
	MessageTypeReply
	MessageTypeRelease
	MessageTypeDecline
	MessageTypeReconfigure
	MessageTypeInformationRequest
	MessageTypeRelayForward
	MessageTypeRelayReply
)

func (t MessageType) String() string {
	name := func() string {
		switch t {
		case MessageTypeSolicit:
			return "Solicit"
		case MessageTypeAdvertise:
			return "Advertise"
		case MessageTypeRequest:
			return "Request"
		case MessageTypeConfirm:
			return "Confirm"
		case MessageTypeRenew:
			return "Renew"
		case MessageTypeRebind:
			return "Rebind"
		case MessageTypeReply:
			return "Reply"
		case MessageTypeRelease:
			return "Release"
		case MessageTypeDecline:
			return "Decline"
		case MessageTypeReconfigure:
			return "Reconfigure"
		case MessageTypeInformationRequest:
			return "Information Request"
		case MessageTypeRelayForward:
			return "Relay Forward"
		case MessageTypeRelayReply:
			return "Relay Reply"
		default:
			return "Unknown"
		}
	}
	return fmt.Sprintf("message type %s (%d)", name(), t)
}

type Options []Option

type Message struct {
	MessageType MessageType
	Xid         uint32
	Options     Options
}

func ParseMessage(data []byte) (*Message, error) {
	// the first 4 bytes of a  message contain message type and transaction-id
	// so that's the least amount of bytes expected
	if len(data) < 4 {
		return nil, errMessageTooShort
	}

	d := &Message{
		MessageType: MessageType(data[0]),
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
