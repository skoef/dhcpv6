package dhcpv6

import (
	"encoding/binary"
	"errors"
	"fmt"
)

var (
	errMessageTooShort = errors.New("message too short")
	typeUnknown        = "Unknown"
)

// MessageType describes DHCPv6 message types
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
			return typeUnknown
		}
	}
	return fmt.Sprintf("%s (%d)", name(), t)
}

// Message represents a DHCPv6 message
type Message struct {
	MessageType MessageType
	Xid         uint32
	Options     Options
}

// HasOption returns Option if this Message has OptionType t as option or
// nil otherwise
func (m Message) HasOption(t OptionType) Option {
	for _, o := range m.Options {
		if o.Type() == t {
			return o
		}
	}

	return nil
}

// AddOption adds given Option to slice of Options of Message
func (m *Message) AddOption(o Option) {
	m.Options = append(m.Options, o)
}

// Marshal returns byte slice representing this Message or error
func (m Message) Marshal() ([]byte, error) {
	// prepare byte slice of appropriate length
	b := make([]byte, 4)
	// set transaction-id and then message type
	// the other way around would be more logical, but since transaction-id is
	// 3 bytes, this way is easier
	binary.BigEndian.PutUint32(b[0:4], m.Xid)
	b[0] = uint8(m.MessageType)
	// append option bytes
	if len(m.Options) > 0 {
		optb, err := m.Options.Marshal()
		if err != nil {
			return nil, err
		}
		b = append(b, optb...)
	}

	return b, nil
}

// DecodeMessage takes DHCPv6 message bytes and tries to decode the message and
// optionally its options and returns decoded Message or error if any occurs
func DecodeMessage(data []byte) (*Message, error) {
	// the first 4 bytes of a  message contain message type and transaction-id
	// so that's the least amount of bytes expected
	if len(data) < 4 {
		return nil, errMessageTooShort
	}

	d := &Message{
		MessageType: MessageType(data[0]),
	}
	d.Xid = binary.BigEndian.Uint32(append([]byte{0}, data[1:4]...))

	// additional options to decode
	if len(data) > 4 {
		options, err := DecodeOptions(data[4:])
		if err != nil {
			return nil, fmt.Errorf("could not decode options: %s", err)
		}

		d.Options = options
	}

	return d, nil
}
