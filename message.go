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
	DHCPv6MsgTypeSolicit DHCPv6MsgType = iota
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
