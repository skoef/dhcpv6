package dhcpv6

import (
	"bytes"
	"strings"
	"testing"
)

func TestMessageTypeString(t *testing.T) {
	tests := []struct {
		in  MessageType
		out string
	}{
		{0, "Unknown (0)"},
		{MessageTypeSolicit, "Solicit (1)"},
		{MessageTypeAdvertise, "Advertise (2)"},
		{MessageTypeRequest, "Request (3)"},
		{MessageTypeConfirm, "Confirm (4)"},
		{MessageTypeRenew, "Renew (5)"},
		{MessageTypeRebind, "Rebind (6)"},
		{MessageTypeReply, "Reply (7)"},
		{MessageTypeRelease, "Release (8)"},
		{MessageTypeDecline, "Decline (9)"},
		{MessageTypeReconfigure, "Reconfigure (10)"},
		{MessageTypeInformationRequest, "Information Request (11)"},
		{MessageTypeRelayForward, "Relay Forward (12)"},
		{MessageTypeRelayReply, "Relay Reply (13)"},
	}

	for _, test := range tests {
		if strings.Compare(test.in.String(), test.out) != 0 {
			t.Errorf("expected %s but got %s", test.out, test.in.String())
		}
	}
}

func TestDecodeMessage(t *testing.T) {
	tests := []struct {
		fixture []byte
		mtype   MessageType
		xid     uint32
		opts    []OptionType
		nopt    OptionType
	}{
		// Solicit
		{
			[]byte{1, 1, 226, 64, 0, 1, 0, 14, 0, 1, 0, 1, 32, 138, 112, 171, 82, 84,
				0, 250, 153, 31},
			MessageTypeSolicit, 123456, []OptionType{OptionTypeClientID},
			OptionTypeAuthentication,
		},
		// Advertise
		{
			[]byte{2, 3, 148, 71, 0, 3, 0, 12, 0, 250, 153, 31, 0, 0, 1, 44, 0, 0, 1, 194,
				0, 6, 0, 0},
			MessageTypeAdvertise, 234567, []OptionType{OptionTypeIANA, OptionTypeOptionRequest},
			OptionTypeInterfaceID,
		},
		// Request
		{
			[]byte{3, 5, 70, 78, 0, 3, 0, 12, 0, 250, 153, 31, 0, 0, 1, 44, 0, 0, 1, 194,
				0, 6, 0, 0},
			MessageTypeRequest, 345678, []OptionType{OptionTypeIANA, OptionTypeOptionRequest},
			OptionTypeInterfaceID,
		},
		// Confirm
		{
			[]byte{4, 6, 248, 85, 0, 8, 0, 2, 0, 10},
			MessageTypeConfirm, 456789, []OptionType{OptionTypeElapsedTime},
			OptionTypeRapidCommit,
		},
		// Reply
		{
			[]byte{7, 10, 91, 245, 0, 14, 0, 0},
			MessageTypeReply, 678901, []OptionType{OptionTypeRapidCommit},
			OptionTypeElapsedTime,
		},
	}

	for _, test := range tests {
		// decode bytes
		msg, err := DecodeMessage(test.fixture)
		if err != nil {
			t.Errorf("could not decode fixture for %s", test.mtype)
		}

		// check type of message
		if msg.MessageType != test.mtype {
			t.Errorf("expected type %s, got %s\n", test.mtype, msg.MessageType)
		}

		// check Xid
		if msg.Xid != test.xid {
			t.Errorf("expected XID %d, got %d\n", test.xid, msg.Xid)
		}

		// check options
		if len(msg.Options) != len(test.opts) {
			t.Errorf("expected %d options, got %d (%s)\n", len(test.opts), len(msg.Options), msg.Options)
		}
		for _, opttype := range test.opts {
			if msg.HasOption(opttype) == nil {
				t.Errorf("expected msg to have %s", opttype)
			}
		}
		if msg.HasOption(test.nopt) != nil {
			t.Errorf("expected msg not to have %s", test.nopt)
		}

		// check if marshal matches
		if mshByte, err := msg.Marshal(); err != nil {
			t.Errorf("error marshalling message: %s", err)
		} else if bytes.Compare(mshByte, test.fixture) != 0 {
			t.Errorf("marshalled message didn't match fixture!\nfixture: %v\nmarshal: %v", test.fixture, mshByte)
		}
	}
}
