package csp

import (
	"bytes"
	"testing"
)

func TestParseCspPacket(t *testing.T) {
	input := []byte{0x40, 0x89, 0xAB, 0xC0, 0x01, 0x02, 0x03}
	packet, err := ParseCspPacket(input)

	if err != nil {
		t.Fatal(err)
	}

	if packet.Priority != 1 {
		t.Errorf("Expected Priority 1, got %d", packet.Priority)
	}

	if packet.Source != 0 {
		t.Errorf("Expected Source 0, got %d", packet.Source)
	}

	if packet.Destination != 8 {
		t.Errorf("Expected Destination 8, got %d", packet.Destination)
	}

	if packet.DestinationPort != 38 {
		t.Errorf("Expected DestinationPort 38, got %d", packet.DestinationPort)
	}

	if packet.SourcePort != 43 {
		t.Errorf("Expected SourcePort 43, got %d", packet.SourcePort)
	}

	if packet.Reserved != 12 {
		t.Errorf("Expected Reserved 12, got %d", packet.Reserved)
	}

	if packet.HMAC != 0 {
		t.Errorf("Expected HMAC 0, got %d", packet.HMAC)
	}

	if packet.XTEA != 0 {
		t.Errorf("Expected XTEA 0, got %d", packet.XTEA)
	}

	if packet.RDP != 0 {
		t.Errorf("Expected RDP 0, got %d", packet.RDP)
	}

	if packet.CRC != 0 {
		t.Errorf("Expected CRC 0, got %d", packet.CRC)
	}
}

func TestSerialize(t *testing.T) {
	packet := &CspPacket{
		Priority:        1,
		Source:          0,
		Destination:     8,
		DestinationPort: 38,
		SourcePort:      43,
		Reserved:        12,
		HMAC:            0,
		XTEA:            0,
		RDP:             0,
		CRC:             0,
		Data:            []byte{0x01, 0x02, 0x03},
	}

	expected := []byte{0x40, 0x89, 0xAB, 0xC0, 0x01, 0x02, 0x03}
	serialized := packet.Serialize()

	if !bytes.Equal(serialized, expected) {
		t.Errorf("Expected serialized data %v, got %v", expected, serialized)
	}
}
