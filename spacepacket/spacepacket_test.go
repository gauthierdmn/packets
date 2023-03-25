package spacepacket

import (
	"bytes"
	"testing"
)

func TestParseSpacePacket(t *testing.T) {
	data := []byte{0x10, 0x01, 0x40, 0x01, 0x00, 0x03, 0xDE, 0xAD, 0xBE, 0xEF}
	packet, err := ParseSpacePacket(data)
	if err != nil {
		t.Fatal(err)
	}

	if packet.PacketVersionNumber != 0 {
		t.Errorf("Expected PacketVersionNumber 0, got %d", packet.PacketVersionNumber)
	}

	if packet.PacketType != TelecommandPacketType {
		t.Errorf("Expected PacketType TelecommandPacketType, got %d", packet.PacketType)
	}

	if packet.SecondaryHeaderFlag != 0 {
		t.Errorf("Expected SecondaryHeaderFlag 0, got %d", packet.SecondaryHeaderFlag)
	}

	if packet.ApplicationProcessID != 1 {
		t.Errorf("Expected ApplicationProcessID 1, got %d", packet.ApplicationProcessID)
	}

	if packet.SequenceFlags != FirstSegment {
		t.Errorf("Expected SequenceFlags FirstSegment, got %d", packet.SequenceFlags)
	}

	if packet.PacketSequenceCount != 1 {
		t.Errorf("Expected PacketSequenceCount 1, got %0d", packet.PacketSequenceCount)
	}

	if packet.PacketDataLength != 3 {
		t.Errorf("Expected PacketDataLength 3, got %d", packet.PacketDataLength)
	}

	expectedPacketDataField := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	if !bytes.Equal(packet.PacketDataField, expectedPacketDataField) {
		t.Errorf("Expected UserData %v, got %v", expectedPacketDataField, packet.PacketDataField)
	}
}

func TestSerialize(t *testing.T) {
	packet := &SpacePacket{
		PacketVersionNumber:  0,
		PacketType:           TelecommandPacketType,
		SecondaryHeaderFlag:  0,
		ApplicationProcessID: 0x0001,
		SequenceFlags:        0x01,
		PacketSequenceCount:  0x0001,
		PacketDataLength:     3,
		PacketDataField:      []byte{0xDE, 0xAD, 0xBE, 0xEF},
	}

	serializedData := packet.Serialize()
	expectedSerializedData := []byte{0x10, 0x01, 0x40, 0x01, 0x00, 0x03, 0xDE, 0xAD, 0xBE, 0xEF}
	if !bytes.Equal(serializedData, expectedSerializedData) {
		t.Errorf("Expected serialized data %v, got %v", expectedSerializedData, serializedData)
	}
}
