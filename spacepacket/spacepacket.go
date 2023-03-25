package spacepacket

import (
	"encoding/binary"
	"errors"
	"fmt"
)

type PacketType uint8

const (
	TelemetryPacketType PacketType = iota
	TelecommandPacketType
)

type SequenceFlags uint8

const (
	Continuation SequenceFlags = iota
	FirstSegment
	LastSegment
	Unsegmented
)

type SpacePacket struct {
	PacketVersionNumber  uint8
	PacketType           PacketType
	SecondaryHeaderFlag  uint8
	ApplicationProcessID uint16
	SequenceFlags        SequenceFlags
	PacketSequenceCount  uint16
	PacketDataLength     uint16
	PacketDataField      []byte
}

func ParseSpacePacket(data []byte) (*SpacePacket, error) {
	// Check that the data is neither too short nor too long to be a valid Space Packet
	if len(data) < 6 {
		return nil, fmt.Errorf("data too short to be a valid Space Packet")
	}
	if len(data) > 65535 {
		return nil, fmt.Errorf("data too long to be a valid Space Packet")
	}

	// Parse the Space Packet header
	header := data[0:6]
	primaryHeaderFirstByte := header[0]
	primaryHeaderSecondByte := header[1]
	primaryHeaderThirdByte := header[2]

	// Parse the Packet Version Number
	packetVersionNumber := uint8(primaryHeaderFirstByte >> 5)
	if packetVersionNumber != 0 {
		return nil, errors.New("invalid version number")
	}

	// Parse the Packet Type
	packetType := PacketType((primaryHeaderFirstByte >> 4) & 0x01)
	if packetType != TelecommandPacketType && packetType != TelemetryPacketType {
		return nil, errors.New("invalid packet type")
	}

	// Parse the Secondary Header Flag
	secondaryHeaderFlag := uint8((primaryHeaderFirstByte >> 3) & 0x01)

	// Parse the Application Process ID
	applicationProcessID := (uint16(primaryHeaderFirstByte&0x07)<<8 | uint16(primaryHeaderSecondByte)) & 0x07FF

	// Parse the Sequence Flags
	sequenceFlags := SequenceFlags(primaryHeaderThirdByte >> 6)
	if sequenceFlags != Continuation && sequenceFlags != FirstSegment && sequenceFlags != LastSegment && sequenceFlags != Unsegmented {
		return nil, errors.New("invalid sequence flags")
	}

	// Parse the Packet Sequence Count
	packetSequenceCount := binary.BigEndian.Uint16(header[2:4]) & 0x3FFF

	// Parse the Packet Data Length
	packetDataLength := binary.BigEndian.Uint16(header[4:6]) & 0x07FF

	// Parse the Packet Data Field
	packetDataField := data[6:]

	return &SpacePacket{
		PacketVersionNumber:  packetVersionNumber,
		PacketType:           packetType,
		SecondaryHeaderFlag:  secondaryHeaderFlag,
		ApplicationProcessID: applicationProcessID,
		SequenceFlags:        sequenceFlags,
		PacketSequenceCount:  packetSequenceCount,
		PacketDataLength:     packetDataLength,
		PacketDataField:      packetDataField,
	}, nil
}

func (p *SpacePacket) Serialize() []byte {
	header := make([]byte, 6)

	// Set the Packet Version Number
	header[0] = (p.PacketVersionNumber << 5)
	// Set the Packet Type
	header[0] = header[0] | (uint8(p.PacketType) << 4)
	// Set the Secondary Header Flag
	header[0] = header[0] | (p.SecondaryHeaderFlag << 3)
	// Set the Application Process ID
	header[0] = header[0] | uint8((p.ApplicationProcessID>>8)&0x07)
	header[1] = uint8(p.ApplicationProcessID & 0xFF)
	// Set the Sequence Flags
	header[2] = uint8(p.SequenceFlags) << 6
	// Set the Packet Sequence Count
	header[2] = header[2] | uint8((p.PacketSequenceCount&0x3FC0)>>8)
	header[3] = uint8(p.PacketSequenceCount & 0xFF)
	// Set the Packet Data Length
	binary.BigEndian.PutUint16(header[4:], p.PacketDataLength)

	return append(header, p.PacketDataField...)
}
