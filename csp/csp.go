package csp

import (
	"encoding/binary"
	"errors"
)

type CspPacket struct {
	Priority        uint8
	Source          uint8
	Destination     uint8
	DestinationPort uint8
	SourcePort      uint8
	Reserved        uint8
	HMAC            uint8
	XTEA            uint8
	RDP             uint8
	CRC             uint8
	Data            []byte
}

func ParseCspPacket(data []byte) (*CspPacket, error) {
	// Check that the data is neither too short nor too long to be a valid Space Packe
	if len(data) < 4 {
		return nil, errors.New("data too short to be a valid CSP packet")
	}
	if len(data) > 65535 {
		return nil, errors.New("data too long to be a valid CSP packet")
	}

	header := binary.BigEndian.Uint32(data[:4])

	priority := uint8((header >> 30) & 0x01)
	source := uint8((header >> 25) & 0x1F)
	destination := uint8((header >> 20) & 0x1F)
	destPort := uint8((header >> 14) & 0x3F)
	sourcePort := uint8((header >> 8) & 0x3F)
	reserved := uint8((header >> 4) & 0x0F)
	hmac := uint8((header >> 3) & 0x01)
	xtea := uint8((header >> 2) & 0x01)
	rdp := uint8((header >> 1) & 0x01)
	crc := uint8(header & 0x01)

	cspPacket := &CspPacket{
		Priority:        priority,
		Source:          source,
		Destination:     destination,
		DestinationPort: destPort,
		SourcePort:      sourcePort,
		Reserved:        reserved,
		HMAC:            hmac,
		XTEA:            xtea,
		RDP:             rdp,
		CRC:             crc,
		Data:            data[4:],
	}

	return cspPacket, nil
}

func (p *CspPacket) Serialize() []byte {
	header := uint32(p.Priority)<<30 | uint32(p.Source)<<25 | uint32(p.Destination)<<20 | uint32(p.DestinationPort)<<14 | uint32(p.SourcePort)<<8 | uint32(p.Reserved)<<4 | uint32(p.HMAC)<<3 | uint32(p.XTEA)<<2 | uint32(p.RDP)<<1 | uint32(p.CRC)
	headerBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(headerBytes, header)
	return append(headerBytes, p.Data...)
}
