package wire

import (
	"bytes"
	"fmt"
	"io"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/qerr"
	"github.com/lucas-clemente/quic-go/internal/utils"
)

// The Header is the version independent part of the header
type Header struct {
	Version          protocol.VersionNumber
	SrcConnectionID  protocol.ConnectionID
	DestConnectionID protocol.ConnectionID

	IsLongHeader bool
	Type         protocol.PacketType
	Length       protocol.ByteCount

	Token                []byte
	SupportedVersions    []protocol.VersionNumber // sent in a Version Negotiation Packet
	OrigDestConnectionID protocol.ConnectionID    // sent in the Retry packet

	typeByte byte
	len      int // how many bytes were read while parsing this header
}

// ParseHeader parses the header.
// For short header packets: up to the packet number.
// For long header packets:
// * if we understand the version: up to the packet number
// * if not, only the invariant part of the header
func ParseHeader(b *bytes.Reader, shortHeaderConnIDLen int) (*Header, error) {
	startLen := b.Len()
	h, err := parseHeaderImpl(b, shortHeaderConnIDLen)
	if err != nil {
		return nil, err
	}
	h.len = startLen - b.Len()
	return h, nil
}

func parseHeaderImpl(b *bytes.Reader, shortHeaderConnIDLen int) (*Header, error) {
	typeByte, err := b.ReadByte()
	if err != nil {
		return nil, err
	}

	h := &Header{
		typeByte:     typeByte,
		IsLongHeader: typeByte&0x80 > 0,
	}

	if !h.IsLongHeader {
		if err := h.parseShortHeader(b, shortHeaderConnIDLen); err != nil {
			return nil, err
		}
		return h, nil
	}
	if err := h.parseLongHeader(b); err != nil {
		return nil, err
	}
	return h, nil
}

func (h *Header) parseShortHeader(b *bytes.Reader, shortHeaderConnIDLen int) error {
	var err error
	h.DestConnectionID, err = protocol.ReadConnectionID(b, shortHeaderConnIDLen)
	return err
}

func (h *Header) parseLongHeader(b *bytes.Reader) error {
	v, err := utils.BigEndian.ReadUint32(b)
	if err != nil {
		return err
	}
	h.Version = protocol.VersionNumber(v)
	connIDLenByte, err := b.ReadByte()
	if err != nil {
		return err
	}
	dcil, scil := decodeConnIDLen(connIDLenByte)
	h.DestConnectionID, err = protocol.ReadConnectionID(b, dcil)
	if err != nil {
		return err
	}
	h.SrcConnectionID, err = protocol.ReadConnectionID(b, scil)
	if err != nil {
		return err
	}
	if h.Version == 0 {
		return h.parseVersionNegotiationPacket(b)
	}
	// If we don't understand the version, we have no idea how to interpret the rest of the bytes
	if !protocol.IsSupportedVersion(protocol.SupportedVersions, h.Version) {
		return nil
	}

	h.Type = protocol.PacketType(h.typeByte & 0x7f)
	if h.Type != protocol.PacketTypeInitial && h.Type != protocol.PacketTypeRetry && h.Type != protocol.PacketType0RTT && h.Type != protocol.PacketTypeHandshake {
		return qerr.Error(qerr.InvalidPacketHeader, fmt.Sprintf("Received packet with invalid packet type: %d", h.Type))
	}

	if h.Type == protocol.PacketTypeRetry {
		odcilByte, err := b.ReadByte()
		if err != nil {
			return err
		}
		odcil := decodeSingleConnIDLen(odcilByte & 0xf)
		h.OrigDestConnectionID, err = protocol.ReadConnectionID(b, odcil)
		if err != nil {
			return err
		}
		h.Token = make([]byte, b.Len())
		if _, err := io.ReadFull(b, h.Token); err != nil {
			return err
		}
		return nil
	}

	if h.Type == protocol.PacketTypeInitial {
		tokenLen, err := utils.ReadVarInt(b)
		if err != nil {
			return err
		}
		if tokenLen > uint64(b.Len()) {
			return io.EOF
		}
		h.Token = make([]byte, tokenLen)
		if _, err := io.ReadFull(b, h.Token); err != nil {
			return err
		}
	}

	pl, err := utils.ReadVarInt(b)
	if err != nil {
		return err
	}
	h.Length = protocol.ByteCount(pl)
	return nil
}

func (h *Header) parseVersionNegotiationPacket(b *bytes.Reader) error {
	if b.Len() == 0 {
		return qerr.Error(qerr.InvalidVersionNegotiationPacket, "empty version list")
	}
	h.SupportedVersions = make([]protocol.VersionNumber, b.Len()/4)
	for i := 0; b.Len() > 0; i++ {
		v, err := utils.BigEndian.ReadUint32(b)
		if err != nil {
			return qerr.InvalidVersionNegotiationPacket
		}
		h.SupportedVersions[i] = protocol.VersionNumber(v)
	}
	return nil
}

// IsVersionNegotiation says if this a version negotiation packet
func (h *Header) IsVersionNegotiation() bool {
	return h.IsLongHeader && h.Version == 0
}

// ParseExtended parses the version dependent part of the header.
// The Reader has to be set such that it points to the first byte of the header.
func (h *Header) ParseExtended(b *bytes.Reader, sentBy protocol.Perspective, ver protocol.VersionNumber) (*ExtendedHeader, error) {
	if _, err := b.Seek(int64(h.len), io.SeekCurrent); err != nil {
		return nil, err
	}
	return h.toExtendedHeader().parse(b, sentBy, ver)
}

func (h *Header) toExtendedHeader() *ExtendedHeader {
	return &ExtendedHeader{Header: *h}
}

func decodeConnIDLen(enc byte) (int /*dest conn id len*/, int /*src conn id len*/) {
	return decodeSingleConnIDLen(enc >> 4), decodeSingleConnIDLen(enc & 0xf)
}

func decodeSingleConnIDLen(enc uint8) int {
	if enc == 0 {
		return 0
	}
	return int(enc) + 3
}
