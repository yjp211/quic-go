package wire

import (
	"bytes"
	"io"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/qerr"
	"github.com/lucas-clemente/quic-go/internal/utils"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Header Parsing", func() {
	appendPacketNumber := func(data []byte, pn protocol.PacketNumber, pnLen protocol.PacketNumberLen) []byte {
		buf := &bytes.Buffer{}
		utils.WriteVarIntPacketNumber(buf, pn, pnLen)
		return append(data, buf.Bytes()...)
	}

	Context("Version Negotiation Packets", func() {
		It("parses", func() {
			srcConnID := protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
			destConnID := protocol.ConnectionID{9, 8, 7, 6, 5, 4, 3, 2, 1}
			versions := []protocol.VersionNumber{0x22334455, 0x33445566}
			data, err := ComposeVersionNegotiation(destConnID, srcConnID, versions)
			Expect(err).ToNot(HaveOccurred())
			iHdr, err := ParseInvariantHeader(bytes.NewReader(data), 0)
			Expect(err).ToNot(HaveOccurred())
			Expect(iHdr.DestConnectionID).To(Equal(destConnID))
			Expect(iHdr.SrcConnectionID).To(Equal(srcConnID))
			Expect(iHdr.IsLongHeader).To(BeTrue())
			b := bytes.NewReader(data)
			hdr, err := iHdr.Parse(b, protocol.PerspectiveServer, versionIETFFrames)
			Expect(err).ToNot(HaveOccurred())
			Expect(hdr.IsVersionNegotiation).To(BeTrue())
			Expect(hdr.Version).To(BeZero())
			Expect(hdr.DestConnectionID).To(Equal(destConnID))
			Expect(hdr.SrcConnectionID).To(Equal(srcConnID))
			for _, v := range versions {
				Expect(hdr.SupportedVersions).To(ContainElement(v))
			}
			Expect(b.Len()).To(BeZero())
		})

		It("errors if it contains versions of the wrong length", func() {
			connID := protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8}
			versions := []protocol.VersionNumber{0x22334455, 0x33445566}
			data, err := ComposeVersionNegotiation(connID, connID, versions)
			Expect(err).ToNot(HaveOccurred())
			data = data[:len(data)-2]
			iHdr, err := ParseInvariantHeader(bytes.NewReader(data), 0)
			Expect(err).ToNot(HaveOccurred())
			_, err = iHdr.Parse(bytes.NewReader(data), protocol.PerspectiveServer, versionIETFFrames)
			Expect(err).To(MatchError(qerr.InvalidVersionNegotiationPacket))
		})

		It("errors if the version list is empty", func() {
			connID := protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8}
			versions := []protocol.VersionNumber{0x22334455}
			data, err := ComposeVersionNegotiation(connID, connID, versions)
			Expect(err).ToNot(HaveOccurred())
			// remove 8 bytes (two versions), since ComposeVersionNegotiation also added a reserved version number
			data = data[:len(data)-8]
			iHdr, err := ParseInvariantHeader(bytes.NewReader(data), 0)
			Expect(err).ToNot(HaveOccurred())
			_, err = iHdr.Parse(bytes.NewReader(data), protocol.PerspectiveServer, versionIETFFrames)
			Expect(err).To(MatchError("InvalidVersionNegotiationPacket: empty version list"))
		})
	})

	Context("Long Headers", func() {
		It("parses a Long Header", func() {
			destConnID := protocol.ConnectionID{9, 8, 7, 6, 5, 4, 3, 2, 1}
			srcConnID := protocol.ConnectionID{0xde, 0xad, 0xbe, 0xef}
			data := []byte{
				0x80 ^ uint8(protocol.PacketTypeInitial),
				0x1, 0x2, 0x3, 0x4, // version number
				0x61, // connection ID lengths
			}
			data = append(data, destConnID...)
			data = append(data, srcConnID...)
			data = append(data, encodeVarInt(6)...)      // token length
			data = append(data, []byte("foobar")...)     // token
			data = append(data, encodeVarInt(0x1337)...) // length
			// packet number
			data = appendPacketNumber(data, 0xbeef, protocol.PacketNumberLen4)

			iHdr, err := ParseInvariantHeader(bytes.NewReader(data), 0)
			Expect(err).ToNot(HaveOccurred())
			Expect(iHdr.IsLongHeader).To(BeTrue())
			Expect(iHdr.DestConnectionID).To(Equal(destConnID))
			Expect(iHdr.SrcConnectionID).To(Equal(srcConnID))
			b := bytes.NewReader(data)
			hdr, err := iHdr.Parse(b, protocol.PerspectiveServer, versionIETFFrames)
			Expect(err).ToNot(HaveOccurred())
			Expect(hdr.Type).To(Equal(protocol.PacketTypeInitial))
			Expect(hdr.IsLongHeader).To(BeTrue())
			Expect(hdr.DestConnectionID).To(Equal(destConnID))
			Expect(hdr.SrcConnectionID).To(Equal(srcConnID))
			Expect(hdr.Token).To(Equal([]byte("foobar")))
			Expect(hdr.Length).To(Equal(protocol.ByteCount(0x1337)))
			Expect(hdr.PacketNumber).To(Equal(protocol.PacketNumber(0xbeef)))
			Expect(hdr.PacketNumberLen).To(Equal(protocol.PacketNumberLen4))
			Expect(hdr.Version).To(Equal(protocol.VersionNumber(0x1020304)))
			Expect(hdr.IsVersionNegotiation).To(BeFalse())
			Expect(b.Len()).To(BeZero())
		})

		It("parses a Long Header without a destination connection ID", func() {
			data := []byte{
				0x80 ^ uint8(protocol.PacketTypeInitial),
				0x1, 0x2, 0x3, 0x4, // version number
				0x01,                   // connection ID lengths
				0xde, 0xad, 0xbe, 0xef, // source connection ID
			}
			data = append(data, encodeVarInt(0x42)...) // length
			data = append(data, []byte{0xde, 0xca, 0xfb, 0xad}...)
			iHdr, err := ParseInvariantHeader(bytes.NewReader(data), 0)
			Expect(err).ToNot(HaveOccurred())
			Expect(iHdr.SrcConnectionID).To(Equal(protocol.ConnectionID{0xde, 0xad, 0xbe, 0xef}))
			Expect(iHdr.DestConnectionID).To(BeEmpty())
		})

		It("parses a Long Header without a source connection ID", func() {
			data := []byte{
				0x80 ^ uint8(protocol.PacketTypeInitial),
				0x1, 0x2, 0x3, 0x4, // version number
				0x70,                          // connection ID lengths
				1, 2, 3, 4, 5, 6, 7, 8, 9, 10, // source connection ID
			}
			data = append(data, encodeVarInt(0x42)...) // length
			data = append(data, []byte{0xde, 0xca, 0xfb, 0xad}...)
			iHdr, err := ParseInvariantHeader(bytes.NewReader(data), 0)
			Expect(err).ToNot(HaveOccurred())
			Expect(iHdr.SrcConnectionID).To(BeEmpty())
			Expect(iHdr.DestConnectionID).To(Equal(protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}))
		})

		It("parses a Long Header with a 2 byte packet number", func() {
			data := []byte{
				0x80 ^ uint8(protocol.PacketTypeInitial),
				0x1, 0x2, 0x3, 0x4, // version number
				0x0, // connection ID lengths
			}
			data = append(data, encodeVarInt(0)...)    // token length
			data = append(data, encodeVarInt(0x42)...) // length
			data = appendPacketNumber(data, 0x123, protocol.PacketNumberLen2)

			iHdr, err := ParseInvariantHeader(bytes.NewReader(data), 0)
			Expect(err).ToNot(HaveOccurred())
			b := bytes.NewReader(data)
			hdr, err := iHdr.Parse(b, protocol.PerspectiveServer, versionIETFFrames)
			Expect(err).ToNot(HaveOccurred())
			Expect(hdr.PacketNumber).To(Equal(protocol.PacketNumber(0x123)))
			Expect(hdr.PacketNumberLen).To(Equal(protocol.PacketNumberLen2))
			Expect(b.Len()).To(BeZero())
		})

		It("parses a Retry packet", func() {
			data := []byte{
				0x80 ^ uint8(protocol.PacketTypeRetry),
				0x1, 0x2, 0x3, 0x4, // version number
				0x0,                           // connection ID lengths
				0x97,                          // Orig Destination Connection ID length
				1, 2, 3, 4, 5, 6, 7, 8, 9, 10, // source connection ID
				'f', 'o', 'o', 'b', 'a', 'r', // token
			}
			iHdr, err := ParseInvariantHeader(bytes.NewReader(data), 0)
			Expect(err).ToNot(HaveOccurred())
			b := bytes.NewReader(data)
			hdr, err := iHdr.Parse(b, protocol.PerspectiveServer, versionIETFFrames)
			Expect(err).ToNot(HaveOccurred())
			Expect(hdr.Type).To(Equal(protocol.PacketTypeRetry))
			Expect(hdr.OrigDestConnectionID).To(Equal(protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}))
			Expect(hdr.Token).To(Equal([]byte("foobar")))
			Expect(b.Len()).To(BeZero())
		})

		It("rejects packets sent with an unknown packet type", func() {
			srcConnID := protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8}
			buf := &bytes.Buffer{}
			err := (&Header{
				IsLongHeader:    true,
				Type:            42,
				SrcConnectionID: srcConnID,
				Version:         0x10203040,
				PacketNumber:    1,
				PacketNumberLen: protocol.PacketNumberLen1,
			}).Write(buf, protocol.PerspectiveClient, protocol.VersionTLS)
			Expect(err).ToNot(HaveOccurred())
			b := bytes.NewReader(buf.Bytes())
			iHdr, err := ParseInvariantHeader(b, 0)
			Expect(err).ToNot(HaveOccurred())
			_, err = iHdr.Parse(b, protocol.PerspectiveClient, versionIETFFrames)
			Expect(err).To(MatchError("InvalidPacketHeader: Received packet with invalid packet type: 42"))
		})

		It("errors if the token length is too large", func() {
			data := []byte{
				0x80 ^ uint8(protocol.PacketTypeInitial),
				0x1, 0x2, 0x3, 0x4, // version number
				0x0, // connection ID lengths
			}
			data = append(data, encodeVarInt(4)...)                           // token length: 4 bytes (1 byte too long)
			data = append(data, encodeVarInt(0x42)...)                        // length, 1 byte
			data = appendPacketNumber(data, 0x123, protocol.PacketNumberLen2) // 2 bytes

			b := bytes.NewReader(data)
			iHdr, err := ParseInvariantHeader(b, 0)
			Expect(err).ToNot(HaveOccurred())
			_, err = iHdr.Parse(b, protocol.PerspectiveServer, versionIETFFrames)
			Expect(err).To(MatchError(io.EOF))
		})

		It("errors on EOF, when parsing the invariant header", func() {
			data := []byte{
				0x80 ^ uint8(protocol.PacketTypeInitial),
				0x1, 0x2, 0x3, 0x4, // version number
				0x55,                                           // connection ID lengths
				0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0x13, 0x37, // destination connection ID
				0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0x13, 0x37, // source connection ID
			}
			for i := 0; i < len(data); i++ {
				_, err := ParseInvariantHeader(bytes.NewReader(data[:i]), 0)
				Expect(err).To(Equal(io.EOF))
			}
		})

		It("errors on EOF, when parsing the header", func() {
			data := []byte{
				0x80 ^ uint8(protocol.PacketTypeInitial),
				0x1, 0x2, 0x3, 0x4, // version number
				0x0, // connection ID lengths
			}
			iHdrLen := len(data)
			data = append(data, encodeVarInt(0x1337)...)
			data = appendPacketNumber(data, 0xdeadbeef, protocol.PacketNumberLen4)
			for i := iHdrLen; i < len(data); i++ {
				b := bytes.NewReader(data[:i])
				iHdr, err := ParseInvariantHeader(b, 0)
				Expect(err).ToNot(HaveOccurred())
				_, err = iHdr.Parse(b, protocol.PerspectiveServer, versionIETFFrames)
				Expect(err).To(Equal(io.EOF))
			}
		})

		It("errors on EOF, for a Retry packet", func() {
			data := []byte{
				0x80 ^ uint8(protocol.PacketTypeRetry),
				0x1, 0x2, 0x3, 0x4, // version number
				0x0, // connection ID lengths
			}
			iHdrLen := len(data)
			data = append(data, []byte{
				0x97,                          // Orig Destination Connection ID length
				1, 2, 3, 4, 5, 6, 7, 8, 9, 10, // source connection ID
			}...)
			for i := iHdrLen; i < len(data); i++ {
				b := bytes.NewReader(data[:i])
				iHdr, err := ParseInvariantHeader(b, 0)
				Expect(err).ToNot(HaveOccurred())
				_, err = iHdr.Parse(b, protocol.PerspectiveServer, versionIETFFrames)
				Expect(err).To(Equal(io.EOF))
			}
		})
	})

	Context("Short Headers", func() {
		It("reads a Short Header with a 8 byte connection ID", func() {
			connID := protocol.ConnectionID{0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0x13, 0x37}
			data := append([]byte{0x30}, connID...)
			data = appendPacketNumber(data, 0x42, protocol.PacketNumberLen1)
			iHdr, err := ParseInvariantHeader(bytes.NewReader(data), 8)
			Expect(err).ToNot(HaveOccurred())
			Expect(iHdr.IsLongHeader).To(BeFalse())
			Expect(iHdr.DestConnectionID).To(Equal(connID))
			b := bytes.NewReader(data)
			hdr, err := iHdr.Parse(b, protocol.PerspectiveClient, versionIETFFrames)
			Expect(err).ToNot(HaveOccurred())
			Expect(hdr.KeyPhase).To(Equal(0))
			Expect(hdr.DestConnectionID).To(Equal(connID))
			Expect(hdr.SrcConnectionID).To(BeEmpty())
			Expect(hdr.PacketNumber).To(Equal(protocol.PacketNumber(0x42)))
			Expect(hdr.IsVersionNegotiation).To(BeFalse())
			Expect(b.Len()).To(BeZero())
		})

		It("reads a Short Header with a 5 byte connection ID", func() {
			connID := protocol.ConnectionID{1, 2, 3, 4, 5}
			data := append([]byte{0x30}, connID...)
			data = appendPacketNumber(data, 0x42, protocol.PacketNumberLen1)
			iHdr, err := ParseInvariantHeader(bytes.NewReader(data), 5)
			Expect(err).ToNot(HaveOccurred())
			Expect(iHdr.IsLongHeader).To(BeFalse())
			Expect(iHdr.DestConnectionID).To(Equal(connID))
			b := bytes.NewReader(data)
			hdr, err := iHdr.Parse(b, protocol.PerspectiveClient, versionIETFFrames)
			Expect(err).ToNot(HaveOccurred())
			Expect(hdr.KeyPhase).To(Equal(0))
			Expect(hdr.DestConnectionID).To(Equal(connID))
			Expect(hdr.SrcConnectionID).To(BeEmpty())
			Expect(b.Len()).To(BeZero())
		})

		It("reads the Key Phase Bit", func() {
			data := []byte{
				0x30 ^ 0x40,
				0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, // connection ID
			}
			data = appendPacketNumber(data, 11, protocol.PacketNumberLen1)
			iHdr, err := ParseInvariantHeader(bytes.NewReader(data), 6)
			Expect(err).ToNot(HaveOccurred())
			b := bytes.NewReader(data)
			hdr, err := iHdr.Parse(b, protocol.PerspectiveServer, versionIETFFrames)
			Expect(err).ToNot(HaveOccurred())
			Expect(hdr.IsLongHeader).To(BeFalse())
			Expect(hdr.KeyPhase).To(Equal(1))
			Expect(b.Len()).To(BeZero())
		})

		It("reads a header with a 2 byte packet number", func() {
			data := []byte{
				0x30 ^ 0x40 ^ 0x1,
				0xde, 0xad, 0xbe, 0xef, // connection ID
			}
			data = appendPacketNumber(data, 0x1337, protocol.PacketNumberLen2)
			iHdr, err := ParseInvariantHeader(bytes.NewReader(data), 4)
			Expect(err).ToNot(HaveOccurred())
			b := bytes.NewReader(data)
			hdr, err := iHdr.Parse(b, protocol.PerspectiveClient, versionIETFFrames)
			Expect(err).ToNot(HaveOccurred())
			Expect(hdr.IsLongHeader).To(BeFalse())
			Expect(hdr.PacketNumber).To(Equal(protocol.PacketNumber(0x1337)))
			Expect(hdr.PacketNumberLen).To(Equal(protocol.PacketNumberLen2))
			Expect(b.Len()).To(BeZero())
		})

		It("reads a header with a 4 byte packet number", func() {
			data := []byte{
				0x30 ^ 0x40 ^ 0x2,
				0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0x1, 0x2, 0x3, 0x4, // connection ID
			}
			data = appendPacketNumber(data, 0x99beef, protocol.PacketNumberLen4)
			iHdr, err := ParseInvariantHeader(bytes.NewReader(data), 10)
			Expect(err).ToNot(HaveOccurred())
			b := bytes.NewReader(data)
			hdr, err := iHdr.Parse(b, protocol.PerspectiveServer, versionIETFFrames)
			Expect(err).ToNot(HaveOccurred())
			Expect(hdr.IsLongHeader).To(BeFalse())
			Expect(hdr.PacketNumber).To(Equal(protocol.PacketNumber(0x99beef)))
			Expect(hdr.PacketNumberLen).To(Equal(protocol.PacketNumberLen4))
			Expect(b.Len()).To(BeZero())
		})

		It("errors on EOF, when parsing the invariant header", func() {
			data := []byte{
				0x30 ^ 0x2,
				0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0x13, 0x37, // connection ID
			}
			for i := 0; i < len(data); i++ {
				_, err := ParseInvariantHeader(bytes.NewReader(data[:i]), 8)
				Expect(err).To(Equal(io.EOF))
			}
		})

		It("errors on EOF, when parsing the invariant header", func() {
			data := []byte{
				0x30 ^ 0x2,
				0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, // connection ID
			}
			iHdrLen := len(data)
			data = appendPacketNumber(data, 0xdeadbeef, protocol.PacketNumberLen4)
			for i := iHdrLen; i < len(data); i++ {
				b := bytes.NewReader(data[:i])
				iHdr, err := ParseInvariantHeader(b, 6)
				Expect(err).ToNot(HaveOccurred())
				_, err = iHdr.Parse(b, protocol.PerspectiveClient, versionIETFFrames)
				Expect(err).To(Equal(io.EOF))
			}
		})
	})
})
