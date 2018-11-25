package quic

import (
	"bytes"
	"math/rand"
	"net"

	"github.com/golang/mock/gomock"
	"github.com/lucas-clemente/quic-go/internal/ackhandler"
	"github.com/lucas-clemente/quic-go/internal/handshake"
	"github.com/lucas-clemente/quic-go/internal/mocks"
	"github.com/lucas-clemente/quic-go/internal/mocks/ackhandler"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/wire"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Packet packer", func() {
	const maxPacketSize protocol.ByteCount = 1357
	var (
		packer          *packetPacker
		framer          *MockFrameSource
		ackFramer       *MockAckFrameSource
		initialStream   *MockCryptoStream
		handshakeStream *MockCryptoStream
		sealingManager  *MockSealingManager
		sealer          *mocks.MockSealer
		pnManager       *mockackhandler.MockSentPacketHandler
		token           []byte
	)

	checkLength := func(data []byte) {
		iHdr, err := wire.ParseInvariantHeader(bytes.NewReader(data), 0)
		Expect(err).ToNot(HaveOccurred())
		r := bytes.NewReader(data)
		hdr, err := iHdr.Parse(r, protocol.PerspectiveServer, protocol.VersionWhatever)
		Expect(err).ToNot(HaveOccurred())
		ExpectWithOffset(0, hdr.Length).To(BeEquivalentTo(r.Len() + int(hdr.PacketNumberLen)))
	}

	expectAppendStreamFrames := func(frames ...wire.Frame) {
		framer.EXPECT().AppendStreamFrames(gomock.Any(), gomock.Any()).DoAndReturn(func(fs []wire.Frame, _ protocol.ByteCount) []wire.Frame {
			return append(fs, frames...)
		})
	}

	expectAppendControlFrames := func(frames ...wire.Frame) {
		framer.EXPECT().AppendControlFrames(gomock.Any(), gomock.Any()).DoAndReturn(func(fs []wire.Frame, _ protocol.ByteCount) ([]wire.Frame, protocol.ByteCount) {
			var length protocol.ByteCount
			for _, f := range frames {
				length += f.Length(packer.version)
			}
			return append(fs, frames...), length
		})
	}

	BeforeEach(func() {
		rand.Seed(GinkgoRandomSeed())
		version := protocol.VersionWhatever
		mockSender := NewMockStreamSender(mockCtrl)
		mockSender.EXPECT().onHasStreamData(gomock.Any()).AnyTimes()
		initialStream = NewMockCryptoStream(mockCtrl)
		handshakeStream = NewMockCryptoStream(mockCtrl)
		framer = NewMockFrameSource(mockCtrl)
		ackFramer = NewMockAckFrameSource(mockCtrl)
		sealingManager = NewMockSealingManager(mockCtrl)
		pnManager = mockackhandler.NewMockSentPacketHandler(mockCtrl)
		sealer = mocks.NewMockSealer(mockCtrl)
		sealer.EXPECT().Overhead().Return(7).AnyTimes()
		sealer.EXPECT().Seal(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(func(dst, src []byte, pn protocol.PacketNumber, associatedData []byte) []byte {
			return append(src, bytes.Repeat([]byte{0}, 7)...)
		}).AnyTimes()

		token = []byte("initial token")

		packer = newPacketPacker(
			protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8},
			protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8},
			initialStream,
			handshakeStream,
			pnManager,
			&net.TCPAddr{},
			token, // token
			sealingManager,
			framer,
			ackFramer,
			protocol.PerspectiveServer,
			version,
		)
		packer.hasSentPacket = true
		packer.version = version
		packer.maxPacketSize = maxPacketSize
	})

	Context("determining the maximum packet size", func() {
		It("uses the minimum initial size, if it can't determine if the remote address is IPv4 or IPv6", func() {
			Expect(getMaxPacketSize(&net.TCPAddr{})).To(BeEquivalentTo(protocol.MinInitialPacketSize))
		})

		It("uses the maximum IPv4 packet size, if the remote address is IPv4", func() {
			addr := &net.UDPAddr{IP: net.IPv4(11, 12, 13, 14), Port: 1337}
			Expect(getMaxPacketSize(addr)).To(BeEquivalentTo(protocol.MaxPacketSizeIPv4))
		})

		It("uses the maximum IPv6 packet size, if the remote address is IPv6", func() {
			ip := net.ParseIP("2001:0db8:85a3:0000:0000:8a2e:0370:7334")
			addr := &net.UDPAddr{IP: ip, Port: 1337}
			Expect(getMaxPacketSize(addr)).To(BeEquivalentTo(protocol.MaxPacketSizeIPv6))
		})
	})

	Context("generating a packet header", func() {
		It("uses the Long Header format", func() {
			pnManager.EXPECT().PeekPacketNumber().Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2)
			h := packer.getHeader(protocol.EncryptionHandshake)
			Expect(h.IsLongHeader).To(BeTrue())
			Expect(h.PacketNumber).To(Equal(protocol.PacketNumber(0x42)))
			Expect(h.PacketNumberLen).To(Equal(protocol.PacketNumberLen2))
			Expect(h.Version).To(Equal(packer.version))
		})

		It("sets source and destination connection ID", func() {
			pnManager.EXPECT().PeekPacketNumber().Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2)
			srcConnID := protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8}
			destConnID := protocol.ConnectionID{8, 7, 6, 5, 4, 3, 2, 1}
			packer.srcConnID = srcConnID
			packer.destConnID = destConnID
			h := packer.getHeader(protocol.EncryptionHandshake)
			Expect(h.SrcConnectionID).To(Equal(srcConnID))
			Expect(h.DestConnectionID).To(Equal(destConnID))
		})

		It("changes the destination connection ID", func() {
			pnManager.EXPECT().PeekPacketNumber().Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2).Times(2)
			srcConnID := protocol.ConnectionID{1, 1, 1, 1, 1, 1, 1, 1}
			packer.srcConnID = srcConnID
			dest1 := protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8}
			dest2 := protocol.ConnectionID{8, 7, 6, 5, 4, 3, 2, 1}
			packer.ChangeDestConnectionID(dest1)
			h := packer.getHeader(protocol.EncryptionInitial)
			Expect(h.SrcConnectionID).To(Equal(srcConnID))
			Expect(h.DestConnectionID).To(Equal(dest1))
			packer.ChangeDestConnectionID(dest2)
			h = packer.getHeader(protocol.EncryptionInitial)
			Expect(h.SrcConnectionID).To(Equal(srcConnID))
			Expect(h.DestConnectionID).To(Equal(dest2))
		})

		It("uses the Short Header format for 1-RTT packets", func() {
			pnManager.EXPECT().PeekPacketNumber().Return(protocol.PacketNumber(0x1337), protocol.PacketNumberLen4)
			h := packer.getHeader(protocol.Encryption1RTT)
			Expect(h.IsLongHeader).To(BeFalse())
			Expect(h.PacketNumber).To(Equal(protocol.PacketNumber(0x1337)))
			Expect(h.PacketNumberLen).To(Equal(protocol.PacketNumberLen4))
		})
	})

	Context("packing normal packets", func() {
		BeforeEach(func() {
			initialStream.EXPECT().HasData().AnyTimes()
			handshakeStream.EXPECT().HasData().AnyTimes()
		})

		It("returns nil when no packet is queued", func() {
			pnManager.EXPECT().PeekPacketNumber().Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2)
			// don't expect any calls to PopPacketNumber
			sealingManager.EXPECT().GetSealer().Return(protocol.Encryption1RTT, sealer)
			ackFramer.EXPECT().GetAckFrame()
			framer.EXPECT().AppendControlFrames(nil, gomock.Any())
			framer.EXPECT().AppendStreamFrames(nil, gomock.Any())
			p, err := packer.PackPacket()
			Expect(p).To(BeNil())
			Expect(err).ToNot(HaveOccurred())
		})

		It("packs single packets", func() {
			pnManager.EXPECT().PeekPacketNumber().Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2)
			pnManager.EXPECT().PopPacketNumber().Return(protocol.PacketNumber(0x42))
			sealingManager.EXPECT().GetSealer().Return(protocol.Encryption1RTT, sealer)
			ackFramer.EXPECT().GetAckFrame()
			expectAppendControlFrames()
			f := &wire.StreamFrame{
				StreamID: 5,
				Data:     []byte{0xde, 0xca, 0xfb, 0xad},
			}
			expectAppendStreamFrames(f)
			p, err := packer.PackPacket()
			Expect(err).ToNot(HaveOccurred())
			Expect(p).ToNot(BeNil())
			b := &bytes.Buffer{}
			f.Write(b, packer.version)
			Expect(p.frames).To(Equal([]wire.Frame{f}))
			Expect(p.raw).To(ContainSubstring(b.String()))
		})

		It("stores the encryption level a packet was sealed with", func() {
			pnManager.EXPECT().PeekPacketNumber().Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2)
			pnManager.EXPECT().PopPacketNumber().Return(protocol.PacketNumber(0x42))
			sealingManager.EXPECT().GetSealer().Return(protocol.Encryption1RTT, sealer)
			ackFramer.EXPECT().GetAckFrame()
			expectAppendControlFrames()
			expectAppendStreamFrames(&wire.StreamFrame{
				StreamID: 5,
				Data:     []byte("foobar"),
			})
			p, err := packer.PackPacket()
			Expect(err).ToNot(HaveOccurred())
			Expect(p.encryptionLevel).To(Equal(protocol.Encryption1RTT))
		})

		It("packs a single ACK", func() {
			pnManager.EXPECT().PeekPacketNumber().Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2)
			pnManager.EXPECT().PopPacketNumber().Return(protocol.PacketNumber(0x42))
			ack := &wire.AckFrame{AckRanges: []wire.AckRange{{Largest: 42, Smallest: 1}}}
			ackFramer.EXPECT().GetAckFrame().Return(ack)
			sealingManager.EXPECT().GetSealer().Return(protocol.Encryption1RTT, sealer)
			expectAppendControlFrames()
			expectAppendStreamFrames()
			p, err := packer.PackPacket()
			Expect(err).NotTo(HaveOccurred())
			Expect(p).ToNot(BeNil())
			Expect(p.frames[0]).To(Equal(ack))
		})

		It("packs a CONNECTION_CLOSE", func() {
			pnManager.EXPECT().PeekPacketNumber().Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2)
			pnManager.EXPECT().PopPacketNumber().Return(protocol.PacketNumber(0x42))
			// expect no framer.PopStreamFrames
			ccf := wire.ConnectionCloseFrame{
				ErrorCode:    0x1337,
				ReasonPhrase: "foobar",
			}
			sealingManager.EXPECT().GetSealer().Return(protocol.Encryption1RTT, sealer)
			p, err := packer.PackConnectionClose(&ccf)
			Expect(err).ToNot(HaveOccurred())
			Expect(p.frames).To(HaveLen(1))
			Expect(p.frames[0]).To(Equal(&ccf))
		})

		It("packs control frames", func() {
			pnManager.EXPECT().PeekPacketNumber().Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2)
			pnManager.EXPECT().PopPacketNumber().Return(protocol.PacketNumber(0x42))
			sealingManager.EXPECT().GetSealer().Return(protocol.Encryption1RTT, sealer)
			ackFramer.EXPECT().GetAckFrame()
			frames := []wire.Frame{&wire.ResetStreamFrame{}, &wire.MaxDataFrame{}}
			expectAppendControlFrames(frames...)
			expectAppendStreamFrames()
			p, err := packer.PackPacket()
			Expect(p).ToNot(BeNil())
			Expect(err).ToNot(HaveOccurred())
			Expect(p.frames).To(Equal(frames))
			Expect(p.raw).NotTo(BeEmpty())
		})

		It("accounts for the space consumed by control frames", func() {
			pnManager.EXPECT().PeekPacketNumber().Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2)
			sealingManager.EXPECT().GetSealer().Return(protocol.Encryption1RTT, sealer)
			ackFramer.EXPECT().GetAckFrame()
			var maxSize protocol.ByteCount
			gomock.InOrder(
				framer.EXPECT().AppendControlFrames(gomock.Any(), gomock.Any()).DoAndReturn(func(fs []wire.Frame, maxLen protocol.ByteCount) ([]wire.Frame, protocol.ByteCount) {
					maxSize = maxLen
					return fs, 444
				}),
				framer.EXPECT().AppendStreamFrames(gomock.Any(), gomock.Any()).Do(func(_ []wire.Frame, maxLen protocol.ByteCount) []wire.Frame {
					Expect(maxLen).To(Equal(maxSize - 444 + 1 /* data length of the STREAM frame */))
					return nil
				}),
			)
			_, err := packer.PackPacket()
			Expect(err).ToNot(HaveOccurred())
		})

		Context("packing ACK packets", func() {
			It("doesn't pack a packet if there's no ACK to send", func() {
				ackFramer.EXPECT().GetAckFrame()
				p, err := packer.MaybePackAckPacket()
				Expect(err).ToNot(HaveOccurred())
				Expect(p).To(BeNil())
			})

			It("packs ACK packets", func() {
				pnManager.EXPECT().PeekPacketNumber().Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2)
				pnManager.EXPECT().PopPacketNumber().Return(protocol.PacketNumber(0x42))
				sealingManager.EXPECT().GetSealer().Return(protocol.Encryption1RTT, sealer)
				ack := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 1, Largest: 10}}}
				ackFramer.EXPECT().GetAckFrame().Return(ack)
				p, err := packer.MaybePackAckPacket()
				Expect(err).NotTo(HaveOccurred())
				Expect(p.frames).To(Equal([]wire.Frame{ack}))
			})
		})

		Context("making ACK packets retransmittable", func() {
			sendMaxNumNonRetransmittableAcks := func() {
				for i := 0; i < protocol.MaxNonRetransmittableAcks; i++ {
					pnManager.EXPECT().PeekPacketNumber().Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2)
					pnManager.EXPECT().PopPacketNumber().Return(protocol.PacketNumber(0x42))
					sealingManager.EXPECT().GetSealer().Return(protocol.Encryption1RTT, sealer)
					ackFramer.EXPECT().GetAckFrame().Return(&wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 1, Largest: 1}}})
					expectAppendControlFrames()
					expectAppendStreamFrames()
					p, err := packer.PackPacket()
					Expect(p).ToNot(BeNil())
					Expect(err).ToNot(HaveOccurred())
					Expect(p.frames).To(HaveLen(1))
				}
			}

			It("adds a PING frame when it's supposed to send a retransmittable packet", func() {
				sendMaxNumNonRetransmittableAcks()
				pnManager.EXPECT().PeekPacketNumber().Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2)
				pnManager.EXPECT().PopPacketNumber().Return(protocol.PacketNumber(0x42))
				sealingManager.EXPECT().GetSealer().Return(protocol.Encryption1RTT, sealer)
				ackFramer.EXPECT().GetAckFrame().Return(&wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 1, Largest: 1}}})
				expectAppendControlFrames()
				expectAppendStreamFrames()
				p, err := packer.PackPacket()
				Expect(p).ToNot(BeNil())
				Expect(err).ToNot(HaveOccurred())
				Expect(p.frames).To(ContainElement(&wire.PingFrame{}))
				// make sure the next packet doesn't contain another PING
				pnManager.EXPECT().PeekPacketNumber().Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2)
				pnManager.EXPECT().PopPacketNumber().Return(protocol.PacketNumber(0x42))
				sealingManager.EXPECT().GetSealer().Return(protocol.Encryption1RTT, sealer)
				ackFramer.EXPECT().GetAckFrame().Return(&wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 1, Largest: 1}}})
				expectAppendControlFrames()
				expectAppendStreamFrames()
				p, err = packer.PackPacket()
				Expect(p).ToNot(BeNil())
				Expect(err).ToNot(HaveOccurred())
				Expect(p.frames).To(HaveLen(1))
			})

			It("waits until there's something to send before adding a PING frame", func() {
				sendMaxNumNonRetransmittableAcks()
				// nothing to send
				pnManager.EXPECT().PeekPacketNumber().Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2)
				sealingManager.EXPECT().GetSealer().Return(protocol.Encryption1RTT, sealer)
				expectAppendControlFrames()
				expectAppendStreamFrames()
				ackFramer.EXPECT().GetAckFrame()
				p, err := packer.PackPacket()
				Expect(err).ToNot(HaveOccurred())
				Expect(p).To(BeNil())
				// now add some frame to send
				expectAppendControlFrames()
				expectAppendStreamFrames()
				pnManager.EXPECT().PeekPacketNumber().Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2)
				pnManager.EXPECT().PopPacketNumber().Return(protocol.PacketNumber(0x42))
				sealingManager.EXPECT().GetSealer().Return(protocol.Encryption1RTT, sealer)
				ackFramer.EXPECT().GetAckFrame().Return(&wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 1, Largest: 1}}})
				p, err = packer.PackPacket()
				Expect(err).ToNot(HaveOccurred())
				Expect(p.frames).To(HaveLen(2))
				Expect(p.frames).To(ContainElement(&wire.PingFrame{}))
			})

			It("doesn't send a PING if it already sent another retransmittable frame", func() {
				sendMaxNumNonRetransmittableAcks()
				pnManager.EXPECT().PeekPacketNumber().Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2)
				pnManager.EXPECT().PopPacketNumber().Return(protocol.PacketNumber(0x42))
				sealingManager.EXPECT().GetSealer().Return(protocol.Encryption1RTT, sealer)
				ackFramer.EXPECT().GetAckFrame()
				expectAppendStreamFrames()
				expectAppendControlFrames(&wire.MaxDataFrame{})
				p, err := packer.PackPacket()
				Expect(err).ToNot(HaveOccurred())
				Expect(p).ToNot(BeNil())
				Expect(p.frames).ToNot(ContainElement(&wire.PingFrame{}))
			})
		})

		Context("STREAM frame handling", func() {
			It("does not split a STREAM frame with maximum size", func() {
				pnManager.EXPECT().PeekPacketNumber().Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2)
				pnManager.EXPECT().PopPacketNumber().Return(protocol.PacketNumber(0x42))
				ackFramer.EXPECT().GetAckFrame()
				sealingManager.EXPECT().GetSealer().Return(protocol.Encryption1RTT, sealer)
				expectAppendControlFrames()
				sf := &wire.StreamFrame{
					Offset:         1,
					StreamID:       5,
					DataLenPresent: true,
				}
				framer.EXPECT().AppendStreamFrames(gomock.Any(), gomock.Any()).DoAndReturn(func(_ []wire.Frame, maxSize protocol.ByteCount) ([]wire.Frame, protocol.ByteCount) {
					sf.Data = bytes.Repeat([]byte{'f'}, int(maxSize-sf.Length(packer.version)))
					return []wire.Frame{sf}, sf.Length(packer.version)
				})
				p, err := packer.PackPacket()
				Expect(err).ToNot(HaveOccurred())
				Expect(p.frames).To(HaveLen(1))
				Expect(p.raw).To(HaveLen(int(maxPacketSize)))
				Expect(p.frames[0].(*wire.StreamFrame).Data).To(HaveLen(len(sf.Data)))
				Expect(p.frames[0].(*wire.StreamFrame).DataLenPresent).To(BeFalse())
			})

			It("packs multiple small STREAM frames into single packet", func() {
				f1 := &wire.StreamFrame{
					StreamID:       5,
					Data:           []byte("frame 1"),
					DataLenPresent: true,
				}
				f2 := &wire.StreamFrame{
					StreamID:       5,
					Data:           []byte("frame 2"),
					DataLenPresent: true,
				}
				f3 := &wire.StreamFrame{
					StreamID:       3,
					Data:           []byte("frame 3"),
					DataLenPresent: true,
				}
				pnManager.EXPECT().PeekPacketNumber().Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2)
				pnManager.EXPECT().PopPacketNumber().Return(protocol.PacketNumber(0x42))
				sealingManager.EXPECT().GetSealer().Return(protocol.Encryption1RTT, sealer)
				ackFramer.EXPECT().GetAckFrame()
				expectAppendControlFrames()
				expectAppendStreamFrames(f1, f2, f3)
				p, err := packer.PackPacket()
				Expect(p).ToNot(BeNil())
				Expect(err).ToNot(HaveOccurred())
				Expect(p.frames).To(HaveLen(3))
				Expect(p.frames[0].(*wire.StreamFrame).Data).To(Equal([]byte("frame 1")))
				Expect(p.frames[0].(*wire.StreamFrame).DataLenPresent).To(BeTrue())
				Expect(p.frames[1].(*wire.StreamFrame).Data).To(Equal([]byte("frame 2")))
				Expect(p.frames[1].(*wire.StreamFrame).DataLenPresent).To(BeTrue())
				Expect(p.frames[2].(*wire.StreamFrame).Data).To(Equal([]byte("frame 3")))
				Expect(p.frames[2].(*wire.StreamFrame).DataLenPresent).To(BeFalse())
			})

			It("doesn't send unencrypted stream data on a data stream", func() {
				pnManager.EXPECT().PeekPacketNumber().Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2)
				sealingManager.EXPECT().GetSealer().Return(protocol.EncryptionInitial, sealer)
				ackFramer.EXPECT().GetAckFrame()
				expectAppendControlFrames()
				// don't expect a call to framer.PopStreamFrames
				p, err := packer.PackPacket()
				Expect(err).NotTo(HaveOccurred())
				Expect(p).To(BeNil())
			})
		})

		Context("retransmissions", func() {
			It("retransmits a small packet", func() {
				pnManager.EXPECT().PeekPacketNumber().Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2)
				pnManager.EXPECT().PopPacketNumber().Return(protocol.PacketNumber(0x42))
				sealingManager.EXPECT().GetSealerWithEncryptionLevel(protocol.Encryption1RTT).Return(sealer, nil)
				frames := []wire.Frame{
					&wire.MaxDataFrame{ByteOffset: 0x1234},
					&wire.StreamFrame{StreamID: 42, Data: []byte("foobar")},
				}
				packets, err := packer.PackRetransmission(&ackhandler.Packet{
					EncryptionLevel: protocol.Encryption1RTT,
					Frames:          frames,
				})
				Expect(err).ToNot(HaveOccurred())
				Expect(packets).To(HaveLen(1))
				p := packets[0]
				Expect(p.encryptionLevel).To(Equal(protocol.Encryption1RTT))
				Expect(p.frames).To(Equal(frames))
			})

			It("packs two packets for retransmission if the original packet contained many control frames", func() {
				pnManager.EXPECT().PeekPacketNumber().Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2).Times(2)
				pnManager.EXPECT().PopPacketNumber().Return(protocol.PacketNumber(0x42)).Times(2)
				sealingManager.EXPECT().GetSealerWithEncryptionLevel(protocol.Encryption1RTT).Return(sealer, nil)
				var frames []wire.Frame
				var totalLen protocol.ByteCount
				// pack a bunch of control frames, such that the packet is way bigger than a single packet
				for i := 0; totalLen < maxPacketSize*3/2; i++ {
					f := &wire.MaxStreamDataFrame{
						StreamID:   protocol.StreamID(i),
						ByteOffset: protocol.ByteCount(i),
					}
					frames = append(frames, f)
					totalLen += f.Length(packer.version)
				}
				packets, err := packer.PackRetransmission(&ackhandler.Packet{
					EncryptionLevel: protocol.Encryption1RTT,
					Frames:          frames,
				})
				Expect(err).ToNot(HaveOccurred())
				Expect(packets).To(HaveLen(2))
				Expect(len(packets[0].frames) + len(packets[1].frames)).To(Equal(len(frames)))
				Expect(packets[1].frames).To(Equal(frames[len(packets[0].frames):]))
				// check that the first packet was filled up as far as possible:
				// if the first frame (after the STOP_WAITING) was packed into the first packet, it would have overflown the MaxPacketSize
				Expect(len(packets[0].raw) + int(packets[1].frames[1].Length(packer.version))).To(BeNumerically(">", maxPacketSize))
			})

			It("splits a STREAM frame that doesn't fit", func() {
				pnManager.EXPECT().PeekPacketNumber().Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2).Times(2)
				pnManager.EXPECT().PopPacketNumber().Return(protocol.PacketNumber(0x42)).Times(2)
				sealingManager.EXPECT().GetSealerWithEncryptionLevel(protocol.Encryption1RTT).Return(sealer, nil)
				packets, err := packer.PackRetransmission(&ackhandler.Packet{
					EncryptionLevel: protocol.Encryption1RTT,
					Frames: []wire.Frame{&wire.StreamFrame{
						StreamID: 42,
						Offset:   1337,
						Data:     bytes.Repeat([]byte{'a'}, int(maxPacketSize)*3/2),
					}},
				})
				Expect(err).ToNot(HaveOccurred())
				Expect(packets).To(HaveLen(2))
				Expect(packets[0].frames[0]).To(BeAssignableToTypeOf(&wire.StreamFrame{}))
				Expect(packets[1].frames[0]).To(BeAssignableToTypeOf(&wire.StreamFrame{}))
				sf1 := packets[0].frames[0].(*wire.StreamFrame)
				sf2 := packets[1].frames[0].(*wire.StreamFrame)
				Expect(sf1.StreamID).To(Equal(protocol.StreamID(42)))
				Expect(sf1.Offset).To(Equal(protocol.ByteCount(1337)))
				Expect(sf1.DataLenPresent).To(BeFalse())
				Expect(sf2.StreamID).To(Equal(protocol.StreamID(42)))
				Expect(sf2.Offset).To(Equal(protocol.ByteCount(1337) + sf1.DataLen()))
				Expect(sf2.DataLenPresent).To(BeFalse())
				Expect(sf1.DataLen() + sf2.DataLen()).To(Equal(maxPacketSize * 3 / 2))
				Expect(packets[0].raw).To(HaveLen(int(maxPacketSize)))
			})

			It("splits STREAM frames, if necessary", func() {
				pnManager.EXPECT().PeekPacketNumber().Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2).AnyTimes()
				pnManager.EXPECT().PopPacketNumber().Return(protocol.PacketNumber(0x42)).AnyTimes()
				for i := 0; i < 100; i++ {
					sealingManager.EXPECT().GetSealerWithEncryptionLevel(protocol.Encryption1RTT).Return(sealer, nil).MaxTimes(2)
					sf1 := &wire.StreamFrame{
						StreamID: 42,
						Offset:   1337,
						Data:     bytes.Repeat([]byte{'a'}, 1+int(rand.Int31n(int32(maxPacketSize*4/5)))),
					}
					sf2 := &wire.StreamFrame{
						StreamID: 2,
						Offset:   42,
						Data:     bytes.Repeat([]byte{'b'}, 1+int(rand.Int31n(int32(maxPacketSize*4/5)))),
					}
					expectedDataLen := sf1.DataLen() + sf2.DataLen()
					frames := []wire.Frame{sf1, sf2}
					packets, err := packer.PackRetransmission(&ackhandler.Packet{
						EncryptionLevel: protocol.Encryption1RTT,
						Frames:          frames,
					})
					Expect(err).ToNot(HaveOccurred())

					if len(packets) > 1 {
						Expect(packets[0].raw).To(HaveLen(int(maxPacketSize)))
					}

					var dataLen protocol.ByteCount
					for _, p := range packets {
						for _, f := range p.frames {
							dataLen += f.(*wire.StreamFrame).DataLen()
						}
					}
					Expect(dataLen).To(Equal(expectedDataLen))
				}
			})

			It("packs two packets for retransmission if the original packet contained many STREAM frames", func() {
				pnManager.EXPECT().PeekPacketNumber().Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2).Times(2)
				pnManager.EXPECT().PopPacketNumber().Return(protocol.PacketNumber(0x42)).Times(2)
				sealingManager.EXPECT().GetSealerWithEncryptionLevel(protocol.Encryption1RTT).Return(sealer, nil)
				var frames []wire.Frame
				var totalLen protocol.ByteCount
				// pack a bunch of control frames, such that the packet is way bigger than a single packet
				for i := 0; totalLen < maxPacketSize*3/2; i++ {
					f := &wire.StreamFrame{
						StreamID:       protocol.StreamID(i),
						Data:           []byte("foobar"),
						DataLenPresent: true,
					}
					frames = append(frames, f)
					totalLen += f.Length(packer.version)
				}
				packets, err := packer.PackRetransmission(&ackhandler.Packet{
					EncryptionLevel: protocol.Encryption1RTT,
					Frames:          frames,
				})
				Expect(err).ToNot(HaveOccurred())
				Expect(packets).To(HaveLen(2))
				Expect(len(packets[0].frames) + len(packets[1].frames)).To(Equal(len(frames))) // all frames
				Expect(packets[1].frames).To(Equal(frames[len(packets[0].frames):]))
				// check that the first packet was filled up as far as possible:
				// if the first frame was packed into the first packet, it would have overflown the MaxPacketSize
				Expect(len(packets[0].raw) + int(packets[1].frames[1].Length(packer.version))).To(BeNumerically(">", maxPacketSize-protocol.MinStreamFrameSize))
			})

			It("correctly sets the DataLenPresent on STREAM frames", func() {
				pnManager.EXPECT().PeekPacketNumber().Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2)
				pnManager.EXPECT().PopPacketNumber().Return(protocol.PacketNumber(0x42))
				sealingManager.EXPECT().GetSealerWithEncryptionLevel(protocol.Encryption1RTT).Return(sealer, nil)
				frames := []wire.Frame{
					&wire.StreamFrame{StreamID: 4, Data: []byte("foobar"), DataLenPresent: true},
					&wire.StreamFrame{StreamID: 5, Data: []byte("barfoo")},
				}
				packets, err := packer.PackRetransmission(&ackhandler.Packet{
					EncryptionLevel: protocol.Encryption1RTT,
					Frames:          frames,
				})
				Expect(err).ToNot(HaveOccurred())
				Expect(packets).To(HaveLen(1))
				p := packets[0]
				Expect(p.frames).To(HaveLen(2))
				Expect(p.frames[0]).To(BeAssignableToTypeOf(&wire.StreamFrame{}))
				Expect(p.frames[1]).To(BeAssignableToTypeOf(&wire.StreamFrame{}))
				sf1 := p.frames[0].(*wire.StreamFrame)
				sf2 := p.frames[1].(*wire.StreamFrame)
				Expect(sf1.StreamID).To(Equal(protocol.StreamID(4)))
				Expect(sf1.DataLenPresent).To(BeTrue())
				Expect(sf2.StreamID).To(Equal(protocol.StreamID(5)))
				Expect(sf2.DataLenPresent).To(BeFalse())
			})
		})

		Context("max packet size", func() {
			It("sets the maximum packet size", func() {
				pnManager.EXPECT().PeekPacketNumber().Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2).Times(2)
				sealingManager.EXPECT().GetSealer().Return(protocol.Encryption1RTT, sealer).Times(2)
				ackFramer.EXPECT().GetAckFrame().Times(2)
				var initialMaxPacketSize protocol.ByteCount
				framer.EXPECT().AppendControlFrames(gomock.Any(), gomock.Any()).Do(func(_ []wire.Frame, maxLen protocol.ByteCount) ([]wire.Frame, protocol.ByteCount) {
					initialMaxPacketSize = maxLen
					return nil, 0
				})
				expectAppendStreamFrames()
				_, err := packer.PackPacket()
				Expect(err).ToNot(HaveOccurred())
				// now reduce the maxPacketSize
				packer.HandleTransportParameters(&handshake.TransportParameters{
					MaxPacketSize: maxPacketSize - 10,
				})
				framer.EXPECT().AppendControlFrames(gomock.Any(), gomock.Any()).Do(func(_ []wire.Frame, maxLen protocol.ByteCount) ([]wire.Frame, protocol.ByteCount) {
					Expect(maxLen).To(Equal(initialMaxPacketSize - 10))
					return nil, 0
				})
				expectAppendStreamFrames()
				_, err = packer.PackPacket()
				Expect(err).ToNot(HaveOccurred())
			})

			It("doesn't increase the max packet size", func() {
				pnManager.EXPECT().PeekPacketNumber().Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2).Times(2)
				sealingManager.EXPECT().GetSealer().Return(protocol.Encryption1RTT, sealer).Times(2)
				ackFramer.EXPECT().GetAckFrame().Times(2)
				var initialMaxPacketSize protocol.ByteCount
				framer.EXPECT().AppendControlFrames(gomock.Any(), gomock.Any()).Do(func(_ []wire.Frame, maxLen protocol.ByteCount) ([]wire.Frame, protocol.ByteCount) {
					initialMaxPacketSize = maxLen
					return nil, 0
				})
				expectAppendStreamFrames()
				_, err := packer.PackPacket()
				Expect(err).ToNot(HaveOccurred())
				// now try to increase the maxPacketSize
				packer.HandleTransportParameters(&handshake.TransportParameters{
					MaxPacketSize: maxPacketSize + 10,
				})
				framer.EXPECT().AppendControlFrames(gomock.Any(), gomock.Any()).Do(func(_ []wire.Frame, maxLen protocol.ByteCount) ([]wire.Frame, protocol.ByteCount) {
					Expect(maxLen).To(Equal(initialMaxPacketSize))
					return nil, 0
				})
				expectAppendStreamFrames()
				_, err = packer.PackPacket()
				Expect(err).ToNot(HaveOccurred())
			})
		})
	})

	Context("packing crypto packets", func() {
		It("sets the length", func() {
			pnManager.EXPECT().PeekPacketNumber().Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2)
			pnManager.EXPECT().PopPacketNumber().Return(protocol.PacketNumber(0x42))
			f := &wire.CryptoFrame{
				Offset: 0x1337,
				Data:   []byte("foobar"),
			}
			ackFramer.EXPECT().GetAckFrame()
			initialStream.EXPECT().HasData().Return(true)
			initialStream.EXPECT().PopCryptoFrame(gomock.Any()).Return(f)
			sealingManager.EXPECT().GetSealerWithEncryptionLevel(protocol.EncryptionInitial).Return(sealer, nil)
			p, err := packer.PackPacket()
			Expect(err).ToNot(HaveOccurred())
			checkLength(p.raw)
		})

		It("packs a maximum size crypto packet", func() {
			var f *wire.CryptoFrame
			pnManager.EXPECT().PeekPacketNumber().Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2)
			pnManager.EXPECT().PopPacketNumber().Return(protocol.PacketNumber(0x42))
			sealingManager.EXPECT().GetSealerWithEncryptionLevel(protocol.EncryptionHandshake).Return(sealer, nil)
			ackFramer.EXPECT().GetAckFrame()
			initialStream.EXPECT().HasData()
			handshakeStream.EXPECT().HasData().Return(true)
			handshakeStream.EXPECT().PopCryptoFrame(gomock.Any()).DoAndReturn(func(size protocol.ByteCount) *wire.CryptoFrame {
				f = &wire.CryptoFrame{Offset: 0x1337}
				f.Data = bytes.Repeat([]byte{'f'}, int(size-f.Length(packer.version)-1))
				Expect(f.Length(packer.version)).To(Equal(size))
				return f
			})
			p, err := packer.PackPacket()
			Expect(err).ToNot(HaveOccurred())
			Expect(p.frames).To(HaveLen(1))
			expectedPacketLen := packer.maxPacketSize
			Expect(p.raw).To(HaveLen(int(expectedPacketLen)))
			Expect(p.header.IsLongHeader).To(BeTrue())
			checkLength(p.raw)
		})

		It("pads Initial packets to the required minimum packet size", func() {
			f := &wire.CryptoFrame{Data: []byte("foobar")}
			pnManager.EXPECT().PeekPacketNumber().Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2)
			pnManager.EXPECT().PopPacketNumber().Return(protocol.PacketNumber(0x42))
			sealingManager.EXPECT().GetSealerWithEncryptionLevel(protocol.EncryptionInitial).Return(sealer, nil)
			ackFramer.EXPECT().GetAckFrame()
			initialStream.EXPECT().HasData().Return(true)
			initialStream.EXPECT().PopCryptoFrame(gomock.Any()).Return(f)
			packer.hasSentPacket = false
			packer.perspective = protocol.PerspectiveClient
			packet, err := packer.PackPacket()
			Expect(err).ToNot(HaveOccurred())
			Expect(packet.header.Token).To(Equal(token))
			Expect(packet.raw).To(HaveLen(protocol.MinInitialPacketSize))
			Expect(packet.frames).To(HaveLen(1))
			cf := packet.frames[0].(*wire.CryptoFrame)
			Expect(cf.Data).To(Equal([]byte("foobar")))
		})

		It("sets the correct length for an Initial packet", func() {
			pnManager.EXPECT().PeekPacketNumber().Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2)
			pnManager.EXPECT().PopPacketNumber().Return(protocol.PacketNumber(0x42))
			sealingManager.EXPECT().GetSealerWithEncryptionLevel(protocol.EncryptionInitial).Return(sealer, nil)
			ackFramer.EXPECT().GetAckFrame()
			initialStream.EXPECT().HasData().Return(true)
			initialStream.EXPECT().PopCryptoFrame(gomock.Any()).Return(&wire.CryptoFrame{
				Data: []byte("foobar"),
			})
			packer.hasSentPacket = false
			packer.perspective = protocol.PerspectiveClient
			packet, err := packer.PackPacket()
			Expect(err).ToNot(HaveOccurred())
			checkLength(packet.raw)
		})

		It("adds an ACK frame", func() {
			f := &wire.CryptoFrame{Data: []byte("foobar")}
			ack := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 42, Largest: 1337}}}
			pnManager.EXPECT().PeekPacketNumber().Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2)
			pnManager.EXPECT().PopPacketNumber().Return(protocol.PacketNumber(0x42))
			sealingManager.EXPECT().GetSealerWithEncryptionLevel(protocol.EncryptionInitial).Return(sealer, nil)
			ackFramer.EXPECT().GetAckFrame().Return(ack)
			initialStream.EXPECT().HasData().Return(true)
			initialStream.EXPECT().PopCryptoFrame(gomock.Any()).Return(f)
			packer.version = protocol.VersionTLS
			packer.hasSentPacket = false
			packer.perspective = protocol.PerspectiveClient
			packet, err := packer.PackPacket()
			Expect(err).ToNot(HaveOccurred())
			Expect(packet.header.Token).To(Equal(token))
			Expect(packet.raw).To(HaveLen(protocol.MinInitialPacketSize))
			Expect(packet.frames).To(HaveLen(2))
			Expect(packet.frames[0]).To(Equal(ack))
		})

		Context("retransmitions", func() {
			sf := &wire.StreamFrame{Data: []byte("foobar")}

			It("packs a retransmission with the right encryption level", func() {
				pnManager.EXPECT().PeekPacketNumber().Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2)
				pnManager.EXPECT().PopPacketNumber().Return(protocol.PacketNumber(0x42))
				sealingManager.EXPECT().GetSealerWithEncryptionLevel(protocol.EncryptionInitial).Return(sealer, nil)
				packet := &ackhandler.Packet{
					PacketType:      protocol.PacketTypeHandshake,
					EncryptionLevel: protocol.EncryptionInitial,
					Frames:          []wire.Frame{sf},
				}
				p, err := packer.PackRetransmission(packet)
				Expect(err).ToNot(HaveOccurred())
				Expect(p).To(HaveLen(1))
				Expect(p[0].header.Type).To(Equal(protocol.PacketTypeHandshake))
				Expect(p[0].frames).To(Equal([]wire.Frame{sf}))
				Expect(p[0].encryptionLevel).To(Equal(protocol.EncryptionInitial))
			})

			// this should never happen, since non forward-secure packets are limited to a size smaller than MaxPacketSize, such that it is always possible to retransmit them without splitting the StreamFrame
			It("refuses to send a packet larger than MaxPacketSize", func() {
				pnManager.EXPECT().PeekPacketNumber().Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2)
				sealingManager.EXPECT().GetSealerWithEncryptionLevel(gomock.Any()).Return(sealer, nil)
				packet := &ackhandler.Packet{
					EncryptionLevel: protocol.EncryptionHandshake,
					Frames: []wire.Frame{
						&wire.StreamFrame{
							StreamID: 1,
							Data:     bytes.Repeat([]byte{'f'}, int(maxPacketSize)),
						},
					},
				}
				_, err := packer.PackRetransmission(packet)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("PacketPacker BUG: packet too large"))
			})

			It("packs a retransmission for an Initial packet", func() {
				pnManager.EXPECT().PeekPacketNumber().Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2)
				pnManager.EXPECT().PopPacketNumber().Return(protocol.PacketNumber(0x42))
				sealingManager.EXPECT().GetSealerWithEncryptionLevel(protocol.EncryptionInitial).Return(sealer, nil)
				packer.perspective = protocol.PerspectiveClient
				packet := &ackhandler.Packet{
					PacketType:      protocol.PacketTypeInitial,
					EncryptionLevel: protocol.EncryptionInitial,
					Frames:          []wire.Frame{sf},
				}
				p, err := packer.PackRetransmission(packet)
				Expect(err).ToNot(HaveOccurred())
				Expect(p).To(HaveLen(1))
				Expect(p[0].frames).To(Equal([]wire.Frame{sf}))
				Expect(p[0].encryptionLevel).To(Equal(protocol.EncryptionInitial))
				Expect(p[0].header.Type).To(Equal(protocol.PacketTypeInitial))
				Expect(p[0].header.Token).To(Equal(token))
			})
		})
	})
})
