package quic

import (
	"bytes"
	"errors"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/internal/wire"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Packet Handler Map", func() {
	var (
		handler *packetHandlerMap
		conn    *mockPacketConn
	)

	getPacket := func(connID protocol.ConnectionID) []byte {
		buf := &bytes.Buffer{}
		err := (&wire.ExtendedHeader{
			IsLongHeader:     true,
			Type:             protocol.PacketTypeHandshake,
			DestConnectionID: connID,
			PacketNumberLen:  protocol.PacketNumberLen1,
			Length:           1,
			Version:          protocol.VersionWhatever,
		}).Write(buf, protocol.PerspectiveServer, protocol.VersionWhatever)
		Expect(err).ToNot(HaveOccurred())
		return buf.Bytes()
	}

	BeforeEach(func() {
		conn = newMockPacketConn()
		handler = newPacketHandlerMap(conn, 5, utils.DefaultLogger).(*packetHandlerMap)
	})

	It("closes", func() {
		testErr := errors.New("test error	")
		sess1 := NewMockPacketHandler(mockCtrl)
		sess1.EXPECT().destroy(testErr)
		sess2 := NewMockPacketHandler(mockCtrl)
		sess2.EXPECT().destroy(testErr)
		handler.Add(protocol.ConnectionID{1, 1, 1, 1}, sess1)
		handler.Add(protocol.ConnectionID{2, 2, 2, 2}, sess2)
		handler.close(testErr)
	})

	Context("handling packets", func() {
		It("handles packets for different packet handlers on the same packet conn", func() {
			connID1 := protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8}
			connID2 := protocol.ConnectionID{8, 7, 6, 5, 4, 3, 2, 1}
			packetHandler1 := NewMockPacketHandler(mockCtrl)
			packetHandler2 := NewMockPacketHandler(mockCtrl)
			handledPacket1 := make(chan struct{})
			handledPacket2 := make(chan struct{})
			packetHandler1.EXPECT().handlePacket(gomock.Any()).Do(func(p *receivedPacket) {
				Expect(p.header.DestConnectionID).To(Equal(connID1))
				close(handledPacket1)
			})
			packetHandler1.EXPECT().GetVersion()
			packetHandler1.EXPECT().GetPerspective().Return(protocol.PerspectiveClient)
			packetHandler2.EXPECT().handlePacket(gomock.Any()).Do(func(p *receivedPacket) {
				Expect(p.header.DestConnectionID).To(Equal(connID2))
				close(handledPacket2)
			})
			packetHandler2.EXPECT().GetVersion()
			packetHandler2.EXPECT().GetPerspective().Return(protocol.PerspectiveClient)
			handler.Add(connID1, packetHandler1)
			handler.Add(connID2, packetHandler2)

			conn.dataToRead <- getPacket(connID1)
			conn.dataToRead <- getPacket(connID2)
			Eventually(handledPacket1).Should(BeClosed())
			Eventually(handledPacket2).Should(BeClosed())

			// makes the listen go routine return
			packetHandler1.EXPECT().destroy(gomock.Any()).AnyTimes()
			packetHandler2.EXPECT().destroy(gomock.Any()).AnyTimes()
			close(conn.dataToRead)
		})

		It("drops unparseable packets", func() {
			err := handler.handlePacket(nil, []byte{0, 1, 2, 3})
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("error parsing invariant header:"))
		})

		It("deletes removed session immediately", func() {
			handler.deleteRetiredSessionsAfter = time.Hour
			connID := protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8}
			handler.Add(connID, NewMockPacketHandler(mockCtrl))
			handler.Remove(connID)
			Expect(handler.handlePacket(nil, getPacket(connID))).To(MatchError("received a packet with an unexpected connection ID 0x0102030405060708"))
		})

		It("deletes retired session entries after a wait time", func() {
			handler.deleteRetiredSessionsAfter = scaleDuration(10 * time.Millisecond)
			connID := protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8}
			handler.Add(connID, NewMockPacketHandler(mockCtrl))
			handler.Retire(connID)
			time.Sleep(scaleDuration(30 * time.Millisecond))
			Expect(handler.handlePacket(nil, getPacket(connID))).To(MatchError("received a packet with an unexpected connection ID 0x0102030405060708"))
		})

		It("passes packets arriving late for closed sessions to that session", func() {
			handler.deleteRetiredSessionsAfter = time.Hour
			connID := protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8}
			packetHandler := NewMockPacketHandler(mockCtrl)
			packetHandler.EXPECT().GetVersion().Return(protocol.VersionWhatever)
			packetHandler.EXPECT().GetPerspective().Return(protocol.PerspectiveClient)
			packetHandler.EXPECT().handlePacket(gomock.Any())
			handler.Add(connID, packetHandler)
			handler.Retire(connID)
			err := handler.handlePacket(nil, getPacket(connID))
			Expect(err).ToNot(HaveOccurred())
		})

		It("drops packets for unknown receivers", func() {
			connID := protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8}
			err := handler.handlePacket(nil, getPacket(connID))
			Expect(err).To(MatchError("received a packet with an unexpected connection ID 0x0102030405060708"))
		})

		It("errors on packets that are smaller than the length in the packet header", func() {
			connID := protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8}
			packetHandler := NewMockPacketHandler(mockCtrl)
			packetHandler.EXPECT().GetVersion().Return(protocol.VersionWhatever)
			packetHandler.EXPECT().GetPerspective().Return(protocol.PerspectiveClient)
			handler.Add(connID, packetHandler)
			hdr := &wire.ExtendedHeader{
				IsLongHeader:     true,
				Type:             protocol.PacketTypeHandshake,
				Length:           1000,
				DestConnectionID: connID,
				PacketNumberLen:  protocol.PacketNumberLen2,
				Version:          protocol.VersionWhatever,
			}
			buf := &bytes.Buffer{}
			Expect(hdr.Write(buf, protocol.PerspectiveServer, protocol.VersionWhatever)).To(Succeed())
			buf.Write(bytes.Repeat([]byte{0}, 500-2 /* for packet number length */))

			err := handler.handlePacket(nil, buf.Bytes())
			Expect(err).To(MatchError("packet length (500 bytes) is smaller than the expected length (1000 bytes)"))
		})

		It("errors when receiving a packet that has a length smaller than the packet number length", func() {
			connID := protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8}
			packetHandler := NewMockPacketHandler(mockCtrl)
			packetHandler.EXPECT().GetVersion().Return(protocol.VersionWhatever)
			packetHandler.EXPECT().GetPerspective().Return(protocol.PerspectiveClient)
			handler.Add(connID, packetHandler)
			hdr := &wire.Header{
				IsLongHeader:     true,
				Type:             protocol.PacketTypeHandshake,
				Length:           3,
				DestConnectionID: connID,
				PacketNumberLen:  protocol.PacketNumberLen4,
				Version:          protocol.VersionWhatever,
			}
			buf := &bytes.Buffer{}
			Expect(hdr.Write(buf, protocol.PerspectiveServer, protocol.VersionWhatever)).To(Succeed())
			Expect(handler.handlePacket(nil, buf.Bytes())).To(MatchError("packet length (3 bytes) shorter than packet number (4 bytes)"))
		})

		It("cuts packets to the right length", func() {
			connID := protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8}
			packetHandler := NewMockPacketHandler(mockCtrl)
			packetHandler.EXPECT().GetVersion().Return(protocol.VersionWhatever)
			packetHandler.EXPECT().GetPerspective().Return(protocol.PerspectiveClient)
			handler.Add(connID, packetHandler)
			packetHandler.EXPECT().handlePacket(gomock.Any()).Do(func(p *receivedPacket) {
				Expect(p.data).To(HaveLen(456 - int(p.header.PacketNumberLen)))
			})

			hdr := &wire.ExtendedHeader{
				IsLongHeader:     true,
				Type:             protocol.PacketTypeHandshake,
				Length:           456,
				DestConnectionID: connID,
				PacketNumberLen:  protocol.PacketNumberLen1,
				Version:          protocol.VersionWhatever,
			}
			buf := &bytes.Buffer{}
			Expect(hdr.Write(buf, protocol.PerspectiveServer, protocol.VersionWhatever)).To(Succeed())
			buf.Write(bytes.Repeat([]byte{0}, 500))
			Expect(handler.handlePacket(nil, buf.Bytes())).To(Succeed())
		})

		It("closes the packet handlers when reading from the conn fails", func() {
			done := make(chan struct{})
			packetHandler := NewMockPacketHandler(mockCtrl)
			packetHandler.EXPECT().destroy(gomock.Any()).Do(func(e error) {
				Expect(e).To(HaveOccurred())
				close(done)
			})
			handler.Add(protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8}, packetHandler)
			conn.Close()
			Eventually(done).Should(BeClosed())
		})
	})

	Context("stateless reset handling", func() {
		It("handles packets for connections added with a reset token", func() {
			packetHandler := NewMockPacketHandler(mockCtrl)
			connID := protocol.ConnectionID{0xde, 0xca, 0xfb, 0xad}
			token := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
			handler.AddWithResetToken(connID, packetHandler, token)
			// first send a normal packet
			handledPacket := make(chan struct{})
			packetHandler.EXPECT().GetPerspective()
			packetHandler.EXPECT().GetVersion()
			packetHandler.EXPECT().handlePacket(gomock.Any()).Do(func(p *receivedPacket) {
				Expect(p.header.DestConnectionID).To(Equal(connID))
				close(handledPacket)
			})
			conn.dataToRead <- getPacket(connID)
			Eventually(handledPacket).Should(BeClosed())
		})

		It("handles stateless resets", func() {
			packetHandler := NewMockPacketHandler(mockCtrl)
			connID := protocol.ConnectionID{0xde, 0xca, 0xfb, 0xad}
			token := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
			handler.AddWithResetToken(connID, packetHandler, token)
			packet := append([]byte{0x40} /* short header packet */, make([]byte, 50)...)
			packet = append(packet, token[:]...)
			destroyed := make(chan struct{})
			packetHandler.EXPECT().destroy(errors.New("received a stateless reset")).Do(func(error) {
				close(destroyed)
			})
			conn.dataToRead <- packet
			Eventually(destroyed).Should(BeClosed())
		})

		It("deletes reset tokens when the session is retired", func() {
			handler.deleteRetiredSessionsAfter = scaleDuration(10 * time.Millisecond)
			connID := protocol.ConnectionID{0xde, 0xad, 0xbe, 0xef, 0x42}
			token := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
			handler.AddWithResetToken(connID, NewMockPacketHandler(mockCtrl), token)
			handler.Retire(connID)
			time.Sleep(scaleDuration(30 * time.Millisecond))
			Expect(handler.handlePacket(nil, getPacket(connID))).To(MatchError("received a packet with an unexpected connection ID 0xdeadbeef42"))
			packet := append([]byte{0x40, 0xde, 0xca, 0xfb, 0xad, 0x99} /* short header packet */, make([]byte, 50)...)
			packet = append(packet, token[:]...)
			Expect(handler.handlePacket(nil, packet)).To(MatchError("received a short header packet with an unexpected connection ID 0xdecafbad99"))
			Expect(handler.resetTokens).To(BeEmpty())
		})
	})

	Context("running a server", func() {
		It("adds a server", func() {
			connID := protocol.ConnectionID{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
			p := getPacket(connID)
			server := NewMockUnknownPacketHandler(mockCtrl)
			server.EXPECT().handlePacket(gomock.Any()).Do(func(p *receivedPacket) {
				Expect(p.header.DestConnectionID).To(Equal(connID))
			})
			handler.SetServer(server)
			Expect(handler.handlePacket(nil, p)).To(Succeed())
		})

		It("closes all server sessions", func() {
			clientSess := NewMockPacketHandler(mockCtrl)
			clientSess.EXPECT().GetPerspective().Return(protocol.PerspectiveClient)
			serverSess := NewMockPacketHandler(mockCtrl)
			serverSess.EXPECT().GetPerspective().Return(protocol.PerspectiveServer)
			serverSess.EXPECT().Close()

			handler.Add(protocol.ConnectionID{1, 1, 1, 1}, clientSess)
			handler.Add(protocol.ConnectionID{2, 2, 2, 2}, serverSess)
			handler.CloseServer()
		})

		It("stops handling packets with unknown connection IDs after the server is closed", func() {
			connID := protocol.ConnectionID{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
			p := getPacket(connID)
			server := NewMockUnknownPacketHandler(mockCtrl)
			handler.SetServer(server)
			handler.CloseServer()
			Expect(handler.handlePacket(nil, p)).To(MatchError("received a packet with an unexpected connection ID 0x1122334455667788"))
		})
	})
})
