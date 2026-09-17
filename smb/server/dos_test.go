package server

import (
	"encoding/binary"
	"testing"

	"github.com/sonroyaalmerol/go-smb-server/smb/transport"
	"github.com/sonroyaalmerol/go-smb-server/smb/wire"
)

func TestDoS_ReadLengthExceedsMax(t *testing.T) {
	client, srvConn := newPipeConns()
	defer client.Close()

	backend := newMemBackend()
	srv := newTestServer(backend)
	srv.maxRead = 1024 // 1 KB max read

	cancel := serveOn(srv, srvConn)
	defer cancel()

	fc := transport.NewFramedConn(client)

	// 1. Negotiate
	negBody := make([]byte, 38)
	binary.LittleEndian.PutUint16(negBody[0:2], 36)
	binary.LittleEndian.PutUint16(negBody[2:4], 1)
	binary.LittleEndian.PutUint16(negBody[36:38], wire.DialectSMB302)
	hdr := wire.NewHeader(wire.CmdNegotiate)
	hdr.MessageId = 0
	hdr.Credit = 1
	mustWrite(t, fc, append(hdr.Append(nil), negBody...))
	_, _ = readReply(t, fc)

	// 2. SessionSetup
	mustWrite(t, fc, buildSessionSetup([]byte{0x60, 0x04, 0xbe, 0xef}))
	rh, _ := readReply(t, fc)
	sessID := rh.SessionId

	// 3. TreeConnect
	mustWrite(t, fc, buildTreeConnect(sessID, `\\server\share`))
	rh, _ = readReply(t, fc)
	treeID := rh.TreeId

	// 4. Create file
	mustWrite(t, fc, buildCreate(sessID, treeID, "small.txt", wire.FileCreate))
	rh, resp := readReply(t, fc)
	if rh.Status != wire.StatusSuccess {
		t.Fatalf("create failed: %x", rh.Status)
	}
	var fid [16]byte
	copy(fid[:], resp[64+64:64+80])

	// 5. Read with length 1MB (exceeding srv.maxRead of 1024)
	readHdr := wire.NewHeader(wire.CmdRead)
	readHdr.SessionId = sessID
	readHdr.TreeId = treeID
	readHdr.MessageId = 4
	readHdr.Credit = 1
	readBody := make([]byte, 49)
	binary.LittleEndian.PutUint16(readBody[0:2], 49)
	binary.LittleEndian.PutUint32(readBody[4:8], 1<<20) // 1MB > 1KB
	binary.LittleEndian.PutUint64(readBody[8:16], 0)
	copy(readBody[16:32], fid[:])
	mustWrite(t, fc, append(readHdr.Append(nil), readBody...))

	readReplyHdr, _ := readReply(t, fc)
	if readReplyHdr.Status != wire.StatusInvalidParameter {
		t.Fatalf("expected STATUS_INVALID_PARAMETER (0x%08x) on oversized read, got 0x%08x",
			wire.StatusInvalidParameter, readReplyHdr.Status)
	}

	// 6. Write with payload exceeding srv.maxWrite (1024)
	srv.maxWrite = 1024
	writeHdr := wire.NewHeader(wire.CmdWrite)
	writeHdr.SessionId = sessID
	writeHdr.TreeId = treeID
	writeHdr.MessageId = 5
	writeHdr.Credit = 1
	oversizedData := make([]byte, 2048)
	writeBody := make([]byte, 48+len(oversizedData))
	binary.LittleEndian.PutUint16(writeBody[0:2], 49)
	binary.LittleEndian.PutUint16(writeBody[2:4], uint16(wire.HeaderSize+48))
	binary.LittleEndian.PutUint32(writeBody[4:8], uint32(len(oversizedData)))
	copy(writeBody[48:], oversizedData)
	mustWrite(t, fc, append(writeHdr.Append(nil), writeBody...))

	writeReplyHdr, _ := readReply(t, fc)
	if writeReplyHdr.Status != wire.StatusInvalidParameter {
		t.Fatalf("expected STATUS_INVALID_PARAMETER on oversized write, got 0x%08x", writeReplyHdr.Status)
	}

	// 7. Negative offset read
	readHdr.MessageId = 6
	binary.LittleEndian.PutUint32(readBody[4:8], 100)
	binary.LittleEndian.PutUint64(readBody[8:16], 0x8000000000000000) // negative int64
	mustWrite(t, fc, append(readHdr.Append(nil), readBody...))
	negOffsetReplyHdr, _ := readReply(t, fc)
	if negOffsetReplyHdr.Status != wire.StatusInvalidParameter {
		t.Fatalf("expected STATUS_INVALID_PARAMETER on negative offset read, got 0x%08x", negOffsetReplyHdr.Status)
	}
}
