package server

import (
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/sonroyaalmerol/go-smb-server/smb/transport"
	"github.com/sonroyaalmerol/go-smb-server/smb/vfs"
	"github.com/sonroyaalmerol/go-smb-server/smb/wire"
)

func TestDirectoryPagination_MultipleBuffers(t *testing.T) {
	client, srvConn := newPipeConns()
	defer client.Close()

	backend := newMemBackend()
	// Create 20 files in root directory
	for i := range 20 {
		name := fmt.Sprintf("file_%02d.txt", i)
		h, err := backend.Open(nil, vfs.OpenOptions{Path: name, Disposition: vfs.DispositionCreate})
		if err != nil {
			t.Fatal(err)
		}
		_ = h.Close(nil)
	}

	srv := newTestServer(backend)
	cancel := serveOn(srv, srvConn)
	defer cancel()

	fc := transport.NewFramedConn(client)

	// 1. Negotiate
	negBody := make([]byte, 38)
	binary.LittleEndian.PutUint16(negBody[0:2], 36)
	binary.LittleEndian.PutUint16(negBody[2:4], 1)
	binary.LittleEndian.PutUint16(negBody[36:38], wire.DialectSMB302)
	hdr := wire.NewHeader(wire.CmdNegotiate)
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

	// 4. Open root directory
	mustWrite(t, fc, buildCreate(sessID, treeID, "", wire.FileOpen))
	rh, resp := readReply(t, fc)
	if rh.Status != wire.StatusSuccess {
		t.Fatalf("open root dir failed: %x", rh.Status)
	}
	var dirFid [16]byte
	copy(dirFid[:], resp[64+64:64+80])

	// 5. QueryDirectory with small buffer (e.g. 250 bytes) repeatedly until StatusNoMoreFiles
	totalFilesFound := 0
	msgID := uint64(5)
	for {
		qHdr := wire.NewHeader(wire.CmdQueryDirectory)
		qHdr.SessionId = sessID
		qHdr.TreeId = treeID
		qHdr.MessageId = msgID
		msgID++
		qHdr.Credit = 1

		qBody := make([]byte, 32+2) // 32 fixed + 2 bytes for pattern "*"
		binary.LittleEndian.PutUint16(qBody[0:2], 33)
		qBody[2] = wire.FileDirectoryInformation
		qBody[3] = 0 // Flags
		binary.LittleEndian.PutUint32(qBody[4:8], 0)
		copy(qBody[8:24], dirFid[:])
		binary.LittleEndian.PutUint16(qBody[24:26], uint16(wire.HeaderSize+32))
		binary.LittleEndian.PutUint16(qBody[26:28], 2) // len("*") in utf16 = 2
		binary.LittleEndian.PutUint32(qBody[28:32], 250) // Small 250 byte output buffer
		copy(qBody[32:], wire.UTF16ToBytes("*"))

		mustWrite(t, fc, append(qHdr.Append(nil), qBody...))
		qReplyHdr, qReplyMsg := readReply(t, fc)
		if qReplyHdr.Status == wire.StatusNoMoreFiles {
			break
		}
		if qReplyHdr.Status != wire.StatusSuccess {
			t.Fatalf("query_directory returned unexpected status: 0x%08x", qReplyHdr.Status)
		}

		// Count entries in this buffer
		outLen := binary.LittleEndian.Uint32(qReplyMsg[64+4 : 64+8])
		if outLen > 0 {
			buf := qReplyMsg[64+8 : 64+8+outLen]
			off := 0
			for off < len(buf) {
				totalFilesFound++
				nextOff := binary.LittleEndian.Uint32(buf[off : off+4])
				if nextOff == 0 {
					break
				}
				off += int(nextOff)
			}
		}
	}

	if totalFilesFound != 20 {
		t.Fatalf("expected 20 files across pages, but found %d", totalFilesFound)
	}
}
