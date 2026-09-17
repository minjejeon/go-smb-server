package server

import (
	"encoding/binary"
	"testing"

	"github.com/sonroyaalmerol/go-smb-server/smb/auth"
	"github.com/sonroyaalmerol/go-smb-server/smb/transport"
	"github.com/sonroyaalmerol/go-smb-server/smb/vfs"
	"github.com/sonroyaalmerol/go-smb-server/smb/wire"
)

func TestReadOnlyShare_RejectsMutations(t *testing.T) {
	client, srvConn := newPipeConns()
	defer client.Close()

	backend := newMemBackend()
	roShare := vfs.NewReadOnlyDiskShare("roshare", backend)
	srv := &Server{
		shareByName: map[string]vfs.Share{"roshare": roShare},
		shares:      []vfs.Share{roShare},
		authFactory: auth.AlwaysAllowFactory(),
		dialect:     wire.DialectSMB302,
		maxTransact: 65536,
		maxRead:     1 << 20,
		maxWrite:    1 << 20,
		log:         discardLogger(),
	}

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
	msg := hdr.Append(nil)
	msg = append(msg, negBody...)
	mustWrite(t, fc, msg)
	_, _ = readReply(t, fc)

	// 2. SessionSetup
	mustWrite(t, fc, buildSessionSetup([]byte{0x60, 0x04, 0xbe, 0xef}))
	rh, _ := readReply(t, fc)
	sessID := rh.SessionId

	// 3. TreeConnect to roshare
	mustWrite(t, fc, buildTreeConnect(sessID, `\\server\roshare`))
	rh, resp := readReply(t, fc)
	if rh.Status != wire.StatusSuccess {
		t.Fatalf("tree connect status = 0x%08x", rh.Status)
	}
	treeID := rh.TreeId

	// MaximalAccess in TreeConnect response is at offset 64+8 (4 bytes)
	maximalAccess := binary.LittleEndian.Uint32(resp[64+8 : 64+12])
	if maximalAccess == 0x001f01ff {
		t.Errorf("expected read-only MaximalAccess, got full access: 0x%08x", maximalAccess)
	}

	// 4. Create (FileCreate disposition) on read-only share must fail with STATUS_ACCESS_DENIED
	mustWrite(t, fc, buildCreate(sessID, treeID, "newfile.txt", wire.FileCreate))
	createReplyHdr, _ := readReply(t, fc)
	if createReplyHdr.Status != wire.StatusAccessDenied {
		t.Fatalf("expected STATUS_ACCESS_DENIED (0x%08x) on read-only share create, got 0x%08x",
			wire.StatusAccessDenied, createReplyHdr.Status)
	}
}
