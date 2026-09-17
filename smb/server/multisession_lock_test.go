package server

import (
	"encoding/binary"
	"testing"

	"github.com/sonroyaalmerol/go-smb-server/smb/transport"
	"github.com/sonroyaalmerol/go-smb-server/smb/wire"
)

func TestMultiSessionLockConflict(t *testing.T) {
	backend := newMemBackend()
	srv := newTestServer(backend)

	// Client 1 connection
	client1, srvConn1 := newPipeConns()
	defer client1.Close()
	cancel1 := serveOn(srv, srvConn1)
	defer cancel1()
	fc1 := transport.NewFramedConn(client1)

	// Client 2 connection
	client2, srvConn2 := newPipeConns()
	defer client2.Close()
	cancel2 := serveOn(srv, srvConn2)
	defer cancel2()
	fc2 := transport.NewFramedConn(client2)

	// Setup Client 1: Negotiate, SessionSetup, TreeConnect, Create "shared.txt"
	negBody := make([]byte, 38)
	binary.LittleEndian.PutUint16(negBody[0:2], 36)
	binary.LittleEndian.PutUint16(negBody[2:4], 1)
	binary.LittleEndian.PutUint16(negBody[36:38], wire.DialectSMB302)
	hdr1 := wire.NewHeader(wire.CmdNegotiate)
	mustWrite(t, fc1, append(hdr1.Append(nil), negBody...))
	_, _ = readReply(t, fc1)

	mustWrite(t, fc1, buildSessionSetup([]byte{0x60, 0x04, 0xbe, 0xef}))
	rh1, _ := readReply(t, fc1)
	sessID1 := rh1.SessionId

	mustWrite(t, fc1, buildTreeConnect(sessID1, `\\server\share`))
	rh1, _ = readReply(t, fc1)
	treeID1 := rh1.TreeId

	mustWrite(t, fc1, buildCreate(sessID1, treeID1, "shared.txt", wire.FileCreate))
	rh1, resp1 := readReply(t, fc1)
	if rh1.Status != wire.StatusSuccess {
		t.Fatalf("client 1 create failed: 0x%08x", rh1.Status)
	}
	var fid1 [16]byte
	copy(fid1[:], resp1[64+64:64+80])

	// Setup Client 2: Negotiate, SessionSetup, TreeConnect, Open "shared.txt"
	hdr2 := wire.NewHeader(wire.CmdNegotiate)
	mustWrite(t, fc2, append(hdr2.Append(nil), negBody...))
	_, _ = readReply(t, fc2)

	mustWrite(t, fc2, buildSessionSetup([]byte{0x60, 0x04, 0xbe, 0xef}))
	rh2, _ := readReply(t, fc2)
	sessID2 := rh2.SessionId

	mustWrite(t, fc2, buildTreeConnect(sessID2, `\\server\share`))
	rh2, _ = readReply(t, fc2)
	treeID2 := rh2.TreeId

	mustWrite(t, fc2, buildCreate(sessID2, treeID2, "shared.txt", wire.FileOpen))
	rh2, resp2 := readReply(t, fc2)
	if rh2.Status != wire.StatusSuccess {
		t.Fatalf("client 2 open failed: 0x%08x", rh2.Status)
	}
	var fid2 [16]byte
	copy(fid2[:], resp2[64+64:64+80])

	// Client 1 acquires Exclusive Lock on range [0, 100]
	lockHdr1 := wire.NewHeader(wire.CmdLock)
	lockHdr1.SessionId = sessID1
	lockHdr1.TreeId = treeID1
	lockHdr1.MessageId = 4
	lockHdr1.Credit = 1
	lockBody1 := buildLockRequest(fid1, 0, 100, wire.LockFlagExclusiveLock|wire.LockFlagFailImmediately)
	mustWrite(t, fc1, append(lockHdr1.Append(nil), lockBody1...))
	lrh1, _ := readReply(t, fc1)
	if lrh1.Status != wire.StatusSuccess {
		t.Fatalf("client 1 acquire lock failed: 0x%08x", lrh1.Status)
	}

	// Client 2 attempts to acquire Exclusive Lock on overlapping range [50, 150]
	lockHdr2 := wire.NewHeader(wire.CmdLock)
	lockHdr2.SessionId = sessID2
	lockHdr2.TreeId = treeID2
	lockHdr2.MessageId = 4
	lockHdr2.Credit = 1
	lockBody2 := buildLockRequest(fid2, 50, 100, wire.LockFlagExclusiveLock|wire.LockFlagFailImmediately)
	mustWrite(t, fc2, append(lockHdr2.Append(nil), lockBody2...))
	lrh2, _ := readReply(t, fc2)
	if lrh2.Status != wire.StatusLockConflict {
		t.Fatalf("expected STATUS_LOCK_CONFLICT (0x%08x) for client 2, got 0x%08x",
			wire.StatusLockConflict, lrh2.Status)
	}

	// Client 2 attempts to write to range [10, 20] covered by client 1's lock -> should fail
	mustWrite(t, fc2, buildWrite(sessID2, treeID2, fid2, 10, []byte("fail")))
	wrh2, _ := readReply(t, fc2)
	if wrh2.Status != wire.StatusLockConflict {
		t.Fatalf("expected STATUS_LOCK_CONFLICT (0x%08x) for client 2 write, got 0x%08x",
			wire.StatusLockConflict, wrh2.Status)
	}

	// Client 1 unlocks range [0, 100]
	unlockHdr1 := wire.NewHeader(wire.CmdLock)
	unlockHdr1.SessionId = sessID1
	unlockHdr1.TreeId = treeID1
	unlockHdr1.MessageId = 5
	unlockHdr1.Credit = 1
	unlockBody1 := buildLockRequest(fid1, 0, 100, wire.LockFlagUnlock)
	mustWrite(t, fc1, append(unlockHdr1.Append(nil), unlockBody1...))
	urh1, _ := readReply(t, fc1)
	if urh1.Status != wire.StatusSuccess {
		t.Fatalf("client 1 unlock failed: 0x%08x", urh1.Status)
	}

	// Client 2 now attempts to acquire Exclusive Lock on range [50, 150] -> should succeed
	lockHdr2.MessageId = 6
	mustWrite(t, fc2, append(lockHdr2.Append(nil), lockBody2...))
	lrh2, _ = readReply(t, fc2)
	if lrh2.Status != wire.StatusSuccess {
		t.Fatalf("expected STATUS_SUCCESS (0x%08x) for client 2 lock after unlock, got 0x%08x",
			wire.StatusSuccess, lrh2.Status)
	}
}

func buildLockRequest(fid [16]byte, offset, length uint64, flags uint32) []byte {
	b := make([]byte, 48+24)
	binary.LittleEndian.PutUint16(b[0:2], 48)
	binary.LittleEndian.PutUint16(b[2:4], 1)
	copy(b[8:24], fid[:])
	binary.LittleEndian.PutUint64(b[48:56], offset)
	binary.LittleEndian.PutUint64(b[56:64], length)
	binary.LittleEndian.PutUint32(b[64:68], flags)
	return b
}

func TestMultiSessionOplockBreak(t *testing.T) {
	backend := newMemBackend()
	srv := newTestServer(backend)

	// Client 1 connection
	client1, srvConn1 := newPipeConns()
	defer client1.Close()
	cancel1 := serveOn(srv, srvConn1)
	defer cancel1()
	fc1 := transport.NewFramedConn(client1)

	// Client 2 connection
	client2, srvConn2 := newPipeConns()
	defer client2.Close()
	cancel2 := serveOn(srv, srvConn2)
	defer cancel2()
	fc2 := transport.NewFramedConn(client2)

	// Negotiate & SessionSetup & TreeConnect for Client 1
	negBody := make([]byte, 38)
	binary.LittleEndian.PutUint16(negBody[0:2], 36)
	binary.LittleEndian.PutUint16(negBody[2:4], 1)
	binary.LittleEndian.PutUint16(negBody[36:38], wire.DialectSMB302)
	hdr1 := wire.NewHeader(wire.CmdNegotiate)
	mustWrite(t, fc1, append(hdr1.Append(nil), negBody...))
	_, _ = readReply(t, fc1)

	mustWrite(t, fc1, buildSessionSetup([]byte{0x60, 0x04, 0xbe, 0xef}))
	rh1, _ := readReply(t, fc1)
	sessID1 := rh1.SessionId

	mustWrite(t, fc1, buildTreeConnect(sessID1, `\\server\share`))
	rh1, _ = readReply(t, fc1)
	treeID1 := rh1.TreeId

	// Client 1 opens "oplock.txt" requesting oplock level 1
	mustWrite(t, fc1, buildCreateWithOplock(sessID1, treeID1, "oplock.txt", wire.FileCreate, 1))
	rh1, resp1 := readReply(t, fc1)
	if rh1.Status != wire.StatusSuccess {
		t.Fatalf("client 1 create failed: 0x%08x", rh1.Status)
	}
	if resp1[64+2] != 1 {
		t.Fatalf("client 1 expected oplock level 1, got %d", resp1[64+2])
	}

	// Negotiate & SessionSetup & TreeConnect for Client 2
	hdr2 := wire.NewHeader(wire.CmdNegotiate)
	mustWrite(t, fc2, append(hdr2.Append(nil), negBody...))
	_, _ = readReply(t, fc2)

	mustWrite(t, fc2, buildSessionSetup([]byte{0x60, 0x04, 0xbe, 0xef}))
	rh2, _ := readReply(t, fc2)
	sessID2 := rh2.SessionId

	mustWrite(t, fc2, buildTreeConnect(sessID2, `\\server\share`))
	rh2, _ = readReply(t, fc2)
	treeID2 := rh2.TreeId

	// Client 2 opens "oplock.txt" requesting oplock level 1 -> should trigger break on client 1
	mustWrite(t, fc2, buildCreateWithOplock(sessID2, treeID2, "oplock.txt", wire.FileOpen, 1))
	rh2, resp2 := readReply(t, fc2)
	if rh2.Status != wire.StatusSuccess {
		t.Fatalf("client 2 open failed: 0x%08x", rh2.Status)
	}
	if resp2[64+2] != 0 {
		t.Fatalf("client 2 expected oplock level 0, got %d", resp2[64+2])
	}

	// Client 1 should receive OplockBreak notification
	breakHdr, _ := readReply(t, fc1)
	if breakHdr.Command != wire.CmdOplockBreak {
		t.Fatalf("expected CmdOplockBreak (0x%04x) on client 1, got 0x%04x", wire.CmdOplockBreak, breakHdr.Command)
	}
}

func buildCreateWithOplock(sessID uint64, treeID uint32, name string, disposition uint32, oplockLevel uint8) []byte {
	b := buildCreate(sessID, treeID, name, disposition)
	b[wire.HeaderSize+3] = oplockLevel
	return b
}
