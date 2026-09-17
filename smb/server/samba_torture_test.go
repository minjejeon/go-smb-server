package server

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"

	"github.com/sonroyaalmerol/go-smb-server/smb/transport"
	"github.com/sonroyaalmerol/go-smb-server/smb/wire"
)

// TestSamba_Lock_OrphanedCleanupOnDisconnect reproduces Samba's smb2.lock test
// verifying that when a client abruptly closes its TCP connection while holding
// byte-range locks, the server automatically recovers and releases all orphaned locks
// so other clients can access the locked byte ranges immediately.
func TestSamba_Lock_OrphanedCleanupOnDisconnect(t *testing.T) {
	backend := newMemBackend()
	srv := newTestServer(backend)

	// Client 1 connects
	client1, srvConn1 := newPipeConns()
	cancel1 := serveOn(srv, srvConn1)
	defer cancel1()
	fc1 := transport.NewFramedConn(client1)

	// Client 1: Negotiate, SessionSetup, TreeConnect, Create "orphan.txt"
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

	mustWrite(t, fc1, buildCreate(sessID1, treeID1, "orphan.txt", wire.FileCreate))
	rh1, resp1 := readReply(t, fc1)
	if rh1.Status != wire.StatusSuccess {
		t.Fatalf("client 1 create failed: 0x%08x", rh1.Status)
	}
	var fid1 [16]byte
	copy(fid1[:], resp1[64+64:64+80])

	// Client 1 acquires Exclusive Lock on range [0, 500]
	lockHdr1 := wire.NewHeader(wire.CmdLock)
	lockHdr1.SessionId = sessID1
	lockHdr1.TreeId = treeID1
	lockHdr1.MessageId = 4
	lockHdr1.Credit = 1
	lockBody1 := buildLockRequest(fid1, 0, 500, wire.LockFlagExclusiveLock|wire.LockFlagFailImmediately)
	mustWrite(t, fc1, append(lockHdr1.Append(nil), lockBody1...))
	lrh1, _ := readReply(t, fc1)
	if lrh1.Status != wire.StatusSuccess {
		t.Fatalf("client 1 acquire lock failed: 0x%08x", lrh1.Status)
	}

	// Client 1 abruptly drops connection (simulating crash/disconnect)
	_ = client1.Close()
	time.Sleep(50 * time.Millisecond) // allow serveConn cleanup goroutine to finish

	// Client 2 connects to the server
	client2, srvConn2 := newPipeConns()
	defer client2.Close()
	cancel2 := serveOn(srv, srvConn2)
	defer cancel2()
	fc2 := transport.NewFramedConn(client2)

	hdr2 := wire.NewHeader(wire.CmdNegotiate)
	mustWrite(t, fc2, append(hdr2.Append(nil), negBody...))
	_, _ = readReply(t, fc2)

	mustWrite(t, fc2, buildSessionSetup([]byte{0x60, 0x04, 0xbe, 0xef}))
	rh2, _ := readReply(t, fc2)
	sessID2 := rh2.SessionId

	mustWrite(t, fc2, buildTreeConnect(sessID2, `\\server\share`))
	rh2, _ = readReply(t, fc2)
	treeID2 := rh2.TreeId

	mustWrite(t, fc2, buildCreate(sessID2, treeID2, "orphan.txt", wire.FileOpen))
	rh2, resp2 := readReply(t, fc2)
	if rh2.Status != wire.StatusSuccess {
		t.Fatalf("client 2 open failed: 0x%08x", rh2.Status)
	}
	var fid2 [16]byte
	copy(fid2[:], resp2[64+64:64+80])

	// Client 2 acquires Exclusive Lock on the previously locked range [0, 500]
	// Since client 1 disconnected, the orphaned lock MUST be cleaned up and client 2 MUST succeed!
	lockHdr2 := wire.NewHeader(wire.CmdLock)
	lockHdr2.SessionId = sessID2
	lockHdr2.TreeId = treeID2
	lockHdr2.MessageId = 4
	lockHdr2.Credit = 1
	lockBody2 := buildLockRequest(fid2, 0, 500, wire.LockFlagExclusiveLock|wire.LockFlagFailImmediately)
	mustWrite(t, fc2, append(lockHdr2.Append(nil), lockBody2...))
	lrh2, _ := readReply(t, fc2)
	if lrh2.Status != wire.StatusSuccess {
		t.Fatalf("client 2 failed to acquire lock after client 1 disconnect: got 0x%08x, want 0x00000000", lrh2.Status)
	}
}

// TestSamba_Lock_Uint64OverflowValidation reproduces Samba's lock bounds check
// ensuring that length 0 or integer overflow (Offset + Length < Offset) is rejected
// with STATUS_INVALID_PARAMETER (MS-SMB2 section 3.3.5.14).
func TestSamba_Lock_Uint64OverflowValidation(t *testing.T) {
	backend := newMemBackend()
	srv := newTestServer(backend)

	client, srvConn := newPipeConns()
	defer client.Close()
	cancel := serveOn(srv, srvConn)
	defer cancel()
	fc := transport.NewFramedConn(client)

	negBody := make([]byte, 38)
	binary.LittleEndian.PutUint16(negBody[0:2], 36)
	binary.LittleEndian.PutUint16(negBody[2:4], 1)
	binary.LittleEndian.PutUint16(negBody[36:38], wire.DialectSMB302)
	hdr := wire.NewHeader(wire.CmdNegotiate)
	mustWrite(t, fc, append(hdr.Append(nil), negBody...))
	_, _ = readReply(t, fc)

	mustWrite(t, fc, buildSessionSetup([]byte{0x60, 0x04, 0xbe, 0xef}))
	rh, _ := readReply(t, fc)
	sessID := rh.SessionId

	mustWrite(t, fc, buildTreeConnect(sessID, `\\server\share`))
	rh, _ = readReply(t, fc)
	treeID := rh.TreeId

	mustWrite(t, fc, buildCreate(sessID, treeID, "bounds.txt", wire.FileCreate))
	rh, resp := readReply(t, fc)
	if rh.Status != wire.StatusSuccess {
		t.Fatalf("create failed: 0x%08x", rh.Status)
	}
	var fid [16]byte
	copy(fid[:], resp[64+64:64+80])

	// Case 1: Length == 0
	lockHdr := wire.NewHeader(wire.CmdLock)
	lockHdr.SessionId = sessID
	lockHdr.TreeId = treeID
	lockHdr.MessageId = 4
	lockHdr.Credit = 1
	bodyZeroLen := buildLockRequest(fid, 100, 0, wire.LockFlagExclusiveLock)
	mustWrite(t, fc, append(lockHdr.Append(nil), bodyZeroLen...))
	lrh, _ := readReply(t, fc)
	if lrh.Status != wire.StatusInvalidParameter {
		t.Fatalf("expected STATUS_INVALID_PARAMETER (0x%08x) for length 0, got 0x%08x",
			wire.StatusInvalidParameter, lrh.Status)
	}

	// Case 2: Uint64 Overflow (Offset + Length < Offset)
	lockHdr.MessageId = 5
	bodyOverflow := buildLockRequest(fid, 0xFFFFFFFFFFFFFFFE, 10, wire.LockFlagExclusiveLock)
	mustWrite(t, fc, append(lockHdr.Append(nil), bodyOverflow...))
	lrh, _ = readReply(t, fc)
	if lrh.Status != wire.StatusInvalidParameter {
		t.Fatalf("expected STATUS_INVALID_PARAMETER (0x%08x) for uint64 overflow, got 0x%08x",
			wire.StatusInvalidParameter, lrh.Status)
	}
}

// TestSamba_Lock_MaxUint64OffsetValid tests that valid byte ranges near the uint64 boundary
// (e.g. Offset = 0xFFFFFFFFFFFFFFF0, Length = 10) work correctly and properly conflict.
func TestSamba_Lock_MaxUint64OffsetValid(t *testing.T) {
	backend := newMemBackend()
	srv := newTestServer(backend)

	client1, srvConn1 := newPipeConns()
	defer client1.Close()
	cancel1 := serveOn(srv, srvConn1)
	defer cancel1()
	fc1 := transport.NewFramedConn(client1)

	client2, srvConn2 := newPipeConns()
	defer client2.Close()
	cancel2 := serveOn(srv, srvConn2)
	defer cancel2()
	fc2 := transport.NewFramedConn(client2)

	negBody := make([]byte, 38)
	binary.LittleEndian.PutUint16(negBody[0:2], 36)
	binary.LittleEndian.PutUint16(negBody[2:4], 1)
	binary.LittleEndian.PutUint16(negBody[36:38], wire.DialectSMB302)

	// Setup Client 1
	hdr1 := wire.NewHeader(wire.CmdNegotiate)
	mustWrite(t, fc1, append(hdr1.Append(nil), negBody...))
	_, _ = readReply(t, fc1)
	mustWrite(t, fc1, buildSessionSetup([]byte{0x60, 0x04, 0xbe, 0xef}))
	rh1, _ := readReply(t, fc1)
	sessID1 := rh1.SessionId
	mustWrite(t, fc1, buildTreeConnect(sessID1, `\\server\share`))
	rh1, _ = readReply(t, fc1)
	treeID1 := rh1.TreeId
	mustWrite(t, fc1, buildCreate(sessID1, treeID1, "max64.txt", wire.FileCreate))
	rh1, resp1 := readReply(t, fc1)
	var fid1 [16]byte
	copy(fid1[:], resp1[64+64:64+80])

	// Setup Client 2
	hdr2 := wire.NewHeader(wire.CmdNegotiate)
	mustWrite(t, fc2, append(hdr2.Append(nil), negBody...))
	_, _ = readReply(t, fc2)
	mustWrite(t, fc2, buildSessionSetup([]byte{0x60, 0x04, 0xbe, 0xef}))
	rh2, _ := readReply(t, fc2)
	sessID2 := rh2.SessionId
	mustWrite(t, fc2, buildTreeConnect(sessID2, `\\server\share`))
	rh2, _ = readReply(t, fc2)
	treeID2 := rh2.TreeId
	mustWrite(t, fc2, buildCreate(sessID2, treeID2, "max64.txt", wire.FileOpen))
	rh2, resp2 := readReply(t, fc2)
	var fid2 [16]byte
	copy(fid2[:], resp2[64+64:64+80])

	// Client 1 locks near max uint64: [0xFFFFFFFFFFFFFFF0, 0xFFFFFFFFFFFFFFFA]
	lockHdr1 := wire.NewHeader(wire.CmdLock)
	lockHdr1.SessionId = sessID1
	lockHdr1.TreeId = treeID1
	lockHdr1.MessageId = 4
	lockHdr1.Credit = 1
	body1 := buildLockRequest(fid1, 0xFFFFFFFFFFFFFFF0, 10, wire.LockFlagExclusiveLock)
	mustWrite(t, fc1, append(lockHdr1.Append(nil), body1...))
	lrh1, _ := readReply(t, fc1)
	if lrh1.Status != wire.StatusSuccess {
		t.Fatalf("client 1 acquire lock at max uint64 failed: 0x%08x", lrh1.Status)
	}

	// Client 2 attempts to lock overlapping range [0xFFFFFFFFFFFFFFF5, 0xFFFFFFFFFFFFFFFA]
	lockHdr2 := wire.NewHeader(wire.CmdLock)
	lockHdr2.SessionId = sessID2
	lockHdr2.TreeId = treeID2
	lockHdr2.MessageId = 4
	lockHdr2.Credit = 1
	body2 := buildLockRequest(fid2, 0xFFFFFFFFFFFFFFF5, 5, wire.LockFlagExclusiveLock|wire.LockFlagFailImmediately)
	mustWrite(t, fc2, append(lockHdr2.Append(nil), body2...))
	lrh2, _ := readReply(t, fc2)
	if lrh2.Status != wire.StatusLockConflict {
		t.Fatalf("expected STATUS_LOCK_CONFLICT (0x%08x) for client 2, got 0x%08x",
			wire.StatusLockConflict, lrh2.Status)
	}
}

// TestSamba_Dir_WildcardMatching verifies Samba smb2.dir wildcard handling:
// - "*.*" matches all files (including those without extension)
// - Case-insensitive matching ("*.TXT" matches "file1.txt")
// - '?' single-character matching ("file?.txt")
func TestSamba_Dir_WildcardMatching(t *testing.T) {
	backend := newMemBackend()
	srv := newTestServer(backend)

	client, srvConn := newPipeConns()
	defer client.Close()
	cancel := serveOn(srv, srvConn)
	defer cancel()
	fc := transport.NewFramedConn(client)

	negBody := make([]byte, 38)
	binary.LittleEndian.PutUint16(negBody[0:2], 36)
	binary.LittleEndian.PutUint16(negBody[2:4], 1)
	binary.LittleEndian.PutUint16(negBody[36:38], wire.DialectSMB302)
	hdr := wire.NewHeader(wire.CmdNegotiate)
	mustWrite(t, fc, append(hdr.Append(nil), negBody...))
	_, _ = readReply(t, fc)

	mustWrite(t, fc, buildSessionSetup([]byte{0x60, 0x04, 0xbe, 0xef}))
	rh, _ := readReply(t, fc)
	sessID := rh.SessionId

	mustWrite(t, fc, buildTreeConnect(sessID, `\\server\share`))
	rh, _ = readReply(t, fc)
	treeID := rh.TreeId

	// Create test files
	fileNames := []string{"file1.txt", "FILE2.TXT", "doc.pdf", "README"}
	for i, fn := range fileNames {
		ch := wire.NewHeader(wire.CmdCreate)
		ch.SessionId = sessID
		ch.TreeId = treeID
		ch.MessageId = uint64(10 + i)
		ch.Credit = 1
		mustWrite(t, fc, append(ch.Append(nil), buildCreateBody(fn, wire.FileCreate)...))
		crh, resp := readReply(t, fc)
		if crh.Status != wire.StatusSuccess {
			t.Fatalf("failed to create %s: 0x%08x", fn, crh.Status)
		}
		var cfid [16]byte
		copy(cfid[:], resp[64+64:64+80])
		mustWrite(t, fc, buildClose(sessID, treeID, cfid))
		_, _ = readReply(t, fc)
	}

	// Open share root directory for querying
	mustWrite(t, fc, buildCreate(sessID, treeID, "", wire.FileOpen))
	drh, dresp := readReply(t, fc)
	if drh.Status != wire.StatusSuccess {
		t.Fatalf("failed to open root dir: 0x%08x", drh.Status)
	}
	var dirFid [16]byte
	copy(dirFid[:], dresp[64+64:64+80])

	// 1. Query with "*.*" -> Should match ALL 4 files
	qMsg1 := buildQueryDirectoryWithFlags(sessID, treeID, dirFid, "*.*", wire.QueryDirRestartScans)
	mustWrite(t, fc, qMsg1)
	qrh1, qresp1 := readReply(t, fc)
	if qrh1.Status != wire.StatusSuccess {
		t.Fatalf("query *.* failed: 0x%08x", qrh1.Status)
	}
	foundStarDotStar := parseDirNames(qresp1)
	if len(foundStarDotStar) != 4 {
		t.Fatalf("query *.* expected 4 files, got %d: %v", len(foundStarDotStar), foundStarDotStar)
	}

	// 2. Query with "*.txt" -> Should match "file1.txt" and "FILE2.TXT" (case-insensitive)
	qMsg2 := buildQueryDirectoryWithFlags(sessID, treeID, dirFid, "*.txt", wire.QueryDirRestartScans)
	mustWrite(t, fc, qMsg2)
	qrh2, qresp2 := readReply(t, fc)
	if qrh2.Status != wire.StatusSuccess {
		t.Fatalf("query *.txt failed: 0x%08x", qrh2.Status)
	}
	foundTxt := parseDirNames(qresp2)
	if len(foundTxt) != 2 {
		t.Fatalf("query *.txt expected 2 files, got %d: %v", len(foundTxt), foundTxt)
	}

	// 3. Query with "file?.txt" -> Should match "file1.txt" and "FILE2.TXT"
	qMsg3 := buildQueryDirectoryWithFlags(sessID, treeID, dirFid, "file?.txt", wire.QueryDirRestartScans)
	mustWrite(t, fc, qMsg3)
	qrh3, qresp3 := readReply(t, fc)
	if qrh3.Status != wire.StatusSuccess {
		t.Fatalf("query file?.txt failed: 0x%08x", qrh3.Status)
	}
	foundFileQuest := parseDirNames(qresp3)
	if len(foundFileQuest) != 2 {
		t.Fatalf("query file?.txt expected 2 files, got %d: %v", len(foundFileQuest), foundFileQuest)
	}
}

// TestSamba_Compound_FourStepChaining reproduces Samba smb2.compound:
// Chain 4 operations in a single NetBIOS message:
// Create -> Write -> Read -> Close
// All steps succeed in a single round-trip with inherited FileId.
func TestSamba_Compound_FourStepChaining(t *testing.T) {
	backend := newMemBackend()
	srv := newTestServer(backend)

	client, srvConn := newPipeConns()
	defer client.Close()
	cancel := serveOn(srv, srvConn)
	defer cancel()
	fc := transport.NewFramedConn(client)

	// Setup Session & Tree
	negBody := make([]byte, 38)
	binary.LittleEndian.PutUint16(negBody[0:2], 36)
	binary.LittleEndian.PutUint16(negBody[2:4], 1)
	binary.LittleEndian.PutUint16(negBody[36:38], wire.DialectSMB302)
	hdr := wire.NewHeader(wire.CmdNegotiate)
	mustWrite(t, fc, append(hdr.Append(nil), negBody...))
	_, _ = readReply(t, fc)

	mustWrite(t, fc, buildSessionSetup([]byte{0x60, 0x04, 0xbe, 0xef}))
	rh, _ := readReply(t, fc)
	sessID := rh.SessionId

	mustWrite(t, fc, buildTreeConnect(sessID, `\\server\share`))
	rh, _ = readReply(t, fc)
	treeID := rh.TreeId

	// Prepare dummy inherited FileId (0xFF)
	var relFileId [16]byte
	for i := range relFileId {
		relFileId[i] = 0xFF
	}

	// 1. Create Command
	createHdr := wire.NewHeader(wire.CmdCreate)
	createHdr.SessionId = sessID
	createHdr.TreeId = treeID
	createHdr.MessageId = 5
	createHdr.Credit = 1
	createBody := align8Bytes(buildCreateBody("chained.txt", wire.FileCreate))
	createHdr.NextCommand = uint32(wire.HeaderSize + len(createBody))
	createMsg := append(createHdr.Append(nil), createBody...)

	// 2. Write Command (Related)
	writeHdr := wire.NewHeader(wire.CmdWrite)
	writeHdr.SessionId = sessID
	writeHdr.TreeId = treeID
	writeHdr.MessageId = 5
	writeHdr.Flags = wire.FlagRelatedOps
	writeData := []byte("samba-torture-4step")
	writeBody := make([]byte, 48+len(writeData))
	binary.LittleEndian.PutUint16(writeBody[0:2], 49)
	binary.LittleEndian.PutUint16(writeBody[2:4], uint16(wire.HeaderSize+48))
	binary.LittleEndian.PutUint32(writeBody[4:8], uint32(len(writeData)))
	copy(writeBody[16:32], relFileId[:])
	copy(writeBody[48:], writeData)
	writeBody = align8Bytes(writeBody)
	writeHdr.NextCommand = uint32(wire.HeaderSize + len(writeBody))
	writeMsg := append(writeHdr.Append(nil), writeBody...)

	// 3. Read Command (Related)
	readHdr := wire.NewHeader(wire.CmdRead)
	readHdr.SessionId = sessID
	readHdr.TreeId = treeID
	readHdr.MessageId = 5
	readHdr.Flags = wire.FlagRelatedOps
	readBody := make([]byte, 49)
	binary.LittleEndian.PutUint16(readBody[0:2], 49)
	binary.LittleEndian.PutUint32(readBody[4:8], uint32(len(writeData)))
	binary.LittleEndian.PutUint64(readBody[8:16], 0) // offset 0
	copy(readBody[16:32], relFileId[:])
	readBody = align8Bytes(readBody)
	readHdr.NextCommand = uint32(wire.HeaderSize + len(readBody))
	readMsg := append(readHdr.Append(nil), readBody...)

	// 4. Close Command (Related)
	closeHdr := wire.NewHeader(wire.CmdClose)
	closeHdr.SessionId = sessID
	closeHdr.TreeId = treeID
	closeHdr.MessageId = 5
	closeHdr.Flags = wire.FlagRelatedOps
	closeHdr.NextCommand = 0
	closeBody := make([]byte, 24)
	binary.LittleEndian.PutUint16(closeBody[0:2], 24)
	copy(closeBody[8:24], relFileId[:])
	closeMsg := append(closeHdr.Append(nil), closeBody...)

	// Combine all 4 into one compound packet
	compoundReq := append(createMsg, writeMsg...)
	compoundReq = append(compoundReq, readMsg...)
	compoundReq = append(compoundReq, closeMsg...)
	mustWrite(t, fc, compoundReq)

	// Read reply frame
	replyHdr1, replyMsg := readReply(t, fc)
	if replyHdr1.Status != wire.StatusSuccess {
		t.Fatalf("1. Create failed in compound: 0x%08x", replyHdr1.Status)
	}
	if replyHdr1.NextCommand == 0 {
		t.Fatal("expected NextCommand on reply 1")
	}

	// 2. Write reply
	off2 := replyHdr1.NextCommand
	var replyHdr2 wire.Header
	if err := replyHdr2.Parse(replyMsg[off2:]); err != nil {
		t.Fatalf("parse write response: %v", err)
	}
	if replyHdr2.Status != wire.StatusSuccess {
		t.Fatalf("2. Write failed in compound: 0x%08x", replyHdr2.Status)
	}
	if replyHdr2.NextCommand == 0 {
		t.Fatal("expected NextCommand on reply 2")
	}

	// 3. Read reply
	off3 := off2 + replyHdr2.NextCommand
	var replyHdr3 wire.Header
	if err := replyHdr3.Parse(replyMsg[off3:]); err != nil {
		t.Fatalf("parse read response: %v", err)
	}
	if replyHdr3.Status != wire.StatusSuccess {
		t.Fatalf("3. Read failed in compound: 0x%08x", replyHdr3.Status)
	}
	readRespBody := replyMsg[off3+wire.HeaderSize:]
	readDataOff := binary.LittleEndian.Uint16(readRespBody[2:4])
	readDataLen := binary.LittleEndian.Uint32(readRespBody[4:8])
	readData := replyMsg[off3+uint32(readDataOff) : off3+uint32(readDataOff)+readDataLen]
	if !bytes.Equal(readData, writeData) {
		t.Fatalf("read data mismatch: got %q, want %q", readData, writeData)
	}
	if replyHdr3.NextCommand == 0 {
		t.Fatal("expected NextCommand on reply 3")
	}

	// 4. Close reply
	off4 := off3 + replyHdr3.NextCommand
	var replyHdr4 wire.Header
	if err := replyHdr4.Parse(replyMsg[off4:]); err != nil {
		t.Fatalf("parse close response: %v", err)
	}
	if replyHdr4.Status != wire.StatusSuccess {
		t.Fatalf("4. Close failed in compound: 0x%08x", replyHdr4.Status)
	}
	if replyHdr4.NextCommand != 0 {
		t.Fatalf("expected NextCommand == 0 on final response, got %d", replyHdr4.NextCommand)
	}
}

func align8Bytes(b []byte) []byte {
	rem := len(b) % 8
	if rem != 0 {
		b = append(b, make([]byte, 8-rem)...)
	}
	return b
}

func buildQueryDirectoryWithFlags(sessID uint64, treeID uint32, fid [16]byte, pattern string, flags uint8) []byte {
	nameBytes := wire.UTF16ToBytes(pattern)
	hdr := wire.NewHeader(wire.CmdQueryDirectory)
	hdr.SessionId = sessID
	hdr.TreeId = treeID
	hdr.MessageId = 20
	hdr.Credit = 1

	const fixed = 32
	nameOff := wire.HeaderSize + fixed
	body := make([]byte, fixed+len(nameBytes))
	binary.LittleEndian.PutUint16(body[0:2], 33)
	body[2] = wire.FileDirectoryInformation
	body[3] = flags
	binary.LittleEndian.PutUint32(body[4:8], 0) // FileIndex
	copy(body[8:24], fid[:])
	binary.LittleEndian.PutUint16(body[24:26], uint16(nameOff))
	binary.LittleEndian.PutUint16(body[26:28], uint16(len(nameBytes)))
	binary.LittleEndian.PutUint32(body[28:32], 65536) // OutputBufferLength
	copy(body[fixed:], nameBytes)

	return append(hdr.Append(nil), body...)
}

func parseDirNames(msg []byte) []string {
	if len(msg) < wire.HeaderSize+8 {
		return nil
	}
	body := msg[wire.HeaderSize:]
	outOff := int(binary.LittleEndian.Uint16(body[2:4]))
	outLen := int(binary.LittleEndian.Uint32(body[4:8]))
	if outOff+outLen > len(msg) {
		return nil
	}
	data := msg[outOff : outOff+outLen]
	var names []string
	off := 0
	for off+64 <= len(data) {
		nextOff := int(binary.LittleEndian.Uint32(data[off : off+4]))
		nameLen := int(binary.LittleEndian.Uint32(data[off+60 : off+64]))
		if off+64+nameLen <= len(data) {
			rawName := data[off+64 : off+64+nameLen]
			name := wire.UTF16FromBytes(rawName)
			if name != "." && name != ".." {
				names = append(names, name)
			}
		}
		if nextOff == 0 {
			break
		}
		off += nextOff
	}
	return names
}
