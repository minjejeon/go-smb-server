package server

import (
	"encoding/binary"
	"testing"

	"github.com/sonroyaalmerol/go-smb-server/smb/signing"
	"github.com/sonroyaalmerol/go-smb-server/smb/transport"
	"github.com/sonroyaalmerol/go-smb-server/smb/wire"
)

func TestSignedCompoundRelated(t *testing.T) {
	client, srvConn := newPipeConns()
	defer client.Close()

	backend := newMemBackend()
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

	// Get signer for session (key is derived from SessionKey; AlwaysAllow has empty session key so derive from empty)
	key := signing.DeriveSigningKey(nil)
	signer, err := signing.NewSigner(key)
	if err != nil {
		t.Fatal(err)
	}

	// 4. Build Compound Request: Create + Write (related)
	// Create request
	createHdr := wire.NewHeader(wire.CmdCreate)
	createHdr.SessionId = sessID
	createHdr.TreeId = treeID
	createHdr.MessageId = 4
	createHdr.Credit = 1
	createHdr.Flags = wire.FlagSigned
	createBody := buildCreateBody("compound.txt", wire.FileCreate)
	createHdr.NextCommand = uint32(wire.HeaderSize + len(createBody))

	// Write request (Related)
	writeHdr := wire.NewHeader(wire.CmdWrite)
	writeHdr.SessionId = sessID
	writeHdr.TreeId = treeID
	writeHdr.MessageId = 4
	writeHdr.Flags = wire.FlagSigned | wire.FlagRelatedOps
	// In related ops, client sets fileId to 0xFF...
	var relFileId [16]byte
	for i := range relFileId {
		relFileId[i] = 0xFF
	}
	writeData := []byte("compound data")
	writeBody := make([]byte, 48+len(writeData))
	binary.LittleEndian.PutUint16(writeBody[0:2], 49)
	binary.LittleEndian.PutUint16(writeBody[2:4], uint16(wire.HeaderSize+48))
	binary.LittleEndian.PutUint32(writeBody[4:8], uint32(len(writeData)))
	copy(writeBody[16:32], relFileId[:])
	copy(writeBody[48:], writeData)

	createMsg := append(createHdr.Append(nil), createBody...)
	writeMsg := append(writeHdr.Append(nil), writeBody...)

	// Client signs each message chunk as sent
	if err := signer.Sign(createMsg); err != nil {
		t.Fatal(err)
	}
	if err := signer.Sign(writeMsg); err != nil {
		t.Fatal(err)
	}

	compoundReq := append(createMsg, writeMsg...)
	mustWrite(t, fc, compoundReq)

	// Read compound reply (single TCP frame containing both responses)
	replyHdr1, replyMsg := readReply(t, fc)
	if replyHdr1.Status != wire.StatusSuccess {
		t.Fatalf("create in compound failed: 0x%08x", replyHdr1.Status)
	}
	if replyHdr1.NextCommand == 0 {
		t.Fatalf("expected NextCommand in compound response, got 0")
	}

	// Parse second response header from the same message
	subResp := replyMsg[replyHdr1.NextCommand:]
	var replyHdr2 wire.Header
	if err := replyHdr2.Parse(subResp); err != nil {
		t.Fatalf("parse second response header: %v", err)
	}
	if replyHdr2.Status != wire.StatusSuccess {
		t.Fatalf("write in compound failed: 0x%08x (expected SUCCESS)", replyHdr2.Status)
	}
}

func buildCreateBody(name string, disposition uint32) []byte {
	nameBytes := wire.UTF16ToBytes(name)
	body := make([]byte, 56+len(nameBytes))
	binary.LittleEndian.PutUint16(body[0:2], 57)
	binary.LittleEndian.PutUint32(body[36:40], disposition)
	binary.LittleEndian.PutUint16(body[44:46], uint16(wire.HeaderSize+56))
	binary.LittleEndian.PutUint16(body[46:48], uint16(len(nameBytes)))
	copy(body[56:], nameBytes)
	return body
}
