package client

import (
	//"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/google/uuid"

	userlib "github.com/cs161-staff/project2-userlib"
)

func TamperWithUserData(username string) error {
	userUUID, err := deriveUserUUID(username)
	if err != nil {
		return err
	}

	wrapperBytes, ok := userlib.DatastoreGet(userUUID)
	if !ok {
		return errors.New("no such user")
	}

	var secureWrapper SecureWrapper
	err = json.Unmarshal(wrapperBytes, &secureWrapper)
	if err != nil {
		return err
	}

	secureWrapper.Data[0] = secureWrapper.Data[0] ^ 1

	corruptedWrapperBytes, err := json.Marshal(secureWrapper)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(userUUID, corruptedWrapperBytes)

	return nil
}

func TamperWithFileIndex(username string) error {
	// The file index UUID is derived deterministically.
	fileIndexUUID, err := uuid.FromBytes(userlib.Hash([]byte(username + "fileIndex"))[:16])
	if err != nil {
		return err
	}

	wrapperBytes, ok := userlib.DatastoreGet(fileIndexUUID)
	if !ok {
		return errors.New("no such file index to tamper with")
	}

	var secureWrapper SecureWrapper
	err = json.Unmarshal(wrapperBytes, &secureWrapper)
	if err != nil {
		return err
	}

	// Corrupt the first byte of the encrypted data (the file index map).
	secureWrapper.Data[0] = secureWrapper.Data[0] ^ 1

	corruptedWrapperBytes, err := json.Marshal(secureWrapper)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(fileIndexUUID, corruptedWrapperBytes)

	return nil
}

func TamperWithFileInfo(username string) error {
	// First, we need the user's personal keys to decrypt their file index.
	// We can't get the password, so we need a way to get the keys.
	// This requires a helper function in your main client code that is NOT exported,
	// but can be called by this attack function since they are in the same package.
	// For now, let's assume we can re-derive them if we knew the password.
	// NOTE: A true attack might not be able to do this, but for testing, we need a reliable way.

	// Let's get the user to get their own keys.
	// A placeholder password; in a real test you might need to manage this better.
	user, err := GetUser(username, "password") // Assumes "password" is the default.
	if err != nil {
		return errors.New("cannot get user to perform attack")
	}

	// Now, follow the pointers correctly.
	fileIndex, err := user.getFileIndex()
	if err != nil {
		return err
	}

	// Find the first FileInfo UUID in the index.
	var fileInfoUUID uuid.UUID
	for _, val := range fileIndex {
		fileInfoUUID = val
		break // Just tamper with the first one found.
	}

	if fileInfoUUID == uuid.Nil {
		return errors.New("could not find a FileInfo to tamper with in the index")
	}

	// Now that we have the CORRECT UUID, we can tamper with it.
	wrapperBytes, ok := userlib.DatastoreGet(fileInfoUUID)
	if !ok {
		return errors.New("could not retrieve FileInfo to tamper with")
	}
	var secureWrapper SecureWrapper
	err = json.Unmarshal(wrapperBytes, &secureWrapper)
	if err != nil {
		return err
	}

	// Corrupt the first byte of the encrypted FileInfo data.
	secureWrapper.Data[0] = secureWrapper.Data[0] ^ 1

	corruptedWrapperBytes, err := json.Marshal(secureWrapper)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(fileInfoUUID, corruptedWrapperBytes)
	return nil
}

func TamperWithFileChunk(username string) error {
	user, err := GetUser(username, "password")
	if err != nil {
		return errors.New("cannot get user to perform attack: " + err.Error())
	}

	targetFilename := "aliceFile.txt"

	// 1. Get the FileInfo to find the FileHeader's location.
	fileInfo, _, err := user.getFileInfoAndUUID(targetFilename)
	if err != nil {
		return err
	}

	// 2. Fetch the shared FileHeader.
	headerBytes, ok := userlib.DatastoreGet(fileInfo.FileHeaderUUID)
	if !ok {
		return errors.New("could not find file header to get chunk UUID")
	}
	var header FileHeader
	if err = json.Unmarshal(headerBytes, &header); err != nil {
		return err
	}

	// 3. Get the chunk's UUID from the header.
	chunkUUID := header.CurrChunkUUID
	if chunkUUID == uuid.Nil {
		return errors.New("file has no content chunks to tamper with")
	}

	// 4. Now that we have the CORRECT chunk UUID, fetch and tamper with it.
	wrapperBytes, ok := userlib.DatastoreGet(chunkUUID)
	if !ok {
		return errors.New("could not retrieve the targeted chunk to tamper with")
	}

	var secureWrapper SecureWrapper
	if err = json.Unmarshal(wrapperBytes, &secureWrapper); err != nil {
		return err
	}

	secureWrapper.Data[0] = secureWrapper.Data[0] ^ 1 // Flip a bit

	corruptedWrapperBytes, err := json.Marshal(secureWrapper)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(chunkUUID, corruptedWrapperBytes)

	return nil
}

func TamperWithAccessNode(username string) error {
	// We need the user object to use its keys and helper methods.
	// This assumes the user was created with the default password for the test.
	user, err := GetUser(username, "password")
	if err != nil {
		return errors.New("cannot get user to perform attack: " + err.Error())
	}

	// For the test, we must assume a known filename.
	targetFilename := "aliceFile.txt"

	// 1. Get the FileInfo struct, which contains the pointer to the AccessNode.
	fileInfo, _, err := user.getFileInfoAndUUID(targetFilename)
	if err != nil {
		return err
	}

	accessNodeUUID := fileInfo.AccessNodeUUID
	if accessNodeUUID == uuid.Nil {
		return errors.New("could not find an AccessNode to tamper with")
	}

	// 2. Now that we have the CORRECT AccessNode UUID, fetch and tamper with it.
	wrapperBytes, ok := userlib.DatastoreGet(accessNodeUUID)
	if !ok {
		return errors.New("could not retrieve the targeted AccessNode to tamper with")
	}

	// The owner's AccessNode is symmetrically encrypted, so we expect a SecureWrapper.
	var secureWrapper SecureWrapper
	err = json.Unmarshal(wrapperBytes, &secureWrapper)
	if err != nil {
		return err
	}

	// Corrupt the first byte of the encrypted AccessNode data by flipping a bit.
	secureWrapper.Data[0] = secureWrapper.Data[0] ^ 1

	corruptedWrapperBytes, err := json.Marshal(secureWrapper)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(accessNodeUUID, corruptedWrapperBytes)

	return nil
}

func TamperWithInbox(username string) error {
	user, err := GetUser(username, "password")
	if err != nil {
		return err
	}
	fileInfo, _, err := user.getFileInfoAndUUID("aliceFile.txt")
	if err != nil {
		return err
	}

	inboxUUID := fileInfo.InboxUUID

	// Create a garbage request (just random bytes, not a valid encrypted request).
	garbageRequest := userlib.RandomBytes(16)

	// Get the current inbox and add the garbage to it.
	inboxBytes, _ := userlib.DatastoreGet(inboxUUID)
	var encryptedRequests [][]byte
	if len(inboxBytes) > 0 {
		json.Unmarshal(inboxBytes, &encryptedRequests)
	}
	encryptedRequests = append(encryptedRequests, garbageRequest)
	newInboxBytes, _ := json.Marshal(encryptedRequests)
	userlib.DatastoreSet(inboxUUID, newInboxBytes)

	return nil
}

func TamperWithFileHeader(username string) error {
	user, err := GetUser(username, "password")
	if err != nil {
		return err
	}
	targetFilename := "aliceFile.txt"

	// 1. Get the FileInfo to find the FileHeader's location.
	fileInfo, _, err := user.getFileInfoAndUUID(targetFilename)
	if err != nil {
		return err
	}

	// 2. Fetch the FileHeader.
	headerBytes, ok := userlib.DatastoreGet(fileInfo.FileHeaderUUID)
	if !ok {
		return errors.New("could not find file header to tamper with")
	}
	var header FileHeader
	if err = json.Unmarshal(headerBytes, &header); err != nil {
		return err
	}

	// 3. Corrupt the header by pointing it to a garbage UUID.
	header.CurrChunkUUID = uuid.New()

	// 4. Save the corrupted header back.
	corruptedHeaderBytes, err := json.Marshal(header)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(fileInfo.FileHeaderUUID, corruptedHeaderBytes)

	return nil
}

// RevokedUserAddsToInbox simulates a revoked user crafting a fake share request
// and placing it in the owner's inbox to try and regain access.
func RevokedUserAddsToInbox(ownerUsername string, revokedUsername string, password string, targetFilename string) error {
	// The revoked user needs their user object to get their old file info.
	revokedUser, err := GetUser(revokedUsername, password)
	if err != nil {
		return err
	}

	// From their old file info, they know the owner's username and the InboxUUID.
	fileInfo, _, err := revokedUser.getFileInfoAndUUID(targetFilename)
	if err != nil {
		return err
	}
	inboxUUID := fileInfo.InboxUUID
	ownerPubKey, ok := userlib.KeystoreGet(ownerUsername + "_PKE")
	if !ok {
		return errors.New("revoked user cannot find owner's public key")
	}

	// 1. Craft a malicious UpdateRequest.
	// The revoked user claims to be sharing the file with themself.
	// A dummy UUID is used, as it doesn't matter for this attack.
	maliciousRequest := UpdateRequest{
		ParentUsername:      revokedUsername,
		ChildUsername:       revokedUsername,
		ChildAccessNodeUUID: uuid.New(),
	}
	requestBytes, err := json.Marshal(maliciousRequest)
	if err != nil {
		return err
	}

	// 2. Encrypt it with the owner's public key so it looks legitimate.
	encryptedRequest, err := hybridEncrypt(requestBytes, ownerPubKey)
	if err != nil {
		return err
	}

	// 3. Add the malicious request to the owner's inbox.
	inboxBytes, _ := userlib.DatastoreGet(inboxUUID)
	var inboxData [][]byte
	if len(inboxBytes) > 0 {
		json.Unmarshal(inboxBytes, &inboxData)
	}
	inboxData = append(inboxData, encryptedRequest)
	newInboxBytes, err := json.Marshal(inboxData)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(inboxUUID, newInboxBytes)

	return nil
}

// RevokedUserReadsFutureContent simulates a revoked user trying to access new file content.
// The user knows the FileHeaderUUID from before revocation. They can read the header to find the
// latest chunk's UUID, but they should be unable to decrypt that chunk.
func RevokedUserReadsFutureContent(revokedUsername string, password string, targetFilename string) (err error) {
	// The revoked user gets their user object.
	revokedUser, err := GetUser(revokedUsername, password)
	if err != nil {
		// This is a valid scenario; if login fails, the attack is stopped.
		return nil
	}

	// In a real attack, the user would have their old FileInfo saved.
	// We retrieve it here to get the UUIDs they would know.
	_, _, err = revokedUser.getFileInfoAndUUID(targetFilename)
	if err != nil {
		// This is also a valid defense. If the user deletes their local file
		// entry, they lose the pointers needed for the attack.
		return nil
	}

	// The core of the attack: Try to get the file's content keys.
	// This should fail because the user's AccessNode was deleted during revocation.
	_, err = revokedUser.getAccessNode(targetFilename)
	if err != nil {
		// SUCCESS: The attack was thwarted because the access node is gone.
		// We return nil to indicate the defense worked as expected.
		return nil
	}

	// If getAccessNode somehow succeeded, it's a critical security failure.
	return errors.New("SECURITY FLAW: Revoked user was able to retrieve their access node after revocation")
}
