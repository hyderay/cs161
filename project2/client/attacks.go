package client

import (
	"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/google/uuid"

	userlib "github.com/cs161-staff/project2-userlib"
)

func TamperWithUserData(username string) error {
	userUUID, err := DeriveUserUUID(username)
	if err != nil {
		return err
	}

	wrapperBytes, ok := userlib.DatastoreGet(userUUID)
	if !ok {
		return errors.New("No such user")
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
	// We need the user object to use its keys and helper methods.
	// This assumes the user was created with the default password for the test.
	user, err := GetUser(username, "password")
	if err != nil {
		return errors.New("cannot get user to perform attack: " + err.Error())
	}

	// 1. Get the user's file index to find a file to target.
	fileIndex, err := user.getFileIndex()
	if err != nil {
		return err
	}

	// 2. Find a file to tamper with. In the test suite, Alice creates "aliceFile.txt".
	// We must assume this filename to use the helper functions that require it.
	targetFilename := "aliceFile.txt"
	filenameHash := hex.EncodeToString(userlib.Hash([]byte(targetFilename)))

	if _, ok := fileIndex[filenameHash]; !ok {
		return errors.New("could not find the target file ('aliceFile.txt') to tamper with")
	}

	// 3. Get the access node, which contains the pointer to the most recent chunk.
	accessNode, err := user.getAccessNode(targetFilename)
	if err != nil {
		return err
	}

	chunkUUID := accessNode.CurrChunkUUID
	if chunkUUID == uuid.Nil {
		return errors.New("file has no content chunks to tamper with")
	}

	// 4. Now that we have the CORRECT chunk UUID, fetch and tamper with it.
	wrapperBytes, ok := userlib.DatastoreGet(chunkUUID)
	if !ok {
		return errors.New("could not retrieve the targeted chunk to tamper with")
	}

	var secureWrapper SecureWrapper
	err = json.Unmarshal(wrapperBytes, &secureWrapper)
	if err != nil {
		return err
	}

	// Corrupt the first byte of the encrypted FileChunk data by flipping a bit.
	secureWrapper.Data[0] = secureWrapper.Data[0] ^ 1

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
