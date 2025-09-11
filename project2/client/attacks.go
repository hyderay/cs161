package client

import (
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

func TamperWithFileChunk(username string) error {
	userUUID, err := DeriveUserUUID(username)
	if err != nil {
		return err
	}
	fileIndexUUID, err := uuid.FromBytes(userlib.Hash([]byte(username + "fileIndex"))[:16])
	if err != nil {
		return err
	}

	// Find a chunk UUID to tamper with.
	var chunkUUID uuid.UUID
	datastoreMap := userlib.DatastoreGetMap()
	for key := range datastoreMap {
		if key != userUUID && key != fileIndexUUID {
			chunkUUID = key
			break
		}
	}

	if chunkUUID == uuid.Nil {
		return errors.New("could not find a file chunk to tamper with")
	}

	// Tamper with the identified chunk.
	wrapperBytes, ok := userlib.DatastoreGet(chunkUUID)
	if !ok {
		return errors.New("could not retrieve chunk to tamper with")
	}

	var secureWrapper SecureWrapper
	err = json.Unmarshal(wrapperBytes, &secureWrapper)
	if err != nil {
		return err
	}

	// Corrupt the first byte of the encrypted data (the FileChunk struct).
	secureWrapper.Data[0] = secureWrapper.Data[0] ^ 1

	corruptedWrapperBytes, err := json.Marshal(secureWrapper)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(chunkUUID, corruptedWrapperBytes)

	return nil
}
