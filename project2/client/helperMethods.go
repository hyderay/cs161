package client

import (
	"encoding/hex"
	"encoding/json"
	"errors"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"
)

func deriveUserUUID(userName string) (userUUID uuid.UUID, err error) {
	userNameHash := userlib.Hash([]byte(userName))
	return uuid.FromBytes(userNameHash[:16])
}

func authenticatedEncrypt(data []byte, encKey []byte, macKey []byte) (wrappedBytes []byte, err error) {
	iv := userlib.RandomBytes(16)

	ciphertext := userlib.SymEnc(encKey, iv, data)

	var tag []byte
	tag, err = userlib.HMACEval(macKey, ciphertext)
	if err != nil {
		return nil, err
	}

	var wrapper SecureWrapper
	wrapper.Data = ciphertext
	wrapper.Tag = tag

	return json.Marshal(wrapper)
}

func authenticatedDecrypt(wrapperBytes []byte, encKey []byte, macKey []byte) (plaintext []byte, err error) {
	var wrapper SecureWrapper
	err = json.Unmarshal(wrapperBytes, &wrapper)
	if err != nil {
		return nil, err
	}

	ciphertext := wrapper.Data

	var expectedTag []byte
	expectedTag, err = userlib.HMACEval(macKey, ciphertext)
	if err != nil {
		return nil, err
	}

	ok := userlib.HMACEqual(wrapper.Tag, expectedTag)
	if !ok {
		return nil, errors.New("data was tempered")
	}

	return userlib.SymDec(encKey, ciphertext), nil
}

func (user *User) getFileIndex() (fileIndex map[string]uuid.UUID, err error) {
	fileIndexUUID, err := uuid.FromBytes(userlib.Hash([]byte(user.userName + "fileIndex"))[:16])
	if err != nil {
		return nil, err
	}

	wrappedFileIndex, ok := userlib.DatastoreGet(fileIndexUUID)
	if !ok {
		return make(map[string]uuid.UUID), nil
	}

	fileIndexBytes, err := authenticatedDecrypt(wrappedFileIndex, user.fileEncKey, user.fileMacKey)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(fileIndexBytes, &fileIndex)
	if err != nil {
		return nil, err
	}

	return fileIndex, nil
}

func (user *User) getFileInfoAndUUID(filename string) (*FileInfo, uuid.UUID, error) {
	fileIndex, err := user.getFileIndex()
	if err != nil {
		return nil, uuid.Nil, err
	}

	filenameHash := hex.EncodeToString(userlib.Hash([]byte(filename)))

	fileInfoUUID, ok := fileIndex[filenameHash]
	if !ok {
		return nil, uuid.Nil, errors.New("file info under this name does not exist")
	}

	wrappedFileInfo, ok := userlib.DatastoreGet(fileInfoUUID)
	if !ok {
		return nil, uuid.Nil, errors.New("cannot find file info under this filename")
	}

	fileInfoBytes, err := authenticatedDecrypt(wrappedFileInfo, user.fileEncKey, user.fileMacKey)
	if err != nil {
		return nil, uuid.Nil, err
	}

	var fileInfo FileInfo
	err = json.Unmarshal(fileInfoBytes, &fileInfo)
	if err != nil {
		return nil, uuid.Nil, err
	}

	return &fileInfo, fileInfoUUID, nil
}

func (user *User) getAccessNode(filename string) (*AccessNode, error) {
	fileInfo, _, err := user.getFileInfoAndUUID(filename)
	if err != nil {
		return nil, err
	}

	wrappedAccessNode, ok := userlib.DatastoreGet(fileInfo.AccessNodeUUID)
	if !ok {
		return nil, errors.New("this file does have access node")
	}

	var accessNodeBytes []byte
	if fileInfo.OwnerUsername == user.userName {
		accessNodeBytes, err = authenticatedDecrypt(wrappedAccessNode, user.fileEncKey, user.fileMacKey)
		if err != nil {
			return nil, err
		}
	} else {
		accessNodeBytes, err = hybridDecrypt(wrappedAccessNode, user.decKey)
		if err != nil {
			return nil, err
		}
	}

	var accessNode AccessNode
	err = json.Unmarshal(accessNodeBytes, &accessNode)
	if err != nil {
		return nil, err
	}

	return &accessNode, nil
}

func hybridDecrypt(hybridBytes []byte, recipientPKEKey userlib.PKEDecKey) ([]byte, error) {
	var hybridEncrypted HybridEncrypted
	err := json.Unmarshal(hybridBytes, &hybridEncrypted)
	if err != nil {
		return nil, err
	}

	realKey, err := userlib.PKEDec(recipientPKEKey, hybridEncrypted.EncryptedKey)
	if err != nil {
		return nil, err
	}

	encKey, err := userlib.HashKDF(realKey, []byte("enc"))
	if err != nil {
		return nil, err
	}
	macKey, err := userlib.HashKDF(realKey, []byte("mac"))
	if err != nil {
		return nil, err
	}

	plaintext, err := authenticatedDecrypt(hybridEncrypted.Ciphertext, encKey[:16], macKey[:16])
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

func (user *User) getFileMetadata(fileInfo *FileInfo) (*FileMetadata, error) {
	wrappedMetadata, ok := userlib.DatastoreGet(fileInfo.MetadataUUID)
	if !ok {
		return nil, errors.New("cannot find the metadata")
	}

	metadataBytes, err := authenticatedDecrypt(wrappedMetadata, user.fileEncKey, user.fileMacKey)
	if err != nil {
		return nil, err
	}

	var metadata FileMetadata
	err = json.Unmarshal(metadataBytes, &metadata)
	if err != nil {
		return nil, err
	}

	return &metadata, nil
}

func (user *User) syncInbox(fileInfo *FileInfo) (err error) {
	inboxBytes, ok := userlib.DatastoreGet(fileInfo.InboxUUID)
	if !ok {
		return errors.New("cannot find the indox from datastore")
	}

	var wrappedRequest [][]byte
	err = json.Unmarshal(inboxBytes, &wrappedRequest)
	if err != nil {
		return err
	}

	fileMetadata, err := user.getFileMetadata(fileInfo)
	if err != nil {
		return err
	}

	for _, wrappedRequestByte := range wrappedRequest {
		requestByte, err := hybridDecrypt(wrappedRequestByte, user.decKey)
		if err != nil {
			continue
		}

		var request UpdateRequest
		err = json.Unmarshal(requestByte, &request)
		if err != nil {
			continue
		}

		_, isSharerAuthorized := fileMetadata.AccessManifest[request.ParentUsername]
		if !isSharerAuthorized {
			continue
		}

		fileMetadata.AccessManifest[request.ChildUsername] = request.ChildAccessNodeUUID
		fileMetadata.ShareTree[request.ParentUsername] =
			append(fileMetadata.ShareTree[request.ParentUsername], request.ChildUsername)

		childPBKey, ok := userlib.KeystoreGet(request.ChildUsername + "_PKE")
		if !ok {
			continue
		}

		childAccessNode, ok := userlib.DatastoreGet(request.ChildAccessNodeUUID)
		if !ok {
			continue
		}

		accessNodeBytes, err := hybridDecrypt(childAccessNode, user.decKey)
		if err != nil {
			continue
		}

		updatedChildAccessNode, err := hybridEncrypt(accessNodeBytes, childPBKey)
		if err != nil {
			return err
		}
		userlib.DatastoreSet(request.ChildAccessNodeUUID, updatedChildAccessNode)
	}

	metadataBytes, err := json.Marshal(fileMetadata)
	if err != nil {
		return err
	}

	wrappedMetadata, err := authenticatedEncrypt(metadataBytes, user.fileEncKey, user.fileMacKey)
	if err != nil {
		return err
	}

	userlib.DatastoreSet(fileInfo.MetadataUUID, wrappedMetadata)

	emptyInboxBytes, err := json.Marshal([][]byte{})
	if err != nil {
		return err
	}
	userlib.DatastoreSet(fileInfo.InboxUUID, emptyInboxBytes)
	return nil
}

func hybridEncrypt(plaintext []byte, key userlib.PKEEncKey) ([]byte, error) {
	sessionKey := userlib.RandomBytes(16)

	encKey, err := userlib.HashKDF(sessionKey, []byte("enc"))
	if err != nil {
		return nil, err
	}
	macKey, err := userlib.HashKDF(sessionKey, []byte("mac"))
	if err != nil {
		return nil, err
	}

	wrappedSessionKey, err := userlib.PKEEnc(key, sessionKey)
	if err != nil {
		return nil, err
	}

	wrappedText, err := authenticatedEncrypt(plaintext, encKey[:16], macKey[:16])
	if err != nil {
		return nil, err
	}

	var hybridEncrypt HybridEncrypted
	hybridEncrypt.Ciphertext = wrappedText
	hybridEncrypt.EncryptedKey = wrappedSessionKey

	hybridEncryptBytes, err := json.Marshal(hybridEncrypt)
	if err != nil {
		return nil, err
	}

	return hybridEncryptBytes, nil
}
