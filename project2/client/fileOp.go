package client

import (
	"encoding/hex"
	"encoding/json"
	"errors"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"
)

type FileChunk struct {
	Content      []byte
	PreChunkUUID uuid.UUID
}

type FileInfo struct {
	IsOwner        bool
	AccessNodeUUID uuid.UUID
	MetadataUUID   uuid.UUID
}

type AccessNode struct {
	ContentEncKey []byte
	ContentMacKey []byte
	CurrChunkUUID uuid.UUID
}

type FileMetadata struct {
	Owner          string
	AccessManifest map[string]uuid.UUID
	ShareTree      map[string][]string
}

func AuthenticatedEncrypt(data []byte, encKey []byte, macKey []byte) (wrappedBytes []byte, err error) {
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

func AuthenticatedDecrypt(wrapperBytes []byte, encKey []byte, macKey []byte) (plaintext []byte, err error) {
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

	fileIndexBytes, err := AuthenticatedDecrypt(wrappedFileIndex, user.fileEncKey, user.fileMacKey)
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

	fileInfoBytes, err := AuthenticatedDecrypt(wrappedFileInfo, user.fileEncKey, user.fileMacKey)
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

func (user *User) getAccessNode(filename string) (accessNode *AccessNode, err error) {
	fileInfo, _, err := user.getFileInfoAndUUID(filename)
	if err != nil {
		return nil, err
	}

	wrappedAccessNode, ok := userlib.DatastoreGet(fileInfo.AccessNodeUUID)
	if !ok {
		return nil, errors.New("this file does have access node")
	}

	accessNodeBytes, err := AuthenticatedDecrypt(wrappedAccessNode, user.fileEncKey, user.fileMacKey)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(accessNodeBytes, &accessNode)
	if err != nil {
		return nil, err
	}

	return accessNode, nil
}

/*
*
This instance method is used to both create a file for the first time,
or to overwrite an existing file entirely with new contents.
To use this method, the user passes in the filename to identify the file,
as well as the contents that they wish to store.
*/
func (user *User) StoreFile(filename string, content []byte) (err error) {
	fileIndex, err := user.getFileIndex()
	if err != nil {
		return err
	}

	filenameHash := hex.EncodeToString(userlib.Hash([]byte(filename)))

	_, ok := fileIndex[filenameHash]

	if ok {
		accessNode, err := user.getAccessNode(filename)
		if err != nil {
			return err
		}

		var newChunk FileChunk
		newChunk.Content = content
		newChunk.PreChunkUUID = uuid.Nil
		chunkBytes, _ := json.Marshal(newChunk)
		wrappedChunk, err := AuthenticatedEncrypt(chunkBytes, accessNode.ContentEncKey, accessNode.ContentMacKey)
		if err != nil {
			return err
		}

		newChunkUUID := uuid.New()

		userlib.DatastoreSet(newChunkUUID, wrappedChunk)

		accessNode.CurrChunkUUID = newChunkUUID
		accessNodeBytes, _ := json.Marshal(accessNode)
		wrappedAccessNode, err := AuthenticatedEncrypt(accessNodeBytes, user.fileEncKey, user.fileMacKey)
		if err != nil {
			return err
		}

		fileInfo, _, _ := user.getFileInfoAndUUID(filename)
		userlib.DatastoreSet(fileInfo.AccessNodeUUID, wrappedAccessNode)

	} else {
		contentEncKey := userlib.RandomBytes(16)
		contentMacKey := userlib.RandomBytes(16)

		var newChunk FileChunk
		newChunk.Content = content
		newChunk.PreChunkUUID = uuid.Nil

		chunkBytes, _ := json.Marshal(newChunk)
		wrappedChunk, err := AuthenticatedEncrypt(chunkBytes, contentEncKey, contentMacKey)
		if err != nil {
			return err
		}

		newChunkUUID := uuid.New()
		userlib.DatastoreSet(newChunkUUID, wrappedChunk)

		var accessNode AccessNode
		accessNode.ContentEncKey = contentEncKey
		accessNode.ContentMacKey = contentMacKey
		accessNode.CurrChunkUUID = newChunkUUID

		accessNodeBytes, _ := json.Marshal(accessNode)
		wrappedAccessNode, err := AuthenticatedEncrypt(accessNodeBytes, user.fileEncKey, user.fileMacKey)
		accessNodeUUID := uuid.New()
		userlib.DatastoreSet(accessNodeUUID, wrappedAccessNode)

		accessManifest := make(map[string]uuid.UUID)
		accessManifest[user.userName] = accessNodeUUID

		shareTree := make(map[string][]string)

		var fileMetadata FileMetadata
		fileMetadata.Owner = user.userName
		fileMetadata.AccessManifest = accessManifest
		fileMetadata.ShareTree = shareTree

		metadataBytes, _ := json.Marshal(fileMetadata)
		wrappedMeta, err := AuthenticatedEncrypt(metadataBytes, user.fileEncKey, user.fileMacKey)
		if err != nil {
			return err
		}

		metadataUUID := uuid.New()
		userlib.DatastoreSet(metadataUUID, wrappedMeta)

		var fileInfo FileInfo
		fileInfo.IsOwner = true
		fileInfo.AccessNodeUUID = accessNodeUUID
		fileInfo.MetadataUUID = metadataUUID

		fileInfoBytes, _ := json.Marshal(fileInfo)
		wrappedFileInfo, err := AuthenticatedEncrypt(fileInfoBytes, user.fileEncKey, user.fileMacKey)
		if err != nil {
			return err
		}

		fileInfoUUID := uuid.New()
		userlib.DatastoreSet(fileInfoUUID, wrappedFileInfo)

		fileIndex[filenameHash] = fileInfoUUID
		fileIndexBytes, _ := json.Marshal((fileIndex))
		wrappedFileIndex, err := AuthenticatedEncrypt(fileIndexBytes, user.fileEncKey, user.fileMacKey)
		if err != nil {
			return err
		}

		fileIndexUUID, _ := uuid.FromBytes(userlib.Hash([]byte(user.userName + "fileIndex"))[:16])
		userlib.DatastoreSet(fileIndexUUID, wrappedFileIndex)
	}

	return nil
}

/*
*
Given a filename in the personal namespace of the caller,
this function downloads and returns the content of the corresponding file.
*/
func (user *User) LoadFile(filename string) (content []byte, err error) {
	accessNode, err := user.getAccessNode(filename)
	if err != nil {
		return nil, err
	}

	currChunkUUID := accessNode.CurrChunkUUID

	for currChunkUUID != uuid.Nil {
		wrappedCurrChunk, ok := userlib.DatastoreGet(currChunkUUID)
		if !ok {
			return nil, errors.New("cannot find the chunk in datastore")
		}

		currChunkBytes, err := AuthenticatedDecrypt(wrappedCurrChunk, accessNode.ContentEncKey, accessNode.ContentMacKey)
		if err != nil {
			return nil, err
		}

		var currChunk FileChunk
		_ = json.Unmarshal(currChunkBytes, &currChunk)

		content = append(currChunk.Content, content...)

		currChunkUUID = currChunk.PreChunkUUID
	}

	return content, nil
}

/*
*
Given a filename in the personal namespace of the caller,
this function appends the given content to the end of the corresponding file.
*/
func (user *User) AppendToFile(filename string, content []byte) (err error) {
	accessNode, err := user.getAccessNode(filename)
	if err != nil {
		return err
	}

	var newChunk FileChunk
	newChunk.Content = content
	newChunk.PreChunkUUID = accessNode.CurrChunkUUID

	newChunkBytes, _ := json.Marshal(newChunk)
	wrappedNewChunk, _ := AuthenticatedEncrypt(newChunkBytes, accessNode.ContentEncKey, accessNode.ContentMacKey)

	newChunkUUID := uuid.New()
	userlib.DatastoreSet(newChunkUUID, wrappedNewChunk)

	accessNode.CurrChunkUUID = newChunkUUID
	accessNodeBytes, _ := json.Marshal(accessNode)

	wrappedAccessNode, err := AuthenticatedEncrypt(accessNodeBytes, user.fileEncKey, user.fileMacKey)
	if err != nil {
		return err
	}

	fileInfo, _, _ := user.getFileInfoAndUUID(filename)
	userlib.DatastoreSet(fileInfo.AccessNodeUUID, wrappedAccessNode)

	return nil
}
