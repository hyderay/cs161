package client

import (
	"encoding/hex"
	"encoding/json"
	"errors"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"
)

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
		fileInfo, _, err := user.getFileInfoAndUUID(filename)
		if err != nil {
			return err
		}

		if fileInfo.OwnerUsername == user.userName {
			err = user.syncInbox(fileInfo)
			if err != nil {
				return err
			}
		}

		accessNode, err := user.getAccessNode(filename)
		if err != nil {
			return err
		}

		var newChunk FileChunk
		newChunk.Content = content
		newChunk.PreChunkUUID = uuid.Nil
		chunkBytes, err := json.Marshal(newChunk)
		if err != nil {
			return err
		}
		wrappedChunk, err := authenticatedEncrypt(chunkBytes, accessNode.ContentEncKey, accessNode.ContentMacKey)
		if err != nil {
			return err
		}

		newChunkUUID := uuid.New()
		userlib.DatastoreSet(newChunkUUID, wrappedChunk)

		var fileHeader FileHeader
		fileHeader.CurrChunkUUID = newChunkUUID
		fileHeaderBytes, err := json.Marshal(fileHeader)
		if err != nil {
			return err
		}
		userlib.DatastoreSet(fileInfo.FileHeaderUUID, fileHeaderBytes)

		accessNodeBytes, err := json.Marshal(accessNode)
		if err != nil {
			return nil
		}
		wrappedAccessNode, err := authenticatedEncrypt(accessNodeBytes, user.fileEncKey, user.fileMacKey)
		if err != nil {
			return err
		}

		userlib.DatastoreSet(fileInfo.AccessNodeUUID, wrappedAccessNode)

	} else {
		contentEncKey := userlib.RandomBytes(16)
		contentMacKey := userlib.RandomBytes(16)

		var newChunk FileChunk
		newChunk.Content = content
		newChunk.PreChunkUUID = uuid.Nil

		chunkBytes, _ := json.Marshal(newChunk)
		wrappedChunk, err := authenticatedEncrypt(chunkBytes, contentEncKey, contentMacKey)
		if err != nil {
			return err
		}

		newChunkUUID := uuid.New()
		userlib.DatastoreSet(newChunkUUID, wrappedChunk)

		var fileHeader FileHeader
		fileHeader.CurrChunkUUID = newChunkUUID
		fileHeaderBytes, err := json.Marshal(fileHeader)
		if err != nil {
			return err
		}
		fileHeaderUUID := uuid.New()
		userlib.DatastoreSet(fileHeaderUUID, fileHeaderBytes)

		var accessNode AccessNode
		accessNode.ContentEncKey = contentEncKey
		accessNode.ContentMacKey = contentMacKey

		accessNodeBytes, _ := json.Marshal(accessNode)
		wrappedAccessNode, err := authenticatedEncrypt(accessNodeBytes, user.fileEncKey, user.fileMacKey)
		if err != nil {
			return err
		}
		accessNodeUUID := uuid.New()
		userlib.DatastoreSet(accessNodeUUID, wrappedAccessNode)

		inboxUUID := uuid.New()
		emptyInboxBytes, _ := json.Marshal([][]byte{})
		userlib.DatastoreSet(inboxUUID, emptyInboxBytes)

		accessManifest := make(map[string]uuid.UUID)

		shareTree := make(map[string][]string)

		var fileMetadata FileMetadata
		fileMetadata.AccessManifest = accessManifest
		fileMetadata.ShareTree = shareTree

		metadataBytes, _ := json.Marshal(fileMetadata)
		wrappedMeta, err := authenticatedEncrypt(metadataBytes, user.fileEncKey, user.fileMacKey)
		if err != nil {
			return err
		}

		metadataUUID := uuid.New()
		userlib.DatastoreSet(metadataUUID, wrappedMeta)

		var fileInfo FileInfo
		fileInfo.AccessNodeUUID = accessNodeUUID
		fileInfo.MetadataUUID = metadataUUID
		fileInfo.OwnerUsername = user.userName
		fileInfo.InboxUUID = inboxUUID
		fileInfo.FileHeaderUUID = fileHeaderUUID

		fileInfoBytes, _ := json.Marshal(fileInfo)
		wrappedFileInfo, err := authenticatedEncrypt(fileInfoBytes, user.fileEncKey, user.fileMacKey)
		if err != nil {
			return err
		}

		fileInfoUUID := uuid.New()
		userlib.DatastoreSet(fileInfoUUID, wrappedFileInfo)

		fileIndex[filenameHash] = fileInfoUUID
		fileIndexBytes, _ := json.Marshal((fileIndex))
		wrappedFileIndex, err := authenticatedEncrypt(fileIndexBytes, user.fileEncKey, user.fileMacKey)
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
	fileInfo, _, err := user.getFileInfoAndUUID(filename)
	if err != nil {
		return nil, err
	}

	accessNode, err := user.getAccessNode(filename)
	if err != nil {
		return nil, err
	}

	fileHeaderBytes, ok := userlib.DatastoreGet(fileInfo.FileHeaderUUID)
	if !ok {
		return nil, errors.New("cannot find the file header")
	}
	var fileHeader FileHeader
	err = json.Unmarshal(fileHeaderBytes, &fileHeader)
	if err != nil {
		return nil, err
	}
	currChunkUUID := fileHeader.CurrChunkUUID

	for currChunkUUID != uuid.Nil {
		wrappedCurrChunk, ok := userlib.DatastoreGet(currChunkUUID)
		if !ok {
			return nil, errors.New("cannot find the chunk in datastore")
		}

		currChunkBytes, err := authenticatedDecrypt(wrappedCurrChunk, accessNode.ContentEncKey, accessNode.ContentMacKey)
		if err != nil {
			return nil, err
		}

		var currChunk FileChunk
		err = json.Unmarshal(currChunkBytes, &currChunk)
		if err != nil {
			return nil, err
		}

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
	fileInfo, _, err := user.getFileInfoAndUUID(filename)
	if err != nil {
		return err
	}

	if fileInfo.OwnerUsername == user.userName {
		err = user.syncInbox(fileInfo)
		if err != nil {
			return err
		}
	}

	accessNode, err := user.getAccessNode(filename)
	if err != nil {
		return err
	}

	fileHeaderBytes, ok := userlib.DatastoreGet(fileInfo.FileHeaderUUID)
	if !ok {
		return errors.New("cannot find the file header")
	}
	var fileHeader FileHeader
	err = json.Unmarshal(fileHeaderBytes, &fileHeader)
	if err != nil {
		return err
	}

	var newChunk FileChunk
	newChunk.Content = content
	newChunk.PreChunkUUID = fileHeader.CurrChunkUUID

	newChunkBytes, _ := json.Marshal(newChunk)
	wrappedNewChunk, err := authenticatedEncrypt(newChunkBytes, accessNode.ContentEncKey, accessNode.ContentMacKey)
	if err != nil {
		return err
	}

	newChunkUUID := uuid.New()
	userlib.DatastoreSet(newChunkUUID, wrappedNewChunk)

	fileHeader.CurrChunkUUID = newChunkUUID
	fileHeaderBytes, err = json.Marshal(fileHeader)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(fileInfo.FileHeaderUUID, fileHeaderBytes)
	return nil
}
