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
	ContentEncKey []byte
	ContentMacKey []byte
	CurrChunkUUID uuid.UUID
}

func AuthenticatedEncrypt(data []byte, encKey []byte, macKey []byte) (wrappedBytes []byte, err error) {
	var iv []byte
	iv = userlib.RandomBytes(16)

	var ciphertext []byte
	ciphertext = userlib.SymEnc(encKey, iv, data)

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

	var ciphertext []byte
	ciphertext = wrapper.Data

	var expectedTag []byte
	expectedTag, err = userlib.HMACEval(macKey, ciphertext)
	if err != nil {
		return nil, err
	}

	var ok bool
	ok = userlib.HMACEqual(wrapper.Tag, expectedTag)
	if !ok {
		return nil, errors.New("Data was tempered.")
	}

	return userlib.SymDec(encKey, ciphertext), nil
}

/*
*
This instance method is used to both create a file for the first time,
or to overwrite an existing file entirely with new contents.
To use this method, the user passes in the filename to identify the file,
as well as the contents that they wish to store.
*/
func (user *User) StoreFile(filename string, content []byte) (err error) {
	var fileIndexUUID uuid.UUID
	fileIndexUUID, err = uuid.FromBytes(userlib.Hash([]byte(user.userName + "fileIndex"))[:16])
	if err != nil {
		return err
	}

	fileIndex := make(map[string]uuid.UUID)
	wrapperIndexBytes, ok := userlib.DatastoreGet(fileIndexUUID)
	if ok {
		indexBytes, err := AuthenticatedDecrypt(wrapperIndexBytes, user.fileEncKey, user.fileMacKey)
		if err != nil {
			return err
		}

		err = json.Unmarshal(indexBytes, &fileIndex)
		if err != nil {
			return err
		}
	}

	var chunk FileChunk
	chunk.Content = content
	chunk.PreChunkUUID = uuid.Nil

	chunkBytes, err := json.Marshal(chunk)
	if err != nil {
		return err
	}

	var filenameHash string
	filenameHash = hex.EncodeToString(userlib.Hash([]byte(filename)))
	fileInfoUUID, fileExist := fileIndex[filenameHash]
	var fileInfo FileInfo

	if fileExist {
		wrappedInfo, ok := userlib.DatastoreGet(fileInfoUUID)
		if !ok {
			return errors.New("File info is missing.")
		}

		fileInfoBytes, err := AuthenticatedDecrypt(wrappedInfo, user.fileEncKey, user.fileMacKey)
		if err != nil {
			return err
		}

		err = json.Unmarshal(fileInfoBytes, &fileInfo)
		if err != nil {
			return err
		}
	} else {
		fileInfoUUID = uuid.New()
		fileInfo.ContentEncKey = userlib.RandomBytes(16)
		fileInfo.ContentMacKey = userlib.RandomBytes(16)
	}

	wrappedChunk, err := AuthenticatedEncrypt(chunkBytes, fileInfo.ContentEncKey, fileInfo.ContentEncKey)
	if err != nil {
		return err
	}
	chunkUUID := uuid.New()
	userlib.DatastoreSet(chunkUUID, wrappedChunk)

	fileInfo.CurrChunkUUID = chunkUUID

	fileIndex[filenameHash] = fileInfoUUID

	indexBytes, err := json.Marshal(fileIndex)
	if err != nil {
		return err
	}

	wrappedIndex, err := AuthenticatedEncrypt(indexBytes, user.fileEncKey, user.fileMacKey)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(fileIndexUUID, wrappedIndex)

	return nil
}

/*
*
Given a filename in the personal namespace of the caller,
this function downloads and returns the content of the corresponding file.
*/
func (user *User) LoadFile(filename string) (content []byte, err error) {
	fileIndexUUID, err := uuid.FromBytes(userlib.Hash([]byte(user.userName + "fileIndex"))[:16])
	if err != nil {
		return nil, err
	}

	wrapperIndexBytes, ok := userlib.DatastoreGet(fileIndexUUID)
	if !ok {
		return nil, errors.New("No such file.")
	}

	indexBytes, err := AuthenticatedDecrypt(wrapperIndexBytes, user.fileEncKey, user.fileMacKey)
	if err != nil {
		return nil, err
	}

	var fileIndex map[string]uuid.UUID
	err = json.Unmarshal(indexBytes, &fileIndex)
	if err != nil {
		return nil, err
	}

	filenameHash := hex.EncodeToString(userlib.Hash([]byte(filename)))
	fileInfoUUID, ok := fileIndex[filenameHash]
	if !ok {
		return nil, errors.New("File info is missing.")
	}

	wrappedInfo, ok := userlib.DatastoreGet(fileInfoUUID)
	if !ok {
		return nil, errors.New("Data were tempered.")
	}

	infoBytes, err := AuthenticatedDecrypt(wrappedInfo, user.fileEncKey, user.fileMacKey)
	if err != nil {
		return nil, err
	}

	var fileInfo FileInfo
	err = json.Unmarshal(infoBytes, &fileInfo)
	if err != nil {
		return nil, err
	}

	wrappedChunk, ok := userlib.DatastoreGet(fileInfo.CurrChunkUUID)
	if !ok {
		return nil, errors.New("No chunk info obtained.")
	}

	chunkBytes, err := AuthenticatedDecrypt(wrappedChunk, fileInfo.ContentEncKey, fileInfo.ContentMacKey)
	if err != nil {
		return nil, err
	}

	var chunk FileChunk
	err = json.Unmarshal(chunkBytes, &chunk)
	if err != nil {
		return nil, err
	}

	var currChunkUUID uuid.UUID
	currChunkUUID = chunk.PreChunkUUID

	var fullContent []byte
	fullContent = chunk.Content
	for currChunkUUID != uuid.Nil {
		wrappedChunk, ok = userlib.DatastoreGet(currChunkUUID)
		if !ok {
			return nil, errors.New("Data were tempered.")
		}

		chunkBytes, err = AuthenticatedDecrypt(wrappedChunk, user.fileEncKey, user.fileMacKey)
		if err != nil {
			return nil, err
		}

		err = json.Unmarshal(chunkBytes, &chunk)
		if err != nil {
			return nil, err
		}

		fullContent = append(chunk.Content, fullContent...)
		currChunkUUID = chunk.PreChunkUUID
	}

	return fullContent, nil
}

/*
*
Given a filename in the personal namespace of the caller,
this function appends the given content to the end of the corresponding file.
*/
func (user *User) AppendToFile(filename string, content []byte) (err error) {
	var fileIndexUUID uuid.UUID
	fileIndexUUID, err = uuid.FromBytes(userlib.Hash([]byte(user.userName + "fileIndex"))[:16])
	if err != nil {
		return err
	}

	wrappedIndexBytes, ok := userlib.DatastoreGet(fileIndexUUID)
	if !ok {
		return errors.New("No such file.")
	}

	indexBytes, err := AuthenticatedDecrypt(wrappedIndexBytes, user.fileEncKey, user.fileMacKey)
	if err != nil {
		return err
	}

	var fileIndex map[string]uuid.UUID
	err = json.Unmarshal(indexBytes, &fileIndex)
	if err != nil {
		return err
	}

	filenameHash := hex.EncodeToString(userlib.Hash([]byte(filename)))
	fileInfoUUID, ok := fileIndex[filenameHash]
	if !ok {
		return errors.New("No such file.")
	}

	wrappedFileInfo, ok := userlib.DatastoreGet(fileInfoUUID)
	if !ok {
		return errors.New("File info is missing.")
	}

	fileInfoBytes, err := AuthenticatedDecrypt(wrappedFileInfo, user.fileEncKey, user.fileMacKey)
	if err != nil {
		return err
	}

	var fileInfo FileInfo
	err = json.Unmarshal(fileInfoBytes, &fileInfo)
	if err != nil {
		return err
	}

	var newChunkUUID uuid.UUID
	newChunkUUID = uuid.New()

	var newChunk FileChunk
	newChunk.Content = content
	newChunk.PreChunkUUID = fileInfo.CurrChunkUUID

	chunkBytes, err := json.Marshal(newChunk)
	if err != nil {
		return err
	}

	wrappedChunkBytes, err := AuthenticatedEncrypt(chunkBytes, user.fileEncKey, user.fileMacKey)
	if err != nil {
		return err
	}

	userlib.DatastoreSet(newChunkUUID, wrappedChunkBytes)

	fileInfo.CurrChunkUUID = newChunkUUID
	fileInfoBytes, err = json.Marshal(fileInfo)
	if err != nil {
		return err
	}

	wrappedFileInfo, err = AuthenticatedEncrypt(fileInfoBytes, user.fileEncKey, user.fileMacKey)
	if err != nil {
		return err
	}

	userlib.DatastoreSet(fileInfoUUID, wrappedFileInfo)

	return nil
}
