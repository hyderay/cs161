package client

/**
import (
	"encoding/hex"
	"encoding/json"
	"errors"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"
)

func (user *User) storeFileIndex(fileIndex map[string]uuid.UUID) (err error) {
	fileIndexUUID, err := uuid.FromBytes(userlib.Hash([]byte(user.userName + "fileIndex"))[:16])
	if err != nil { return err }

	fileIndexBytes, err := json.Marshal(fileIndex)
	if err != nil { return err }

	wrappedFileIndex, err := AuthenticatedEncrypt(fileIndexBytes, user.fileEncKey, user.fileMacKey)
	if err != nil { return err }

	userlib.DatastoreSet(fileIndexUUID, wrappedFileIndex)

	return nil
}

func (user *User) getFileInfoAndUUID(filename string) (*FileInfo, uuid.UUID, error) {
	fileIndex, err := user.getFileIndex()
	if err != nil { return nil, uuid.Nil, err }

	filenameHash := hex.EncodeToString(userlib.Hash([]byte(filename)))

	fileInfoUUID, ok := fileIndex[filenameHash]
	if !ok {
		return nil, uuid.Nil, errors.New("File info under this name does not exist.")
	}

	wrappedFileInfo, ok := userlib.DatastoreGet(fileInfoUUID)
	if !ok {
		return nil, uuid.Nil, errors.New("Cannot find file info under this filename.")
	}

	fileInfoBytes, err := AuthenticatedDecrypt(wrappedFileInfo, user.fileEncKey, user.fileMacKey)
	if err != nil { return nil, uuid.Nil, err }

	var fileInfo FileInfo
	err = json.Unmarshal(fileInfoBytes, &fileInfo)
	if err != nil { return nil, uuid.Nil, err }

	return &fileInfo, fileInfoUUID, nil
}

type Invitation struct {
	FileInfoUUID uuid.UUID
	FileEncKey []byte
	FileMacKey []byte
}

type InvitationWrapper struct {
	WrappedInvitation []byte
	Signature []byte
}

func (user *User) CreateInvitation(filename string, recipientUsername string) (invitationPtr uuid.UUID, err error) {
	fileInfo, fileIndexUUID, err := user.getFileInfoAndUUID(filename)
	if err != nil { return uuid.Nil, err }

	publicKey, ok := userlib.KeystoreGet(recipientUsername + "_PKE")
	if !ok {
		return uuid.Nil, errors.New("Recipient user does not exist.")
	}

	var invitation Invitation
	invitation.FileInfoUUID = fileIndexUUID
	invitation.FileEncKey = fileInfo.ContentEncKey
	invitation.FileMacKey = fileInfo.ContentMacKey

	invitationBytes, err := json.Marshal(invitation)
	if err != nil { return uuid.Nil, err }

	wrappedInvitation, err := userlib.PKEEnc(publicKey, invitationBytes)
	if err != nil { return uuid.Nil, err }

	signature, err := userlib.DSSign(user.signKey, wrappedInvitation)
	if err != nil { return uuid.Nil, err }

	var invitationWrapper InvitationWrapper
	invitationWrapper.Signature = signature
	invitationWrapper.WrappedInvitation = wrappedInvitation

	invitationWrapperBytes, err := json.Marshal(invitationWrapper)

	invitationPtr = uuid.New()
	userlib.DatastoreSet(invitationPtr, invitationWrapperBytes)

	return invitationPtr, nil
}

func (user *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) (err error) {
	fileIndex, err := user.getFileIndex()
	if err != nil { return err }

	filenameHash := hex.EncodeToString(userlib.Hash([]byte(filename)))
	_, ok := fileIndex[filenameHash]
	if ok {
		return errors.New("Recipitant already had this file.")
	}

	invitationWrapperBytes, ok := userlib.DatastoreGet(invitationPtr)
	if !ok {
		return errors.New("No such invitation.")
	}

	var invitationWrapper InvitationWrapper
	err = json.Unmarshal(invitationWrapperBytes, &invitationWrapper)
	if err != nil { return err }

	publicVerifyKey, ok := userlib.KeystoreGet(senderUsername + "_DSVerify")
	if !ok {
		return errors.New("Cannot find the sender's DS verify key.")
	}

	err = userlib.DSVerify(publicVerifyKey, invitationWrapper.WrappedInvitation, invitationWrapper.Signature)
	if err != nil { return err }

	invitationBytes, err := userlib.PKEDec(user.decKey, invitationWrapper.WrappedInvitation)
	if err != nil { return err }

	var invitaion Invitation
	err = json.Unmarshal(invitationBytes, &invitaion)
	if err != nil { return err }

	wrappedFileInfo, ok := userlib.DatastoreGet(invitaion.FileInfoUUID)
	if !ok {
		return errors.New("Cannot fetch the file info.")
	}


}
*/
