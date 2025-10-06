package client

import (
	"encoding/hex"
	"encoding/json"
	"errors"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"
)

func (user *User) CreateInvitation(filename string, recipientName string) (invitationPtr uuid.UUID, err error) {
	fileInfo, _, err := user.getFileInfoAndUUID(filename)
	if err != nil {
		return uuid.Nil, err
	}

	accessNode, err := user.getAccessNode(filename)
	if err != nil {
		return uuid.Nil, err
	}

	recipientPBKey, ok := userlib.KeystoreGet(recipientName + "_PKE")
	if !ok {
		return uuid.Nil, errors.New("cannot find the recipient's public key")
	}

	var recipientAccessNode AccessNode
	recipientAccessNode.ContentEncKey = accessNode.ContentEncKey
	recipientAccessNode.ContentMacKey = accessNode.ContentMacKey

	reACNodeBytes, err := json.Marshal(recipientAccessNode)
	if err != nil {
		return uuid.Nil, err
	}

	hybridEncryptBytes, err := hybridEncrypt(reACNodeBytes, recipientPBKey)
	if err != nil {
		return uuid.Nil, err
	}

	reACNodeUUID := uuid.New()
	userlib.DatastoreSet(reACNodeUUID, hybridEncryptBytes)

	if fileInfo.OwnerUsername == user.userName {
		metadata, err := user.getFileMetadata(fileInfo)
		if err != nil {
			return uuid.Nil, err
		}

		metadata.AccessManifest[recipientName] = reACNodeUUID
		metadata.ShareTree[user.userName] = append(metadata.ShareTree[user.userName], recipientName)

		metadataBytes, err := json.Marshal(metadata)
		if err != nil {
			return uuid.Nil, err
		}
		wrappedMetadata, err := authenticatedEncrypt(metadataBytes, user.fileEncKey, user.fileMacKey)
		if err != nil {
			return uuid.Nil, err
		}
		userlib.DatastoreSet(fileInfo.MetadataUUID, wrappedMetadata)

	} else {
		var request UpdateRequest
		request.ParentUsername = user.userName
		request.ChildUsername = recipientName
		request.ChildAccessNodeUUID = reACNodeUUID

		requestBytes, err := json.Marshal(request)
		if err != nil {
			return uuid.Nil, err
		}

		ownerPubKey, ok := userlib.KeystoreGet(fileInfo.OwnerUsername + "_PKE")
		if !ok {
			return uuid.Nil, errors.New("cannot find owner's public key")
		}

		hybridEncryptBytes, err := hybridEncrypt(requestBytes, ownerPubKey)
		if err != nil {
			return uuid.Nil, err
		}

		inboxBytes, ok := userlib.DatastoreGet(fileInfo.InboxUUID)
		if !ok {
			return uuid.Nil, errors.New("cannot find the inbox for this file")
		}
		var inboxData [][]byte
		err = json.Unmarshal(inboxBytes, &inboxData)
		if err != nil {
			return uuid.Nil, err
		}
		inboxData = append(inboxData, hybridEncryptBytes)
		newInboxBytes, err := json.Marshal(inboxData)
		if err != nil {
			return uuid.Nil, err
		}
		userlib.DatastoreSet(fileInfo.InboxUUID, newInboxBytes)
	}

	var invitation Invitation
	invitation.AccessNodeUUID = reACNodeUUID
	invitation.InboxUUID = fileInfo.InboxUUID
	invitation.MetadataUUID = fileInfo.MetadataUUID
	invitation.OwnerUsername = fileInfo.OwnerUsername
	invitation.FileHeaderUUID = fileInfo.FileHeaderUUID

	invitationBytes, err := json.Marshal(invitation)
	if err != nil {
		return uuid.Nil, err
	}
	wrappedInvitation, err := hybridEncrypt(invitationBytes, recipientPBKey)
	if err != nil {
		return uuid.Nil, err
	}
	signature, err := userlib.DSSign(user.signKey, wrappedInvitation)
	if err != nil {
		return uuid.Nil, err
	}

	var invitationWrapper InvitationWrapper
	invitationWrapper.WrappedInvitation = wrappedInvitation
	invitationWrapper.Signature = signature

	inviWrapperBytes, err := json.Marshal(invitationWrapper)
	if err != nil {
		return uuid.Nil, err
	}
	invitationPtr = uuid.New()
	userlib.DatastoreSet(invitationPtr, inviWrapperBytes)

	return invitationPtr, nil
}

func (user *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) (err error) {
	fileIndex, err := user.getFileIndex()
	if err != nil {
		return err
	}

	filenameHash := hex.EncodeToString(userlib.Hash([]byte(filename)))
	_, ok := fileIndex[filenameHash]
	if ok {
		return errors.New("a file with name already exists")
	}

	invitationWrapperBytes, ok := userlib.DatastoreGet(invitationPtr)
	if !ok {
		return errors.New("there is something wrong with the given invitationPtr")
	}
	var invitationWrapper InvitationWrapper
	err = json.Unmarshal(invitationWrapperBytes, &invitationWrapper)
	if err != nil {
		return err
	}

	DSVerifyKey, ok := userlib.KeystoreGet(senderUsername + "_DSVerify")
	if !ok {
		return errors.New("cannot get the sender's signature key")
	}
	err = userlib.DSVerify(DSVerifyKey, invitationWrapper.WrappedInvitation, invitationWrapper.Signature)
	if err != nil {
		return err
	}

	invitationBytes, err := hybridDecrypt(invitationWrapper.WrappedInvitation, user.decKey)
	if err != nil {
		return err
	}

	var invitation Invitation
	err = json.Unmarshal(invitationBytes, &invitation)
	if err != nil {
		return err
	}

	var fileInfo FileInfo
	fileInfo.AccessNodeUUID = invitation.AccessNodeUUID
	fileInfo.InboxUUID = invitation.InboxUUID
	fileInfo.MetadataUUID = invitation.MetadataUUID
	fileInfo.OwnerUsername = invitation.OwnerUsername
	fileInfo.FileHeaderUUID = invitation.FileHeaderUUID

	fileInfoBytes, err := json.Marshal(fileInfo)
	if err != nil {
		return err
	}
	wrappedFileInfo, err := authenticatedEncrypt(fileInfoBytes, user.fileEncKey, user.fileMacKey)
	if err != nil {
		return err
	}

	fileInfoUUID := uuid.New()
	userlib.DatastoreSet(fileInfoUUID, wrappedFileInfo)

	fileIndex[filenameHash] = fileInfoUUID
	fileIndexBytes, err := json.Marshal(fileIndex)
	if err != nil {
		return err
	}
	wrappedFileIndex, err := authenticatedEncrypt(fileIndexBytes, user.fileEncKey, user.fileMacKey)
	if err != nil {
		return err
	}

	fileIndexUUID, _ := uuid.FromBytes(userlib.Hash([]byte(user.userName + "fileIndex"))[:16])
	userlib.DatastoreSet(fileIndexUUID, wrappedFileIndex)

	return nil
}

func (user *User) RevokeAccess(filename string, recipientUsername string) (err error) {
	fileInfo, _, err := user.getFileInfoAndUUID(filename)
	if err != nil {
		return err
	}

	err = user.syncInbox(fileInfo)
	if err != nil {
		return err
	}

	filemetaData, err := user.getFileMetadata(fileInfo)
	if err != nil {
		return err
	}

	revokedUser := make(map[string]bool)
	queue := []string{recipientUsername}

	_, ok := filemetaData.AccessManifest[recipientUsername]
	if !ok {
		return errors.New("this file is not shared with this user")
	}

	for len(queue) != 0 {
		nextRevoked := queue[0]
		queue = queue[1:]
		revokedUser[nextRevoked] = true
		linkedUsers := filemetaData.ShareTree[nextRevoked]

		for _, linkUser := range linkedUsers {
			if !revokedUser[linkUser] {
				queue = append(queue, linkUser)
			}
		}
	}

	fileContent, err := user.LoadFile(filename)
	if err != nil {
		return err
	}

	newContentEncKey := userlib.RandomBytes(16)
	newContentMacKey := userlib.RandomBytes(16)

	var chunk FileChunk
	chunk.Content = fileContent
	chunk.PreChunkUUID = uuid.Nil
	chunkBytes, _ := json.Marshal(chunk)
	wrappedChunk, err := authenticatedEncrypt(chunkBytes, newContentEncKey, newContentMacKey)
	if err != nil {
		return err
	}
	chunkUUID := uuid.New()
	userlib.DatastoreSet(chunkUUID, wrappedChunk)

	var accessNode AccessNode
	accessNode.ContentEncKey = newContentEncKey
	accessNode.ContentMacKey = newContentMacKey
	accessNodeBytes, _ := json.Marshal(accessNode)
	wrappedAccessNode, err := authenticatedEncrypt(accessNodeBytes, user.fileEncKey, user.fileMacKey)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(fileInfo.AccessNodeUUID, wrappedAccessNode)

	var fileHeader FileHeader
	fileHeader.CurrChunkUUID = chunkUUID
	fileHeaderBytes, err := json.Marshal(fileHeader)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(fileInfo.FileHeaderUUID, fileHeaderBytes)

	accessManifest := make(map[string]uuid.UUID)
	shareTree := make(map[string][]string)

	for otherUser, userAdUUID := range filemetaData.AccessManifest {
		if !revokedUser[otherUser] {
			accessManifest[otherUser] = userAdUUID
			recipientPBKey, ok := userlib.KeystoreGet(otherUser + "_PKE")
			if !ok {
				return errors.New("cannot find this user's public key")
			}
			wrappedAccessNode, err = hybridEncrypt(accessNodeBytes, recipientPBKey)
			if err != nil {
				return err
			}
			userlib.DatastoreSet(userAdUUID, wrappedAccessNode)
		} else {
			userlib.DatastoreDelete(userAdUUID)
		}
	}

	for parent, children := range filemetaData.ShareTree {
		if !revokedUser[parent] {
			var newChildren []string
			for _, child := range children {
				if !revokedUser[child] {
					newChildren = append(newChildren, child)
				}
			}
			if len(newChildren) != 0 {
				shareTree[parent] = newChildren
			}
		}
	}

	var newMetadata FileMetadata
	newMetadata.AccessManifest = accessManifest
	newMetadata.ShareTree = shareTree
	newMetadataBytes, _ := json.Marshal(newMetadata)
	wrappedNewMeta, err := authenticatedEncrypt(newMetadataBytes, user.fileEncKey, user.fileMacKey)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(fileInfo.MetadataUUID, wrappedNewMeta)

	return nil
}
