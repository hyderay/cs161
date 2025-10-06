package client

import (
	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"
)

type User struct {
	userName     string
	masterSecret []byte
	fileEncKey   []byte
	fileMacKey   []byte
	signKey      userlib.DSSignKey
	decKey       userlib.PKEDecKey
}

type StoreUserData struct {
	UserName string
	Salt     []byte
}

type SecureWrapper struct {
	Data []byte
	Tag  []byte
}

type UserPrivateKeys struct {
	SignKey userlib.DSSignKey
	DecKey  userlib.PKEDecKey
}

type FileChunk struct {
	Content      []byte
	PreChunkUUID uuid.UUID
}

type FileInfo struct {
	OwnerUsername  string
	AccessNodeUUID uuid.UUID
	MetadataUUID   uuid.UUID
	InboxUUID      uuid.UUID
	FileHeaderUUID uuid.UUID
}

type AccessNode struct {
	ContentEncKey []byte
	ContentMacKey []byte
}

type FileMetadata struct {
	AccessManifest map[string]uuid.UUID
	ShareTree      map[string][]string
}

type UpdateRequest struct {
	ParentUsername      string
	ChildUsername       string
	ChildAccessNodeUUID uuid.UUID
}

type HybridEncrypted struct {
	EncryptedKey []byte
	Ciphertext   []byte
}

type Invitation struct {
	AccessNodeUUID uuid.UUID
	InboxUUID      uuid.UUID
	MetadataUUID   uuid.UUID
	OwnerUsername  string
	FileHeaderUUID uuid.UUID
}

type InvitationWrapper struct {
	InvitationBytes []byte
	Signature       []byte
}

type FileHeader struct {
	CurrChunkUUID uuid.UUID
}
