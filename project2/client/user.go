package client

import (
	"encoding/json"
	"errors"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"
)

func InitUser(userName string, password string) (user *User, err error) {
	if userName == "" {
		return nil, errors.New("username cannot be empty")
	}

	var userUUID uuid.UUID
	userUUID, err = deriveUserUUID(userName)
	if err != nil {
		return nil, err
	}
	if _, ok := userlib.DatastoreGet(userUUID); ok {
		return nil, errors.New("user already exists")
	}

	salt := userlib.RandomBytes(16)

	masterSecret := userlib.Argon2Key([]byte(password), salt, 16)

	userData := StoreUserData{
		UserName: userName,
		Salt:     salt,
	}

	var userDataBytes []byte
	userDataBytes, err = json.Marshal(userData)
	if err != nil {
		return nil, err
	}

	var tag []byte
	tag, err = userlib.HMACEval(masterSecret, userDataBytes)
	if err != nil {
		return nil, err
	}

	wrapper := SecureWrapper{
		Data: userDataBytes,
		Tag:  tag,
	}

	var wrapperBytes []byte
	wrapperBytes, err = json.Marshal(wrapper)
	if err != nil {
		return nil, err
	}

	userlib.DatastoreSet(userUUID, wrapperBytes)

	var newUser *User
	newUser = &User{
		userName:     userName,
		masterSecret: masterSecret,
	}

	var fileEncKey []byte
	fileEncKey, err = userlib.HashKDF(masterSecret, []byte("file-enc-key"))
	if err != nil {
		return nil, err
	}
	fileEncKey = fileEncKey[:16]
	newUser.fileEncKey = fileEncKey

	var fileMacKey []byte
	fileMacKey, err = userlib.HashKDF(masterSecret, []byte("file-mac-key"))
	if err != nil {
		return nil, err
	}
	fileMacKey = fileMacKey[:16]
	newUser.fileMacKey = fileMacKey

	signKey, verifyKey, err := userlib.DSKeyGen()
	if err != nil {
		return nil, err
	}
	encKey, decKey, err := userlib.PKEKeyGen()
	if err != nil {
		return nil, err
	}

	err = userlib.KeystoreSet(userName+"_DSVerify", verifyKey)
	if err != nil {
		return nil, err
	}
	err = userlib.KeystoreSet(userName+"_PKE", encKey)
	if err != nil {
		return nil, err
	}

	privateKeysUUID, err := uuid.FromBytes(userlib.Hash([]byte(userName + "private-keys"))[:16])
	if err != nil {
		return nil, err
	}

	var userPrivateKeys UserPrivateKeys
	userPrivateKeys.DecKey = decKey
	userPrivateKeys.SignKey = signKey

	userPrivateKeyBytes, err := json.Marshal(userPrivateKeys)
	if err != nil {
		return nil, err
	}

	wrapperUserPriBytes, err := authenticatedEncrypt(userPrivateKeyBytes, fileEncKey, fileMacKey)
	if err != nil {
		return nil, err
	}

	userlib.DatastoreSet(privateKeysUUID, wrapperUserPriBytes)

	newUser.decKey = decKey
	newUser.signKey = signKey

	return newUser, nil
}

func GetUser(username string, password string) (user *User, err error) {
	var UUID uuid.UUID
	UUID, err = deriveUserUUID(username)
	if err != nil {
		return nil, err
	}

	var wrapperBytes []byte
	var ok bool
	wrapperBytes, ok = userlib.DatastoreGet(UUID)
	if !ok {
		err = errors.New("incorrect username")
		return nil, err
	}

	var wrapper SecureWrapper
	err = json.Unmarshal(wrapperBytes, &wrapper)
	if err != nil {
		return nil, err
	}

	var userdata StoreUserData
	err = json.Unmarshal(wrapper.Data, &userdata)
	if err != nil {
		return nil, err
	}

	salt := userdata.Salt

	masterSecret := userlib.Argon2Key([]byte(password), salt, 16)

	var expectedTag []byte
	expectedTag, err = userlib.HMACEval(masterSecret, wrapper.Data)
	if err != nil {
		return nil, err
	}

	ok = userlib.HMACEqual(expectedTag, wrapper.Tag)
	if !ok {
		err = errors.New("incorrect password")
		return nil, err
	}

	user = &User{
		userName:     username,
		masterSecret: masterSecret,
	}

	var fileEncKey []byte
	fileEncKey, err = userlib.HashKDF(masterSecret, []byte("file-enc-key"))
	if err != nil {
		return nil, err
	}
	fileEncKey = fileEncKey[:16]
	user.fileEncKey = fileEncKey

	var fileMacKey []byte
	fileMacKey, err = userlib.HashKDF(masterSecret, []byte("file-mac-key"))
	if err != nil {
		return nil, err
	}
	fileMacKey = fileMacKey[:16]
	user.fileMacKey = fileMacKey

	userPriKeysUUID, err := uuid.FromBytes(userlib.Hash([]byte(username + "private-keys"))[:16])
	if err != nil {
		return nil, err
	}

	wrapperUserPriBytes, ok := userlib.DatastoreGet(userPriKeysUUID)
	if !ok {
		err = errors.New("user does not have private keys")
		return nil, err
	}

	userPriKeysBytes, err := authenticatedDecrypt(wrapperUserPriBytes, fileEncKey, fileMacKey)
	if err != nil {
		return nil, err
	}

	var userPrivateKeys UserPrivateKeys
	err = json.Unmarshal(userPriKeysBytes, &userPrivateKeys)
	if err != nil {
		return nil, err
	}

	user.decKey = userPrivateKeys.DecKey
	user.signKey = userPrivateKeys.SignKey

	return user, nil
}
