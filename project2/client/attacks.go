package client

import (
	"encoding/json"
	"errors"

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
