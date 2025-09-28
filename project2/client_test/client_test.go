package client_test

// You MUST NOT change these default imports.  ANY additional imports may
// break the autograder and everyone will be sad.

import (
	// Some imports use an underscore to prevent the compiler from complaining
	// about unused imports.
	_ "encoding/hex"
	_ "errors"
	_ "strconv"
	_ "strings"
	"testing"

	_ "github.com/google/uuid"

	// A "dot" import is used here so that the functions in the ginko and gomega
	// modules can be used without an identifier. For example, Describe() and
	// Expect() instead of ginko.Describe() and gomega.Expect().
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	userlib "github.com/cs161-staff/project2-userlib"

	"github.com/cs161-staff/project2-starter-code/client"
)

func TestSetupAndExecution(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Client Tests")
}

// ================================================
// Global Variables (feel free to add more!)
// ================================================
const defaultPassword = "password"
const emptyString = ""
const contentOne = "Bitcoin is Nick's favorite "
const contentTwo = "digital "
const contentThree = "cryptocurrency!"

// ================================================
// Describe(...) blocks help you organize your tests
// into functional categories. They can be nested into
// a tree-like structure.
// ================================================

var _ = Describe("Client Tests", func() {

	// A few user declarations that may be used for testing. Remember to initialize these before you
	// attempt to use them!
	var alice *client.User
	//var bob *client.User
	//var charles *client.User
	// var doris *client.User
	// var eve *client.User
	// var frank *client.User
	// var grace *client.User
	// var horace *client.User
	// var ira *client.User

	// These declarations may be useful for multi-session testing.
	//var alicePhone *client.User
	var aliceLaptop *client.User
	//var aliceDesktop *client.User

	var err error

	// A bunch of filenames that may be useful.
	aliceFile := "aliceFile.txt"
	// bobFile := "bobFile.txt"
	// charlesFile := "charlesFile.txt"
	// dorisFile := "dorisFile.txt"
	// eveFile := "eveFile.txt"
	// frankFile := "frankFile.txt"
	// graceFile := "graceFile.txt"
	// horaceFile := "horaceFile.txt"
	// iraFile := "iraFile.txt"

	BeforeEach(func() {
		// This runs before each test within this Describe block (including nested tests).
		// Here, we reset the state of Datastore and Keystore so that tests do not interfere with each other.
		// We also initialize
		userlib.DatastoreClear()
		userlib.KeystoreClear()
	})

	Describe("Basic Tests", func() {

		FSpecify("Basic Test: Testing InitUser/GetUser on a single user.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Alice.")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			Expect(aliceLaptop).ToNot(BeNil())
		})

		FSpecify("Basic Test: Testing Single User Store/Load/Append.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentTwo)
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentThree)
			err = alice.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file...")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		FSpecify("Test: Loading or appending to a non-existent file should fail.", func() {
			// Initialize the user
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			// Attempt to load a file that was never created
			userlib.DebugMsg("Attempting to load a non-existent file.")
			_, err := alice.LoadFile("non_existent_file.txt")
			Expect(err).ToNot(BeNil())

			// Attempt to append to a file that was never created
			userlib.DebugMsg("Attempting to append to a non-existent file.")
			err = alice.AppendToFile("non_existent_file.txt", []byte("some content"))
			Expect(err).ToNot(BeNil())
		})
		/*

			Specify("Basic Test: Testing Create/Accept Invite Functionality with multiple users and multiple instances.", func() {
				userlib.DebugMsg("Initializing users Alice (aliceDesktop) and Bob.")
				aliceDesktop, err = client.InitUser("alice", defaultPassword)
				Expect(err).To(BeNil())

				bob, err = client.InitUser("bob", defaultPassword)
				Expect(err).To(BeNil())

				userlib.DebugMsg("Getting second instance of Alice - aliceLaptop")
				aliceLaptop, err = client.GetUser("alice", defaultPassword)
				Expect(err).To(BeNil())

				userlib.DebugMsg("aliceDesktop storing file %s with content: %s", aliceFile, contentOne)
				err = aliceDesktop.StoreFile(aliceFile, []byte(contentOne))
				Expect(err).To(BeNil())

				userlib.DebugMsg("aliceLaptop creating invite for Bob.")
				invite, err := aliceLaptop.CreateInvitation(aliceFile, "bob")
				Expect(err).To(BeNil())

				userlib.DebugMsg("Bob accepting invite from Alice under filename %s.", bobFile)
				err = bob.AcceptInvitation("alice", invite, bobFile)
				Expect(err).To(BeNil())

				userlib.DebugMsg("Bob appending to file %s, content: %s", bobFile, contentTwo)
				err = bob.AppendToFile(bobFile, []byte(contentTwo))
				Expect(err).To(BeNil())

				userlib.DebugMsg("aliceDesktop appending to file %s, content: %s", aliceFile, contentThree)
				err = aliceDesktop.AppendToFile(aliceFile, []byte(contentThree))
				Expect(err).To(BeNil())

				userlib.DebugMsg("Checking that aliceDesktop sees expected file data.")
				data, err := aliceDesktop.LoadFile(aliceFile)
				Expect(err).To(BeNil())
				Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

				userlib.DebugMsg("Checking that aliceLaptop sees expected file data.")
				data, err = aliceLaptop.LoadFile(aliceFile)
				Expect(err).To(BeNil())
				Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

				userlib.DebugMsg("Checking that Bob sees expected file data.")
				data, err = bob.LoadFile(bobFile)
				Expect(err).To(BeNil())
				Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

				userlib.DebugMsg("Getting third instance of Alice - alicePhone.")
				alicePhone, err = client.GetUser("alice", defaultPassword)
				Expect(err).To(BeNil())

				userlib.DebugMsg("Checking that alicePhone sees Alice's changes.")
				data, err = alicePhone.LoadFile(aliceFile)
				Expect(err).To(BeNil())
				Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
			})

			Specify("Basic Test: Testing Revoke Functionality", func() {
				userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
				alice, err = client.InitUser("alice", defaultPassword)
				Expect(err).To(BeNil())

				bob, err = client.InitUser("bob", defaultPassword)
				Expect(err).To(BeNil())

				charles, err = client.InitUser("charles", defaultPassword)
				Expect(err).To(BeNil())

				userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
				alice.StoreFile(aliceFile, []byte(contentOne))

				userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)

				invite, err := alice.CreateInvitation(aliceFile, "bob")
				Expect(err).To(BeNil())

				err = bob.AcceptInvitation("alice", invite, bobFile)
				Expect(err).To(BeNil())

				userlib.DebugMsg("Checking that Alice can still load the file.")
				data, err := alice.LoadFile(aliceFile)
				Expect(err).To(BeNil())
				Expect(data).To(Equal([]byte(contentOne)))

				userlib.DebugMsg("Checking that Bob can load the file.")
				data, err = bob.LoadFile(bobFile)
				Expect(err).To(BeNil())
				Expect(data).To(Equal([]byte(contentOne)))

				userlib.DebugMsg("Bob creating invite for Charles for file %s, and Charlie accepting invite under name %s.", bobFile, charlesFile)
				invite, err = bob.CreateInvitation(bobFile, "charles")
				Expect(err).To(BeNil())

				err = charles.AcceptInvitation("bob", invite, charlesFile)
				Expect(err).To(BeNil())

				userlib.DebugMsg("Checking that Bob can load the file.")
				data, err = bob.LoadFile(bobFile)
				Expect(err).To(BeNil())
				Expect(data).To(Equal([]byte(contentOne)))

				userlib.DebugMsg("Checking that Charles can load the file.")
				data, err = charles.LoadFile(charlesFile)
				Expect(err).To(BeNil())
				Expect(data).To(Equal([]byte(contentOne)))

				userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile)
				err = alice.RevokeAccess(aliceFile, "bob")
				Expect(err).To(BeNil())

				userlib.DebugMsg("Checking that Alice can still load the file.")
				data, err = alice.LoadFile(aliceFile)
				Expect(err).To(BeNil())
				Expect(data).To(Equal([]byte(contentOne)))

				userlib.DebugMsg("Checking that Bob/Charles lost access to the file.")
				_, err = bob.LoadFile(bobFile)
				Expect(err).ToNot(BeNil())

				_, err = charles.LoadFile(charlesFile)
				Expect(err).ToNot(BeNil())

				userlib.DebugMsg("Checking that the revoked users cannot append to the file.")
				err = bob.AppendToFile(bobFile, []byte(contentTwo))
				Expect(err).ToNot(BeNil())

				err = charles.AppendToFile(charlesFile, []byte(contentTwo))
				Expect(err).ToNot(BeNil())
			})
		*/
	})

	Describe("Security and Integrity Tests for User.go", func() {

		FSpecify("Test: Tampering with a user's StoredUserData in Datastore should prevent login.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			_, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Simulating attacker tampering with Alice's user record in Datastore.")
			err = client.TamperWithUserData("alice")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice attempting to log in with the correct password but tampered data.")
			alice, err = client.GetUser("alice", defaultPassword)

			Expect(err).ToNot(BeNil())
			Expect(alice).To(BeNil())
			userlib.DebugMsg("Successfully detected tampering: GetUser failed as expected.")
		})
	})

	Describe("File Operation Integrity Tests", func() {

		FSpecify("Test: Tampering with the file index should be detected by LoadFile.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			aliceFile := "aliceFile.txt"
			userlib.DebugMsg("Alice storing a file, which creates a file index.")
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("INTEGRATION: Calling attack to tamper with the file index.")
			err = client.TamperWithFileIndex("alice")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice attempting to load a file using the now-corrupted index.")
			_, err = alice.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil()) // This MUST fail!
			userlib.DebugMsg("SUCCESS: LoadFile failed as expected, detecting the tampering.")
		})

		FSpecify("Test: Tampering with a file chunk should be detected by LoadFile.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			aliceFile := "aliceFile.txt"
			userlib.DebugMsg("Alice storing a file, which creates a content chunk.")
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("INTEGRATION: Calling attack to tamper with the file chunk.")
			err = client.TamperWithFileChunk("alice")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice attempting to load the file with a corrupted chunk.")
			_, err = alice.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil()) // This MUST fail!
			userlib.DebugMsg("SUCCESS: LoadFile failed as expected, detecting the tampering.")
		})

		FSpecify("Test: Tampering with a FileInfo metadata block should be detected.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing a file, which creates a FileInfo struct.")
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("INTEGRATION: Calling attack to tamper with the FileInfo.")
			// FIXED: Removed the unused filename parameter from the call.
			err = client.TamperWithFileInfo("alice")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice attempting to load the file using the corrupted FileInfo.")
			_, err = alice.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())
			userlib.DebugMsg("SUCCESS: LoadFile failed as expected, detecting the tampering.")
		})

		FSpecify("Test: Tampering with an AccessNode should be detected by LoadFile.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing a file, which creates an AccessNode.")
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("INTEGRATION: Calling attack to tamper with the AccessNode.")
			err = client.TamperWithAccessNode("alice")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice attempting to load the file using the corrupted AccessNode.")
			_, err = alice.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil()) // This MUST fail!
			userlib.DebugMsg("SUCCESS: LoadFile failed as expected, detecting the tampering.")
		})
	})
})
