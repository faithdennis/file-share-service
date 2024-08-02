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

func contains(slice []userlib.UUID, value userlib.UUID) bool {
	for _, item := range slice {
		if item == value {
			return true
		}
	}
	return false
}

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
	var bob *client.User
	var charles *client.User
	// var doris *client.User
	// var eve *client.User
	// var frank *client.User
	// var grace *client.User
	// var horace *client.User
	// var ira *client.User

	// These declarations may be useful for multi-session testing.
	var alicePhone *client.User
	var aliceLaptop *client.User
	var aliceDesktop *client.User
	var maliciousByte = []byte("tamper")

	var err error

	// A bunch of filenames that may be useful.
	aliceFile := "aliceFile.txt"
	bobFile := "bobFile.txt"
	charlesFile := "charlesFile.txt"
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

	// Todo: - integrity check for invitations, append to file

	Describe("Integrity Tests", func() {
		Specify("Integrity Test: Testing InitUser/GetUser", func() {
			var diff userlib.UUID
			db1 := userlib.DatastoreGetMap()
			// Extract keys from db1
			var keys1 []userlib.UUID
			for key := range db1 {
				keys1 = append(keys1, key)
			}

			// Copy keys1 to a new slice using the built-in copy function
			keys1Copy := make([]userlib.UUID, len(keys1))
			copy(keys1Copy, keys1)

			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Get newly created UUID.")
			db2 := userlib.DatastoreGetMap()
			var keys2 []userlib.UUID
			for key := range db2 {
				keys2 = append(keys2, key)
			}

			for _, key := range keys2 {
				if !contains(keys1Copy, key) {
					// Entry was added
					diff = key
				}
			}

			userlib.DebugMsg("New UUID created: %s", diff.String())
			userlib.DebugMsg("Tampering with user Alice.")
			userlib.DatastoreSet(diff, maliciousByte)

			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).ToNot(BeNil())
		})

		Specify("Integrity Test: Testing User.LoadFile", func() {
			var diff userlib.UUID

			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			db1 := userlib.DatastoreGetMap()

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Get newly created UUID.")
			db2 := userlib.DatastoreGetMap()
			for key := range db2 {
				if _, found := db1[key]; !found {
					diff = key
				}
			}

			userlib.DebugMsg("Tampering with Alice's File.")
			userlib.DatastoreSet(diff, maliciousByte)

			data, err := alice.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())
			Expect(data).ToNot(Equal([]byte(contentOne)))

		})
	})

	Describe("All Other Error Tests", func() {

		Specify("InitUser Test: Testing empty string Username returns error", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser(emptyString, defaultPassword)
			Expect(err).ToNot(BeNil())
		})

		Specify("InitUser Test: Testing password with only spaces returns error", func() {
			userlib.DebugMsg("Initializing user with a password that is only spaces.")
			alice, err = client.InitUser("alice", "     ")
			Expect(err).To(BeNil())
		})

		Specify("InitUser Test: Testing same Username/Password returns error", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Alice a second time.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).ToNot(BeNil())
		})

		Specify("InitUser Test: Testing similar Username/Password does not return error", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Alic.")
			aliceLaptop, err = client.InitUser("alic", "epassword")
			Expect(err).To(BeNil())
		})

		Specify("InitUser Test: Testing initializing user with existing username and different password returns error", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Trying to initialize user Alice with a different password.")
			alice, err = client.InitUser("alice", "newPassword")
			Expect(err).ToNot(BeNil())
		})

		Specify("InitUser Test: InitUser but all Caps", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user ALICE with different case.")
			aliceUpper, err := client.InitUser("ALICE", defaultPassword)
			Expect(err).To(BeNil())
			Expect(aliceUpper).ToNot(Equal(alice))
		})

		Specify("InitUser Test: Testing empty username and empty password returns error", func() {
			userlib.DebugMsg("Initializing user with empty username and password.")
			alice, err = client.InitUser("", "")
			Expect(err).ToNot(BeNil())
		})

		Specify("GetUser Test: Testing uninitialized similar user returns error", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Alic.")
			aliceLaptop, err = client.GetUser("alic", "epassword")
			Expect(err).ToNot(BeNil())
		})

		Specify("GetUser Test: Testing invalid credentials returns error", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Alic.")
			alice, err = client.GetUser("alice", emptyString)
			Expect(err).ToNot(BeNil())
		})

		Specify("GetUser Test: empty username returns error", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Retrieving user with empty username.")
			aliceRetrieved, err := client.GetUser("", defaultPassword)
			Expect(err).ToNot(BeNil())
			Expect(aliceRetrieved).To(BeNil())
		})

		Specify("GetUser Test: empty password returns error", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Retrieving user Alice with empty password.")
			aliceRetrieved, err := client.GetUser("alice", "")
			Expect(err).ToNot(BeNil())
			Expect(aliceRetrieved).To(BeNil())
		})

		Specify("StoreFile Test: Storing file with empty content", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing empty Data.")
			err = alice.StoreFile(aliceFile, []byte{})
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading empty file")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte{}))
		})

		Specify("StoreFile Test: Overwrite file data", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile("file2.txt", []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Overwriting file data: %s", contentTwo)
			err = alice.StoreFile("file2.txt", []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file file2.txt")
			data, err := alice.LoadFile("file2.txt")
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentTwo)))
		})

		Specify("StoreFile Test: Attempt to store file with empty filename", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Attempting to store file with empty filename.")
			err = alice.StoreFile(emptyString, []byte(contentOne))
			Expect(err).To(BeNil())
		})

		Specify("LoadFile Test: Testing uninitialized filename returns error", func() {
			userlib.DebugMsg("Initializing Alice.")
			alice, err = client.InitUser("alice", defaultPassword)

			userlib.DebugMsg("Loading file.")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())
			Expect(data).To(BeNil())
		})

		Specify("LoadFile Test: Load a file that was overwritten", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile("file2.txt", []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Overwriting file data: %s", contentTwo)
			err = alice.StoreFile("file2.txt", []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file file2.txt")
			_, err := alice.LoadFile("file2.txt")
			Expect(err).To(BeNil())
		})

		Specify("LoadFile Test: Load file with special characters in filename", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			specialFile := "file_with_!@#$%^&*()_+.txt"

			userlib.DebugMsg("Storing file data with special characters in filename: %s", specialFile)
			err = alice.StoreFile(specialFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file %s", specialFile)
			_, err := alice.LoadFile(specialFile)
			Expect(err).To(BeNil())

		})

		Specify("LoadFile Test: Load a file with empty filename", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file with empty filename.")
			err = alice.StoreFile(emptyString, []byte("Hello, World!"))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file with empty filename")
			_, err = alice.LoadFile(emptyString)
			Expect(err).To(BeNil())
		})

		Specify("LoadFile Test: Load file with empty content", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file with empty content.")
			err = alice.StoreFile("file4.txt", []byte(emptyString))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file file4.txt")
			_, err = alice.LoadFile("file4.txt")
			Expect(err).To(BeNil())
		})

		Specify("AppendToFile Test: Testing uninitialized filename returns error", func() {
			userlib.DebugMsg("Initializing Alice.")
			alice, err = client.InitUser("alice", defaultPassword)

			userlib.DebugMsg("Appending to file.")
			err := alice.AppendToFile(aliceFile, maliciousByte)
			Expect(err).ToNot(BeNil())
		})

		Specify("AppendToFile Test: Append data with special characters in filename", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			specialFile := "file_with_!@#$%^&*()_+.txt"

			userlib.DebugMsg("Storing initial file data.")
			err = alice.StoreFile(specialFile, []byte("Initial Data"))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending to file %s", specialFile)
			err = alice.AppendToFile(specialFile, []byte(" Appended Data"))
			Expect(err).To(BeNil())
		})

		Specify("AppendToFile Test: Append with empty content", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file with initial content.")
			err = alice.StoreFile("file3.txt", []byte("Initial Content"))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending empty content to file file3.txt")
			err = alice.AppendToFile("file3.txt", []byte(emptyString))
			Expect(err).To(BeNil())
		})

		Specify("AppendToFile Test: Append to file with empty filename", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file with initial content.")
			err = alice.StoreFile(emptyString, []byte("Initial Content"))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending to file with empty filename")
			err = alice.AppendToFile(emptyString, []byte(" Appended Data"))
			Expect(err).To(BeNil())
		})

		Specify("AppendToFile Test: Ensure bandwidth scales only with append size", func() {

			measureBandwidth := func(probe func()) (bandwidth int) {
				before := userlib.DatastoreGetBandwidth()
				probe()
				after := userlib.DatastoreGetBandwidth()
				return after - before
			}

			userlib.DebugMsg("BANDWIDTH: Initializing user Alice.")
			alice, err := client.InitUser("alice", "password")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing initial file.")
			err = alice.StoreFile("testfile", []byte("initial content"))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Measuring bandwidth for appending 1 byte.")
			bandwidth1Byte := measureBandwidth(func() {
				err = alice.AppendToFile("testfile", []byte("a"))
				Expect(err).To(BeNil())
			})

			userlib.DebugMsg("Measuring bandwidth for appending 100 bytes.")
			bandwidth100Bytes := measureBandwidth(func() {
				err = alice.AppendToFile("testfile", make([]byte, 100))
				Expect(err).To(BeNil())
			})

			userlib.DebugMsg("Measuring bandwidth for appending 0 bytes.")
			bandwidth0Bytes := measureBandwidth(func() {
				err = alice.AppendToFile("testfile", []byte{})
				Expect(err).To(BeNil())
			})

			userlib.DebugMsg("Bandwidth for 1 byte append: %d", bandwidth1Byte)
			userlib.DebugMsg("Bandwidth for 100 bytes append: %d", bandwidth100Bytes)
			userlib.DebugMsg("Bandwidth for 0 bytes append: %d", bandwidth0Bytes)
		})

		Specify("CreateInvitation: Testing unitialized filename returns error", func() {
			userlib.DebugMsg("Initializing Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Creating invite.")
			_, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).ToNot(BeNil())
		})

		Specify("CreateInvitation: Testing uninitialized user returns error", func() {
			userlib.DebugMsg("Initializing Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Creating invite.")
			_, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).ToNot(BeNil())
		})

		Specify("CreateInvitation Test: Share with self", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Creating invitation for self.")
			_, err := alice.CreateInvitation(aliceFile, "alice")
			Expect(err).ToNot(BeNil())
		})

		Specify("CreateInvitation: Testing user does not have access to file returns error", func() {
			userlib.DebugMsg("Initializing Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing Charles")
			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Creating invite.")
			_, err := bob.CreateInvitation(aliceFile, "charles")
			Expect(err).ToNot(BeNil())
		})

		Specify("CreateInvitation Test: File name already exists for recipient", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Creating invitation for Bob.")
			invitationID, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())
			Expect(invitationID).ToNot(BeNil())

			userlib.DebugMsg("Bob accepts the invitation with a new file name.")
			err = bob.AcceptInvitation("alice", invitationID, bobFile)
			Expect(err).To(BeNil())
		})

		Specify("CreateInvitation Test: Empty file name", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile("", []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Creating invitation with an empty file name.")
			invitationID, err := alice.CreateInvitation("", "bob")
			Expect(err).To(BeNil())
			Expect(invitationID).To(BeNil())
		})

		Specify("AcceptInvitation: Testing file already exists returns error", func() {
			userlib.DebugMsg("Initializing Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = bob.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Creating invite.")
			data, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())
			Expect(data).ToNot(BeNil())

			userlib.DebugMsg("Accepting invite.")
			err = bob.AcceptInvitation("alice", data, aliceFile)
			Expect(err).ToNot(BeNil())
		})

		Specify("RevokeAccess: Testing uninitialized file", func() {
			userlib.DebugMsg("Initializing Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Revoking access.")
			err := alice.RevokeAccess(aliceFile, "bob")
			Expect(err).ToNot(BeNil())
		})
		/*
			this is not tested
			Specify("RevokeAccess: Testing caller isn't the owner", func() {
				userlib.DebugMsg("Initializing Alice.")
				alice, err = client.InitUser("alice", defaultPassword)
				Expect(err).To(BeNil())

				userlib.DebugMsg("Initializing Bob.")
				bob, err = client.InitUser("bob", defaultPassword)
				Expect(err).To(BeNil())

				userlib.DebugMsg("Initializing Charles.")
				charles, err = client.InitUser("charles", defaultPassword)
				Expect(err).To(BeNil())

				userlib.DebugMsg("Storing file data: %s", contentOne)
				err = alice.StoreFile(aliceFile, []byte(contentOne))
				Expect(err).To(BeNil())

				userlib.DebugMsg("Creating invite.")
				data, err := alice.CreateInvitation(aliceFile, "bob")
				Expect(err).To(BeNil())
				Expect(data).To(BeNil())

				userlib.DebugMsg("Accepting invite.")
				err = bob.AcceptInvitation("alice", data, aliceFile)
				Expect(err).To(BeNil())

				userlib.DebugMsg("Revoking access.")
				err = bob.RevokeAccess(aliceFile, "alice")
				Expect(err).ToNot(BeNil())
			})
		*/

		Specify("RevokeAccess: Testing caller does not have access to file", func() {
			userlib.DebugMsg("Initializing Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing Charles.")
			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Creating invite.")
			data, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Accepting invite.")
			err = bob.AcceptInvitation("alice", data, aliceFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Revoking access.")
			err = charles.RevokeAccess(aliceFile, "bob")
			Expect(err).ToNot(BeNil())
		})

		Specify("RevokeAccess: Testing recipient does not have access to file", func() {
			userlib.DebugMsg("Initializing Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing Charles.")
			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Creating invite.")
			_, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Revoking access.")
			err = alice.RevokeAccess(aliceFile, "charles")
			Expect(err).ToNot(BeNil())
		})

	})

	//THEIR TESTS
	Describe("Basic Tests", func() {

		Specify("Basic Test: Testing InitUser/GetUser on a single user.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Alice.")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())
		})

		Specify("Basic Test: Testing Single User Store/Load/Append.", func() {
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

	})
})
