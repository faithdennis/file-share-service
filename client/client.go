package client

// CS 161 Project 2

// Only the following imports are allowed! ANY additional imports
// may break the autograder!
// - bytes
// - encoding/hex
// - encoding/json
// - errors
// - fmt
// - github.com/cs161-staff/project2-userlib
// - github.com/google/uuid
// - strconv
// - strings

import (
	"encoding/json"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for string manipulation
	"strings"

	// Useful for formatting strings (e.g. `fmt.Sprintf`).
	"fmt"

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	_ "strconv"
)

// This serves two purposes: it shows you a few useful primitives,
// and suppresses warnings for imports not being used. It can be
// safely deleted!
func someUsefulThings() {

	// Creates a random UUID.
	randomUUID := uuid.New()

	// Prints the UUID as a string. %v prints the value in a default format.
	// See https://pkg.go.dev/fmt#hdr-Printing for all Golang format string flags.
	userlib.DebugMsg("Random UUID: %v", randomUUID.String())

	// Creates a UUID deterministically, from a sequence of bytes.
	hash := userlib.Hash([]byte("user-structs/alice"))
	deterministicUUID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		// Normally, we would `return err` here. But, since this function doesn't return anything,
		// we can just panic to terminate execution. ALWAYS, ALWAYS, ALWAYS check for errors! Your
		// code should have hundreds of "if err != nil { return err }" statements by the end of this
		// project. You probably want to avoid using panic statements in your own code.
		panic(errors.New("An error occurred while generating a UUID: " + err.Error()))
	}
	userlib.DebugMsg("Deterministic UUID: %v", deterministicUUID.String())

	// Declares a Course struct type, creates an instance of it, and marshals it into JSON.
	type Course struct {
		name      string
		professor []byte
	}

	course := Course{"CS 161", []byte("Nicholas Weaver")}
	courseBytes, err := json.Marshal(course)
	if err != nil {
		panic(err)
	}

	userlib.DebugMsg("Struct: %v", course)
	userlib.DebugMsg("JSON Data: %v", courseBytes)

	// Generate a random private/public keypair.
	// The "_" indicates that we don't check for the error case here.
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("PKE Key Pair: (%v, %v)", pk, sk)

	// Here's an example of how to use HBKDF to generate a new key from an input key.
	// Tip: generate a new key everywhere you possibly can! It's easier to generate new keys on the fly
	// instead of trying to think about all of the ways a key reuse attack could be performed. It's also easier to
	// store one key and derive multiple keys from that one key, rather than
	originalKey := userlib.RandomBytes(16)
	derivedKey, err := userlib.HashKDF(originalKey, []byte("mac-key"))
	if err != nil {
		panic(err)
	}
	userlib.DebugMsg("Original Key: %v", originalKey)
	userlib.DebugMsg("Derived Key: %v", derivedKey)

	// A couple of tips on converting between string and []byte:
	// To convert from string to []byte, use []byte("some-string-here")
	// To convert from []byte to string for debugging, use fmt.Sprintf("hello world: %s", some_byte_arr).
	// To convert from []byte to string for use in a hashmap, use hex.EncodeToString(some_byte_arr).
	// When frequently converting between []byte and string, just marshal and unmarshal the data.
	//
	// Read more: https://go.dev/blog/strings

	// Here's an example of string interpolation!
	_ = fmt.Sprintf("%s_%d", "file", 1)
}

// This is the type definition for the User struct.
// A Go struct is like a Python or Java class - it can have attributes
// (e.g. like the Username attribute) and methods (e.g. like the StoreFile method below).
const LENGTH = 16

type User struct {
	Username  string
	Sourcekey []byte
	RSAkey    userlib.PKEDecKey
	Sigkey    userlib.DSSignKey

	// You can add other attributes here if you want! But note that in order for attributes to
	// be included when this struct is serialized to/from JSON, they must be capitalized.
	// On the flipside, if you have an attribute that you want to be able to access from
	// this struct's methods, but you DON'T want that value to be included in the serialized value
	// of this struct that's stored in datastore, then you can use a "private" variable (e.g. one that
	// begins with a lowercase letter).
}

type Owner struct {
	Meta        userlib.UUID
	Invitations userlib.UUID
	// keys ?
}

type Access struct {
	Invitation     userlib.UUID
	MetaEncryptkey []byte
	MetaMACkey     []byte
}

type InvitiationMeta struct {
	Invitations map[string]userlib.UUID
}

type Invitation struct {
	Meta           userlib.UUID
	MetaEncryptkey []byte
	MetaMACkey     []byte
}

type Meta struct {
	Start          userlib.UUID
	End            userlib.UUID
	FileEncryptkey []byte
	FileMACkey     []byte
}

type File struct {
	Contents string
	Next     userlib.UUID // is there risk to using same key?
}

// NOTE: The following methods have toy (insecure!) implementations.

func InitUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdata.Username = username
	return &userdata, nil
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata
	return userdataptr, nil
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	storageKey, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	if err != nil {
		return err
	}
	contentBytes, err := json.Marshal(content)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(storageKey, contentBytes)
	return
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	storageKey, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	if err != nil {
		return nil, err
	}
	dataJSON, ok := userlib.DatastoreGet(storageKey)
	if !ok {
		return nil, errors.New(strings.ToTitle("file not found"))
	}
	err = json.Unmarshal(dataJSON, &content)
	return content, err
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (
	invitationPtr uuid.UUID, err error) {
	return
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	return nil
}

// Helper Functions

// assumes password has sufficient entropy to create non-bruteforceable UUID and sourcekey
func GetUserUUIDAndSourceKey(user, password string) (UUID userlib.UUID, sourcekey []byte) {
	// generate uuid
	userbytes := []byte(user)
	salt1 := []byte("UUID")
	UUID, err1 := uuid.FromBytes(userlib.Argon2Key(userbytes, salt1, LENGTH))

	// generate sourcekey
	passwordbytes := []byte(user + password)
	salt2 := []byte("sourcekey")
	sourcekey = userlib.Argon2Key(passwordbytes, salt2, LENGTH)

	// check for error
	if err1 != nil {
		print(err1.Error())
	}
	return
}

func GetAsynchKeys() (pk userlib.PKEEncKey, sk userlib.PKEDecKey, signpriv userlib.DSSignKey, signpub userlib.DSVerifyKey) {
	// generate asymmetric encryption keys
	pk, sk, err1 := userlib.PKEKeyGen()

	// generate asymmetric signature keys
	signpriv, signpub, err2 := userlib.DSKeyGen()

	// check for errors
	if err1 != nil {
		print(err1.Error())
	}
	if err2 != nil {
		print(err2.Error())
	}
	return
}

// given secure source key and secure purposes should produce secure keys
func GetTwoHASHKDFKeys(sourcekey []byte, purpose1, purpose2 string) (key1, key2 []byte) {
	// generate keys
	key1, err1 := userlib.HashKDF(sourcekey, []byte(purpose1))
	key2, err2 := userlib.HashKDF(sourcekey, []byte(purpose2))

	// check for errors
	if err1 != nil {
		print(err1.Error())
	}
	if err2 != nil {
		print(err2.Error())
	}
	return
}

func GetRandomSourceKey() (key []byte) {
	// generate random values
	rand, salt := userlib.RandomBytes(LENGTH), userlib.RandomBytes(LENGTH)
	key = userlib.Argon2Key(rand, salt, LENGTH)
	return
}

func GetTwoRandomSourceKeys() (key1, key2 []byte) {
	// generate random values
	rand1, rand2 := userlib.RandomBytes(LENGTH), userlib.RandomBytes(LENGTH)
	salt1, salt2 := userlib.RandomBytes(LENGTH), userlib.RandomBytes(LENGTH)
	key1, key2 = userlib.Argon2Key(rand1, salt1, LENGTH), userlib.Argon2Key(rand2, salt2, LENGTH)
	return
}

func EncryptThenMac(txt string, key1, key2 []byte) (msg, tag []byte) {
	// encrypt
	rndbytes := userlib.RandomBytes(LENGTH)
	txtbytes, err1 := json.Marshal(txt)
	msg = userlib.SymEnc(key1, rndbytes, txtbytes)

	// mac
	tag, err2 := userlib.HMACEval(key2, msg)

	// check for error
	if err1 != nil {
		print(err1.Error())
	}
	if err2 != nil {
		print(err2.Error())
	}
	return
}
