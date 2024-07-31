package client

/** OH QUESTION:
what could be an alternate to storing source keys and calculating keys with deterministic salts?
can uuids only store marshal-ed data? **/
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
const ENCRYPT = "encrypt"
const MAC = "mac"
const ACCESS = "access"

type User struct {
	Username  string
	RSAkey    userlib.PKEDecKey
	Sigkey    userlib.DSSignKey
	sourceKey []byte
}

type Owner struct {
	Meta           userlib.UUID
	Sourcekey      []byte // used to generate meta keys
	InvitationList userlib.UUID
	ListKey        []byte // used to generate invitation list keys
}

type Access struct {
	Invitation userlib.UUID
	Sourcekey  []byte // used to generate invitation keys
}

type InvitationList struct {
	Invitations map[string]userlib.UUID // username - UUID
}

type InvitationMeta struct {
	Invitation userlib.UUID
	Sourcekey  []byte // used to generate invitation keys
}

type Invitation struct {
	Meta      userlib.UUID
	Sourcekey []byte // used to generate meta keys
}

type Meta struct {
	Start     userlib.UUID
	Last       userlib.UUID
	Sourcekey []byte // used as source key to generate file keys
}

type File struct {
	Contents []byte
	Next     userlib.UUID
}

// NOTE: The following methods have toy (insecure!) implementations.

func InitUser(username string, password string) (userdataptr *User, err error) {

	// error check: check if username is an empty string
	if username == "" {
		return nil, errors.New("username cannot be empty")
	}

	// generate UUID
	userUUID, err := GetUserUUID(username)
	if err != nil {
		return nil, err
	}

	// error check: check if username already exists
	_, ok := userlib.DatastoreGet(userUUID)
	if ok {
		return nil, errors.New("username already exists")
	}

	// generate source key
	sourceKey := GetSourceKey(username, password)

	// generate asynch and symmetric keys
	RSAPublicKey, RSAPrivateKey, DSSignKey, DSVerifyKey, err := GetAsynchKeys()
	if err != nil {
		return nil, errors.New("GetAsynchKeys error")
	}
	encryptKey, hmacKey, err := GetTwoHASHKDFKeys(sourceKey, ENCRYPT, MAC)
	if err != nil {
		return nil, errors.New("GetTwoHASHKDFKeys error")
	}

	// put public values into keystore
	userlib.KeystoreSet(username+" public key", RSAPublicKey)
	userlib.KeystoreSet(username+" signature key", DSVerifyKey)

	// create user struct
	userdata := &User{
		Username:  username,
		RSAkey:    RSAPrivateKey,
		Sigkey:    DSSignKey,
		sourceKey: sourceKey,
	}

	// get encrypted msg and mac tag
	// userBytes, err := json.Marshal(userdata)
	msg, tag, err := EncryptThenMac(userdata, encryptKey, hmacKey)
	if err != nil {
		return nil, err
	}

	// generate value for datastore and store
	value, err := GenerateUUIDVal(msg, tag)
	if err != nil {
		return nil, errors.New("GenerateUUIDVal error")
	}
	userlib.DatastoreSet(userUUID, value)
	return userdata, nil
}

func GetUser(username string, password string) (userdataptr *User, err error) {

	// error check: empty username
	if username == "" {
		return nil, errors.New("username cannot be empty")
	}

	// generate UUID
	userUUID, err := GetUserUUID(username)
	if err != nil {
		return nil, errors.New("GetUserUUID error")
	}
	// error check: user doesn't exist
	encryptedUserdata, ok := userlib.DatastoreGet(userUUID)
	if !ok {
		return nil, errors.New("username does not exist")
	}

	// unpack data into msg and tag
	msg, tag, err := UnpackValue(encryptedUserdata)
	if err != nil {
		return nil, errors.New("failed to unpack user data")
	}

	// Generate the source key, encryption key, and HMAC key from the username and password
	sourceKey := GetSourceKey(username, password)
	encryptKey, hmacKey, err := GetTwoHASHKDFKeys(sourceKey, ENCRYPT, MAC)
	if err != nil {
		return nil, errors.New("failed to generate encryption and HMAC keys")
	}

	// HMAC Check
	err = CheckTag(msg, tag, hmacKey)
	if err != nil {
		return nil, errors.New("data integrity check failed: either wrong credentials or tampering")
	}

	//decrypt + unmarshall message
	decryptedMessage := userlib.SymDec(encryptKey, msg)
	var userdata User
	err = json.Unmarshal(decryptedMessage, &userdata)
	if err != nil {
		return nil, errors.New("failed to unmarshal user data")
	}

	userdata.sourceKey = sourceKey

	//username check
	if userdata.Username != username {
		return nil, errors.New("retrieved username does not match expected username")
	}
	return &userdata, nil
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	// generate new file UUID and file sourcekey
	fileUUID := uuid.New()
	fileSourceKey, err := GetRandomKey(userdata)
	if err != nil {
		return errors.New("Failed to get file sourcekey")
	}

	// add file to database
	nextFileUUID, err := AddFileToDatabase(fileUUID, fileSourceKey, content)
	if err != nil {
		return errors.New("Failed to add file to datastore")
	}

	// generate accessUUID and keys
	accessUUID, err := GetAccessUUID(*userdata, filename)
	if err != nil {
		return errors.New("Failed to get accessUUID")
	}
	accessStruct, ok := userlib.DatastoreGet(accessUUID)
	accessKey, err := GetAccessKey(userdata.sourceKey)
		if err != nil {
			return errors.New("Failed to get access key")
		} 
	accessEncryptKey, accessHMACKey, err := GetTwoHASHKDFKeys(accessKey, ENCRYPT, MAC)

	// check if access struct already exists in database
	if ok {
		// unpack, check tag, decrypt
		encryptedBytes, tag, err := UnpackValue(accessStruct)
		if err != nil {
			return errors.New("Failed to unpack")
		} 
		err = CheckTag(encryptedBytes, tag, accessHMACKey)
		if err != nil {
			return errors.New("Integrity check failed")
		} 
		accessStruct, err := DecryptMsg(encryptedBytes, accessEncryptKey)
		if err != nil {
			return errors.New("Integrity check failed")
		}
	}

	// generate new meta UUID and meta sourcekey
	metaUUID := uuid.New()
	metaSourceKey, err := GetRandomKey(userdata)
	if err != nil {
		return errors.New("Failed to get meta sourcekey")
	}

	// generate encryption and HMAC keys
	metaEncryptKey, metaHMACKey, err2 := GetTwoHASHKDFKeys(metaSourceKey, ENCRYPT, MAC)
	if err != nil {
		return errors.New("Failed to get file HDKF")
	}
	
	// Construct the metadata struct (UUIDs and keys)
	fileMeta := Meta{
		Start:     fileUUID,
		Last:      nextFileUUID,
		Sourcekey: fileSourceKey,
	}

	// Encrypt the metadata and create an HMAC tag
	metaCiphertext, metaTag, err := EncryptThenMac(fileMeta, metaEncryptKey, metaHMACKey)
	if err != nil {
		return errors.New("Failed to package data for entry into DataStore")
	}

	// Store the encrypted metadata and the HMAC tag in the datastore
	// metaData, err := GenerateUUIDVal(metaCiphertext, metaTag)
	// if err != nil {
	//	return errors.New("failed to generate metadata for storage")
	//}
	userlib.DatastoreSet(metaUUID, metaData)
	
	// else {
	//	access := Owner {
	//		Meta: metaUUID,
	//		Sourcekey: metaSourceKey,
	//		InvitationList: uuid.New(),
	//		ListKey: nil //FIX THIS PLEASE PLEASE PLEASE
	//	}

	//}




	
	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {

	//load UUID

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








func (userdata *User) AppendToFile(filename string, content []byte) error {
	
	accessUUID, err := GetAccessUUID(*userdata, filename)
	encryptKey, hmacKey, err := GetTwoHASHKDFKeys(accessSourceKey, ENCRYPT, MAC)

	// Generate the source key, encryption key, and HMAC key from the username and password
	accessSourceKey := GetAccessKey(sourceKey)
	encryptKey, hmacKey, err := GetTwoHASHKDFKeys(accessSourceKey, ENCRYPT, MAC)
	if err != nil {
		return nil, errors.New("failed to generate encryption and HMAC keys")
	}

	// HMAC Check
	err = CheckTag(msg, tag, hmacKey)
	if err != nil {
		return nil, errors.New("data integrity check failed: file has been tampered with")
	}

	//decrypt + unmarshall message
	decryptedMessage := userlib.SymDec(encryptKey, msg)
	var accessFile Owner
	err = json.Unmarshal(decryptedMessage, &accessFile)
	if err != nil {
		return nil, errors.New("failed to unmarshal file")
	}

	metaUUID := Owner.Meta
	//Retrieve the file metadata
	metaDataEncrypted, ok := userlib.DatastoreGet(metaUUID)
	if !ok {
		return errors.New("file metadata not found")
	}

	metaMsg, metaTag, err := UnpackValue(metaDataEncrypted)
	if err != nil {
		return err
	}

	// Generate encryption and MAC keys for the metadata
	metaEncKey, metaMacKey, err := GetTwoHASHKDFKeys(userdata.sourceKey, "metaEncrypt", "metaMac")
	if err != nil {
		return err
	}

	// HMAC check
	err = CheckTag(metaMsg, metaTag, metaMacKey)
	if err != nil {
		return errors.New("file metadata integrity check failed")
	}

	//Decrypt Metadata
	decryptedMeta := DecryptMsg(metaMsg, metaEncKey)

	// go to last value in Meta

	//encrypt file 
	// add it to wherever we put the store file
	//generate new uuid

	return nil
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
// only use the username to determine where the stuff is at,
func GetUserUUID(user string) (UUID userlib.UUID, err error) {
	// generate uuid
	userbytes := []byte(user)
	salt1 := []byte("UUID")
	UUID, err = uuid.FromBytes(userlib.Argon2Key(userbytes, salt1, LENGTH))

	// check for error
	if err != nil {
		return uuid.UUID{}, errors.New(strings.ToTitle("Conversion to UUID failed"))
	}
	return
}

func GetSourceKey(user, password string) (sourcekey []byte) {
	passwordbytes := []byte(password)
	sourcekey = userlib.Argon2Key(passwordbytes, []byte(user), LENGTH)
	return
}

func GetAsynchKeys() (pk userlib.PKEEncKey, sk userlib.PKEDecKey, signpriv userlib.DSSignKey, signpub userlib.DSVerifyKey, err error) {
	// generate asymmetric encryption keys
	pk, sk, err = userlib.PKEKeyGen()

	// generate asymmetric signature keys
	signpriv, signpub, err1 := userlib.DSKeyGen()

	// check for errors
	if err != nil {
		return pk, sk, signpriv, signpub, errors.New(strings.ToTitle("RSA KeyGen failed"))
	}
	if err1 != nil {
		return pk, sk, signpriv, signpub, errors.New(strings.ToTitle("Signature KeyGen failed"))
	}
	return
}

// given secure source key this should produce fast secure keys
func GetTwoHASHKDFKeys(sourcekey []byte, purpose1, purpose2 string) (key1, key2 []byte, err error) {
	// generate keys and check errors
	key1, err = userlib.HashKDF(sourcekey, []byte(purpose1))
	if err != nil {
		return nil, nil, errors.New(strings.ToTitle("Key creation failed"))
	}

	key2, err = userlib.HashKDF(sourcekey, []byte(purpose2))
	if err != nil {
		return nil, nil, errors.New(strings.ToTitle("Key creation failed"))
	}
	return
}

func GetAccessUUID(user User, filename string) (UUID userlib.UUID, err error) {
	// hash username and check error
	accessbytes := []byte(filename)
	accesshash, err := userlib.HashKDF(user.sourceKey, accessbytes)
	if err != nil {
		return uuid.UUID{}, errors.New(strings.ToTitle("Hashing failed"))
	}

	// convert to byte and check error
	UUID, err = uuid.FromBytes(accesshash[:LENGTH])
	if err != nil {
		return uuid.UUID{}, errors.New(strings.ToTitle("Conversion to UUID failed"))
	}
	return
}

func GetInviteUUID(owner *User, sharee, filename string) (UUID userlib.UUID, err error) {
	// hash username and check error
	invitebytes := []byte(owner.Username + filename + sharee)
	invitehash, err := userlib.HashKDF(owner.sourceKey, invitebytes)
	if err != nil {
		return uuid.UUID{}, errors.New(strings.ToTitle("Hashing failed"))
	}

	// convert to byte and check error
	UUID, err = uuid.FromBytes(invitehash[:LENGTH])
	if err != nil {
		return uuid.UUID{}, errors.New(strings.ToTitle("file not found"))
	}
	return
}

func GenerateUUIDVal(msg, tag []byte) (value []byte, err error) {
	// create map
	Map := map[string][]byte{
		"msg": msg,
		"tag": tag,
	}

	// generate byte array
	value, err = json.Marshal(Map)
	if err != nil {
		return nil, errors.New(strings.ToTitle("file not found"))
	}
	return
}

func UnpackValue(value []byte) (msg, tag []byte, err error) {
	// unmarshall datastore value
	unpackedData := make(map[string][]byte)
	err = json.Unmarshal(value, &unpackedData)

	// check for error unmarshalling and return
	if err != nil {
		return nil, nil, errors.New(strings.ToTitle("Unmarshal failed"))
	}
	msg, tag = unpackedData["msg"], unpackedData["tag"]
	return
}

func EncryptThenMac(txt interface{}, key1, key2 []byte) (msg, tag []byte, err Error) {
	// convert text to bytes and check for error
	plaintext, err := json.Marshal(txt)
	if err != nil {
		return nil, nil, errors.New(strings.ToTitle("Marshal failed"))
	}

	// encrypt and mac
	rndbytes := userlib.RandomBytes(LENGTH)
	msg = userlib.SymEnc(key1, rndbytes, plaintext)
	tag, err = userlib.HMACEval(key2, msg)

	// check for error and return
	if err != nil {
		return nil, nil, errors.New(strings.ToTitle("HMAC failed"))
	}
	return
}

func EncryptThenSign(txt interface{}, user string, sk userlib.DSSignKey) (msg, sig []byte, err error) {
	// convert to byte array, check for error
	plaintext, err := json.Marshal(txt)
	if err != nil {
		return nil, nil, errors.New(strings.ToTitle("Marshal failed"))
	}

	// encrypt using user public key, check for error
	pubkey, ok := userlib.KeystoreGet(user + " public key")
	if !ok {
		return nil, nil, errors.New(strings.ToTitle("KeystoreGet failed"))
	}
	ciphertext, err := userlib.PKEEnc(pubkey, plaintext)
	if err != nil {
		return nil, nil, errors.New(strings.ToTitle("Encryption failed"))
	}

	// sign, check for error, and return
	sig, err = userlib.DSSign(sk, ciphertext)
	if err != nil {
		return nil, nil, errors.New(strings.ToTitle("Signing failed"))
	}
	return
}

func CheckTag(msg, tag, key2 []byte) (err error) {
	// compute tag and check error
	computedTag, err := userlib.HMACEval(key2, msg)
	if err != nil {
		return err
	}

	if userlib.HMACEqual(tag, computedTag) {
		return
	}
	return errors.New("Integrity check failed")
}

func CheckSignature(msg, sig []byte, user string) (err error) {
	// get verification key, check error
	sk, ok := userlib.KeystoreGet(user + " signature key")
	if !ok {
		return errors.New("Could not get sign key")
	}

	// verify signature
	err = userlib.DSVerify(sk, msg, sig)
	if err != nil {
		return errors.New("Could not verify sign key")
	}
	return
}

func DecryptMsg(msg, key1 []byte) (data interface{}, err error) {
	// decrypt msg
	plaintext := userlib.SymDec(key1, msg)

	// unmarshal data to get original struct
	err = json.Unmarshal(plaintext, &data)
	if err != nil {
		return nil, errors.New(strings.ToTitle("Unmarshalling failed"))
	}
	return
}

func DecryptAsynchMsg(msg []byte, pk userlib.PKEDecKey) (data interface{}, err error) {
	// decrypt msg
	plaintext, err := userlib.PKEDec(pk, msg)
	if err != nil {
		return nil, errors.New(strings.ToTitle("Decryption failed"))
	}

	// unmarshal data to get original struct and check for error
	err = json.Unmarshal(plaintext, &data)
	if err != nil {
		return nil, errors.New(strings.ToTitle("Unmarshalling failed"))
	}
	return
}

func GetRandomKey(user *User) (key []byte, err error) {
	// generate new random key
	sourcekey, salt := user.sourceKey, userlib.RandomBytes(LENGTH)
	key, err = userlib.HashKDF(sourcekey, salt)

	// check for error
	if err != nil {
		return nil, errors.New(strings.ToTitle("file not found"))
	}
	return
}

func GetAccessStruct(invitation userlib.UUID, sourcekey []byte) (access interface{}) {
	access = Access{
		Invitation: invitation,
		Sourcekey: sourcekey,
	}
	return 
}

func GetAccessKey(sourcekey []byte) (key []byte, err error) {
	key, err = userlib.HashKDF(sourcekey, []byte(ACCESS))
	if err != nil {
		return nil, nil, errors.New(strings.ToTitle("Key creation failed"))
	}
	return
}

func AddFileToDatabase(fileUUID userlib.UUID, fileSourceKey, content []byte) (nextFileUUID userlib.UUID, err error) {
	// generate UUID for next
	nextFileUUID = uuid.New()
	
	// generate keys 
	fileEncryptKey, fileHMACKey, err := GetTwoHASHKDFKeys(fileSourceKey, ENCRYPT, MAC)
	if err != nil {
		return fileUUID, nextFileUUID, nil, errors.New("Failed to get keys")
	}

	// generate file struct
	file := File{
		Contents: content,
		Next:     nextFileUUID,
	}

	// encrypt file struct
	encryptedBytes, tag, err := EncryptThenMac(file, fileEncryptKey, fileHMACKey)
	if err != nil {
		return fileUUID, nextFileUUID, nil, errors.New("Failed to EncryptThenMac")
	}

	// create value and add to Datastore
	value, err := GenerateUUIDVal(encryptedBytes, tag)
	if err != nil {
		return fileUUID, nextFileUUID, nil, errors.New("Failed to package data for entry into DataStore")
	}
	userlib.DatastoreSet(fileUUID, value)
	return
}