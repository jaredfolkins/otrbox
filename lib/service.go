package src

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"

	"golang.org/x/crypto/nacl/box"
)

const MsgMaxBytes = 8192 - 1

type Pub struct {
	Key    *[32]byte
	HexStr string
}
type Prv struct {
	Key    *[32]byte
	HexStr string
}

func DoesKeyExist(keyFn string) bool {
	b, err := KeyByFilename(keyFn)
	if err != nil {
		Errl(err)
		return false
	}

	if len(b) == 32 {
		return true
	}

	return false
}

func GenerateKeysAndSave(pubFn, prvFn string) (*Pub, *Prv) {
	pubk, prvk := GenerateKeys()
	CreateKey(pubFn, pubk.HexStr)
	CreateKey(prvFn, prvk.HexStr)
	return pubk, prvk
}

func GenerateKeys() (*Pub, *Prv) {
	reader := rand.Reader
	pubkey, prvkey, err := box.GenerateKey(reader)
	if err != nil {
		Fatall(err)
	}

	pub := hex.EncodeToString(pubkey[:])
	prv := hex.EncodeToString(prvkey[:])
	pubk := &Pub{Key: pubkey, HexStr: pub}
	prvk := &Prv{Key: prvkey, HexStr: prv}
	return pubk, prvk
}

func CreateKey(keyName, key string) {
	cwd, err := os.Getwd()
	if err != nil {
		Fatall(err)
	}

	fp := filepath.Join(cwd, keyName)
	f, err := os.Create(fp)
	if err != nil {
		Fatall(err)
	}
	defer f.Close()

	_, err = f.WriteString(key + "\n")
	if err != nil {
		Fatall(err)
	}
}

func DecodeKey(s string) *[32]byte {
	hexKey, err := hex.DecodeString(s)
	if err != nil {
		Fatall(err)
	}

	var ret [32]byte
	for k, v := range hexKey {
		ret[k] = v
	}

	if len(ret) != 32 {
		Fatall(errors.New("Key length must be [32]byte"))
	}

	return &ret
}

func KeyByString(key string) *[32]byte {
	return DecodeKey(key)
}

// the pub/prv keys are stored in POSIX compliant files
// we open a file, snag the key, but it will have LF characters on the end
// so we pass the first 64 bytes to the DecodeKey() function, else it will fail
func KeyByFilename(keyFname string) (*[32]byte, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return nil, err
	}

	fp := filepath.Join(cwd, keyFname)
	b, err := ioutil.ReadFile(fp)
	if err != nil {
		return nil, err
	}

	return DecodeKey(string(b[:64])), nil
}

func Encrypt(msg string, theirPublicKey, yourPrivateKey *[32]byte) []byte {
	cryptoReader := rand.Reader
	var nonce [24]byte
	if _, err := io.ReadFull(cryptoReader, nonce[:]); err != nil {
		Fatall(err)
	}

	b := []byte(msg)
	if len(b) >= MsgMaxBytes {
		s := fmt.Sprintf("We only allow messages %d bytes in size or less", MsgMaxBytes)
		Fatall(errors.New(s))
	}

	encrypted := box.Seal(nonce[:], b, &nonce, theirPublicKey, yourPrivateKey)
	return encrypted
}

func Decrypt(e string, theirPublicKey, yourPrivateKey *[32]byte) []byte {
	encrypted, err := hex.DecodeString(e)
	if err != nil {
		Fatall(err)
	}

	var decryptNonce [24]byte
	copy(decryptNonce[:], encrypted[:24])
	decrypted, ok := box.Open(nil, encrypted[24:], &decryptNonce, theirPublicKey, yourPrivateKey)
	if !ok {
		Fatall(errors.New("Failed to decrypt the message"))
	}
	return decrypted
}
