package main

import (
	otrbox "github.com/jaredfolkins/otrbox/lib"
	"errors"
	"flag"
	"fmt"
)

const pubFn = "otrbox.pub"
const privFn = "otrbox.prv"

var ypub, yprv bool     // PrintYourPublicKey, PrintYourPrivateKey
var ct, msg, tpk string // CipherText, Message, TheirPublicKey

func init() {
	if !otrbox.DoesKeyExist(pubFn) || !otrbox.DoesKeyExist(privFn) {
		otrbox.Logl("Generating public and private keys...")
		otrbox.GenerateKeysAndSave(pubFn, privFn)
	}
}

func main() {

	flag.StringVar(&msg, "encrypt", "", "the plaintext message that you'd like to encrypt")
	flag.StringVar(&ct, "decrypt", "", "the ciphertext that you'd like to decrypt in order to read the message")
	flag.BoolVar(&ypub, "myPublicKey", false, "prints the hex encoded value of your public key")
	flag.BoolVar(&yprv, "myPrivateKey", false, "prints the hex encoded value of your private key")
	flag.StringVar(&tpk, "theirPublicKey", "", "the public key of the individual you'd like to communitcate with")
	flag.Parse()

	pub, err := otrbox.KeyByFilename(pubFn)
	if err != nil {

	}
	prv, err := otrbox.KeyByFilename(privFn)
	if err != nil {

	}

	yourPublic := &otrbox.Pub{Key: pub}
	yourPrivate := &otrbox.Prv{Key: prv}

	// print your public key
	if ypub {
		s := fmt.Sprintf("%x", yourPublic.Key[:])
		otrbox.Logl(s)
		return
	}

	// print your private key
	if yprv {
		s := fmt.Sprintf("%x", yourPrivate.Key[:])
		otrbox.Logl(s)
		return
	}

	// you must seletct something
	if exists(ct) && exists(msg) {
		otrbox.Fatall(errors.New("You must either input a message or a ciphertext, not both"))
		return
	} else if totalBytes(ct) == 0 && totalBytes(msg) == 0 {
		otrbox.Fatall(errors.New("You must either input a message or a ciphertext, both are blank"))
		return
	}

	// encrypt
	if exists(msg) && totalBytes(msg) <= otrbox.MsgMaxBytes && exists(tpk) {
		theirPublic := &otrbox.Pub{Key: otrbox.KeyByString((tpk))}
		e := otrbox.Encrypt(msg, theirPublic.Key, yourPrivate.Key)

		fmt.Printf("Your Public Key:\t%x\n", yourPublic.Key[:])
		fmt.Printf("Your Encrypted Message:\t%x\n", e)
		return
	}

	// decrypt
	if exists(ct) && totalBytes(ct) <= otrbox.MsgMaxBytes && exists(tpk) {
		theirPublic := &otrbox.Pub{Key: otrbox.KeyByString((tpk))}
		d := otrbox.Decrypt(ct, theirPublic.Key, yourPrivate.Key)

		fmt.Printf("Your Public Key:\t%x\n", yourPublic.Key[:])
		fmt.Printf("Your PlainTxt Message:\t%s\n", d)
		return
	}

}

func exists(s string) bool {
	if len([]byte(s)) > 0 {
		return true
	}
	return false
}

func totalBytes(s string) int {
	return len([]byte(s))
}
