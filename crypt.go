package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"io"
)

func encrypt(keyString string, plaintext io.Reader) (cipherReader io.Reader) {
	key, _ := hex.DecodeString(keyString)
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	nonce, _ := hex.DecodeString("37b8e8a308c354048d245f6d00000000")

	stream := cipher.NewCFBEncrypter(block, nonce)
	cipherReader = &cipher.StreamReader{S: stream, R: plaintext}

	return cipherReader

}

func decrypt(keyString string, ciphertext io.Reader) (plainReader io.Reader) {
	key, _ := hex.DecodeString(keyString)

	nonce, _ := hex.DecodeString("37b8e8a308c354048d245f6d00000000")

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}
	stream := cipher.NewCFBDecrypter(block, nonce)
	plainReader = &cipher.StreamReader{S: stream, R: ciphertext}

	return plainReader
}
