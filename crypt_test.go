package main

import (
	"io/ioutil"
	"strings"
	"testing"
)

func TestCrypt(t *testing.T) {
	s := "Some string"
	reader := strings.NewReader(s)

	key := "keykeykeykeykeykeykeykeykeykeykeykeykeykeykeykeykeykeykeykeykeky"

	ciphertextReader := encrypt(key, reader)

	key = "keykeykeykeykeykeykeykeykeykeykeykeykeykeykeykeykeykeykeykeykeky"
	plaintextReader := decrypt(key, ciphertextReader)
	tBytes, _ := ioutil.ReadAll(plaintextReader)

	if s != string(tBytes) {
		t.Fatal("Not the same")
	}
}
