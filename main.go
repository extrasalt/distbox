package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/hex"
	//"fmt"
	"github.com/gorilla/mux"
	ipfs "github.com/ipfs/go-ipfs-api"
	"io"
	"net/http"
)

func main() {

	r := mux.NewRouter()
	r.HandleFunc("/login", LoginHandler)
	r.HandleFunc("/file/{id}", GetFileHandler).Methods("GET")
	r.HandleFunc("/file", FileUploadHandler).Methods("POST")
	r.PathPrefix("/").Handler(http.FileServer(http.Dir("./static/")))

	http.ListenAndServe(":3000", r)
}

func GetFileHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]
	resp, err := http.Get("http://127.0.0.1:8080/ipfs/" + id)

	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	_, err = io.Copy(w, resp.Body)
}

func FileUploadHandler(w http.ResponseWriter, r *http.Request) {

	r.ParseForm()
	data := r.Form["data"][0]

	//Find Key
	sha := sha256.New()
	sha.Write([]byte(data))
	key := hex.EncodeToString(sha.Sum(nil))

	plaintext := bytes.NewReader([]byte(data))

	ciphertext := encrypt(key, plaintext)

	shell := ipfs.NewShell("localhost:5001")
	hash, err := shell.Add(ciphertext)

	if err != nil {
		panic(err)
	}

	w.Write([]byte(hash))
	w.Write([]byte("\n\n"))

	w.Write([]byte((key)))

}

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

// func authenticate(next http.Handler) http.Handler {

// 	return func(w http.ResponseWriter, r *http.Request){
// 		if cookies == authenticated {
// 			next(w, r)
// 		} else {
// 			http.Redirect(w)
// 		}

// 	}

// }

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		panic(err)
	}

	username := r.Form["name"][0]
	password := r.Form["password"][0]

	if username == "mohan" && password == "momo" {
		cookie := &http.Cookie{Name: "rcs", Value: username, MaxAge: 3600, Secure: false, HttpOnly: true, Raw: username}
		http.SetCookie(w, cookie)
		w.Write([]byte("authenticated"))
	} else {
		w.Write([]byte("Wrong password"))
	}
}
