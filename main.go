package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"github.com/gorilla/mux"
	"gopkg.in/mgo.v2"
	"io"
	"labix.org/v2/mgo/bson"
	"net/http"

	ipfs "github.com/ipfs/go-ipfs-api"
)

var session *mgo.Session

func main() {
	var err error

	url := "0.0.0.0:27017"
	session, err = mgo.Dial(url)
	if err != nil {
		panic(err)
	}

	r := mux.NewRouter()
	r.HandleFunc("/login", LoginHandler)
	r.HandleFunc("/signup", SignUpHandler).Methods("POST")
	r.HandleFunc("/file/{id}", authenticate(GetFileHandler)).Methods("GET")
	r.HandleFunc("/file", authenticate(FileUploadHandler)).Methods("POST")
	r.PathPrefix("/").Handler(http.FileServer(http.Dir("./static/")))

	http.ListenAndServe(":3000", r)
}

func GetFileHandler(w http.ResponseWriter, r *http.Request) {
	//For a given key, find the content-address of the file,
	// fetch the file and decrypt it.

	//Get id from the path
	vars := mux.Vars(r)
	key := vars["id"]

	cookie, _ := r.Cookie("rcs")
	username := cookie.Value

	var qhash string

	var user User

	usersCollection := session.DB("RCS").C("User")

	err := usersCollection.Find(bson.M{"username": username}).One(&user)

	for _, file := range user.Files {
		if file.Key == key {
			qhash = file.ContentAddr
		}
	}

	//sends a GET to Ipfs daemon
	//with hash corresponding to the key in url
	resp, err := http.Get("http://127.0.0.1:8080/ipfs/" + qhash)

	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	decryptedReader := decrypt(key, resp.Body)
	_, err = io.Copy(w, decryptedReader)
}

func FileUploadHandler(w http.ResponseWriter, r *http.Request) {

	r.ParseForm()
	data := r.Form["data"][0]

	cookie, _ := r.Cookie("rcs")
	username := cookie.Value

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

	var user User
	usersCollection := session.DB("RCS").C("User")
	err = usersCollection.Find(bson.M{"username": username}).One(&user)

	if err != nil {
		panic(err)
	}

	//Add the hash received from ipfs and the key to the database
	// _, err = DB.Exec("insert into files values($1, $2)", hash, key)

	user.Files = append(user.Files, FileStruct{
		Name:        "File",
		Key:         key,
		ContentAddr: hash,
	})

	w.Write([]byte(hash))
	w.Write([]byte("Uploaded"))

	w.Write([]byte((key)))

}
