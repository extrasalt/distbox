package main

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"github.com/gorilla/mux"
	ipfs "github.com/ipfs/go-ipfs-api"
	_ "github.com/lib/pq"
	"io"
	"net/http"
)

var DB *sql.DB

func main() {
	var err error

	DB, err = sql.Open("postgres", "password=password  user=user dbname=my_db sslmode=disable")
	if err != nil {
		panic(err)
	}

	_, err = DB.Exec("CREATE TABLE IF NOT EXISTS login(name varchar, password varchar)")

	if err != nil {
		panic(err)
	}

	//Replace with proper relational tables.
	_, err = DB.Exec("CREATE TABLE IF NOT EXISTS files(qhash varchar, keyhash varchar)")

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
	vars := mux.Vars(r)
	key := vars["id"]

	var qhash string

	rows, err := DB.Query("Select qhash from files where keyhash=$1", key)

	if err != nil {
		panic(err)
	}

	for rows.Next() {
		err = rows.Scan(&qhash)

		if err != nil {
			panic(err)
		}

		break

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

	//Add the hash received from ipfs and the key to the database
	_, err = DB.Exec("insert into files values($1, $2)", hash, key)

	w.Write([]byte(hash))
	w.Write([]byte("\n\n"))

	w.Write([]byte((key)))

}
