package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"github.com/gorilla/mux"
	ipfs "github.com/ipfs/go-ipfs-api"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
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

	//Add the hash received from ipfs and the key to the database
	_, err = DB.Exec("insert into files values($1, $2)", hash, key)

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

func authenticate(next http.HandlerFunc) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		_, err := r.Cookie("rcs")
		if err != nil {
			http.Redirect(w, r, "/login", 302)
		} else {
			next(w, r)
		}

	}

}

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		panic(err)
	}

	username := r.Form["name"][0]
	password := r.Form["password"][0]

	err = authorize(username, password)

	if err == nil {
		cookie := &http.Cookie{Name: "rcs", Value: username, MaxAge: 3600, Secure: false, HttpOnly: true, Raw: username}
		http.SetCookie(w, cookie)
		w.Write([]byte("authenticated"))
	} else {
		w.Write([]byte("Wrong password"))
	}
}

func SignUpHandler(w http.ResponseWriter, r *http.Request) {

	err := r.ParseForm()

	if err != nil {
		panic(err)
	}

	username := r.Form["name"][0]
	password := r.Form["password"][0]

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

	if err != nil {
		fmt.Println(err)
	}
	_, err = DB.Exec("insert into login values($1, $2)", username, hashedPassword)
	http.Redirect(w, r, "/", 302)
}

func authorize(username string, password string) (autherr error) {

	var dbpassword string

	rows, err := DB.Query("Select password from login where name=$1", username)

	if err != nil {
		panic(err)
	}

	for rows.Next() {
		err = rows.Scan(&dbpassword)

		if err != nil {
			panic(err)
		}

		break

	}

	err = bcrypt.CompareHashAndPassword([]byte(dbpassword), []byte(password))

	if err == nil {

		return nil

	} else {
		autherr = fmt.Errorf("Cannot authorize %q", username)

		return autherr
	}

}
