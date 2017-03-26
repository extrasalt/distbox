package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/gorilla/mux"
	"gopkg.in/mgo.v2"
	"html/template"
	"io"
	"labix.org/v2/mgo/bson"
	"net/http"
	"os"

	ipfs "github.com/ipfs/go-ipfs-api"
)

var session *mgo.Session

func main() {
	var err error

	username := os.Getenv("MONGO_USER")
	password := os.Getenv("MONGO_PASSWORD")

	//TODO: URL is still hardcoded
	url := fmt.Sprintf("mongodb://%s:%s@ds143030.mlab.com:43030/rcs", username, password)
	session, err = mgo.Dial(url)
	if err != nil {
		panic(err)
	}

	r := mux.NewRouter()
	r.HandleFunc("/", ShowLoginPageHandler).Methods("GET")
	r.HandleFunc("/login", LoginHandler)
	r.HandleFunc("/logout", LogoutHandler)
	r.HandleFunc("/signup", SignUpHandler).Methods("POST")
	r.HandleFunc("/file/{id}", authenticate(GetFileHandler)).Methods("GET")
	r.HandleFunc("/file", authenticate(FileUploadHandler)).Methods("POST")
	r.HandleFunc("/files", authenticate(ListFilesHandler)).Methods("GET")
	r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("./static/"))))

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

	usersCollection := session.DB("rcs").C("User")

	err := usersCollection.Find(bson.M{"username": username}).One(&user)

	for _, file := range user.Files {
		fmt.Println(file.Key)
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

	r.ParseMultipartForm(32 << 20)
	file, header, err := r.FormFile("data")

	if err != nil {
		panic(err)
	}

	cookie, _ := r.Cookie("rcs")
	username := cookie.Value

	var b []byte
	buf := bytes.NewBuffer(b)

	fileCopy := io.TeeReader(file, buf)

	//Find Key
	sha := sha256.New()
	io.Copy(sha, fileCopy)
	key := hex.EncodeToString(sha.Sum(nil))

	ciphertext := encrypt(key, buf)

	shell := ipfs.NewShell("localhost:5001")
	hash, err := shell.Add(ciphertext)

	if err != nil {
		panic(err)
	}

	var user User
	usersCollection := session.DB("rcs").C("User")
	err = usersCollection.Find(bson.M{"username": username}).One(&user)

	if err != nil {
		panic(err)
	}

	//Add the hash received from ipfs and the key to the database
	// _, err = DB.Exec("insert into files values($1, $2)", hash, key)

	user.Files = append(user.Files, FileStruct{
		Name:        header.Filename,
		Key:         key,
		ContentAddr: hash,
	})

	err = usersCollection.Update(bson.M{"username": username}, user)

	//Redirect to Files list if no errors
	if err != nil {
		w.Write([]byte("Unable to upload"))
	}
	http.Redirect(w, r, "/files", 302)

}

func ListFilesHandler(w http.ResponseWriter, r *http.Request) {

	//Get username
	cookie, _ := r.Cookie("rcs")
	username := cookie.Value

	//var user User
	var user User
	usersCollection := session.DB("rcs").C("User")
	err := usersCollection.Find(bson.M{"username": username}).One(&user)

	if err != nil {
		panic(err)
	}

	tmpl, err := template.ParseFiles("templates/files.html")

	if err != nil {
		panic(err)
	}

	tmpl.Execute(w, user)
}

func ShowLoginPageHandler(w http.ResponseWriter, r *http.Request) {
	tmpl, _ := template.ParseFiles("templates/login.html")
	tmpl.Execute(w, nil)
}

func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	cookie, _ := r.Cookie("rcs")
	cookie.MaxAge = -1
	http.SetCookie(w, cookie)
	http.Redirect(w, r, "/", 302)
}
