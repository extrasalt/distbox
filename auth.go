package main

import (
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"labix.org/v2/mgo/bson"
	"net/http"
)

type User struct {
	Username string
	Password string
	Files    []FileStruct
}

type FileStruct struct {
	Name        string
	Key         string
	ContentAddr string
}

func authorize(username string, password string) (autherr error) {
	var user User
	usersCollection := session.DB("RCS").C("User")
	usersCollection.Find(bson.M{"username": username}).One(&user)

	err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
	if err == nil {
		return nil
	} else {
		autherr = fmt.Errorf("Cannot authorize %q", username)
		return autherr
	}
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
		http.Redirect(w, r, "/files", 302)
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

	usersCollection := session.DB("RCS").C("User")
	err = usersCollection.Insert(&User{
		Username: username,
		Password: string(hashedPassword),
	})

	if err != nil {
		panic(err)
	}
	http.Redirect(w, r, "/", 302)
}
