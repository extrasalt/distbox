package main

import (
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"net/http"
)

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