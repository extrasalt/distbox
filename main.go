package main 

import (
    "net/http"
    "github.com/gorilla/mux"
    "crypto/sha256"
    "encoding/base64"
)

func main(){

    r:= mux.NewRouter()
    r.HandleFunc("/file", FileUploadHandler).Methods("POST")
    r.PathPrefix("/").Handler(http.FileServer(http.Dir("./static/")))
    

    http.ListenAndServe(":3000", r)
}


func FileUploadHandler(w http.ResponseWriter, r *http.Request){

    sha := sha256.New()


    r.ParseForm()

    data := r.Form["data"][0]

    hashOfFile := sha.Sum([]byte(data))
    hashString := base64.URLEncoding.EncodeToString(hashOfFile)

    //w.Write([]byte(data))
    w.Write([]byte(hashString))


}
