package main 

import (
    "net/http"
    "github.com/gorilla/mux"
    "crypto/sha256"
    "encoding/hex"
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

    sha.Write([]byte(data))
    hashString := hex.EncodeToString(sha.Sum(nil))

    //w.Write([]byte(data))
    w.Write([]byte(hashString))


}
