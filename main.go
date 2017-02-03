package main 

import (
    "net/http"
    "github.com/gorilla/mux"
)

func main(){

    r:= mux.NewRouter()
    r.HandleFunc("/file", FileUploadHandler).Methods("POST")
    r.PathPrefix("/").Handler(http.FileServer(http.Dir("./static/")))
    

    http.ListenAndServe(":3000", r)
}


func FileUploadHandler(w http.ResponseWriter, r *http.Request){

    r.ParseForm()

    data := r.Form["data"][0]

    w.Write([]byte(data))


}
