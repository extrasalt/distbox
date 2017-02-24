package main 

import (
    "net/http"
    "github.com/gorilla/mux"
    "crypto/sha256"
    "encoding/hex"
    "crypto/aes"
    //"crypto/rand"
    "crypto/cipher"
    //"io"
    "fmt"
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
    key:=sha.Sum(nil)
    plaintext := []byte(data)

    intermediate := encrypt(key, plaintext)

    decrypt(key, intermediate)

    
}

func encrypt(key []byte, plaintext []byte) (ciphertext []byte){
    block, err := aes.NewCipher(key)
    if err != nil {
        panic(err.Error())
    }

    // nonce := make([]byte, 12)
    // if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
    //     panic(err.Error())
    // }

    nonce, _ := hex.DecodeString("37b8e8a308c354048d245f6d")

    aesgcm, err := cipher.NewGCM(block)
    if err != nil {
        panic(err.Error())
    }

    ciphertext = aesgcm.Seal(nil, nonce, plaintext, nil)

    return ciphertext
    
} 

func decrypt(key []byte, ciphertext []byte) (plaintext []byte){
    nonce, _ := hex.DecodeString("37b8e8a308c354048d245f6d")

    block, err := aes.NewCipher(key)
    if err != nil {
        panic(err.Error())
    }

    aesgcm, err := cipher.NewGCM(block)
    if err != nil {
        panic(err.Error())
    }

    plaintext, err = aesgcm.Open(nil, nonce, ciphertext, nil)
    if err != nil {
        panic(err.Error())
    }

    fmt.Printf("%s\n", plaintext)

    return plaintext

}