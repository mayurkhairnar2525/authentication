package main

import (
	"auth/authentication/jwt-middleware/handler"
	"log"
	"net/http"
)

func main() {
	http.HandleFunc("/login", handler.Login)
	http.HandleFunc("/home", handler.IsAuthorised(handler.Home))
	log.Fatal(http.ListenAndServe(":8080", nil))

}
