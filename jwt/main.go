package main

import (
	"auth/authentication/jwt/handler"
	"log"
	"net/http"
)

func main() {
	http.HandleFunc("/login", handler.Login)
	http.HandleFunc("/home", handler.Home)

	log.Fatal(http.ListenAndServe(":8080", nil))

}
