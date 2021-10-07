package main

import (
	"fmt"
	"github.com/dgrijalva/jwt-go"
)

var mySigningKey = []byte("SuperSecretKey")

func GenerateJWT() (string, error) {
	token := jwt.New(jwt.SigningMethodHS256)
	//claims := token.Claims.(jwt.MapClaims)
	//claims["authorized"] = true
	//claims["user"] = "mayur"
	//claims["exp"] = time.Now().Add(time.Minute * 30).Unix()

	tokenstring, err := token.SignedString(mySigningKey)
	if err != nil {
		fmt.Printf("Something went wrong %s\n", err)
	}
	return tokenstring, err

}

func main() {
	fmt.Println("My simple client")
	tokenstring, err := GenerateJWT()
	if err != nil {
		fmt.Println("err", err)
	}
	fmt.Println("Success:", tokenstring)
}
