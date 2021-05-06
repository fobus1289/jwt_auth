package jwt_auth

import (
	"fmt"
	"time"
)

const secret = "secret@secret"

type User struct {
	Id   int    `json:"id"`
	Name string `json:"name"`
	Age  int    `json:"age"`
}

func (user *User) Expired() time.Duration {
	return 15
}

func Q() {

	go b()
	for true {
		time.Sleep(5 * time.Second)
	}
}

func b() {

	u := User{
		Id:   1,
		Name: "fobus",
		Age:  88,
	}

	h := NewHmac256(secret, &u)
	r := h.Encode()

	fmt.Println(h.Decode(r))
}

func asd() interface{} {

	return User{
		Id:   1,
		Name: "fobus",
		Age:  88,
	}
}
