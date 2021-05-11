package main

import (
	"fmt"
	"github.com/fobus1289/jwt_auth"
	"time"
)

func main() {
	for i := 0; i < 100000; i++ {
		test(i)
	}

	for true {
		time.Sleep(time.Second * 10)
		break
	}

	fmt.Println("start")

	for i := 0; i < 1000000; i++ {
		go test(i)
	}

	for true {
		time.Sleep(time.Second * 10)
		break
	}
	fmt.Println("end")
}

func test(i int) bool {

	mac := jwt_auth.NewHmac256("asdasd", &jwt_auth.User{
		Id:      i,
		Login:   "fobus",
		Expired: 15,
	}, nil)

	_, err := mac.Encode()

	if err != nil {
		return false
	}

	return true
}
