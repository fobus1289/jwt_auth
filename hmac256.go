package jwt_auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash"
	"time"
	"unsafe"
)

var sha = sha256.New

type head struct {
	Alg  string
	Type string
}

var Head = &head{
	"HS256",
	"JWT",
}

type hmac256 struct {
	hash.Hash
	User IUser
}

type IUser interface {
	Expired() time.Duration
}

func NewHmac256(secret string, user IUser) *hmac256 {
	h := hmac.New(sha, *(*[]byte)(unsafe.Pointer(&secret)))
	return &hmac256{
		h,
		user,
	}
}

func (h *hmac256) Decode(token string) IUser {

	var i int8
	var indexes = make([]int, 2, 2)

	for index, t := range token {
		if t == 46 {

			if i > 2 {
				return nil
			}

			indexes[i] = index
			i++
		}
	}

	if i != 2 {
		return nil
	}

	_head := token[0:indexes[0]]
	_payload := token[indexes[0]+1 : indexes[1]]
	_signature := _head + _payload
	_hasSignature := token[indexes[1]+1:]

	if !h.ValidMAC(*(*[]byte)(unsafe.Pointer(&_signature)), *(*[]byte)(unsafe.Pointer(&_hasSignature))) {
		return nil
	}

	usr, err := base64.StdEncoding.DecodeString(_payload)

	err = json.Unmarshal(usr, h.User)
	fmt.Println(err)
	return h.User
}

func (h *hmac256) Encode() string {

	_head, _err := json.Marshal(Head)

	if _err != nil {
		return ""
	}

	_payload, _err := json.Marshal(h.User)

	if _err != nil {
		return ""
	}

	_stringHead := base64.StdEncoding.EncodeToString(_head)
	_stringPayload := base64.StdEncoding.EncodeToString(_payload)
	_signature := _stringHead + _stringPayload

	sum := h.Sum([]byte(_signature))
	bb := base64.StdEncoding.EncodeToString(sum)
	return _stringHead + "." + _stringPayload + "." + bb
}

func (h *hmac256) ValidMAC(message, messageMAC []byte) bool {
	b, err := base64.StdEncoding.DecodeString(*(*string)(unsafe.Pointer(&messageMAC)))

	fmt.Println(err)

	return hmac.Equal(h.Sum(message), b)
}
