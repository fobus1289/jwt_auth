package jwt_auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"hash"
	"log"
	"os"
	"time"
)

var invalidSignature = errors.New("invalid signature")
var tokenExpired = errors.New("token expired")
var logger *log.Logger
var sha = sha256.New

type head struct {
	Alg        string
	Type       string
	HeadString []byte `json:"-"`
}

func (h *head) toJson() *head {
	_head, _err := json.Marshal(h)

	if _err != nil {
		logger.Println(_err.Error())
		return nil
	}
	h.HeadString = _head
	return h
}

var ifNotLogger = log.New(os.Stdout, "WARNING: ", log.Ltime|log.Lshortfile)

var Head = (&head{
	"HS256",
	"JWT",
	nil,
}).toJson()

type hmac256 struct {
	hash.Hash
	User User
}

type User struct {
	Id      int      `json:"id"`
	Login   string   `json:"login"`
	Roles   []string `json:"roles"`
	Expired time.Duration
}

func NewHmac256(secret string, user *User, _logger *log.Logger) *hmac256 {

	if _logger != nil {
		logger = _logger
	} else {
		logger = ifNotLogger
	}

	mac := &hmac256{
		hmac.New(sha, []byte(secret)),
		*user,
	}

	return mac
}

func (h *hmac256) Decode(token string) (*User, error) {
	var i int
	var indexes = make([]int, 2, 2)

	for index, t := range token {
		if t == 46 {

			if len(indexes) <= i {
				logger.Println(invalidSignature.Error())
				return nil, invalidSignature
			}

			indexes[i] = index
			i++
		}
	}

	if i != 2 {
		logger.Println(invalidSignature.Error())
		return nil, invalidSignature
	}

	_head := token[0:indexes[0]]
	_payload := token[indexes[0]+1 : indexes[1]]
	_signature := _head + _payload
	_hasSignature := token[indexes[1]+1:]

	if ok, _ := h.Valid([]byte(_signature), []byte(_hasSignature)); !ok {
		logger.Println(invalidSignature.Error())
		return nil, invalidSignature
	}

	usr, err := base64.StdEncoding.DecodeString(_payload)

	err = json.Unmarshal(usr, &h.User)

	if err != nil {
		logger.Println(err.Error())
		return nil, err
	}

	now := time.Now()

	if now.Unix() > int64(h.User.Expired) {
		logger.Println(tokenExpired.Error())
		return nil, tokenExpired
	}
	return &h.User, nil
}

func (h *hmac256) Encode() (string, error) {

	exp := time.Now().Add(h.User.Expired * time.Minute).Unix()
	h.User.Expired = time.Duration(exp)
	_payload, _err := json.Marshal(h.User)

	if _err != nil {
		logger.Println(_err.Error())
		return "", _err
	}

	_stringHead := base64.StdEncoding.EncodeToString(Head.HeadString)

	_stringPayload := base64.StdEncoding.EncodeToString(_payload)
	_signature := _stringHead + _stringPayload

	sum := h.Sum([]byte(_signature))
	readySignature := base64.StdEncoding.EncodeToString(sum)

	return _stringHead + "." + _stringPayload + "." + readySignature, nil
}

func (h *hmac256) Valid(message, messageMAC []byte) (bool, error) {
	result, err := base64.StdEncoding.DecodeString(string(messageMAC))
	return hmac.Equal(h.Sum(message), result), err
}
