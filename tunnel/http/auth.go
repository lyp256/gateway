package http

import (
	"fmt"
	"net/http"
)

const (
	APIKEY = "api-key"
)

type AuthenticationFunc func(*http.Request) error

func GetAPIKey(req *http.Request) string {
	key := req.URL.Query().Get(APIKEY)
	if key != "" {
		return key
	}
	key = req.Header.Get(APIKEY)
	if key != "" {
		return key
	}
	if ck, _ := req.Cookie(APIKEY); ck.Value != "" {
		return ck.Value
	}
	return ""
}

func NewKeyAuth(key string) AuthenticationFunc {
	if key == "" {
		return nil
	}
	return func(r *http.Request) error {
		if GetAPIKey(r) != key {
			return fmt.Errorf("Unauthorized")
		}
		return nil
	}
}
