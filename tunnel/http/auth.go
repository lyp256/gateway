package http

import "net/http"

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
