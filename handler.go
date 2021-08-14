package csrp

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"io"
	"net/http"

	"github.com/julienschmidt/httprouter"
)

const (
	cookieName  = "csrf"
	tokenLength = 32
)

func CSRF(h httprouter.Handle) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
		sentToken, err := base64.StdEncoding.DecodeString(r.Header.Get(cookieName))
		if err != nil {
			errorhandler(w)
			return
		}

		var realToken []byte
		tokenCookie, err := r.Cookie(cookieName)
		if err == nil {
			realToken, err = base64.StdEncoding.DecodeString(tokenCookie.Value)
			if err != nil {
				errorhandler(w)
				return
			}
		}

		if len(realToken) != tokenLength || !verifyToken(realToken, sentToken) {
			errorhandler(w)
			return
		}

		h(w, r, p)
	}
}

func errorhandler(w http.ResponseWriter) {
	http.Error(w, http.StatusText(400), 400)
}

func Token(w http.ResponseWriter, r *http.Request) string {
	var token []byte
	tokenCookie, err := r.Cookie(cookieName)
	if err == nil {
		token, err = base64.StdEncoding.DecodeString(tokenCookie.Value)
		if err == nil {
			return base64.StdEncoding.EncodeToString(maskToken(token))
		}
	}
	token = generateToken()
	cookie := http.Cookie{
		Name:     cookieName,
		Value:    base64.StdEncoding.EncodeToString(token),
		MaxAge:   86400,
		HttpOnly: true,
		Path:     "/",
		Secure:   true,
	}
	http.SetCookie(w, &cookie)
	return base64.StdEncoding.EncodeToString(maskToken(token))
}

func generateToken() []byte {
	bytes := make([]byte, tokenLength)
	io.ReadFull(rand.Reader, bytes)
	return bytes
}

func verifyToken(realToken, sentToken []byte) bool {
	realN := len(realToken)
	sentN := len(sentToken)
	unmasked := unmaskToken(sentToken)
	if realN == tokenLength && sentN == 2*tokenLength {
		return subtle.ConstantTimeCompare(realToken, unmasked) == 1
	}
	return false
}

func oneTimePad(data, key []byte) {
	n := len(data)
	if n != len(key) {
		panic("Lengths of slices are not equal")
	}

	for i := 0; i < n; i++ {
		data[i] ^= key[i]
	}
}

func maskToken(data []byte) []byte {
	if len(data) != tokenLength {
		return nil
	}

	result := make([]byte, 2*tokenLength)
	key := result[:tokenLength]
	token := result[tokenLength:]
	copy(token, data)

	io.ReadFull(rand.Reader, key)

	oneTimePad(token, key)
	return result
}

func unmaskToken(data []byte) []byte {
	if len(data) != tokenLength*2 {
		return nil
	}

	token := data[tokenLength:]
	oneTimePad(token, data[:tokenLength])

	return token
}
