package cookies

import (
	"net/http"
	"strings"
	"time"
)

type Cookies struct {
	url string
}

func New(url string) *Cookies {
	return &Cookies{url}
}

func (c *Cookies) Set(name string, value string, date time.Time, w http.ResponseWriter) {
	cookie := &http.Cookie{
		Name:     name,
		Value:    value,
		HttpOnly: true,
		Expires:  date,
		Path:     "/api",
	}
	if !strings.HasPrefix(c.url, "http://localhost:") {
		cookie.SameSite = http.SameSiteNoneMode
		cookie.Secure = true
	}
	http.SetCookie(w, cookie)
}

func (c *Cookies) Clear(name string, w http.ResponseWriter) {
	cookie := &http.Cookie{
		Name:     name,
		Value:    "",
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
		Path:     "/api",
	}
	if !strings.HasPrefix(c.url, "http://localhost:") {
		cookie.SameSite = http.SameSiteNoneMode
		cookie.Secure = true
	}
	http.SetCookie(w, cookie)
}
