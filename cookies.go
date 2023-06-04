package main

import (
	http "github.com/Noooste/fhttp"
	"net/url"
	"strings"
	"time"
)

type Cookie struct {
	Name  string `json:"name"`
	Value string `json:"value"`

	Path    string `json:"path"`
	Domain  string `json:"domain"`
	Expires string `json:"expires"`

	MaxAge   int  `json:"max-age"`
	Secure   bool `json:"secure"`
	HttpOnly bool `json:"http-only"`
}

func filterCookie(header http.Header) []*http.Cookie {
	var alreadyPutValues []string
	var filteredCookies []*http.Cookie

	cookies := http.ReadSetCookies(header)

	for _, cookie := range cookies {
		valid := false

		if contains(alreadyPutValues, cookie.Name) {
			continue
		}

		if cookie.MaxAge != 0 {
			if cookie.MaxAge != -1 {
				valid = true
			}

		} else {
			if !cookie.Expires.IsZero() {
				valid = cookie.Expires.UnixMilli() > time.Now().UnixMilli()
			} else {
				valid = true
			}
		}

		if valid {
			filteredCookies = append(filteredCookies, cookie)
			alreadyPutValues = append(alreadyPutValues, cookie.Name)
		}
	}

	return filteredCookies
}

func getHostCookies(sessionId uint64, url *url.URL) []*http.Cookie {
	session, _ := Sessions.Get(sessionId, false)
	return session.Cookies.Cookies(url)
}

func cookiesToJSON(cookies []*http.Cookie) map[string]string {
	returnCookies := map[string]string{}

	for _, cookie := range cookies {
		returnCookies[cookie.Name] = cookie.Value
	}

	return returnCookies
}

func cookiesToString(cookies []*http.Cookie) string {
	finalString := ""
	for _, el := range cookies {
		finalString += el.Name + "=" + el.Value + "; "
	}

	if finalString != "" {
		return finalString[:len(finalString)-2]
	}

	return finalString
}

func cookiesStringToJSON(cookies string) map[string]string {
	cookiesSplit := strings.Split(cookies, ";")

	returnCookies := make(map[string]string, len(cookiesSplit))
	for _, cookie := range cookiesSplit {
		cookie = strings.Trim(cookie, " ")
		keyValue := strings.Split(cookie, "=")
		returnCookies[keyValue[0]] = keyValue[1]
	}

	return returnCookies
}

func cookiesJSONToString(cookies map[string]string) string {
	returnCookies := ""

	for key, value := range cookies {
		returnCookies += key + "=" + value + "; "
	}

	if len(returnCookies) > 2 {
		return returnCookies[:len(returnCookies)-2]
	}

	return ""
}
