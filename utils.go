package main

import (
	"bytes"
	"encoding/json"
	http "github.com/Noooste/fhttp"
	"io/ioutil"
	"math/rand"
	URL "net/url"
	"strconv"
	"strings"
	"time"
)

const (
	wrongFormat = "a value is in wrong format"
	isInvalid   = "not valid json"
)

func contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

func extractHost(url string) string {
	parsed, err := URL.Parse(url)

	if err != nil {
		return ""
	}

	return parsed.Host
}

func extractDomainFromHost(host string) string {
	splitHost := strings.Split(host, ".")

	if len(splitHost) > 2 {
		return splitHost[len(splitHost)-2] + "." + splitHost[len(splitHost)-1]
	}

	return strings.Join(splitHost, ".")
}

func setContentType(headers map[string]string, data string) string {
	if data != "" {
		if _, ok := headers["content-type"]; !ok {
			var contentType string
			if data[0] == '{' || data[0] == '[' {
				contentType = "application/json"
			} else {
				contentType = http.DetectContentType([]byte(data))
			}
			return contentType
		}
	}

	return ""
}

func (c *Context) buildRequest(req *Request) (*http.Request, error) {
	var newReq *http.Request
	var err error

	//prepare new request
	switch req.Data {
	case "":
		newReq, err = http.NewRequest(strings.ToUpper(req.Method), req.Url, nil)

	default:
		newReq, err = http.NewRequest(strings.ToUpper(req.Method), req.Url, bytes.NewBuffer([]byte(req.Data)))
	}

	if err != nil {
		return nil, err
	}

	newReq.Header = req.Header

	newReq.Header[http.HeaderOrderKey] = req.HeaderOrder

	var order = make([]string, 4)

	if req.PHeader != nil && len(req.PHeader) == 4 {
		for i, el := range req.PHeader {
			if el[0] != ':' {
				el = ":" + el
			}
			order[i] = el
		}
	} else {
		switch guessMyNavigator(newReq.Header["user-agent"][0]) {
		case firefox:
			order = []string{Method, Path, Authority, Scheme}

		case chrome, opera, edge: //chrome sub products
			order = []string{Method, Authority, Scheme, Path}
		}
	}

	newReq.Header[http.PHeaderOrderKey] = order

	return newReq, nil
}

func isRedirectStatusCode(statusCode int) bool {
	return statusCode == 301 || statusCode == 302 || statusCode == 303 || statusCode == 307
}

func (response *Response) toString() string {
	returnElement, _ := json.Marshal(response)
	return string(returnElement)
}

func formatHeader(header map[string]string) map[string]string {
	newHeader := map[string]string{}
	for key, value := range header {
		newHeader[strings.ToLower(key)] = value
	}
	return newHeader
}

func formatHeaderOrder(order []string) []string {
	var newOrder []string
	for _, el := range order {
		newOrder = append(newOrder, strings.ToLower(el))
	}
	return newOrder
}

func cleanHeader(header map[string]string) map[string]string {
	newHeaders := header
	for key, value := range header {
		if value == "" {
			delete(newHeaders, key)
		}
	}
	return newHeaders
}

func getRandomId() uint64 {
	rand.Seed(time.Now().UnixNano())
	return rand.Uint64()
}

func returnWeb(success *SuccessReturn) []byte {
	dumped, err := json.Marshal(success)

	if err != nil {
		return []byte("{}")
	}

	return dumped
}

func returnError(error string) []byte {
	return returnWeb(&SuccessReturn{
		Success: false,
		Error:   error,
	})
}

func returnSuccess() []byte {
	return returnWeb(&SuccessReturn{
		Success: true,
		Error:   "",
	})
}

func getBodyString(request *http.Request) string {
	var body string

	encoding := request.Header.Get("Content-Encoding")

	bodyBytes, err := ioutil.ReadAll(request.Body)

	if err != nil {
		body = "error"
	} else if encoding != "" {
		body = string(DecompressBody(bodyBytes, encoding))
	} else {
		body = string(bodyBytes)
	}

	return body
}

func loadsJSONFromBody(request *http.Request) interface{} {
	var information interface{}
	//loads headers in params
	if err := json.Unmarshal([]byte(getBodyString(request)), &information); err != nil {
		return nil
	}
	return information
}

func getSid(req *http.Request) (uint64, []byte) {
	query := req.URL.Query()
	if !query.Has("sid") {
		return 0, returnError("no sid provided")
	} else {
		sid, err := strconv.ParseUint(query.Get("sid"), 10, 64)
		if err != nil {
			return 0, returnError("sid is not valid")
		}
		if !sessionExists(sid) {
			return 0, returnError("no session exists with this id")
		}
		return sid, nil
	}
}

func guessMyNavigator(userAgent string) string {
	useragent := strings.ToLower(userAgent)
	switch {
	case strings.Contains(useragent, firefox):
		return firefox

	case strings.Contains(useragent, chrome):
		return chrome

	case strings.Contains(useragent, "edg"):
		return edge

	case strings.Contains(useragent, "opr"):
		return opera

	case strings.Contains(useragent, safari):
		return safari

	default:
		return chrome
	}
}
