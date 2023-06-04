package main

import (
	"encoding/base64"
	"fmt"
	http "github.com/Noooste/fhttp"
	"io/ioutil"
	"log"
	"strings"
)

func BuildResponse(response *Response, httpResponse *http.Response) *Response {
	defer httpResponse.Body.Close()

	encoding := httpResponse.Header.Get("content-encoding")

	bodyBytes, err := ioutil.ReadAll(httpResponse.Body)

	if err != nil {
		log.Print(err)
		return nil
	}

	var Header = map[string]string{}

	for key, value := range httpResponse.Header {
		Header[key] = value[0]
	}

	result := DecompressBody(bodyBytes, encoding)

	if strings.Contains(httpResponse.Header.Get("content-type"), "octet-stream") {
		response.Body = base64.StdEncoding.EncodeToString(result)
		response.IsBase64Encoded = true
	} else {
		response.Body = string(result)
		response.IsBase64Encoded = false
	}

	response.Id = getRandomId()
	response.StatusCode = httpResponse.StatusCode
	response.Headers = Header
	response.Cookies = cookiesToJSON(filterCookie(httpResponse.Header))
	response.Url = httpResponse.Request.URL.String()

	return response
}

func BuildServerPushResponse(response *http.Response) *ServerPush {
	defer response.Body.Close()

	var body string

	encoding := response.Header.Get("content-encoding")

	bodyBytes, err := ioutil.ReadAll(response.Body)

	var IsBase64Encoded bool

	if err != nil {
		body = "error"
	} else if encoding != "" {
		result := DecompressBody(bodyBytes, encoding)
		if strings.Contains(response.Header.Get("content-type"), "octet-stream") {
			body = base64.StdEncoding.EncodeToString(result)
			IsBase64Encoded = true
		} else {
			body = string(result)
			IsBase64Encoded = false
		}

	} else {
		body = string(bodyBytes)
	}

	var Header = map[string]string{}

	for key, value := range response.Header {
		Header[key] = value[0]
	}

	return &ServerPush{
		StatusCode:      response.StatusCode,
		Body:            body,
		Headers:         Header,
		Cookies:         cookiesToJSON(http.ReadSetCookies(response.Header)),
		Url:             response.Request.URL.String(),
		IsBase64Encoded: IsBase64Encoded,
	}
}

// DecompressBody unzips compressed data
func DecompressBody(Body []byte, encoding string) (parsedBody []byte) {
	if len(encoding) > 0 {
		if encoding == "gzip" {
			unz, err := GUnzipData(Body)
			if err != nil {
				return Body
			}
			parsedBody = unz

		} else if encoding == "deflate" {
			unz, err := EnflateData(Body)
			if err != nil {
				return Body
			}
			parsedBody = unz

		} else if encoding == "br" {
			unz, err := UnBrotliData(Body)
			if err != nil {
				return Body
			}
			parsedBody = unz

		} else {
			fmt.Print("Unknown Encoding" + encoding)
			parsedBody = Body
		}

	} else {
		parsedBody = Body
	}

	return parsedBody
}
