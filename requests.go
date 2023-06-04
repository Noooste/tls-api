package main

import (
	"bufio"
	"errors"
	http "github.com/Noooste/fhttp"
	"github.com/Noooste/fhttp/http2"
	"log"
	URL "net/url"
	"strings"
	"sync"
	"time"
)

/*
Handle non secured request
*/
func sendNonSecuredRequest(request *Request) (*Response, error) {
	var response = &Response{}

	c := getContext(request.SessionId, extractHost(request.Url))
	session, _ := Sessions.Get(c.Id, false)

	client := http.Client{}

	client.Timeout = time.Duration(request.TimeOut) * time.Second

	httpRequest, err := c.buildRequest(request)

	if err != nil {
		return nil, err
	}

	httpResponse, err := client.Do(httpRequest)
	if err != nil {
		return nil, err
	}

	parsed, _ := URL.Parse(request.Url)
	cookies := http.ReadSetCookies(httpResponse.Header)
	for _, cookie := range cookies {
		request.Cookies[cookie.Name] = cookie.Value
	}
	session.Cookies.SetCookies(parsed, cookies)
	session.update(c)

	if request.AllowRedirect && isRedirectStatusCode(httpResponse.StatusCode) {
		response, err = c.handleRedirection(request, httpResponse.Header.Get("location"))

		if err != nil {
			return nil, err
		}
	}

	response = BuildResponse(response, httpResponse)

	return response, nil
}

func sendSecuredRequest(request *Request) (*Response, error) {
	var response = &Response{ServerPush: []*ServerPush{}}

	var host = extractHost(request.Url)

	c := getContext(request.SessionId, host)

	session, ok := Sessions.Get(c.Id, false)

	if !ok {
		return nil, errors.New("session doesn't exists")
	}

	httpRequest, err := c.buildRequest(request)

	if err != nil {
		return nil, err
	}

	if c.TLSConnection == nil || request.Proxy != c.ProxyUrl {
		tConn, err := c.getTconn(request, session)
		if err != nil {
			return nil, err
		}
		c.TLSConnection = tConn
		c.Connection = nil
	}

	switch c.TLSConnection.ConnectionState().NegotiatedProtocol {

	case "h2":
		if c.Connection == nil || !c.Connection.CanTakeNewRequest() {
			err := c.SetupTransport(request, session)
			if err != nil {
				return nil, err
			}
			//generate new client connection
			cConn, err := c.Transport.NewClientConn(c.TLSConnection)
			if err != nil && err.Error() == "tls: use of closed connection" {
				c.TLSConnection = nil
				session.update(c)
				return sendSecuredRequest(request)
			} else if err != nil {
				return nil, err
			}

			c.Connection = cConn
		}

		if request.FetchServerPush {
			c.Transport.PushHandler = &DefaultPushHandler{
				response: response,
				request:  request,
				mu:       &sync.Mutex{},
			}
		} else {
			c.Transport.PushHandler = &http2.DefaultPushHandler{}
		}

		session.update(c)

		response, err = c.http2Request(request, httpRequest, response)

		if err != nil {
			return nil, err
		}

	default:
		err = httpRequest.Write(c.TLSConnection)

		if err != nil {
			return nil, err
		}

		httpResponse, err := http.ReadResponse(bufio.NewReader(c.TLSConnection), httpRequest)

		if err != nil {
			return nil, err
		}

		parsed, _ := URL.Parse(request.Url)
		cookies := http.ReadSetCookies(httpResponse.Header)
		for _, cookie := range cookies {
			request.Cookies[cookie.Name] = cookie.Value
		}
		session.Cookies.SetCookies(parsed, cookies)
		Sessions.Set(c.Id, session)

		response = BuildResponse(response, httpResponse)

		if request.AllowRedirect && isRedirectStatusCode(httpResponse.StatusCode) {
			session.update(c)
			return c.handleRedirection(request, httpResponse.Header.Get("location"))
		}
	}

	session.update(c)

	return response, nil
}

func (c *Context) http2Request(request *Request, httpRequest *http.Request, response *Response) (*Response, error) {
	var httpResponse *http.Response

	var err error
	session, _ := Sessions.Get(c.Id, false)

	httpResponse, err = c.Connection.RoundTrip(httpRequest)

	if err != nil {
		errString := err.Error()
		log.Print(err)
		if strings.Contains(errString, "use of closed network connection") {
			c.Connection = nil
			return sendSecuredRequest(request)
		}
		if errString == "tls: use of closed connection" {
			c.TLSConnection = nil
			return sendSecuredRequest(request)
		}
		return nil, err
	}

	parsed, _ := URL.Parse(request.Url)
	cookies := http.ReadSetCookies(httpResponse.Header)
	for _, cookie := range cookies {
		request.Cookies[cookie.Name] = cookie.Value
	}
	session.Cookies.SetCookies(parsed, cookies)

	session.update(c)

	session, _ = Sessions.Get(c.Id, false)

	if err != nil {
		return nil, err
	}

	if request.AllowRedirect && !request.FetchServerPush && isRedirectStatusCode(httpResponse.StatusCode) {
		return c.handleRedirection(request, httpResponse.Header.Get("location"))
	}

	response = BuildResponse(response, httpResponse)
	return response, nil
}

func (c *Context) handleRedirection(request *Request, url string) (*Response, error) {
	newUrl, _ := URL.Parse(url)
	oldUrl, _ := URL.Parse(request.Url)

	delete(request.Header, "content-type")
	delete(request.Header, "content-length")

	if newUrl.Scheme == "" {
		if len(request.Cookies) > 0 {
			request.Header["cookie"] = []string{cookiesJSONToString(request.Cookies)}
		}
		request.Url = oldUrl.Scheme + "://" + oldUrl.Host + url
		request.Method = "GET"
		request.Data = ""
		newUrl.Scheme = oldUrl.Scheme

	} else {
		session, _ := Sessions.Get(c.Id, false)
		cookies := session.Cookies.Cookies(newUrl)
		cookiesJSON := cookiesToJSON(cookies)
		if len(request.Cookies) > 0 {
			request.Header["cookie"] = []string{cookiesJSONToString(cookiesJSON)}
		}

		request = &Request{
			SessionId:     c.Id,
			Method:        "GET",
			Url:           url,
			Data:          "",
			Proxy:         request.Proxy,
			Cookies:       cookiesJSON,
			Browser:       request.Browser,
			AllowRedirect: request.AllowRedirect,
			TimeOut:       request.TimeOut,
			Verify:        request.Verify,
			PHeader:       request.PHeader,
			Header:        request.Header,
			HeaderOrder:   request.HeaderOrder,
		}
	}

	switch newUrl.Scheme {
	case "http":
		return sendNonSecuredRequest(request)

	case "https":
		return sendSecuredRequest(request)

	default:
		return nil, errors.New("unknown scheme:" + newUrl.Scheme + ".")
	}
}
