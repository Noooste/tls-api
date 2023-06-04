package main

import (
	"encoding/base64"
	"encoding/json"
	http "github.com/Noooste/fhttp"
	"github.com/Noooste/fhttp/http2"
	"github.com/Noooste/utls"
	"github.com/pborman/getopt"
	"io"
	"log"
	URL "net/url"
	"runtime/debug"
	"strconv"
	"strings"
	"time"
)

var auth string
var port string
var forceProxies bool
var inactivityTimer int
var sizeLimitResponse int
var sizeLimitRequest int
var local bool

func main() {
	authTmp := getopt.StringLong("auth", 'a', "", "Authentication key")
	portTmp := getopt.StringLong("port", 'p', "4444", "Listening port")

	proxyTmp := getopt.BoolLong("proxy", 0, "Force proxy usage")
	localTmp := getopt.BoolLong("local", 0, "Force proxy usage")

	timerTmp := getopt.IntLong("inactivity-timeout", 'i', 600, "Remove inactive connections after a given time")
	sizeLimitResponseTmp := getopt.IntLong("response-size-limit", 0, 0, "Set response body size limit")
	sizeLimitRequestTmp := getopt.IntLong("request-size-limit", 0, 0, "Set request body size limit")

	getopt.Parse()

	auth = *authTmp
	port = *portTmp
	inactivityTimer = *timerTmp
	forceProxies = *proxyTmp
	local = *localTmp
	sizeLimitResponse = *sizeLimitResponseTmp
	sizeLimitRequest = *sizeLimitRequestTmp

	if auth == "TOKEN_TEST" {
		go clearMemory()
		go monitorSessions()
		startWebServer()
	}
}

type RequestInformation struct {
	Method        string            `json:"method"`
	Url           string            `json:"url"`
	Data          string            `json:"data"`
	PHeader       []string          `json:"pheader"`
	Header        map[string]string `json:"header"`
	HeaderOrder   []string          `json:"header-order"`
	Proxy         string            `json:"proxy"`
	Browser       string            `json:"navigator"`
	Timeout       int               `json:"timeout"`
	AllowRedirect bool              `json:"allow-redirect"`
	ServerPush    bool              `json:"server-push"`
	Verify        bool              `json:"verify"`
}

func startWebServer() {
	//generate certificate struct
	cert, _ := tls.X509KeyPair([]byte(crt), []byte(privateKey))

	//create custom server with tls
	s := http.Server{
		Addr:    ":" + port,
		Handler: nil,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			NextProtos:   []string{"h2"},
		},
	}

	//handle
	http.HandleFunc("/", checkKey(ping))

	http.HandleFunc("/session/new", checkKey(handleNewSession))
	http.HandleFunc("/session/request", checkKey(handleRequest))

	http.HandleFunc("/session/cookies", checkKey(getCookies))
	http.HandleFunc("/session/cookies/set", checkKey(setCookies))

	http.HandleFunc("/session/close", checkKey(handleCloseSession))
	http.HandleFunc("/session/keep-alive", checkKey(handleKeepAlive))

	http.HandleFunc("/session/tls/ja3", checkKey(applyJA3))

	http.HandleFunc("/session/http2/stream-priorities", checkKey(applyStreamPriorities))
	http.HandleFunc("/session/http2/settings", checkKey(applyHTTP2Settings))
	http.HandleFunc("/session/http2/windows-update", checkKey(applyWindowsUpdate))

	log.Print("starting server at port " + s.Addr)
	log.Fatal(s.ListenAndServeTLS("", ""))
}

func ping(res http.ResponseWriter, req *http.Request) {
	_, _ = res.Write([]byte("{\"status\" : \"ok\"}"))
}

func checkKey(f func(res http.ResponseWriter, req *http.Request)) func(res http.ResponseWriter, req *http.Request) {

	return func(res http.ResponseWriter, req *http.Request) {
		if local && !(strings.Contains(req.RemoteAddr, "localhost") || strings.Contains(req.RemoteAddr, "127.0.0.1") || strings.Contains(req.RemoteAddr, "[::1]")) {
			return
		}

		defer func() {
			if r := recover(); r != nil && res != nil {
				res.WriteHeader(500)
				_, _ = res.Write(returnError("internal error"))
				debug.PrintStack()
			}
		}()

		if req.Method != "POST" {
			_, _ = res.Write([]byte("unauthorized access"))
			return
		}

		if sizeLimitRequest != 0 {
			length := req.Header.Get("content-length")
			value, err := strconv.Atoi(length)

			if err == nil && value > sizeLimitRequest {
				res.WriteHeader(400)
				_, _ = res.Write([]byte("{\"error\" : \"exceeding limit request body size\"}"))
				return
			}
		}

		if value := req.Header.Get("authorization"); value != "" {
			if value == auth {
				f(res, req)
			} else {
				res.WriteHeader(403)
				_, _ = res.Write([]byte(`{"error" : "something went wrong with this key"}`))
			}
		} else {
			res.WriteHeader(400)
			_, _ = res.Write([]byte(`{"error" : "no key was provided"}`))
		}
	}
}

func handleSizeError(res http.ResponseWriter, _ *http.Request) {
	res.WriteHeader(403)
	_, _ = res.Write([]byte("{\"error\" : \"exceeding limit request body size\"}"))
}
func handleNewSession(res http.ResponseWriter, _ *http.Request) {
	sessionID := initSession()
	res.WriteHeader(201)
	_, _ = res.Write([]byte(`{"success": true, "session-id" : ` + strconv.FormatUint(sessionID, 10) + `}`))
}

func handleCloseSession(res http.ResponseWriter, req *http.Request) {
	var sid uint64
	var sidErr []byte

	if sid, sidErr = getSid(req); sidErr != nil {
		res.WriteHeader(400)
		_, _ = res.Write(sidErr)
		return
	}

	Sessions.Remove(sid)

	res.WriteHeader(200)
	_, _ = res.Write(returnSuccess())
}

func handleKeepAlive(res http.ResponseWriter, req *http.Request) {
	var sid uint64
	var sidErr []byte

	if sid, sidErr = getSid(req); sidErr != nil {
		res.WriteHeader(400)
		_, _ = res.Write(sidErr)
		return
	}

	value := time.Now()
	pool, _ := Sessions.Get(sid, true)
	pool.LastActivity = &value
	Sessions.Set(sid, pool)

	_, _ = res.Write(returnSuccess())
}

func handleRequest(res http.ResponseWriter, req *http.Request) {
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
		}
	}(req.Body)

	var sid uint64
	var sidErr []byte

	var context *Context
	var requestInformation RequestInformation

	if sid, sidErr = getSid(req); sidErr != nil {
		res.WriteHeader(400)
		_, _ = res.Write(sidErr)
		return
	}

	bodyString := getBodyString(req)

	if sizeLimitRequest != 0 && len(bodyString) > sizeLimitRequest {
		handleSizeError(res, req)
		return
	}

	//loads headers in params
	if err := json.Unmarshal([]byte(bodyString), &requestInformation); err != nil {
		_, _ = res.Write(returnError(wrongFormat))
		return
	}

	//init request struct with information from parameters
	request := &Request{
		SessionId:       sid,
		Method:          requestInformation.Method,
		Url:             requestInformation.Url,
		Data:            requestInformation.Data,
		Proxy:           requestInformation.Proxy,
		Cookies:         map[string]string{},
		Browser:         requestInformation.Browser,
		AllowRedirect:   requestInformation.AllowRedirect,
		TimeOut:         requestInformation.Timeout,
		FetchServerPush: requestInformation.ServerPush,
		Verify:          requestInformation.Verify,
		PHeader:         requestInformation.PHeader,
	}

	if request.TimeOut <= 0 {
		request.TimeOut = 99999 //no timeout
	}

	if forceProxies && (request.Proxy == "" || strings.Contains(request.Proxy, "localhost") || strings.Contains(request.Proxy, "127.0.0.1")) {
		_, _ = res.Write(returnError("no proxy provided"))
		return
	}

	//if not then search if a context exists with the requested domain (if no domain is associated to a context it will create a new one with the domain)
	context = getContext(sid, extractHost(request.Url))

	//parse url to get information
	urlHandler, err := URL.Parse(request.Url)

	if err != nil {
		_, _ = res.Write(returnError("can't parse url"))
		return
	}

	//clean headers to remove empty values
	requestInformation.Header = formatHeader(cleanHeader(requestInformation.Header))
	request.HeaderOrder = formatHeaderOrder(requestInformation.HeaderOrder)

	session, _ := Sessions.Get(sid, false)

	//handle cookies in header
	if _, ok := requestInformation.Header["cookie"]; !ok && session.Cookies != nil {
		cookies := cookiesToString(session.Cookies.Cookies(urlHandler))
		if cookies != "" {
			requestInformation.Header["cookie"] = cookies
		}
	}

	//find current content-type of request (return nil if body is empty)
	contentType := setContentType(requestInformation.Header, request.Data)

	if contentType != "" {
		requestInformation.Header["content-type"] = contentType
	}

	//handle octet-stream in header
	value := requestInformation.Header["content-type"]
	if strings.Contains(value, "octet-stream") {
		d, err := base64.StdEncoding.DecodeString(request.Data)

		if err != nil {
			_, _ = res.Write(returnError("octet-stream detected : data needs to be base64 encoded."))
			return
		}

		request.Data = string(d)
	}

	//init final headers
	finalHeaders := make(map[string][]string)

	for key, value := range requestInformation.Header {
		finalHeaders[key] = []string{value}
	}

	//set headers information in the request struct
	request.Header = finalHeaders

	session.update(context)

	var response *Response

	//handle scheme to start the right function
	for response == nil {
		switch urlHandler.Scheme {
		case "":
			_, _ = res.Write(returnError("you have to provide a valid scheme (https://)"))
			return

		case "http":
			response, err = sendNonSecuredRequest(request)
			break

		case "https":
			response, err = sendSecuredRequest(request)
			break

		default:
			_, _ = res.Write(returnError("unknown scheme : " + urlHandler.Scheme))
			return
		}

		//if an error occurred during request, return a failed with status code 0 and with error in response body
		if err != nil {
			errString := err.Error()
			switch errString {
			case "http2: timeout awaiting response headers":
				_, _ = res.Write(returnError("request timeout"))
			default:
				if strings.Contains(errString, "wsarecv: An existing connection was forcibly closed by the remote host.") {
					_, _ = res.Write(returnError("An existing connection was forcibly closed by the remote host."))
				} else if strings.Contains(errString, "i/o timeout") {
					_, _ = res.Write(returnError("request timeout"))
				} else {
					_, _ = res.Write(returnError(errString))
				}
			}
			return
		}
	}

	//if everything is alright then return the last response
	_, _ = res.Write([]byte(response.toString()))

	return
}

func applyJA3(res http.ResponseWriter, req *http.Request) {
	var sid uint64
	var sidErr []byte
	var ok bool

	if sid, sidErr = getSid(req); sidErr != nil {
		res.WriteHeader(400)
		_, _ = res.Write(sidErr)
		return
	}

	var request map[string]interface{}

	//loads headers in params
	if response := loadsJSONFromBody(req); response != nil {
		if request, ok = response.(map[string]interface{}); !ok {
			_, _ = res.Write(returnError(wrongFormat))
			return
		}
	} else {
		_, _ = res.Write(returnError(isInvalid))
		return
	}

	var ja3 string
	var specifications = map[string][]interface{}{}
	var navigator string

	if value, ok := request["ja3"].(string); !ok {
		_, _ = res.Write(returnError("no JA3 specified"))
		return
	} else {
		values := strings.Split(value, ",")
		if len(values) != 5 {
			_, _ = res.Write(returnError("specified JA3 is not valid : should follow this struct TLSVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats"))
			return
		}
		if _, err := strconv.Atoi(values[0]); err != nil {
			_, _ = res.Write(returnError("specified JA3 is not valid : TLSVersion is not an integer"))
			return
		}

		ciphers := strings.Split(values[1], "-")
		for _, el := range ciphers {
			if el == "" {
				_, _ = res.Write(returnError("specified JA3 is not valid : a cipher is empty. Received : " + values[1]))
				return
			}
			if _, err := strconv.Atoi(el); err != nil {
				_, _ = res.Write(returnError("specified JA3 is not valid : a cipher is not an integer -> " + el))
				return
			}
		}

		curves := strings.Split(values[2], "-")
		for _, el := range curves {
			if el == "" {
				_, _ = res.Write(returnError("specified JA3 is not valid : a curve is empty. Received : " + values[2]))
				return
			}
			if _, err := strconv.Atoi(el); err != nil {
				_, _ = res.Write(returnError("specified JA3 is not valid : a curve is not an integer -> " + el))
				return
			}
		}

		points := strings.Split(values[3], "-")
		for _, el := range points {
			if el == "" {
				_, _ = res.Write(returnError("specified JA3 is not valid : a point format is empty. Received : " + values[3]))
				return
			}
			if _, err := strconv.Atoi(el); err != nil {
				_, _ = res.Write(returnError("specified JA3 is not valid : a point format is not an integer -> " + el))
				return
			}
		}
		ja3 = value
	}

	if value, ok := (request["Specifications"]).(map[string]interface{}); ok {
		specifications = make(map[string][]interface{}, len(value))
		for key, value := range value {
			casted := value.([]interface{})
			specifications[key] = make([]interface{}, len(casted))
			for i, el := range casted {
				specifications[key][i] = el
			}
		}
	}

	if value, ok := request["navigator"].(string); ok {
		navigator = value
	} else {
		navigator = "chrome" //default navigator
	}

	pool, _ := Sessions.Get(sid, true)
	pool.JA3 = ja3
	pool.Specifications = specifications
	pool.HelloNavigator = navigator
	Sessions.Set(sid, pool)

	_, _ = res.Write(returnSuccess())
}

type StreamInformation struct {
	StreamId  uint32 `json:"stream-id"`
	StreamDep uint32 `json:"stream-dep"`
	Exclusive bool   `json:"exclusive"`
	Weight    uint8  `json:"weight"`
}

func applyStreamPriorities(res http.ResponseWriter, req *http.Request) {
	var sid uint64
	var sidErr []byte

	if sid, sidErr = getSid(req); sidErr != nil {
		res.WriteHeader(400)
		_, _ = res.Write(sidErr)
		return
	}

	var information map[string][]StreamInformation
	var streamInformation []StreamInformation

	//loads headers in params
	if err := json.Unmarshal([]byte(getBodyString(req)), &information); err != nil {
		_, _ = res.Write(returnError(wrongFormat))
		return
	}

	if value, ok := information["streams"]; !ok {
		_, _ = res.Write(returnError("no stream has been provided"))
		return
	} else {
		streamInformation = value
	}

	session, _ := Sessions.Get(sid, false)

	session.StreamPriorities = make([]http2.StreamPriority, len(streamInformation))

	for i, stream := range streamInformation {
		session.StreamPriorities[i] = http2.StreamPriority{
			StreamId: stream.StreamId,
			PriorityParam: http2.PriorityParam{
				StreamDep: stream.StreamDep,
				Exclusive: stream.Exclusive,
				Weight:    stream.Weight,
			},
		}
	}

	for i := range session.AllContext {
		session.AllContext[i].TLSConnection = nil
	}

	Sessions.Set(sid, session)

	_, _ = res.Write(returnSuccess())
}

var settingName = map[string]http2.SettingID{
	"HEADER_TABLE_SIZE":      http2.SettingHeaderTableSize,
	"ENABLE_PUSH":            http2.SettingEnablePush,
	"MAX_CONCURRENT_STREAMS": http2.SettingMaxConcurrentStreams,
	"INITIAL_WINDOW_SIZE":    http2.SettingInitialWindowSize,
	"MAX_FRAME_SIZE":         http2.SettingMaxFrameSize,
	"MAX_HEADER_LIST_SIZE":   http2.SettingMaxHeaderListSize,
}

type Setting struct {
	ID  string `json:"name"`
	Val uint32 `json:"value"`
}

func applyHTTP2Settings(res http.ResponseWriter, req *http.Request) {
	var sid uint64
	var sidErr []byte

	if sid, sidErr = getSid(req); sidErr != nil {
		res.WriteHeader(400)
		_, _ = res.Write(sidErr)
		return
	}

	var information map[string][]Setting
	var settings []Setting

	//loads headers in params
	if err := json.Unmarshal([]byte(getBodyString(req)), &information); err != nil {
		_, _ = res.Write(returnError(wrongFormat))
		return
	}

	session, _ := Sessions.Get(sid, false)

	if value, ok := information["settings"]; !ok {
		_, _ = res.Write(returnError("no setting has been provided"))
		return
	} else {
		settings = value
	}

	session.Settings = make([]http2.Setting, len(settings))

	for i, setting := range settings {
		if value, ok := settingName[setting.ID]; ok {
			session.Settings[i] = http2.Setting{
				ID:  value,
				Val: setting.Val,
			}
		} else {
			_, _ = res.Write(returnError(setting.ID + " is not a valid HTTP/2 setting"))

			return
		}
	}

	for i := range session.AllContext {
		session.AllContext[i].Connection = nil
	}

	tmp, _ := Sessions.Get(sid, true)
	tmp.AllContext = session.AllContext
	tmp.Settings = session.Settings
	Sessions.Set(sid, tmp)

	_, _ = res.Write(returnSuccess())
}

func applyWindowsUpdate(res http.ResponseWriter, req *http.Request) {
	var sid uint64
	var sidErr []byte

	if sid, sidErr = getSid(req); sidErr != nil {
		res.WriteHeader(400)
		_, _ = res.Write(sidErr)
		return
	}

	var information map[string]uint32

	//loads headers in params
	if err := json.Unmarshal([]byte(getBodyString(req)), &information); err != nil {
		_, _ = res.Write(returnError(wrongFormat))
		return
	}
	session, _ := Sessions.Get(sid, false)

	if value, ok := information["value"]; ok {
		session.WindowsUpdate = value
		for i := range session.AllContext {
			session.AllContext[i].Connection = nil
		}
		_, _ = res.Write(returnSuccess())
	} else {
		_, _ = res.Write(returnError("no windows update value has been provided"))
	}

	tmp, _ := Sessions.Get(sid, true)
	tmp.WindowsUpdate = session.WindowsUpdate
	tmp.AllContext = session.AllContext
	Sessions.Set(sid, tmp)
}

func getCookies(res http.ResponseWriter, req *http.Request) {
	var sid uint64
	var sidErr []byte

	if sid, sidErr = getSid(req); sidErr != nil {
		res.WriteHeader(400)
		_, _ = res.Write(sidErr)
		return
	}

	var information map[string]string
	var url string

	//loads headers in params
	if err := json.Unmarshal([]byte(getBodyString(req)), &information); err != nil {
		_, _ = res.Write(returnError(wrongFormat))
		return
	}

	if value, ok := information["domain"]; ok {
		url = value
	} else {
		if value, ok = information["url"]; ok {
			url = value
		} else {
			_, _ = res.Write(returnError("no url has been provided"))
			return
		}
	}

	session, _ := Sessions.Get(sid, false)

	if !strings.Contains(url, "http") {
		url = "https://" + url
	}

	parsed, err := URL.Parse(url)

	if err != nil {
		_, _ = res.Write([]byte(err.Error()))
		return
	}
	cookies := session.Cookies.Cookies(parsed)

	var returnCookies []Cookie

	for _, cookie := range cookies {
		returnCookies = append(returnCookies, Cookie{
			Name:  cookie.Name,
			Value: cookie.Value,

			Path:    cookie.Path,
			Domain:  cookie.Domain,
			Expires: cookie.Expires.Format("Mon, 02-Jan-2006 15:04:05 GMT"),

			Secure:   cookie.Secure,
			HttpOnly: cookie.HttpOnly,
		})
	}

	if returnCookies == nil {
		_, _ = res.Write([]byte("[]"))
		return
	}

	returnElement, _ := json.Marshal(returnCookies)
	_, _ = res.Write(returnElement)
}

func setCookies(res http.ResponseWriter, req *http.Request) {
	var sid uint64
	var sidErr []byte

	if sid, sidErr = getSid(req); sidErr != nil {
		res.WriteHeader(400)
		_, _ = res.Write(sidErr)
		return
	}

	var cookies []Cookie

	//loads headers in params
	if err := json.Unmarshal([]byte(getBodyString(req)), &cookies); err != nil {
		_, _ = res.Write(returnError(wrongFormat))
		return
	}

	session, _ := Sessions.Get(sid, false)

	for _, cookie := range cookies {
		if cookie.Name == "" || cookie.Value == "" {
			_, _ = res.Write(returnError("\"name\" and \"value\" are required in each cookies."))
			return
		}

		finalCookie := &http.Cookie{
			Name:     cookie.Name,
			Value:    cookie.Value,
			MaxAge:   cookie.MaxAge,
			Domain:   cookie.Domain,
			Secure:   cookie.Secure,
			Path:     cookie.Path,
			HttpOnly: cookie.HttpOnly,
		}

		if cookie.Expires != "" {
			cookieTime, err := time.Parse("Mon, 02-Jan-2006 15:04:05 GMT", cookie.Expires)

			if err == nil {
				finalCookie.Expires = cookieTime
			} else {
				_, _ = res.Write(returnError(cookie.Expires + " is not a valid expires. It has to follow this layout : \"Mon, 02-Jan-2006 15:04:05 GMT\""))
				return
			}
		}

		var tmp = make([]*http.Cookie, 1)
		tmp[0] = finalCookie

		if finalCookie.Domain != "" {
			var scheme string
			if finalCookie.Secure {
				scheme = "https"
			} else {
				scheme = "http"
			}

			url := scheme + "://" + finalCookie.Domain

			parsed, _ := URL.Parse(url)

			session.Cookies.SetCookies(parsed, tmp)
		} else {
			session.Cookies.SetCookies(nil, tmp)
		}
	}

	res.WriteHeader(201)
	_, _ = res.Write(returnSuccess())
}
