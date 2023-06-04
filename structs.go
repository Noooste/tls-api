package main

import (
	"github.com/Noooste/fhttp/cookiejar"
	"github.com/Noooste/fhttp/http2"
	"github.com/Noooste/utls"
	"sync"
	"time"
)

const (
	Path      = ":path"
	Method    = ":method"
	Authority = ":authority"
	Scheme    = ":scheme"
)

type Request struct {
	SessionId uint64

	Method      string
	Url         string
	Data        string
	Cookies     map[string]string
	PHeader     []string
	Header      map[string][]string
	HeaderOrder []string

	Browser string

	Proxy         string
	AllowRedirect bool
	TimeOut       int

	IsRedirected bool

	FetchServerPush bool
	Verify          bool
}

type Response struct {
	Id              uint64            `json:"id"`
	StatusCode      int               `json:"status-code"`
	Body            string            `json:"body"`
	Headers         map[string]string `json:"headers"`
	Cookies         map[string]string `json:"cookies"`
	Url             string            `json:"url"`
	IsBase64Encoded bool              `json:"is-base64-encoded"`

	ServerPush []*ServerPush `json:"server-push"`
}

type ServerPush struct {
	StatusCode      int               `json:"status_code"`
	Body            string            `json:"body"`
	Headers         map[string]string `json:"headers"`
	Cookies         map[string]string `json:"cookies"`
	Url             string            `json:"url"`
	IsBase64Encoded bool              `json:"is-base64-encoded"`
}

type Context struct {
	Id uint64

	Host string

	TLSConnection *tls.UConn
	Connection    *http2.ClientConn
	Transport     *http2.Transport

	ProxyUrl string

	cookiesSetAuto bool
}

type Session struct {
	Id         uint64
	AllContext []*Context

	HelloNavigator string
	JA3            string
	Specifications map[string][]interface{}

	StreamPriorities []http2.StreamPriority
	Settings         []http2.Setting
	WindowsUpdate    uint32

	Cookies *cookiejar.Jar

	LastActivity *time.Time
	mu           *sync.Mutex

	locked bool
}

type SuccessReturn struct {
	Success bool   `json:"success"`
	Error   string `json:"error"`
}
