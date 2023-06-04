package main

import (
	"context"
	"errors"
	http "github.com/Noooste/fhttp"
	"github.com/Noooste/fhttp/http2"
	"github.com/Noooste/utls"
	"net"
	URL "net/url"
	"strings"
	"time"
)

func (c *Context) ApplyPresetByHelloId(request *Request, helloId tls.ClientHelloID, pool Session) (*tls.UConn, error) {
	parsedURL, _ := URL.Parse(request.Url)

	addr := parsedURL.Hostname()

	if parsedURL.Port() != "" {
		addr += ":" + parsedURL.Port()
	} else {
		if parsedURL.Scheme == "http" {
			addr += ":80"
		} else {
			addr += ":443"
		}
	}

	var conn net.Conn
	var err error

	//if not proxy
	if request.Proxy != "" {
		conn, err = GetProxyConn(request.Proxy, addr)

		if err != nil {
			if strings.Contains(err.Error(), "i/o timeout") {
				return nil, errors.New("request timeout")
			}
			return nil, err
		}

		c.ProxyUrl = request.Proxy

	} else {
		//normal dial
		conn, err = net.DialTimeout("tcp", addr, time.Duration(request.TimeOut)*time.Second)

		if err != nil {
			if strings.Contains(err.Error(), "i/o timeout") {
				return nil, errors.New("request timeout")
			}
			return nil, err
		}
	}

	config := tls.Config{
		ServerName:         parsedURL.Hostname(),
		InsecureSkipVerify: !request.Verify,
	}

	var tConn *tls.UConn

	if helloId == tls.HelloCustom {
		tConn = tls.UClient(conn, &config, tls.HelloCustom)

		clientSpecs, err := StringToSpec(pool.JA3, pool.Specifications, pool.HelloNavigator)
		if err != nil {
			return nil, err
		}

		err = tConn.ApplyPreset(clientSpecs)

	} else {
		//create client
		tConn = tls.UClient(conn, &config, helloId)
	}

	colonPos := strings.LastIndex(addr, ":")
	if colonPos == -1 {
		colonPos = len(addr)
	}

	tConn.SetSNI(addr[:colonPos])

	_ = tConn.SetDeadline(time.Now().Add(time.Duration(request.TimeOut) * time.Second))
	err = tConn.Handshake()

	if err != nil {
		if strings.Contains(err.Error(), "i/o timeout") {
			return nil, errors.New("handshake timeout")
		}
		return nil, err
	}

	//return client
	return tConn, err
}

func (c *Context) getTconn(request *Request, pool Session) (*tls.UConn, error) {
	var helloId tls.ClientHelloID

	if pool.JA3 != "" {
		helloId = tls.HelloCustom
	} else {
		switch request.Browser {
		case "":
			return nil, errors.New("no navigator has been provided")

		case "firefox":
			helloId = tls.HelloFirefox_99

		case "chrome":
			helloId = tls.HelloChrome_101

		default:
			return nil, errors.New(request.Browser + " is not supported.")
		}
	}

	return c.ApplyPresetByHelloId(request, helloId, pool)
}

func GetProxyConn(proxy string, addr string) (net.Conn, error) {
	dialer, err := newConnectDialer(proxy)
	if err != nil {
		return nil, err
	}
	return dialer.DialContext(context.Background(), "tcp", addr)
}

func (c *Context) SetupTransport(request *Request, pool Session) error {
	tr, err := http2.ConfigureTransports(&http.Transport{
		TLSHandshakeTimeout:   time.Duration(request.TimeOut) * time.Second,
		ResponseHeaderTimeout: time.Duration(request.TimeOut) * time.Second,
	}) // upgrade to HTTP2, while keeping http.Transport

	if err != nil {
		return err
	}

	if pool.StreamPriorities != nil {
		tr.StreamPriorities = pool.StreamPriorities
	} else {
		tr.StreamPriorities = DefaultStreamPriorities(request.Browser)
	}

	if pool.Settings != nil {
		tr.Settings = pool.Settings
	} else {
		tr.Settings = DefaultHeaderSettings(request.Browser)
	}

	if pool.WindowsUpdate != 0 {
		tr.WindowsUpdateSize = pool.WindowsUpdate
	} else {
		tr.WindowsUpdateSize = DefaultWindowsUpdate(request.Browser)
	}

	for _, setting := range tr.Settings {
		switch setting.ID {
		case http2.SettingInitialWindowSize:
			tr.InitialWindowSize = setting.Val

		case http2.SettingHeaderTableSize:
			tr.HeaderTableSize = setting.Val
		}
	}

	c.Transport = tr

	return nil
}
