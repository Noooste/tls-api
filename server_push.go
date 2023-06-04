package main

import (
	"github.com/Noooste/fhttp/http2"
	"sync"
	"time"
)

// DefaultPushHandler default push handler
type DefaultPushHandler struct {
	request  *Request
	response *Response
	mu       *sync.Mutex
}

func (ph *DefaultPushHandler) HandlePush(r *http2.PushedRequest) {
	handleWrite := make(chan struct{})

	go func() {
		defer close(handleWrite)

		push, err := r.ReadResponse(r.Promise.Context())

		if err != nil {
			return
		}

		response := BuildServerPushResponse(push)

		ph.mu.Lock()
		ph.response.ServerPush = append(ph.response.ServerPush, response)
		ph.mu.Unlock()
	}()

	select {
	case <-handleWrite:
	case <-time.After(5 * time.Second):
		r.Cancel()
	}
}
