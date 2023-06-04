package main

import (
	"github.com/Noooste/fhttp/cookiejar"
	"golang.org/x/sync/syncmap"
	"runtime"
	"runtime/debug"
	"sync"
	"time"
)

var Sessions = &SessionStruct{
	list: &syncmap.Map{},
}

type SessionStruct struct {
	list *syncmap.Map
}

func (s *SessionStruct) Get(sid uint64, lock bool) (Session, bool) {
	if value, ok := s.list.Load(sid); ok {
		session := value.(Session)
		if lock {
			session.mu.Lock()
			v, _ := s.list.Load(sid)
			tmp := v.(Session)
			tmp.locked = true
			return tmp, true
		}
		return session, true
	}
	return Session{}, false
}

func (s *SessionStruct) Set(sid uint64, session Session) {
	if session.locked {
		session.locked = false
		session.mu.Unlock()
	}
	s.list.Store(sid, session)
}

func (s *SessionStruct) Remove(sid uint64) {
	s.list.Delete(sid)
	runtime.GC()
}

func initSession() uint64 {
	for {
		newSessionID := getRandomId()
		if _, ok := Sessions.Get(newSessionID, false); !ok {
			jar, _ := cookiejar.New(nil)
			now := time.Now()
			newContext := Session{
				Id:           newSessionID,
				AllContext:   []*Context{},
				Cookies:      jar,
				mu:           &sync.Mutex{},
				LastActivity: &now,
			}
			Sessions.Set(newSessionID, newContext)
			return newSessionID
		}
	}
}

/*
Get specific Session at index id and with matching domain
*/
func getContext(id uint64, host string) *Context {
	session, _ := Sessions.Get(id, false)
	contexts := session.AllContext
	for _, el := range contexts {
		if host == el.Host {
			return el
		}
		if el.TLSConnection != nil {
			if err := el.TLSConnection.VerifyHostname(host); err == nil {
				return el
			}
		}
	}
	context := &Context{
		Id:   id,
		Host: host,
	}
	return context
}

/*
Update context list with given Session context
*/
func (s Session) update(c *Context) {
	var done bool
	var index int

	for i, el := range s.AllContext {
		if c.Host == el.Host {
			index = i
			done = true
			break
		}
	}

	now := time.Now()
	if !done {
		s.AllContext = append(s.AllContext, c)
	} else {
		s.AllContext[index] = c
	}

	tmp, _ := Sessions.Get(s.Id, true)
	tmp.LastActivity = &now
	tmp.AllContext = s.AllContext
	Sessions.Set(c.Id, tmp)
}

func sessionExists(id uint64) bool {
	_, ok := Sessions.Get(id, false)
	return ok
}

func clearMemory() {
	for {
		runtime.GC()
		time.Sleep(10 * time.Second)
	}
}

func monitorSessions() {
	defer func() {
		if r := recover(); r != nil {
			debug.PrintStack()
			time.Sleep(5 * time.Second)
			monitorSessions()
		}
	}()

	for {
		removeId := make([]uint64, 0)
		Sessions.list.Range(func(key any, value any) bool {
			pool := value.(Session)
			if pool.LastActivity.Add(time.Duration(inactivityTimer) * time.Second).Before(time.Now()) {
				removeId = append(removeId, key.(uint64))
			}
			return true
		})

		for _, id := range removeId {
			Sessions.Remove(id)
		}

		time.Sleep(50 * time.Millisecond)
	}
}
