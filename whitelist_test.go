package whitelist_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/bakins/go-http-whitelist"
	h "github.com/bakins/test-helpers"
)

func TestNew(t *testing.T) {
	_, err := whitelist.New([]string{"127.0.0.0/8"})
	h.Ok(t, err)
}

func TestNewFail(t *testing.T) {
	_, err := whitelist.New([]string{"0.0/8"})
	h.Assert(t, err != nil, "new should fail")
}

func newRequest(method, url, remoteAddr string) *http.Request {
	r, err := http.NewRequest(method, url, nil)
	if err != nil {
		panic(err)
	}
	r.RemoteAddr = remoteAddr
	return r
}

func TestHandlerPass(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(200)
		fmt.Fprint(w, "Hello World\n")
	})

	wl, err := whitelist.New([]string{"8.8.0.0/16"})
	h.Ok(t, err)

	request := newRequest("GET", "/foo", "8.8.8.8:9876")
	recorder := httptest.NewRecorder()
	wlHandler := wl.Handler(handler)

	wlHandler.ServeHTTP(recorder, request)

	h.Equals(t, 200, recorder.Code)
}

// probably need a test setup helper, but just copy paste for now

func TestHandlerFail(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(200)
		fmt.Fprint(w, "Hello World\n")
	})

	wl, err := whitelist.New([]string{"8.8.0.0/16"})
	h.Ok(t, err)

	request := newRequest("GET", "/foo", "9.9.9.9:9876")
	recorder := httptest.NewRecorder()
	wlHandler := wl.Handler(handler)

	wlHandler.ServeHTTP(recorder, request)

	h.Equals(t, 403, recorder.Code)
}
