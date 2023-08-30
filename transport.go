package oauth1

import (
	"fmt"
	"net/http"
)

type Auther interface {
	SetRequestAuthHeader(req *http.Request, accessToken *Token) error
}

// Transport is an http.RoundTripper which makes OAuth1 HTTP requests. It
// wraps a base RoundTripper and adds an Authorization header using the
// token from a TokenSource.
//
// Transport is a low-level component, most users should use Config to create
// an http.Client instead.
type Transport struct {
	// Base is the base RoundTripper used to make HTTP requests. If nil, then
	// http.DefaultTransport is used
	Base http.RoundTripper
	// source supplies the token to use when signing a request
	source TokenSource
	// auther adds OAuth1 Authorization headers to requests
	auther Auther
}

// NewTransport returns a new Transport and an error
func NewTransport(baseRoundTripper http.RoundTripper, source TokenSource, auther Auther) (*Transport, error) {
	t := newTransport(baseRoundTripper, source, auther)
	err := t.checkValid()
	if err != nil {
		return nil, err
	}
	return t, nil
}

// newTransport returns a new Transport without checking whether there is an error
func newTransport(baseRoundTripper http.RoundTripper, source TokenSource, auther Auther) *Transport {
	return &Transport{
		Base:   baseRoundTripper,
		source: source,
		auther: auther,
	}
}

// RoundTrip authorizes the request with a signed OAuth1 Authorization header
// using the auther and TokenSource.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	err := t.checkValid()
	if err != nil {
		return nil, err
	}
	accessToken, err := t.source.Token()
	if err != nil {
		return nil, err
	}
	// RoundTripper should not modify the given request, clone it
	req2 := cloneRequest(req)
	err = t.auther.SetRequestAuthHeader(req2, accessToken)
	if err != nil {
		return nil, err
	}
	return t.base().RoundTrip(req2)
}

func (t *Transport) base() http.RoundTripper {
	if t.Base != nil {
		return t.Base
	}
	return http.DefaultTransport
}

// cloneRequest returns a clone of the given *http.Request with a shallow
// copy of struct fields and a deep copy of the Header map.
func cloneRequest(req *http.Request) *http.Request {
	// shallow copy the struct
	r2 := new(http.Request)
	*r2 = *req
	// deep copy Header so setting a header on the clone does not affect original
	r2.Header = make(http.Header, len(req.Header))
	for k, s := range req.Header {
		r2.Header[k] = append([]string(nil), s...)
	}
	return r2
}

func (t *Transport) checkValid() error {
	if t.source == nil {
		return fmt.Errorf("oauth1: Transport's source is nil")
	}
	if t.auther == nil {
		return fmt.Errorf("oauth1: Transport's auther is nil")
	}
	_, err := t.source.Token()
	if err != nil {
		return err
	}
	return nil
}
