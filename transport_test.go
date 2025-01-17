package oauth1

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

var _ Auther = &DefaultAuther{}

func TestTransport(t *testing.T) {
	const (
		expectedToken           = "access_token"
		expectedConsumerKey     = "consumer_key"
		expectedNonce           = "some_nonce"
		expectedSignatureMethod = "HMAC-SHA1"
		expectedTimestamp       = "123456789"
	)
	server := newMockServer(func(w http.ResponseWriter, req *http.Request) {
		params := parseOAuthParamsOrFail(t, req.Header.Get("Authorization"))
		assert.Equal(t, expectedToken, params[oauthTokenParam])
		assert.Equal(t, expectedConsumerKey, params[oauthConsumerKeyParam])
		assert.Equal(t, expectedNonce, params[oauthNonceParam])
		assert.Equal(t, expectedSignatureMethod, params[oauthSignatureMethodParam])
		assert.Equal(t, expectedTimestamp, params[oauthTimestampParam])
		assert.Equal(t, defaultOauthVersion, params[oauthVersionParam])
		// oauth_signature will vary, httptest.Server uses a random port
	})
	defer server.Close()

	config := &Config{
		ConsumerKey:    expectedConsumerKey,
		ConsumerSecret: "consumer_secret",
		Noncer:         &fixedNoncer{expectedNonce},
	}
	auther := &DefaultAuther{
		config: config,
		clock:  &fixedClock{time.Unix(123456789, 0)},
	}
	tr := newTransport(nil, StaticTokenSource(NewToken(expectedToken, "some_secret")), auther)
	client := &http.Client{Transport: tr}

	req, err := http.NewRequest("GET", server.URL, nil)
	assert.Nil(t, err)
	_, err = client.Do(req)
	assert.Nil(t, err)
}

func TestNewTransport(t *testing.T) {
	config := &Config{
		ConsumerKey:    "consumer_key",
		ConsumerSecret: "consumer_secret",
		Noncer:         &fixedNoncer{"some_nonce"},
	}
	auther := &DefaultAuther{
		config: config,
		clock:  &fixedClock{time.Unix(123456789, 0)},
	}
	source := StaticTokenSource(NewToken("access_token", "some_secret"))

	type testCase struct {
		description string
		base        http.RoundTripper
		source      TokenSource
		auther      Auther
		errMsg      string
	}
	for _, tc := range []testCase{
		{
			description: "default base transport",
			base:        nil,
			source:      source,
			auther:      auther,
			errMsg:      "",
		},
		{
			description: "custom base transport",
			base:        &http.Transport{},
			source:      source,
			auther:      auther,
			errMsg:      "",
		},
		{
			description: "nil source",
			base:        nil,
			source:      nil,
			auther:      auther,
			errMsg:      "oauth1: Transport's source is nil",
		},
		{
			description: "empty source",
			base:        nil,
			source:      StaticTokenSource(nil),
			auther:      auther,
			errMsg:      "oauth1: Token is nil",
		},
		{
			description: "nil auther",
			base:        nil,
			source:      source,
			auther:      nil,
			errMsg:      "oauth1: Transport's auther is nil",
		},
	} {
		tr, err := NewTransport(tc.base, tc.source, tc.auther)
		if tc.errMsg == "" {
			assert.Nil(t, err)
			if tc.base == nil {
				assert.Equal(t, http.DefaultTransport, tr.base())
			} else {
				assert.Equal(t, tc.base, tr.base())
			}
		} else {
			assert.Contains(t, err.Error(), tc.errMsg)
			assert.Nil(t, tr)
		}
	}
}

func TestTransport_defaultBaseTransport(t *testing.T) {
	tr := &Transport{
		Base: nil,
	}
	assert.Equal(t, http.DefaultTransport, tr.base())
}
func TestTransport_customBaseTransport(t *testing.T) {
	expected := &http.Transport{}
	tr := &Transport{
		Base: expected,
	}
	assert.Equal(t, expected, tr.base())
}

func TestTransport_nilSource(t *testing.T) {
	tr := newTransport(nil, nil, &DefaultAuther{
		config: &Config{Noncer: &fixedNoncer{"any_nonce"}},
		clock:  &fixedClock{time.Unix(123456789, 0)},
	})
	client := &http.Client{Transport: tr}
	resp, err := client.Get("http://example.com")
	assert.Nil(t, resp)
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "oauth1: Transport's source is nil")
	}
}

func TestTransport_emptySource(t *testing.T) {
	tr := newTransport(nil, StaticTokenSource(nil), &DefaultAuther{
		config: &Config{Noncer: &fixedNoncer{"any_nonce"}},
		clock:  &fixedClock{time.Unix(123456789, 0)},
	})
	client := &http.Client{Transport: tr}
	resp, err := client.Get("http://example.com")
	assert.Nil(t, resp)
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "oauth1: Token is nil")
	}
}

func TestTransport_nilAuther(t *testing.T) {
	tr := newTransport(nil, StaticTokenSource(&Token{}), nil)
	client := &http.Client{Transport: tr}
	resp, err := client.Get("http://example.com")
	assert.Nil(t, resp)
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "oauth1: Transport's auther is nil")
	}
}

func newMockServer(handler func(w http.ResponseWriter, r *http.Request)) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(handler))
}
