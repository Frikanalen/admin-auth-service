package main

import (
	"github.com/alexedwards/scs/v2"
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestLogWithFields(t *testing.T) {
	r, _ := http.NewRequest("GET", "/", nil)
	r.Header.Set("X-Forwarded-For", "client")
	r.Header.Set("X-Forwarded-Proto", "http")
	r.Header.Set("X-Forwarded-Host", "localhost")
	r.Header.Set("X-Forwarded-Port", "8080")
	r.Header.Set("X-Forwarded-Uri", "/uri")

	entry := logWithFields(r)
	assert.NotNil(t, entry)
	assert.Equal(t, "client", entry.Data["client"])
	assert.Equal(t, "http://localhost:8080/uri", entry.Data["url"])
}

func TestFullRequestUrl(t *testing.T) {
	r, _ := http.NewRequest("GET", "/", nil)
	r.Header.Set("X-Forwarded-Proto", "http")
	r.Header.Set("X-Forwarded-Host", "localhost")
	r.Header.Set("X-Forwarded-Port", "8080")
	r.Header.Set("X-Forwarded-Uri", "/uri")

	assert.Equal(t, "http://localhost:8080/uri", fullRequestUrl(r))
}

func TestAuthenticate(t *testing.T) {
	password = "secret" // password is a global variable in your package

	assert.True(t, authenticate("secret"))
	assert.False(t, authenticate("wrong-password"))
}

// This is an example of an integration test.
// We test how different parts of the system work together by simulating an actual HTTP request to the login handler.
func TestLoginHandlerIntegration(t *testing.T) {
	// We're setting password here because the loginHandler relies on it for authentication.
	password = "test-password"

	// Setting up the request
	req, err := http.NewRequest("POST", "/login", nil)
	if err != nil {
		t.Fatal(err)
	}

	req.Form = url.Values{
		"secretKey": {"test-password"},
		"nextUrl":   {"https://goatse.cx:1337/kthx"},
	}

	// Creating a ResponseRecorder to record the response.
	rr := httptest.NewRecorder()
	// Mocking session manager
	sessionManager = scs.New()
	handler := sessionManager.LoadAndSave(http.HandlerFunc(loginHandler))

	// Our handlers satisfy http.Handler, so we can call their ServeHTTP method
	// directly and pass in our Request and ResponseRecorder.
	handler.ServeHTTP(rr, req)

	// Check the status code is what we expect (should redirect after successful login).
	assert.Equal(t, http.StatusSeeOther, rr.Code)

	// This assert checks that after a successful login, the user is redirected to "/auth"
	// You may add additional asserts here to further test your code, e.g. for checking if session is updated correctly.
	location, err := rr.Result().Location()
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, "https://goatse.cx:1337/kthx", location.String())
}
