package main

import (
	"flag"
	"fmt"
	"github.com/alexedwards/scs/v2"
	"github.com/sirupsen/logrus"
	"html/template"
	"net/http"
	"net/url"
	"os"
	"time"
)

var log = logrus.New()
var sessionManager *scs.SessionManager

var (
	passwordFilePath = flag.String("password", "/secrets/password", "File path for the password")
	password         string
	environment      = os.Getenv("ENV")
	authServiceUrl   = os.Getenv("AUTH_SERVICE_URL")
	cookieDomain     = os.Getenv("COOKIE_DOMAIN")
)

type LoginPageData struct {
	Message string
	NextUrl string
}

func logWithFields(r *http.Request) *logrus.Entry {
	return log.WithFields(logrus.Fields{
		"client": r.Header.Get("X-Forwarded-For"),
		"url":    fullRequestUrl(r),
	})
}

func fullRequestUrl(r *http.Request) string {
	proto := r.Header.Get("X-Forwarded-Proto")
	host := r.Header.Get("X-Forwarded-Host")
	port := r.Header.Get("X-Forwarded-Port")
	uri := r.Header.Get("X-Forwarded-Uri")

	if port == "" {
		return fmt.Sprintf("%s://%s%s", proto, host, uri)
	} else {
		return fmt.Sprintf("%s://%s:%s%s", proto, host, port, uri)
	}
}

func main() {
	if authServiceUrl == "" {
		log.Fatalf("Environment variable AUTH_SERVICE_URL is not set")
		os.Exit(1)
	}

	if cookieDomain == "" {
		log.Fatalf("Environment variable COOKIE_DOMAIN is not set")
		os.Exit(1)
	}

	if environment == "production" {
		log.Formatter = &logrus.JSONFormatter{}
	} else {
		log.Formatter = &logrus.TextFormatter{ForceColors: true, FullTimestamp: true}
		log.SetLevel(logrus.DebugLevel)
	}

	flag.Parse()

	var err error

	passwordBytes, err := os.ReadFile(*passwordFilePath)
	if err != nil {
		log.Fatalf("Failed to read password file: %v", err)
		os.Exit(1)
	}
	log.Infof("Reading password from %s", *passwordFilePath)
	password = string(passwordBytes)

	sessionManager = scs.New()
	sessionManager.Lifetime = 6000 * time.Hour
	sessionManager.Cookie.Domain = cookieDomain
	sessionManager.Cookie.Secure = true
	sessionManager.Cookie.HttpOnly = true

	mux := http.NewServeMux()
	mux.HandleFunc("/auth", authHandler)
	mux.HandleFunc("/login", loginHandler)
	mux.HandleFunc("/healthz", healthzHandler)
	err = http.ListenAndServe(":8080", sessionManager.LoadAndSave(mux))
	if err != nil {
		log.Fatalf("could not listen, %v", err)
	}
}

func healthzHandler(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, err := fmt.Fprintln(w, "OK")
	if err != nil {
		log.Fatalf("could not write to healthz, %v", err)
	}
}

func authHandler(w http.ResponseWriter, r *http.Request) {
	logWithFields(r).Debug("Auth handler")
	isAuthenticated := sessionManager.GetBool(r.Context(), "authenticated")

	if !isAuthenticated {
		logWithFields(r).Info("Session is not authenticated. Redirecting to login.")
		redirectToLogin(w, r)
		return
	}

	logWithFields(r).Info("Session is authenticated.")
	w.WriteHeader(http.StatusOK)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {

	if r.Method == "POST" {
		secretKey := r.FormValue("secretKey")

		if authenticate(secretKey) {
			logWithFields(r).Info("Login successful.")
			sessionManager.Put(r.Context(), "authenticated", true)
			nextUrl := r.FormValue("next_url")
			if nextUrl == "" {
				nextUrl = "/auth"
			}
			http.Redirect(w, r, nextUrl, http.StatusSeeOther)
			return
		}
		logWithFields(r).Warn("Failed login attempt.")
	}
	nextUrl := r.URL.Query().Get("next_url")

	logWithFields(r).Infof("Showing login page.")

	tmpl, err := template.ParseFiles("web/login.html")
	if err != nil {
		log.Error(err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	data := LoginPageData{
		Message: "Please enter your secret key.",
		NextUrl: nextUrl,
	}

	err = tmpl.Execute(w, data)
	if err != nil {
		log.Error(err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
}

func redirectToLogin(w http.ResponseWriter, r *http.Request) {
	escapedNextUrl := url.QueryEscape(fullRequestUrl(r))
	loginUrl := fmt.Sprintf("%s/login?next_url=%s", authServiceUrl, escapedNextUrl)

	http.Redirect(w, r, loginUrl, http.StatusSeeOther)
}

func authenticate(secretKey string) bool {
	return secretKey == password
}
