package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/go-session/cookie"
	"github.com/go-session/session"
	"github.com/sirupsen/logrus"
	"html/template"
	"net/http"
	"net/url"
	"os"
)

var log = logrus.New()

var (
	hashKeyFilePath  = flag.String("hashKey", "/secrets/hash_key", "File path for the hash key")
	passwordFilePath = flag.String("password", "/secrets/password", "File path for the password")
	hashKey          []byte
	password         string
	environment      = os.Getenv("ENV")
	authServiceUrl   = os.Getenv("AUTH_SERVICE_URL")
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

	if environment == "production" {
		log.Formatter = &logrus.JSONFormatter{}
	} else {
		log.Formatter = &logrus.TextFormatter{ForceColors: true, FullTimestamp: true}
		log.SetLevel(logrus.DebugLevel)
	}

	flag.Parse()

	var err error
	hashKey, err = os.ReadFile(*hashKeyFilePath)
	if err != nil {
		log.Fatalf("Failed to read hash key file: %v", err)
		os.Exit(1)
	}
	log.Infof("Reading hash key from %s", *hashKeyFilePath)

	passwordBytes, err := os.ReadFile(*passwordFilePath)
	if err != nil {
		log.Fatalf("Failed to read password file: %v", err)
		os.Exit(1)
	}
	log.Infof("Reading password from %s", *passwordFilePath)
	password = string(passwordBytes)

	session.InitManager(
		session.SetStore(
			cookie.NewCookieStore(
				cookie.SetCookieName("fk-admin-auth"),
				cookie.SetHashKey(hashKey),
			),
		),
	)

	http.HandleFunc("/auth", authHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/healthz", healthzHandler)
	err = http.ListenAndServe(":8080", nil)
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
	store, err := session.Start(context.Background(), w, r)
	if err != nil {
		log.Error(err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	value, found := store.Get("authenticated")
	if !found {
		logWithFields(r).Info("No valid session found. Redirecting to login.")
		redirectToLogin(w, r)
		return
	}

	isAuthenticated, ok := value.(bool)
	if !ok || !isAuthenticated {
		logWithFields(r).Info("Session is not authenticated. Redirecting to login.")
		redirectToLogin(w, r)
		return
	}

	logWithFields(r).Info("Session is authenticated.")
	w.WriteHeader(http.StatusOK)
	log.Error(w.Write([]byte("Authenticated!")))
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	store, err := session.Start(context.Background(), w, r)
	if err != nil {
		log.Error(err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	if r.Method == "POST" {
		secretKey := r.FormValue("secretKey")

		if authenticate(secretKey) {
			logWithFields(r).Info("Login successful.")
			store.Set("authenticated", true)
			log.Error(store.Save())
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
