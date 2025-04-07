package services

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
)

type ProxyService interface {
	ProxyRequest(w http.ResponseWriter, r *http.Request, path string, userUUID string)
}

type MainService struct {
	baseURL string
	timeout int
}

func NewMainService(baseURL string, timeout int) *MainService {
	return &MainService{
		baseURL: baseURL,
		timeout: timeout,
	}
}

func (s *MainService) ProxyRequest(w http.ResponseWriter, r *http.Request, path string, userUUID string) {
	for _, param := range chi.URLParam(r, "*") {
		path = strings.Replace(path, "{id}", param, 1)
	}

	targetURL := fmt.Sprint("%s%s", s.baseURL, path)

	var bodyBytes []byte
	var err error
	if r.Body != nil {
		bodyBytes, err = io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Error reading request body", http.StatusInternalServerError)
			return
		}
		r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
	}

	ctx, cancel := context.WithTimeout(r.Context(),
		time.Duration(s.timeout)*time.Second)

	defer cancel()

	proxyReq, err := http.NewRequestWithContext(ctx, r.Method, targetURL, bytes.NewBuffer(bodyBytes))

	if err != nil {
		http.Error(w, "Error creating proxy request", http.StatusInternalServerError)
		return
	}

	for key, values := range r.Header {
		for _, value := range values {
			proxyReq.Header.Add(key, value)
		}
	}

	proxyReq.Header.Set("X-User-UUID", userUUID)

	client := &http.Client{}
	resp, err := client.Do(proxyReq)
	if err != nil {
		http.Error(w, "Error sending request to main service", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	w.WriteHeader(resp.StatusCode)

	io.Copy(w, resp.Body)

}
