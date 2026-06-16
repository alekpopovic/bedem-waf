package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"time"
)

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{
			"service": "bedemwaf-demo-app",
			"message": "request reached the demo application",
			"time":    time.Now().UTC().Format(time.RFC3339),
		})
	})
	mux.HandleFunc("GET /login", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"page": "login", "hint": "rate limit demo endpoint"})
	})
	mux.HandleFunc("GET /admin", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"page": "admin", "hint": "custom rule demo endpoint"})
	})
	mux.HandleFunc("/api/echo", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		writeJSON(w, map[string]any{
			"method":  r.Method,
			"path":    r.URL.Path,
			"headers": r.Header,
			"body":    string(body),
		})
	})
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]string{"status": "ok"})
	})

	server := &http.Server{
		Addr:              ":8080",
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Println("demo app listening on :8080")
	log.Fatal(server.ListenAndServe())
}

func writeJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}
