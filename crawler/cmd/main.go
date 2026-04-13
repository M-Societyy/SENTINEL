// sentinel - microservicio de crawling en go
// m-society & c1q_
// crawlers de alta velocidad para redes sociales, foros y paste sites

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/gocolly/colly/v2"
)

// resultado de un crawl
type CrawlResult struct {
	URL         string            `json:"url"`
	Titulo      string            `json:"titulo"`
	Texto       string            `json:"texto"`
	Links       []string          `json:"links"`
	Emails      []string          `json:"emails"`
	Metadata    map[string]string `json:"metadata"`
	StatusCode  int               `json:"status_code"`
	CrawledAt   string            `json:"crawled_at"`
}

// request de crawl
type CrawlRequest struct {
	URLs          []string `json:"urls"`
	Profundidad   int      `json:"profundidad"`
	MaxPaginas    int      `json:"max_paginas"`
	UserAgent     string   `json:"user_agent"`
	DelayMs       int      `json:"delay_ms"`
	BuscarEmails  bool     `json:"buscar_emails"`
	BuscarTexto   string   `json:"buscar_texto"`
}

// response del crawl
type CrawlResponse struct {
	Resultados []CrawlResult `json:"resultados"`
	Total      int           `json:"total"`
	Duracion   string        `json:"duracion"`
	Errores    []string      `json:"errores"`
}

// crawler principal
type SentinelCrawler struct {
	mu sync.Mutex
}

func NuevoCrawler() *SentinelCrawler {
	return &SentinelCrawler{}
}

func (sc *SentinelCrawler) Crawl(req CrawlRequest) CrawlResponse {
	inicio := time.Now()
	var resultados []CrawlResult
	var errores []string
	var mu sync.Mutex

	// configurar colly
	c := colly.NewCollector(
		colly.MaxDepth(req.Profundidad),
		colly.Async(true),
	)

	if req.UserAgent != "" {
		c.UserAgent = req.UserAgent
	} else {
		c.UserAgent = "SENTINEL-Crawler/1.0 (OSINT Research; +https://github.com/m-society)"
	}

	if req.DelayMs > 0 {
		c.Limit(&colly.LimitRule{
			Delay:       time.Duration(req.DelayMs) * time.Millisecond,
			RandomDelay: time.Duration(req.DelayMs/2) * time.Millisecond,
			Parallelism: 5,
		})
	}

	// contador de paginas
	paginasCrawled := 0
	maxPaginas := req.MaxPaginas
	if maxPaginas == 0 {
		maxPaginas = 100
	}

	c.OnHTML("html", func(e *colly.HTMLElement) {
		mu.Lock()
		defer mu.Unlock()

		if paginasCrawled >= maxPaginas {
			return
		}
		paginasCrawled++

		resultado := CrawlResult{
			URL:        e.Request.URL.String(),
			Titulo:     e.ChildText("title"),
			StatusCode: e.Response.StatusCode,
			CrawledAt:  time.Now().UTC().Format(time.RFC3339),
			Metadata:   make(map[string]string),
			Links:      []string{},
			Emails:     []string{},
		}

		// extraer texto principal
		textoBody := e.ChildText("body")
		if len(textoBody) > 5000 {
			textoBody = textoBody[:5000]
		}
		resultado.Texto = textoBody

		// extraer meta tags
		e.ForEach("meta", func(_ int, el *colly.HTMLElement) {
			nombre := el.Attr("name")
			contenido := el.Attr("content")
			if nombre != "" && contenido != "" {
				resultado.Metadata[nombre] = contenido
			}
		})

		// extraer links
		e.ForEach("a[href]", func(_ int, el *colly.HTMLElement) {
			href := el.Attr("href")
			if href != "" && !strings.HasPrefix(href, "#") && !strings.HasPrefix(href, "javascript:") {
				resultado.Links = append(resultado.Links, href)
			}
		})

		// buscar emails si se solicito
		if req.BuscarEmails {
			emails := extraerEmails(textoBody)
			resultado.Emails = emails
		}

		resultados = append(resultados, resultado)
	})

	// seguir links
	c.OnHTML("a[href]", func(e *colly.HTMLElement) {
		mu.Lock()
		if paginasCrawled >= maxPaginas {
			mu.Unlock()
			return
		}
		mu.Unlock()
		_ = e.Request.Visit(e.Attr("href"))
	})

	c.OnError(func(r *colly.Response, err error) {
		mu.Lock()
		errores = append(errores, fmt.Sprintf("%s: %s", r.Request.URL, err.Error()))
		mu.Unlock()
	})

	// iniciar crawl
	for _, url := range req.URLs {
		if err := c.Visit(url); err != nil {
			errores = append(errores, fmt.Sprintf("error visitando %s: %s", url, err.Error()))
		}
	}

	c.Wait()

	return CrawlResponse{
		Resultados: resultados,
		Total:      len(resultados),
		Duracion:   time.Since(inicio).String(),
		Errores:    errores,
	}
}

// extrae emails de un texto
func extraerEmails(texto string) []string {
	var emails []string
	palabras := strings.Fields(texto)
	for _, palabra := range palabras {
		if strings.Contains(palabra, "@") && strings.Contains(palabra, ".") {
			// limpieza basica
			email := strings.Trim(palabra, ".,;:()[]<>{}")
			if len(email) > 5 && len(email) < 100 {
				emails = append(emails, email)
			}
		}
	}
	return emails
}

// handlers http
func handleCrawl(crawler *SentinelCrawler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req CrawlRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"error": "request invalido"}`, http.StatusBadRequest)
			return
		}

		if len(req.URLs) == 0 {
			http.Error(w, `{"error": "urls requeridas"}`, http.StatusBadRequest)
			return
		}

		resultado := crawler.Crawl(req)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resultado)
	}
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"estado":  "operativo",
		"nombre":  "sentinel-crawler",
		"version": "1.0.0",
		"autor":   "m-society & c1q_",
	})
}

func main() {
	log.Println("╔══════════════════════════════════════════╗")
	log.Println("║  sentinel crawler v1.0.0                 ║")
	log.Println("║  m-society & c1q_                        ║")
	log.Println("╚══════════════════════════════════════════╝")

	crawler := NuevoCrawler()

	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(300 * time.Second))

	r.Get("/health", handleHealth)
	r.Post("/api/v1/crawl", handleCrawl(crawler))

	// puerto configurable
	puerto := os.Getenv("HTTP_PORT")
	if puerto == "" {
		puerto = "8081"
	}

	grpcPort := os.Getenv("GRPC_PORT")
	if grpcPort == "" {
		grpcPort = "50051"
	}

	// servidor http
	httpServer := &http.Server{
		Addr:    ":" + puerto,
		Handler: r,
	}

	// iniciar grpc listener (placeholder)
	go func() {
		lis, err := net.Listen("tcp", ":"+grpcPort)
		if err != nil {
			log.Printf("grpc listener error: %v", err)
			return
		}
		log.Printf("grpc escuchando en :%s", grpcPort)
		_ = lis // se usara con el servidor grpc
	}()

	// graceful shutdown
	go func() {
		log.Printf("http escuchando en :%s", puerto)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("error en servidor http: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("apagando crawler...")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	httpServer.Shutdown(ctx)
	log.Println("crawler detenido")
}
