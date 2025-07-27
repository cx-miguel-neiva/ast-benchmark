package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"

	"github.com/cx-miguel-neiva/ast-benchmark/internal/db"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
)

func main() {
	wd, err := os.Getwd()
	if err != nil {
		log.Fatalf("FATAL: Failed to get working directory: %v", err)
	}

	projectRoot := filepath.Join(wd, "..", "..")
	dbPath := filepath.Join(projectRoot, "data", "benchmark.db")

	log.Printf("INFO: Attempting to connect to database at: %s", dbPath)

	conn, err := db.NewConnection(dbPath)
	if err != nil {
		log.Fatalf("FATAL: Failed to connect to database: %v", err)
	}
	defer conn.Close()

	r := chi.NewRouter()

	r.Use(cors.Handler(cors.Options{
		AllowedOrigins: []string{"http://localhost:5173"},
		AllowedMethods: []string{"GET", "OPTIONS"},
	}))
	r.Use(middleware.Logger)

	// Project summaries
	r.Get("/api/projects/summary", func(w http.ResponseWriter, r *http.Request) {
		summaries, err := conn.GetProjectSummaries()
		w.Header().Set("Content-Type", "application/json")
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": "Failed to fetch project summaries"})
			return
		}
		json.NewEncoder(w).Encode(summaries)
	})

	// Scores
	r.Get("/api/scores", func(w http.ResponseWriter, r *http.Request) {
		groupBy := r.URL.Query().Get("groupBy")
		if groupBy == "" {
			groupBy = "project"
		}
		application := r.URL.Query().Get("application")
		tool := r.URL.Query().Get("tool")
		engine := r.URL.Query().Get("engine")

		scores, err := conn.GetScores(groupBy, application, tool, engine)
		w.Header().Set("Content-Type", "application/json")
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf("Failed to fetch scores: %v", err)})
			return
		}
		json.NewEncoder(w).Encode(scores)
	})

	// Tools
	r.Get("/api/tools", func(w http.ResponseWriter, r *http.Request) {
		tools, err := conn.GetDistinctTools()
		w.Header().Set("Content-Type", "application/json")
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": "Failed to fetch tools"})
			return
		}
		json.NewEncoder(w).Encode(tools)
	})

	// Engines
	r.Get("/api/engines", func(w http.ResponseWriter, r *http.Request) {
		engines, err := conn.GetDistinctEngines()
		w.Header().Set("Content-Type", "application/json")
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": "Failed to fetch engines"})
			return
		}
		json.NewEncoder(w).Encode(engines)
	})

	// TP percentage by tool
	r.Get("/api/tp-percentage/tool/{tool}", func(w http.ResponseWriter, r *http.Request) {
		tool := chi.URLParam(r, "tool")
		percentage, err := conn.GetTruePositivePercentageByTool(tool)
		w.Header().Set("Content-Type", "application/json")
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": "Failed to fetch TP percentage for tool"})
			return
		}
		json.NewEncoder(w).Encode(map[string]float64{"tpPercentage": percentage})
	})

	// TP percentage by engine
	r.Get("/api/tp-percentage/engine/{engine}", func(w http.ResponseWriter, r *http.Request) {
		engine := chi.URLParam(r, "engine")
		percentage, err := conn.GetTruePositivePercentageByEngine(engine)
		w.Header().Set("Content-Type", "application/json")
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": "Failed to fetch TP percentage for engine"})
			return
		}
		json.NewEncoder(w).Encode(map[string]float64{"tpPercentage": percentage})
	})

	// TP percentage by project
	r.Get("/api/tp-percentage/{projectID}", func(w http.ResponseWriter, r *http.Request) {
		projectIDStr := chi.URLParam(r, "projectID")
		projectID, err := strconv.Atoi(projectIDStr)
		w.Header().Set("Content-Type", "application/json")
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "Invalid projectID"})
			return
		}
		percentage, err := conn.GetTruePositivePercentage(projectID)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": "Failed to fetch TP percentage"})
			return
		}
		json.NewEncoder(w).Encode(map[string]float64{"tpPercentage": percentage})
	})

	r.Get("/api/engines/{repo}", func(w http.ResponseWriter, r *http.Request) {
		repo := chi.URLParam(r, "repo")
		repoDecoded, _ := url.PathUnescape(repo)
		engines, err := conn.GetEnginesByRepo(repoDecoded)
		w.Header().Set("Content-Type", "application/json")
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode([]string{}) // devolve array vazio em caso de erro
			return
		}
		if engines == nil {
			engines = []string{}
		}
		json.NewEncoder(w).Encode(engines)
	})

	// Repos by project
	r.Get("/api/repos/{project}", func(w http.ResponseWriter, r *http.Request) {
		project := chi.URLParam(r, "project")
		repos, err := conn.GetReposByProject(project)
		w.Header().Set("Content-Type", "application/json")
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": "Failed to fetch repos"})
			return
		}
		json.NewEncoder(w).Encode(repos)
	})

	// Repos by prefix (moved inside main)
	r.Get("/api/repos", func(w http.ResponseWriter, r *http.Request) {
		prefix := r.URL.Query().Get("prefix")
		if prefix == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "Missing prefix"})
			return
		}
		repos, err := conn.GetReposByProject(prefix)
		w.Header().Set("Content-Type", "application/json")
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": "Failed to fetch repos"})
			return
		}
		json.NewEncoder(w).Encode(repos)
	})

	r.Get("/api/tp-percentage/repo/{repo}", func(w http.ResponseWriter, r *http.Request) {
		repo := chi.URLParam(r, "repo")
		repoDecoded, err := url.PathUnescape(repo)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "Invalid repo encoding"})
			return
		}
		log.Println("Repo param (decoded):", repoDecoded)
		projectID, err := conn.GetProjectIDByName(repoDecoded)
		w.Header().Set("Content-Type", "application/json")
		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{"error": "Project not found"})
			return
		}
		tpPercentage, vulnCount, err := conn.GetTruePositivePercentageWithCount(int(projectID))
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": "Failed to fetch TP percentage"})
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"tpPercentage":       tpPercentage,
			"vulnerabilityCount": vulnCount,
		})
	})

	// TP percentage for engine in repo
	r.Get("/api/tp-percentage/engine/{engine}", func(w http.ResponseWriter, r *http.Request) {
		engine := chi.URLParam(r, "engine")
		repo := r.URL.Query().Get("repo")
		w.Header().Set("Content-Type", "application/json")
		if repo == "" {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "Missing repo"})
			return
		}
		tpPercentage, vulnCount, err := conn.GetTruePositivePercentageByEngineWithCount(engine, repo)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": "Failed to fetch TP percentage"})
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"tpPercentage":       tpPercentage,
			"vulnerabilityCount": vulnCount,
		})
	})

	log.Println("INFO: Server is running and listening on port 3000")
	http.ListenAndServe(":3000", r)
}
