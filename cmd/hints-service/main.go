package main

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

type TaskMeta struct {
	ID             int    `json:"id"`
	Subject        string `json:"subject,omitempty"`
	ExamType       string `json:"examType,omitempty"`
	ExamTaskNumber int    `json:"examTaskNumber,omitempty"`
	Question       string `json:"question,omitempty"`
	ImageURL       string `json:"imageUrl,omitempty"`
}

type Policy struct {
	MaxVerbosity  string `json:"maxVerbosity,omitempty"` // short|medium|long
	NoFinalAnswer bool   `json:"noFinalAnswer,omitempty"`
	Language      string `json:"language,omitempty"` // ru
	Steps         []int  `json:"steps,omitempty"`    // default: 1..4
}

type GenerateRequest struct {
	Task     TaskMeta `json:"task"`
	Solution string   `json:"solution"`
	Policy   Policy   `json:"policy,omitempty"`
}

type HintStep struct {
	Step           int      `json:"step"`
	Title          string   `json:"title"`
	Prompt         string   `json:"prompt"`
	Hint           string   `json:"hint"`
	Checks         []string `json:"checks,omitempty"`
	CommonMistakes []string `json:"common_mistakes,omitempty"`
	NextAction     string   `json:"next_action,omitempty"`
}

type GenerateResponse struct {
	TaskID int        `json:"taskId"`
	Steps  []HintStep `json:"steps"`
	Meta   struct {
		Model      string  `json:"model"`
		Cached     bool    `json:"cached"`
		Confidence float64 `json:"confidence"`
	} `json:"meta"`
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func readJSON(r *http.Request, dst any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	return nil
}

func normalizeSteps(steps []int) []int {
	if len(steps) == 0 {
		return []int{1, 2, 3, 4}
	}
	allowed := map[int]bool{1: true, 2: true, 3: true, 4: true}
	out := make([]int, 0, 4)
	seen := make(map[int]struct{}, 4)
	for _, s := range steps {
		if !allowed[s] {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	if len(out) == 0 {
		return []int{1, 2, 3, 4}
	}
	return out
}

func normalizeSolutionText(solution string) string {
	s := strings.ReplaceAll(solution, "\r\n", "\n")
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}

	// Drop explicit answer lines to avoid spoilers in hints UI.
	lines := strings.Split(s, "\n")
	kept := make([]string, 0, len(lines))
	for _, line := range lines {
		raw := strings.TrimSpace(line)
		if raw == "" {
			kept = append(kept, "")
			continue
		}
		lower := strings.ToLower(raw)
		if strings.HasPrefix(lower, "ответ") {
			continue
		}
		kept = append(kept, line)
	}
	s = strings.TrimSpace(strings.Join(kept, "\n"))
	return s
}

func splitIntoChunks(solution string) []string {
	solution = normalizeSolutionText(solution)
	if solution == "" {
		return nil
	}

	parts := strings.Split(solution, "\n\n")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		out = append(out, p)
	}
	if len(out) > 0 {
		return out
	}
	return nil
}

func buildSolutionSteps(solution string) []HintStep {
	chunks := splitIntoChunks(solution)
	if len(chunks) == 0 {
		return []HintStep{
			{Step: 1, Hint: "Нет текста решения для разбиения на шаги."},
			{Step: 2, Hint: ""},
			{Step: 3, Hint: ""},
			{Step: 4, Hint: ""},
		}
	}

	// If solution has many paragraphs, take first 4. If fewer, reuse.
	get := func(i int) string {
		if i < 0 {
			i = 0
		}
		if i >= len(chunks) {
			return chunks[len(chunks)-1]
		}
		return chunks[i]
	}

	return []HintStep{
		{Step: 1, Hint: get(0)},
		{Step: 2, Hint: get(1)},
		{Step: 3, Hint: get(2)},
		{Step: 4, Hint: get(3)},
	}
}

func buildSteps(req GenerateRequest) []HintStep {
	all := map[int]HintStep{
		1: {Step: 1},
		2: {Step: 2},
		3: {Step: 3},
		4: {Step: 4},
	}

	steps := normalizeSteps(req.Policy.Steps)

	// Build full 1..4 first, then pick requested steps.
	full := buildSolutionSteps(req.Solution)
	for _, s := range full {
		all[s.Step] = s
	}

	out := make([]HintStep, 0, len(steps))
	for _, s := range steps {
		out = append(out, all[s])
	}
	return out
}

func itoa(v int) string {
	// tiny helper to avoid strconv import in this file
	if v == 0 {
		return "0"
	}
	neg := v < 0
	if neg {
		v = -v
	}
	var b [32]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

func validateRequest(req GenerateRequest) error {
	if req.Task.ID <= 0 {
		return errors.New("task.id must be positive")
	}
	if strings.TrimSpace(req.Task.Question) == "" {
		return errors.New("task.question is required")
	}
	if strings.TrimSpace(req.Solution) == "" {
		return errors.New("solution is required")
	}
	if req.Policy.Language != "" && req.Policy.Language != "ru" {
		return errors.New("only policy.language=ru is supported")
	}
	return nil
}

func main() {
	mux := http.NewServeMux()

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	mux.HandleFunc("/v1/hints/generate", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req GenerateRequest
		if err := readJSON(r, &req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if err := validateRequest(req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		resp := GenerateResponse{
			TaskID: req.Task.ID,
			Steps:  buildSteps(req),
		}
		resp.Meta.Model = "rule-based"
		resp.Meta.Cached = false
		resp.Meta.Confidence = 0.55

		writeJSON(w, http.StatusOK, resp)
	})

	port := strings.TrimSpace(os.Getenv("PORT"))
	if port == "" {
		port = "8090"
	}
	srv := &http.Server{
		Addr:              ":" + port,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Printf("hints-service started on :%s", port)
	log.Fatal(srv.ListenAndServe())
}
