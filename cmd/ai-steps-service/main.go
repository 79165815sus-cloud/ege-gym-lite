package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
	Question       string `json:"question"`
}

type Policy struct {
	Language        string `json:"language,omitempty"` // ru
	MaxSteps        int    `json:"maxSteps,omitempty"` // 0 = auto
	NoFinalAnswer   bool   `json:"noFinalAnswer,omitempty"`
	KeepMathLatex   bool   `json:"keepMathLatex,omitempty"`
	PreferShortStep bool   `json:"preferShortStep,omitempty"`
}

type GenerateRequest struct {
	Task     TaskMeta `json:"task"`
	Solution string   `json:"solution,omitempty"` // optional reference
	Policy   Policy   `json:"policy,omitempty"`
}

type GenerateResponse struct {
	TaskID      int      `json:"taskId"`
	HintSteps   []string `json:"hintSteps"`
	GeneratedBy string   `json:"generatedBy"`
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func readJSON(r *http.Request, dst any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(dst)
}

func normalizeSteps(items []string) []string {
	out := make([]string, 0, len(items))
	for _, s := range items {
		s = strings.TrimSpace(strings.ReplaceAll(s, "\r\n", "\n"))
		if s == "" {
			continue
		}
		low := strings.ToLower(s)
		if strings.HasPrefix(low, "ответ") {
			continue
		}
		out = append(out, s)
	}
	return out
}

func env(key, def string) string {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	return v
}

func openAIBaseURL() string {
	return strings.TrimRight(env("OPENAI_BASE_URL", "https://api.openai.com/v1"), "/")
}
func openAIModel() string { return env("OPENAI_MODEL", "gpt-4o-mini") }
func openAIKey() string   { return strings.TrimSpace(os.Getenv("OPENAI_API_KEY")) }

func buildPrompt(req GenerateRequest) (system, user string) {
	p := req.Policy
	if p.Language == "" {
		p.Language = "ru"
	}
	maxSteps := p.MaxSteps
	if maxSteps <= 0 {
		maxSteps = 12
	}
	stepStyle := "Делай шаги компактными, но полноценными."
	if p.PreferShortStep {
		stepStyle = "Делай шаги очень короткими (1–2 предложения)."
	}
	noAnswer := "Можно довести до финального ответа."
	if p.NoFinalAnswer {
		noAnswer = "Не пиши строку «Ответ: …» и не раскрывай финальный числовой/текстовый ответ."
	}
	latex := "Если есть формулы, используй LaTeX как в исходнике."
	if !p.KeepMathLatex {
		latex = "Если есть формулы, можно писать их текстом."
	}

	system = strings.TrimSpace(fmt.Sprintf(`Ты — сервис, который превращает решение школьной задачи в последовательные шаги.
Верни ТОЛЬКО валидный JSON по схеме:
{"hintSteps":["...","..."]}

Требования:
- Язык: %s
- %s
- %s
- Не добавляй «контекст», не задавай вопросы, не добавляй чек-листы.
- Каждый элемент hintSteps — это текст одного шага решения.
- Максимум шагов: %d (если нужно — объединяй).
- Никакого Markdown-оглавления; допускается LaTeX в тексте шага.
`, p.Language, stepStyle, noAnswer, maxSteps))

	// Give both question and optional solution to keep it grounded.
	var b strings.Builder
	b.WriteString("Задача:\n")
	b.WriteString(req.Task.Question)
	b.WriteString("\n")
	if strings.TrimSpace(req.Solution) != "" {
		b.WriteString("\nРешение (для опоры):\n")
		b.WriteString(req.Solution)
		b.WriteString("\n")
	}
	b.WriteString("\n")
	b.WriteString(latex)
	user = b.String()
	return system, user
}

// OpenAI Chat Completions minimal client.
type openAIChatRequest struct {
	Model       string  `json:"model"`
	Temperature float64 `json:"temperature,omitempty"`
	Messages    []struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	} `json:"messages"`
}

type openAIChatResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
}

func callOpenAI(req GenerateRequest) ([]string, error) {
	if openAIKey() == "" {
		return nil, errors.New("OPENAI_API_KEY is not set")
	}

	system, user := buildPrompt(req)

	payload := openAIChatRequest{
		Model:       openAIModel(),
		Temperature: 0.2,
	}
	payload.Messages = make([]struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	}, 0, 2)
	payload.Messages = append(payload.Messages, struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	}{Role: "system", Content: system})
	payload.Messages = append(payload.Messages, struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	}{Role: "user", Content: user})

	data, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	client := &http.Client{Timeout: 20 * time.Second}
	httpReq, err := http.NewRequest(http.MethodPost, openAIBaseURL()+"/chat/completions", bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Authorization", "Bearer "+openAIKey())
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("openai status=%d body=%s", resp.StatusCode, string(body))
	}

	var parsed openAIChatResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, err
	}
	if len(parsed.Choices) == 0 {
		return nil, errors.New("openai: empty choices")
	}
	content := strings.TrimSpace(parsed.Choices[0].Message.Content)
	if content == "" {
		return nil, errors.New("openai: empty content")
	}

	// Expect JSON {"hintSteps":[...]}
	var out struct {
		HintSteps []string `json:"hintSteps"`
	}
	if err := json.Unmarshal([]byte(content), &out); err != nil {
		// Try to extract JSON from surrounding text.
		start := strings.Index(content, "{")
		end := strings.LastIndex(content, "}")
		if start >= 0 && end > start {
			if err2 := json.Unmarshal([]byte(content[start:end+1]), &out); err2 == nil {
				return normalizeSteps(out.HintSteps), nil
			}
		}
		return nil, fmt.Errorf("failed to parse model json: %w", err)
	}

	steps := normalizeSteps(out.HintSteps)
	if len(steps) == 0 {
		return nil, errors.New("openai: no steps produced")
	}
	return steps, nil
}

func validateRequest(req GenerateRequest) error {
	if req.Task.ID <= 0 {
		return errors.New("task.id must be positive")
	}
	if strings.TrimSpace(req.Task.Question) == "" {
		return errors.New("task.question is required")
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

	mux.HandleFunc("/v1/steps/generate", func(w http.ResponseWriter, r *http.Request) {
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

		steps, err := callOpenAI(req)
		if err != nil {
			http.Error(w, "generation failed: "+err.Error(), http.StatusBadGateway)
			return
		}

		writeJSON(w, http.StatusOK, GenerateResponse{
			TaskID:      req.Task.ID,
			HintSteps:   steps,
			GeneratedBy: "openai:" + openAIModel(),
		})
	})

	port := strings.TrimSpace(os.Getenv("PORT"))
	if port == "" {
		port = "8091"
	}
	srv := &http.Server{
		Addr:              ":" + port,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Printf("ai-steps-service started on :%s", port)
	log.Fatal(srv.ListenAndServe())
}
