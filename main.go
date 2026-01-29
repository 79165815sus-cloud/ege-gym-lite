package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Task struct {
	ID             int    `json:"id"`
	Question       string `json:"question"`
	ImageURL       string `json:"imageUrl"`
	Subject        string `json:"subject"`
	ExamTaskNumber int    `json:"examTaskNumber"`
	Subtopic       string `json:"subtopic"`
	ExamType       string `json:"examType"`
	Answer         Answer `json:"answer"`
	Solution       string `json:"solution"`
}

type TaskPublic struct {
	ID             int    `json:"id"`
	Question       string `json:"question"`
	ImageURL       string `json:"imageUrl"`
	Subject        string `json:"subject"`
	ExamTaskNumber int    `json:"examTaskNumber"`
	Subtopic       string `json:"subtopic"`
	ExamType       string `json:"examType"`
}

type FiltersResponse struct {
	ExamTypes       []string `json:"examTypes"`
	Subjects        []string `json:"subjects"`
	ExamTaskNumbers []int    `json:"examTaskNumbers"`
	Subtopics       []string `json:"subtopics"`
}

var tasks []Task
var tasksMu sync.Mutex
var analyticsMu sync.Mutex

type Answer string

func (a *Answer) UnmarshalJSON(data []byte) error {
	if len(data) == 0 {
		*a = ""
		return nil
	}
	if data[0] == '"' {
		var s string
		if err := json.Unmarshal(data, &s); err != nil {
			return err
		}
		*a = Answer(s)
		return nil
	}
	var num json.Number
	if err := json.Unmarshal(data, &num); err != nil {
		return err
	}
	*a = Answer(num.String())
	return nil
}

func loadTasks(path string) ([]Task, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var items []Task
	if err := json.Unmarshal(data, &items); err != nil {
		return nil, err
	}

	return items, nil
}

func saveTasks(path string, items []Task) error {
	data, err := json.MarshalIndent(items, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0o644)
}

type AnalyticsEvent struct {
	AnonID     string                 `json:"anon_id"`
	Event      string                 `json:"event"`
	Properties map[string]interface{} `json:"properties,omitempty"`
	Timestamp  string                 `json:"timestamp"`
}

func toPublic(task Task) TaskPublic {
	return TaskPublic{
		ID:             task.ID,
		Question:       task.Question,
		ImageURL:       task.ImageURL,
		Subject:        task.Subject,
		ExamTaskNumber: task.ExamTaskNumber,
		Subtopic:       task.Subtopic,
		ExamType:       task.ExamType,
	}
}

func filterTasks(items []Task, examType, subject, subtopic string, examTaskNumber *int) []Task {
	filtered := make([]Task, 0, len(items))
	for _, task := range items {
		if examType != "" && !strings.EqualFold(task.ExamType, examType) {
			continue
		}
		if subject != "" && !strings.EqualFold(task.Subject, subject) {
			continue
		}
		if subtopic != "" && !strings.EqualFold(task.Subtopic, subtopic) {
			continue
		}
		if examTaskNumber != nil && task.ExamTaskNumber != *examTaskNumber {
			continue
		}
		filtered = append(filtered, task)
	}
	return filtered
}

func buildFilters(items []Task) FiltersResponse {
	examTypes := make(map[string]struct{})
	subjects := make(map[string]struct{})
	subtopics := make(map[string]struct{})
	examTaskNumbers := make(map[int]struct{})

	for _, task := range items {
		if task.ExamType != "" {
			examTypes[task.ExamType] = struct{}{}
		}
		if task.Subject != "" {
			subjects[task.Subject] = struct{}{}
		}
		if task.Subtopic != "" {
			subtopics[task.Subtopic] = struct{}{}
		}
		if task.ExamTaskNumber != 0 {
			examTaskNumbers[task.ExamTaskNumber] = struct{}{}
		}
	}

	response := FiltersResponse{
		ExamTypes:       make([]string, 0, len(examTypes)),
		Subjects:        make([]string, 0, len(subjects)),
		Subtopics:       make([]string, 0, len(subtopics)),
		ExamTaskNumbers: make([]int, 0, len(examTaskNumbers)),
	}

	for value := range examTypes {
		response.ExamTypes = append(response.ExamTypes, value)
	}
	for value := range subjects {
		response.Subjects = append(response.Subjects, value)
	}
	for value := range subtopics {
		response.Subtopics = append(response.Subtopics, value)
	}
	for value := range examTaskNumbers {
		response.ExamTaskNumbers = append(response.ExamTaskNumbers, value)
	}

	sort.Strings(response.ExamTypes)
	sort.Strings(response.Subjects)
	sort.Strings(response.Subtopics)
	sort.Ints(response.ExamTaskNumbers)

	return response
}

func randomTask() Task {
	return tasks[rand.Intn(len(tasks))]
}

func findTask(id int) (Task, bool) {
	for _, task := range tasks {
		if task.ID == id {
			return task, true
		}
	}
	return Task{}, false
}

func validateTasks(items []Task) error {
	if len(items) == 0 {
		return errors.New("tasks list is empty")
	}
	ids := make(map[int]struct{}, len(items))
	for _, task := range items {
		if task.ID <= 0 {
			return errors.New("task id must be positive")
		}
		if _, exists := ids[task.ID]; exists {
			return errors.New("duplicate task id")
		}
		ids[task.ID] = struct{}{}
	}
	return nil
}

func normalizeAnswer(value string) string {
	value = strings.TrimSpace(value)
	value = strings.ToLower(value)
	value = strings.ReplaceAll(value, ",", ".")
	value = strings.ReplaceAll(value, " ", "")
	return value
}

func answersEqual(expected Answer, given string) bool {
	expectedRaw := string(expected)
	givenNorm := normalizeAnswer(given)
	if givenNorm == "" {
		return false
	}

	options := strings.Split(expectedRaw, "|")
	for _, option := range options {
		expectedNorm := normalizeAnswer(option)
		if expectedNorm == "" {
			continue
		}
		expectedFloat, errExpected := strconv.ParseFloat(expectedNorm, 64)
		givenFloat, errGiven := strconv.ParseFloat(givenNorm, 64)
		if errExpected == nil && errGiven == nil {
			if math.Abs(expectedFloat-givenFloat) < 1e-9 {
				return true
			}
			continue
		}
		if expectedNorm == givenNorm {
			return true
		}
	}
	return false
}

func main() {
	const tasksPath = "tasks.json"
	const uploadsDir = "./static/uploads"

	loadedTasks, err := loadTasks(tasksPath)
	if err != nil {
		log.Fatal(err)
	}
	if len(loadedTasks) == 0 {
		log.Fatal("tasks.json is empty")
	}
	tasks = loadedTasks

	rand.Seed(time.Now().UnixNano())

	// API: получить задачу
	http.HandleFunc("/api/task", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		tasksMu.Lock()
		defer tasksMu.Unlock()

		query := r.URL.Query()
		examType := strings.TrimSpace(query.Get("examType"))
		subject := strings.TrimSpace(query.Get("subject"))
		subtopic := strings.TrimSpace(query.Get("subtopic"))

		var examTaskNumber *int
		if rawNumber := strings.TrimSpace(query.Get("examTaskNumber")); rawNumber != "" {
			parsed, err := strconv.Atoi(rawNumber)
			if err != nil {
				http.Error(w, "bad examTaskNumber", http.StatusBadRequest)
				return
			}
			examTaskNumber = &parsed
		}

		available := filterTasks(tasks, examType, subject, subtopic, examTaskNumber)
		if len(available) == 0 {
			http.Error(w, "no tasks for filters", http.StatusNotFound)
			return
		}

		json.NewEncoder(w).Encode(toPublic(available[rand.Intn(len(available))]))
	})

	// API: проверить ответ
	http.HandleFunc("/api/check", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req struct {
			ID     int `json:"id"`
			Answer string `json:"answer"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		tasksMu.Lock()
		task, ok := findTask(req.ID)
		tasksMu.Unlock()
		if !ok {
			http.Error(w, "task not found", http.StatusNotFound)
			return
		}
		correct := answersEqual(task.Answer, req.Answer)

		json.NewEncoder(w).Encode(map[string]bool{
			"correct": correct,
		})
	})

	// API: показать ответ
	http.HandleFunc("/api/answer", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req struct {
			ID int `json:"id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		tasksMu.Lock()
		task, ok := findTask(req.ID)
		tasksMu.Unlock()
		if !ok {
			http.Error(w, "task not found", http.StatusNotFound)
			return
		}

		json.NewEncoder(w).Encode(map[string]string{
			"answer": string(task.Answer),
		})
	})

	// API: показать решение
	http.HandleFunc("/api/solution", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req struct {
			ID int `json:"id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		tasksMu.Lock()
		task, ok := findTask(req.ID)
		tasksMu.Unlock()
		if !ok {
			http.Error(w, "task not found", http.StatusNotFound)
			return
		}

		json.NewEncoder(w).Encode(map[string]string{
			"solution": task.Solution,
		})
	})

	// API: фильтры
	http.HandleFunc("/api/filters", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		tasksMu.Lock()
		defer tasksMu.Unlock()
		json.NewEncoder(w).Encode(buildFilters(tasks))
	})

	// API: список задач без ответов (для последовательного режима)
	http.HandleFunc("/api/tasks-public", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		query := r.URL.Query()
		examType := strings.TrimSpace(query.Get("examType"))
		subject := strings.TrimSpace(query.Get("subject"))
		subtopic := strings.TrimSpace(query.Get("subtopic"))

		var examTaskNumber *int
		if rawNumber := strings.TrimSpace(query.Get("examTaskNumber")); rawNumber != "" {
			parsed, err := strconv.Atoi(rawNumber)
			if err != nil {
				http.Error(w, "bad examTaskNumber", http.StatusBadRequest)
				return
			}
			examTaskNumber = &parsed
		}

		tasksMu.Lock()
		available := filterTasks(tasks, examType, subject, subtopic, examTaskNumber)
		tasksMu.Unlock()

		sort.Slice(available, func(i, j int) bool {
			if available[i].ExamTaskNumber != available[j].ExamTaskNumber {
				return available[i].ExamTaskNumber < available[j].ExamTaskNumber
			}
			return available[i].ID < available[j].ID
		})

		public := make([]TaskPublic, 0, len(available))
		for _, task := range available {
			public = append(public, toPublic(task))
		}

		json.NewEncoder(w).Encode(public)
	})

	// API: трекинг событий (анонимно)
	http.HandleFunc("/api/track", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var payload AnalyticsEvent
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if strings.TrimSpace(payload.AnonID) == "" || strings.TrimSpace(payload.Event) == "" {
			http.Error(w, "anon_id and event required", http.StatusBadRequest)
			return
		}

		payload.Timestamp = time.Now().UTC().Format(time.RFC3339)
		data, err := json.Marshal(payload)
		if err != nil {
			http.Error(w, "failed to serialize", http.StatusInternalServerError)
			return
		}

		analyticsMu.Lock()
		defer analyticsMu.Unlock()
		file, err := os.OpenFile("analytics.jsonl", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			http.Error(w, "failed to write", http.StatusInternalServerError)
			return
		}
		defer file.Close()
		if _, err := file.Write(append(data, '\n')); err != nil {
			http.Error(w, "failed to write", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusNoContent)
	})

	// API: выгрузка аналитики (jsonl -> json массив)
	http.HandleFunc("/api/analytics", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		analyticsMu.Lock()
		defer analyticsMu.Unlock()

		file, err := os.Open("analytics.jsonl")
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				json.NewEncoder(w).Encode([]AnalyticsEvent{})
				return
			}
			http.Error(w, "failed to read", http.StatusInternalServerError)
			return
		}
		defer file.Close()

		events := make([]AnalyticsEvent, 0, 256)
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}
			var item AnalyticsEvent
			if err := json.Unmarshal([]byte(line), &item); err != nil {
				continue
			}
			events = append(events, item)
		}
		if err := scanner.Err(); err != nil {
			http.Error(w, "failed to read", http.StatusInternalServerError)
			return
		}

		json.NewEncoder(w).Encode(events)
	})

	// API: загрузка картинки
	http.HandleFunc("/api/upload", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		if err := os.MkdirAll(uploadsDir, 0o755); err != nil {
			http.Error(w, "failed to create upload dir", http.StatusInternalServerError)
			return
		}

		r.Body = http.MaxBytesReader(w, r.Body, 5<<20)
		if err := r.ParseMultipartForm(5 << 20); err != nil {
			http.Error(w, "file too large", http.StatusBadRequest)
			return
		}

		file, header, err := r.FormFile("file")
		if err != nil {
			http.Error(w, "file required", http.StatusBadRequest)
			return
		}
		defer file.Close()

		buffer := make([]byte, 512)
		n, err := file.Read(buffer)
		if err != nil && !errors.Is(err, io.EOF) {
			http.Error(w, "failed to read file", http.StatusBadRequest)
			return
		}
		contentType := http.DetectContentType(buffer[:n])
		if !strings.HasPrefix(contentType, "image/") {
			http.Error(w, "only images allowed", http.StatusBadRequest)
			return
		}

		if _, err := file.Seek(0, io.SeekStart); err != nil {
			http.Error(w, "failed to read file", http.StatusBadRequest)
			return
		}

		ext := strings.ToLower(filepath.Ext(header.Filename))
		if ext == "" {
			switch contentType {
			case "image/jpeg":
				ext = ".jpg"
			case "image/png":
				ext = ".png"
			case "image/gif":
				ext = ".gif"
			default:
				ext = ".img"
			}
		}

		filename := fmt.Sprintf("%d-%d%s", time.Now().UnixNano(), rand.Intn(1000), ext)
		dstPath := filepath.Join(uploadsDir, filename)
		dst, err := os.Create(dstPath)
		if err != nil {
			http.Error(w, "failed to save file", http.StatusInternalServerError)
			return
		}
		defer dst.Close()

		if _, err := io.Copy(dst, file); err != nil {
			http.Error(w, "failed to save file", http.StatusInternalServerError)
			return
		}

		json.NewEncoder(w).Encode(map[string]string{
			"url": "/uploads/" + filename,
		})
	})

	// API: полный список задач (админка)
	http.HandleFunc("/api/tasks", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			tasksMu.Lock()
			defer tasksMu.Unlock()
			json.NewEncoder(w).Encode(tasks)
		case http.MethodPut:
			var payload []Task
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}
			if err := validateTasks(payload); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if err := saveTasks(tasksPath, payload); err != nil {
				http.Error(w, "failed to save", http.StatusInternalServerError)
				return
			}

			tasksMu.Lock()
			tasks = payload
			tasksMu.Unlock()

			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})

	// статика
	fs := http.FileServer(http.Dir("./static"))
	http.Handle("/", fs)

	port := strings.TrimSpace(os.Getenv("PORT"))
	if port == "" {
		port = "8080"
	}
	addr := ":" + port
	log.Printf("Server started on %s", addr)
	log.Fatal(http.ListenAndServe(addr, nil))
}
