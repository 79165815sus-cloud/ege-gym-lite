package main

import (
	"bufio"
	"crypto/hmac"
	crand "crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
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

	_ "modernc.org/sqlite"
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

type User struct {
	ID           int    `json:"id"`
	Email        string `json:"email"`
	PasswordHash string `json:"passwordHash"`
	Salt         string `json:"salt"`
	CreatedAt    string `json:"createdAt"`
	Role         string `json:"role"`
}

type PublicUser struct {
	ID        int    `json:"id"`
	Email     string `json:"email"`
	CreatedAt string `json:"createdAt"`
	Role      string `json:"role"`
}

var sessions = make(map[string]int)
var sessionsMu sync.Mutex

const sessionCookieName = "session_id"

var userDB *sql.DB

const roleAdmin = "admin"
const roleUser = "user"

var adminEmails = map[string]struct{}{
	"79165815727@yandex.ru": {},
}

func isAdminEmail(email string) bool {
	_, ok := adminEmails[strings.ToLower(strings.TrimSpace(email))]
	return ok
}

func toPublicUser(user User) PublicUser {
	return PublicUser{
		ID:        user.ID,
		Email:     user.Email,
		CreatedAt: user.CreatedAt,
		Role:      user.Role,
	}
}

func initUserDB(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec(`PRAGMA journal_mode=WAL;`); err != nil {
		return nil, err
	}
	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			email TEXT NOT NULL UNIQUE,
			password_hash TEXT NOT NULL,
			salt TEXT NOT NULL,
			created_at TEXT NOT NULL,
			role TEXT NOT NULL DEFAULT 'user'
		);
	`); err != nil {
		return nil, err
	}
	if _, err := db.Exec(`ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'user'`); err != nil {
		if !strings.Contains(strings.ToLower(err.Error()), "duplicate column") {
			return nil, err
		}
	}
	return db, nil
}

func getUserByEmail(db *sql.DB, email string) (User, bool, error) {
	var user User
	err := db.QueryRow(
		`SELECT id, email, password_hash, salt, created_at, role FROM users WHERE LOWER(email) = LOWER(?) LIMIT 1`,
		email,
	).Scan(&user.ID, &user.Email, &user.PasswordHash, &user.Salt, &user.CreatedAt, &user.Role)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, false, nil
	}
	if err != nil {
		return User{}, false, err
	}
	return user, true, nil
}

func getUserByID(db *sql.DB, id int) (User, bool, error) {
	var user User
	err := db.QueryRow(
		`SELECT id, email, password_hash, salt, created_at, role FROM users WHERE id = ? LIMIT 1`,
		id,
	).Scan(&user.ID, &user.Email, &user.PasswordHash, &user.Salt, &user.CreatedAt, &user.Role)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, false, nil
	}
	if err != nil {
		return User{}, false, err
	}
	return user, true, nil
}

func listUsers(db *sql.DB) ([]PublicUser, error) {
	rows, err := db.Query(`SELECT id, email, created_at, role FROM users ORDER BY id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	users := make([]PublicUser, 0, 32)
	for rows.Next() {
		var item PublicUser
		if err := rows.Scan(&item.ID, &item.Email, &item.CreatedAt, &item.Role); err != nil {
			return nil, err
		}
		users = append(users, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return users, nil
}

func setUserRoleByEmail(db *sql.DB, email, role string) (bool, error) {
	result, err := db.Exec(
		`UPDATE users SET role = ? WHERE LOWER(email) = LOWER(?)`,
		role, email,
	)
	if err != nil {
		return false, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	return affected > 0, nil
}

func migrateUsersJSON(db *sql.DB, path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if strings.TrimSpace(string(data)) == "" {
		return nil
	}
	var items []User
	if err := json.Unmarshal(data, &items); err != nil {
		return err
	}
	for _, user := range items {
		if user.Email == "" || user.PasswordHash == "" || user.Salt == "" {
			continue
		}
		createdAt := user.CreatedAt
		if createdAt == "" {
			createdAt = time.Now().UTC().Format(time.RFC3339)
		}
		role := strings.TrimSpace(strings.ToLower(user.Role))
		if role == "" {
			role = roleUser
		}
		if _, err := db.Exec(
			`INSERT OR IGNORE INTO users (id, email, password_hash, salt, created_at, role) VALUES (?, ?, ?, ?, ?, ?)`,
			user.ID, user.Email, user.PasswordHash, user.Salt, createdAt, role,
		); err != nil {
			return err
		}
	}
	return nil
}

func ensureAdminEmails(db *sql.DB) error {
	if _, err := db.Exec(`UPDATE users SET role = ? WHERE role IS NULL OR TRIM(role) = ''`, roleUser); err != nil {
		return err
	}
	for email := range adminEmails {
		if _, err := db.Exec(
			`UPDATE users SET role = ? WHERE LOWER(email) = LOWER(?)`,
			roleAdmin, email,
		); err != nil {
			return err
		}
	}
	return nil
}

func pbkdf2Key(password, salt []byte, iter, keyLen int) []byte {
	hLen := sha256.Size
	numBlocks := (keyLen + hLen - 1) / hLen
	var out []byte
	for block := 1; block <= numBlocks; block++ {
		mac := hmac.New(sha256.New, password)
		mac.Write(salt)
		mac.Write([]byte{
			byte(block >> 24),
			byte(block >> 16),
			byte(block >> 8),
			byte(block),
		})
		u := mac.Sum(nil)
		t := make([]byte, len(u))
		copy(t, u)
		for i := 1; i < iter; i++ {
			mac = hmac.New(sha256.New, password)
			mac.Write(u)
			u = mac.Sum(nil)
			for j := range t {
				t[j] ^= u[j]
			}
		}
		out = append(out, t...)
	}
	return out[:keyLen]
}

func hashPassword(password, salt string) string {
	key := pbkdf2Key([]byte(password), []byte(salt), 120000, 32)
	return base64.RawStdEncoding.EncodeToString(key)
}

func verifyPassword(password, salt, expectedHash string) bool {
	hash := hashPassword(password, salt)
	return subtle.ConstantTimeCompare([]byte(hash), []byte(expectedHash)) == 1
}

func generateSessionID() (string, error) {
	buf := make([]byte, 32)
	if _, err := crand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func setSessionCookie(w http.ResponseWriter, r *http.Request, sessionID string) {
	cookie := &http.Cookie{
		Name:     sessionCookieName,
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   7 * 24 * 60 * 60,
	}
	if r.TLS != nil {
		cookie.Secure = true
	}
	http.SetCookie(w, cookie)
}

func clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

func getSessionUserID(r *http.Request) (int, bool) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil || cookie.Value == "" {
		return 0, false
	}
	sessionsMu.Lock()
	defer sessionsMu.Unlock()
	id, ok := sessions[cookie.Value]
	return id, ok
}

func requireUser(w http.ResponseWriter, r *http.Request) (User, bool) {
	userID, ok := getSessionUserID(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return User{}, false
	}
	user, exists, err := getUserByID(userDB, userID)
	if err != nil {
		http.Error(w, "failed to load user", http.StatusInternalServerError)
		return User{}, false
	}
	if !exists {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return User{}, false
	}
	return user, true
}

func requireAdmin(w http.ResponseWriter, r *http.Request) (User, bool) {
	user, ok := requireUser(w, r)
	if !ok {
		return User{}, false
	}
	if strings.ToLower(strings.TrimSpace(user.Role)) != roleAdmin {
		http.Error(w, "forbidden", http.StatusForbidden)
		return User{}, false
	}
	return user, true
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
	const usersDBPath = "users.db"
	const legacyUsersPath = "users.json"
	const uploadsDir = "./static/uploads"

	loadedTasks, err := loadTasks(tasksPath)
	if err != nil {
		log.Fatal(err)
	}
	if len(loadedTasks) == 0 {
		log.Fatal("tasks.json is empty")
	}
	tasks = loadedTasks
	userDB, err = initUserDB(usersDBPath)
	if err != nil {
		log.Fatal(err)
	}
	defer userDB.Close()
	if err := migrateUsersJSON(userDB, legacyUsersPath); err != nil {
		log.Fatal(err)
	}
	if err := ensureAdminEmails(userDB); err != nil {
		log.Fatal(err)
	}

	rand.Seed(time.Now().UnixNano())

	// API: регистрация
	http.HandleFunc("/api/signup", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		var req struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		email := strings.TrimSpace(strings.ToLower(req.Email))
		password := strings.TrimSpace(req.Password)
		if email == "" || !strings.Contains(email, "@") {
			http.Error(w, "invalid email", http.StatusBadRequest)
			return
		}
		if len(password) < 6 {
			http.Error(w, "password too short", http.StatusBadRequest)
			return
		}

		if _, exists, err := getUserByEmail(userDB, email); err != nil {
			http.Error(w, "failed to check user", http.StatusInternalServerError)
			return
		} else if exists {
			http.Error(w, "user already exists", http.StatusConflict)
			return
		}

		saltBytes := make([]byte, 16)
		if _, err := crand.Read(saltBytes); err != nil {
			http.Error(w, "failed to create user", http.StatusInternalServerError)
			return
		}
		salt := base64.RawStdEncoding.EncodeToString(saltBytes)
		createdAt := time.Now().UTC().Format(time.RFC3339)
		role := roleUser
		if isAdminEmail(email) {
			role = roleAdmin
		}
		hash := hashPassword(password, salt)
		result, err := userDB.Exec(
			`INSERT INTO users (email, password_hash, salt, created_at, role) VALUES (?, ?, ?, ?, ?)`,
			email, hash, salt, createdAt, role,
		)
		if err != nil {
			http.Error(w, "failed to save user", http.StatusInternalServerError)
			return
		}
		newID, err := result.LastInsertId()
		if err != nil {
			http.Error(w, "failed to save user", http.StatusInternalServerError)
			return
		}
		newUser := User{
			ID:           int(newID),
			Email:        email,
			PasswordHash: hash,
			Salt:         salt,
			CreatedAt:    createdAt,
			Role:         role,
		}

		sessionID, err := generateSessionID()
		if err != nil {
			http.Error(w, "failed to create session", http.StatusInternalServerError)
			return
		}
		sessionsMu.Lock()
		sessions[sessionID] = newUser.ID
		sessionsMu.Unlock()
		setSessionCookie(w, r, sessionID)

		json.NewEncoder(w).Encode(toPublicUser(newUser))
	})

	// API: вход
	http.HandleFunc("/api/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		var req struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		email := strings.TrimSpace(strings.ToLower(req.Email))
		password := strings.TrimSpace(req.Password)
		if email == "" || password == "" {
			http.Error(w, "email and password required", http.StatusBadRequest)
			return
		}

		user, ok, err := getUserByEmail(userDB, email)
		if err != nil {
			http.Error(w, "failed to load user", http.StatusInternalServerError)
			return
		}
		if ok && isAdminEmail(email) && strings.ToLower(strings.TrimSpace(user.Role)) != roleAdmin {
			if _, err := setUserRoleByEmail(userDB, email, roleAdmin); err != nil {
				http.Error(w, "failed to update role", http.StatusInternalServerError)
				return
			}
			user.Role = roleAdmin
		}
		if !ok || !verifyPassword(password, user.Salt, user.PasswordHash) {
			http.Error(w, "invalid credentials", http.StatusUnauthorized)
			return
		}

		sessionID, err := generateSessionID()
		if err != nil {
			http.Error(w, "failed to create session", http.StatusInternalServerError)
			return
		}
		sessionsMu.Lock()
		sessions[sessionID] = user.ID
		sessionsMu.Unlock()
		setSessionCookie(w, r, sessionID)

		json.NewEncoder(w).Encode(toPublicUser(user))
	})

	// API: выход
	http.HandleFunc("/api/logout", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		cookie, err := r.Cookie(sessionCookieName)
		if err == nil && cookie.Value != "" {
			sessionsMu.Lock()
			delete(sessions, cookie.Value)
			sessionsMu.Unlock()
		}
		clearSessionCookie(w)
		w.WriteHeader(http.StatusNoContent)
	})

	// API: текущий пользователь
	http.HandleFunc("/api/me", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		user, ok := requireUser(w, r)
		if !ok {
			return
		}
		json.NewEncoder(w).Encode(toPublicUser(user))
	})

	// API: список пользователей (только админ)
	http.HandleFunc("/api/admin/users", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if _, ok := requireAdmin(w, r); !ok {
			return
		}
		items, err := listUsers(userDB)
		if err != nil {
			http.Error(w, "failed to load users", http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(items)
	})

	// API: назначить роль (только админ)
	http.HandleFunc("/api/admin/role", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if _, ok := requireAdmin(w, r); !ok {
			return
		}
		var req struct {
			Email string `json:"email"`
			Role  string `json:"role"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		email := strings.TrimSpace(strings.ToLower(req.Email))
		if email == "" || !strings.Contains(email, "@") {
			http.Error(w, "invalid email", http.StatusBadRequest)
			return
		}
		role := strings.TrimSpace(strings.ToLower(req.Role))
		if role != roleAdmin && role != roleUser {
			http.Error(w, "invalid role", http.StatusBadRequest)
			return
		}
		updated, err := setUserRoleByEmail(userDB, email, role)
		if err != nil {
			http.Error(w, "failed to update role", http.StatusInternalServerError)
			return
		}
		if !updated {
			http.Error(w, "user not found", http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})

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
			ID     int    `json:"id"`
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
		if _, ok := requireAdmin(w, r); !ok {
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
		if _, ok := requireAdmin(w, r); !ok {
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
		if _, ok := requireAdmin(w, r); !ok {
			return
		}
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
