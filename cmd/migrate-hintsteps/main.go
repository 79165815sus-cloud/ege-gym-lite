package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
)

type AnswerRaw struct {
	Raw json.RawMessage
}

func (a *AnswerRaw) UnmarshalJSON(data []byte) error {
	if len(data) == 0 {
		a.Raw = nil
		return nil
	}
	a.Raw = append(a.Raw[:0], data...)
	return nil
}

func (a AnswerRaw) MarshalJSON() ([]byte, error) {
	if len(a.Raw) == 0 {
		return []byte("null"), nil
	}
	return a.Raw, nil
}

type Task struct {
	ID             int       `json:"id"`
	Question       string    `json:"question"`
	ImageURL       string    `json:"imageUrl"`
	SolutionImage  string    `json:"solutionImageUrl"`
	Subject        string    `json:"subject"`
	ExamTaskNumber int       `json:"examTaskNumber"`
	Variant        int       `json:"variant"`
	Subtopic       string    `json:"subtopic"`
	ExamType       string    `json:"examType"`
	Answer         AnswerRaw `json:"answer"`
	Solution       string    `json:"solution"`
	HintSteps      []string  `json:"hintSteps,omitempty"`
}

func normalizeSolutionText(solution string) string {
	solution = strings.ReplaceAll(solution, "\r\n", "\n")
	lines := strings.Split(solution, "\n")
	kept := make([]string, 0, len(lines))
	for _, line := range lines {
		raw := strings.TrimSpace(line)
		if raw == "" {
			kept = append(kept, "")
			continue
		}
		if strings.HasPrefix(strings.ToLower(raw), "ответ") {
			continue
		}
		kept = append(kept, line)
	}
	return strings.TrimSpace(strings.Join(kept, "\n"))
}

func splitIntoHintChunks(solution string) []string {
	solution = normalizeSolutionText(solution)
	if solution == "" {
		return nil
	}
	parts := strings.Split(solution, "\n\n")
	chunks := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		chunks = append(chunks, p)
	}
	if len(chunks) == 0 {
		return []string{solution}
	}
	if looksLikeWordChunks(chunks) {
		reflowed := reflowChunksToText(chunks)
		sentences := splitIntoSentences(reflowed)
		if len(sentences) > 0 {
			return sentences
		}
		return []string{reflowed}
	}
	return chunks
}

func looksLikeWordChunks(chunks []string) bool {
	if len(chunks) < 10 {
		return false
	}
	short := 0
	total := 0
	for _, c := range chunks {
		r := []rune(strings.TrimSpace(c))
		n := len(r)
		if n == 0 {
			continue
		}
		total++
		if n <= 18 {
			short++
		}
	}
	if total == 0 {
		return false
	}
	return short*100/total >= 55
}

func reflowChunksToText(chunks []string) string {
	var b strings.Builder
	for _, c := range chunks {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		if b.Len() > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(c)
	}
	return strings.Join(strings.Fields(b.String()), " ")
}

func splitIntoSentences(text string) []string {
	text = strings.TrimSpace(text)
	if text == "" {
		return nil
	}
	var (
		out []string
		cur strings.Builder
	)
	flush := func() {
		s := strings.TrimSpace(cur.String())
		cur.Reset()
		if s != "" {
			out = append(out, s)
		}
	}
	runes := []rune(text)
	for i := 0; i < len(runes); i++ {
		ch := runes[i]
		cur.WriteRune(ch)
		if ch != '.' && ch != '!' && ch != '?' {
			continue
		}
		if i+1 >= len(runes) {
			flush()
			continue
		}
		if runes[i+1] == ' ' || runes[i+1] == '\n' || runes[i+1] == '\t' {
			flush()
		}
	}
	flush()

	grouped := make([]string, 0, len(out))
	var buf strings.Builder
	for _, s := range out {
		if buf.Len() == 0 {
			buf.WriteString(s)
			continue
		}
		if len([]rune(buf.String())) < 140 {
			buf.WriteByte(' ')
			buf.WriteString(s)
			continue
		}
		grouped = append(grouped, strings.TrimSpace(buf.String()))
		buf.Reset()
		buf.WriteString(s)
	}
	if buf.Len() > 0 {
		grouped = append(grouped, strings.TrimSpace(buf.String()))
	}
	if len(grouped) > 12 {
		head := grouped[:11]
		tail := strings.Join(grouped[11:], " ")
		return append(head, strings.TrimSpace(tail))
	}
	return grouped
}

func deriveHintSteps(solution string) []string {
	chunks := splitIntoHintChunks(solution)
	if len(chunks) == 0 {
		return []string{"Пошаговое решение пока не добавлено."}
	}
	return chunks
}

func main() {
	var (
		tasksPath   string
		subject     string
		overwrite   bool
		dryRun      bool
		onlyExamEG  bool
	)

	flag.StringVar(&tasksPath, "tasks", "tasks.json", "path to tasks.json")
	flag.StringVar(&subject, "subject", "Математика профиль", "subject to migrate")
	flag.BoolVar(&overwrite, "overwrite", false, "overwrite existing hintSteps")
	flag.BoolVar(&dryRun, "dry-run", false, "do not write file; just print stats")
	flag.BoolVar(&onlyExamEG, "ege-only", false, "apply only to examType=ЕГЭ")
	flag.Parse()

	data, err := os.ReadFile(tasksPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "failed to read:", err)
		os.Exit(1)
	}

	var tasks []Task
	if err := json.Unmarshal(data, &tasks); err != nil {
		fmt.Fprintln(os.Stderr, "failed to parse json:", err)
		os.Exit(1)
	}

	var (
		totalSubject int
		updated      int
		skipped      int
	)

	for i := range tasks {
		if strings.TrimSpace(tasks[i].Subject) != subject {
			continue
		}
		if onlyExamEG && strings.TrimSpace(tasks[i].ExamType) != "ЕГЭ" {
			continue
		}
		totalSubject++

		if len(tasks[i].HintSteps) > 0 && !overwrite {
			skipped++
			continue
		}
		tasks[i].HintSteps = deriveHintSteps(tasks[i].Solution)
		updated++
	}

	fmt.Printf("subject=%q total=%d updated=%d skipped=%d overwrite=%v dryRun=%v egeOnly=%v\n",
		subject, totalSubject, updated, skipped, overwrite, dryRun, onlyExamEG)

	if dryRun {
		return
	}

	out, err := json.MarshalIndent(tasks, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, "failed to serialize json:", err)
		os.Exit(1)
	}
	out = append(out, '\n')
	if err := os.WriteFile(tasksPath, out, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "failed to write:", err)
		os.Exit(1)
	}
}

