package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"math/big"
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
	ID             int      `json:"id"`
	Question       string   `json:"question"`
	ImageURL       string   `json:"imageUrl"`
	SolutionImage  string   `json:"solutionImageUrl"`
	Subject        string   `json:"subject"`
	ExamTaskNumber int      `json:"examTaskNumber"`
	Variant        int      `json:"variant"`
	Subtopic       string   `json:"subtopic"`
	ExamType       string   `json:"examType"`
	Answer         Answer   `json:"answer"`
	Solution       string   `json:"solution"`
	HintSteps      []string `json:"hintSteps,omitempty"`
	Theory         string   `json:"theory,omitempty"`
	TheorySteps    []string `json:"theorySteps,omitempty"`
}

type TaskPublic struct {
	ID             int    `json:"id"`
	Question       string `json:"question"`
	ImageURL       string `json:"imageUrl"`
	Subject        string `json:"subject"`
	ExamTaskNumber int    `json:"examTaskNumber"`
	Variant        int    `json:"variant"`
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

type HintStep struct {
	Step int    `json:"step"`
	Hint string `json:"hint"`
}

type TextStep struct {
	Step int    `json:"step"`
	Text string `json:"text"`
}

func toPublic(task Task) TaskPublic {
	return TaskPublic{
		ID:             task.ID,
		Question:       task.Question,
		ImageURL:       task.ImageURL,
		Subject:        task.Subject,
		ExamTaskNumber: task.ExamTaskNumber,
		Variant:        task.Variant,
		Subtopic:       task.Subtopic,
		ExamType:       task.ExamType,
	}
}

func filterTasks(items []Task, examType, subject, subtopic string, examTaskNumber, variant *int) []Task {
	filtered := make([]Task, 0, len(items))
	for _, task := range items {
		if examType != "" && !strings.EqualFold(task.ExamType, examType) {
			continue
		}
		if subject != "" && !strings.EqualFold(task.Subject, subject) {
			continue
		}
		if variant != nil && task.Variant != *variant {
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

func buildHint(solution string) string {
	solution = strings.ReplaceAll(solution, "\r\n", "\n")
	solution = strings.TrimSpace(solution)
	if solution == "" {
		return ""
	}

	lines := strings.Split(solution, "\n")
	parts := make([]string, 0, 2)
	total := 0
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts = append(parts, line)
		total += len([]rune(line))
		if len(parts) >= 2 || total >= 140 {
			break
		}
	}

	hint := strings.TrimSpace(strings.Join(parts, "\n"))
	if hint == "" {
		return ""
	}

	const maxRunes = 280
	r := []rune(hint)
	if len(r) > maxRunes {
		hint = strings.TrimSpace(string(r[:maxRunes])) + "…"
	}
	return hint
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
	// If the solution came from PDF copy/paste, it may contain lots of "\n\n" between words.
	// Detect that and reflow into more meaningful chunks.
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
	// Heuristic: majority of chunks are tiny => likely word-wrapped.
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
	// Collapse repeated spaces.
	return strings.Join(strings.Fields(b.String()), " ")
}

func splitIntoSentences(text string) []string {
	text = strings.TrimSpace(text)
	if text == "" {
		return nil
	}
	// A lightweight sentence splitter good enough for "fallback" mode.
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
		// Split only if next char is whitespace (or end).
		if i+1 >= len(runes) {
			flush()
			continue
		}
		if runes[i+1] == ' ' || runes[i+1] == '\n' || runes[i+1] == '\t' {
			flush()
		}
	}
	flush()
	// Group very short sentences together.
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
	// Cap at 12 chunks by merging tail.
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

func chemistryTheory(examTaskNumber int) string {
	// Short “theory blocks” per exam task number (ЕГЭ).
	switch examTaskNumber {
	case 1:
		return "Классификация неорганических веществ и формулы.\nВспомни классы: оксиды/кислоты/основания/соли. Проверь валентности/заряды и коэффициенты в формулах."
	case 2:
		return "Степени окисления.\nОпредели тип соединения, расставь степени окисления по правилам (H +1, O −2, F −1, сумма = заряд)."
	case 3:
		return "Окислительно‑восстановительные реакции.\nНайди восстановитель/окислитель по изменениям степеней окисления, уравняй электронным балансом, затем коэффициенты."
	case 4:
		return "Реакции ионного обмена (сокращённое ионное уравнение).\nВыдели сильные электролиты, распиши на ионы, сократи зрителей. Условие протекания: осадок/газ/слабый электролит."
	case 5:
		return "Ряд активности металлов и вытеснение.\nМеталл активнее вытесняет менее активный из соли; H2 вытесняют металлы левее водорода. Учитывай пассивацию (Al, Cr, Fe) в конц. кислотах."
	case 6:
		return "Свойства простых веществ и их типичные реакции.\nДля неметаллов: горение, взаимодействие с металлами/водой/щёлочами (если актуально). Для металлов: с водой/кислотами/солями."
	case 7:
		return "Азот и соединения азота.\nКлючевые формы: NH3/NH4+/NO2−/NO3−, степени окисления N (−3, +3, +5). Реакции: восстановит./окислит. свойства, получение."
	case 8:
		return "Сера и соединения серы.\nСтепени окисления S (−2, 0, +4, +6). SO2/SO3, H2S/H2SO3/H2SO4: кислотные свойства, ОВР (H2S восстановитель, H2SO4(конц) окислитель)."
	case 9:
		return "Галогены и их соединения.\nОкислительные свойства F2>Cl2>Br2>I2. Вытеснение галогенов из солей; реакции с водой/щёлочами (диспропорционирование для Cl2/Br2/I2)."
	case 10:
		return "Щёлочные и щёлочноземельные металлы.\nТипичные реакции: с водой, кислородом, кислотами; растворимость оснований/солей; карбонаты/гидрокарбонаты."
	case 11:
		return "Алюминий и амфотерность.\nAl2O3 и Al(OH)3 реагируют и с кислотами, и со щёлочами (алюмінаты). Учитывай защитную плёнку и условия растворения."
	case 12:
		return "Железо и соединения Fe(II)/Fe(III).\nРазличай Fe2+ и Fe3+, характерные реакции (окисление Fe2+ до Fe3+), гидроксиды и их цвета, качественные признаки."
	case 13:
		return "Качественные реакции на ионы.\nЧастые тесты: SO4^2− (Ba2+ → BaSO4↓), CO3^2− (кислота → CO2↑), Cl− (Ag+ → AgCl↓), NH4+ (щёлочь → NH3↑), Fe3+ (SCN− → красный комплекс)."
	case 14:
		return "Растворимость и условия протекания реакций.\nПользуйся таблицей растворимости. Осадок/газ/вода/слабая кислота — признак необратимости."
	case 15:
		return "Электролитическая диссоциация и pH.\nСильные/слабые электролиты; pH для кислот/щёлочей: pH = −log[H+], pOH = −log[OH−], pH+pOH=14 (при 25°C)."
	case 16:
		return "Гидролиз солей.\nСоль слабой кислоты/основания гидролизуется. Определи среду: катион слабого основания → кислая; анион слабой кислоты → щелочная; оба слабые — сравни Ka/Kb."
	case 17:
		return "Окислительно‑восстановительные превращения в растворах.\nОпредели изменения степеней окисления, составь баланс, учти среду (кислая/щелочная), добавляй H2O/H+/OH− при уравнивании."
	case 18:
		return "Тепловые эффекты и энергетика (если встречается).\nЧитай знак ΔH, экзотермич./эндотермич. процессы. Следи за единицами и стехиометрией."
	case 19:
		return "Скорость реакции и равновесие (если встречается).\nФакторы скорости: концентрация, температура, катализатор, площадь. Смещение равновесия по Ле Шателье: давление/концентрации/температура."
	case 20:
		return "Органика: строение и изомерия.\nОпредели функциональную группу и класс, проверь валентности, типы изомерии (скелетная/позиционная/межклассовая)."
	case 21:
		return "Алканы/циклоалканы.\nРеакции: горение, замещение (галогенирование при hv), крекинг/изомеризация. Номенклатура и общая формула."
	case 22:
		return "Алкены/алкины.\nРеакции присоединения (H2, Hal2, HX, H2O), правило Марковникова (и анти‑Марковникова для пероксидного эффекта HBr), полимеризация."
	case 23:
		return "Ароматика (бензол и производные).\nЭлектрофильное замещение (нитрование, галогенирование, алкилирование/ацилирование), ориентанты (−I/+M и т.п.) в упрощённом виде."
	case 24:
		return "Спирты и фенолы.\nСпирты: окисление, дегидратация, замещение OH (через HX). Фенолы: более кислотны, реакции с Br2(водн), NaOH, комплекс с FeCl3."
	case 25:
		return "Альдегиды/кетоны.\nКарбонильная группа, окисление альдегидов (реакции «серебряного зеркала», Cu(OH)2), восстановление до спиртов."
	case 26:
		return "Карбоновые кислоты и сложные эфиры.\nКислотность, взаимодействие с основаниями/металлами/карбонатами. Эстерификация (кислота + спирт ⇄ эфир + вода, H2SO4(конц))."
	case 27:
		return "Амины, аминокислоты, белки.\nАмины — основания; аминокислоты амфотерны. Пептидная связь, качественные реакции (биуретовая и др., если нужны)."
	case 28:
		return "Полимеры и пластмассы.\nПовторяющееся звено, мономер, тип реакции (полимеризация/поликонденсация). Связь между строением и свойствами."
	case 29:
		return "Задача с расчётами по растворам/массовой доле.\nИспользуй: ω = m(в-ва)/m(р-ра), c = n/V, n = m/M. Проверяй единицы (г, л, моль) и промежуточные данные."
	case 30:
		return "Расчёты по уравнению реакции.\nСоставь уравнение, найди количество вещества (n) из данных, используй стехиометрические коэффициенты. Не забывай про выход/примеси, если указаны."
	case 31:
		return "ОВР/ионные уравнения повышенной сложности.\nСначала определись с средой, уравняй электронным балансом, затем переходи к ионному/молекулярному виду. Контроль: заряды и атомы сходятся."
	case 32:
		return "Цепочки превращений (неорганика + органика).\nОпредели классы веществ на каждом шаге, подбери типичные реагенты. Проверяй условия: катализатор, нагрев, среда, избыток."
	case 33:
		return "Экспериментальная задача/качественный анализ.\nОтталкивайся от наблюдений: цвет осадка/раствора, газ, растворимость. План: гипотеза → реактив → ожидаемый признак."
	case 34:
		return "Комплексная расчётно‑логическая задача.\nРазбей на этапы, введи переменные, составь уравнения/балансы, последовательно подставляй. В конце проверь смысл результата (диапазоны, единицы)."
	default:
		return ""
	}
}

func defaultTheory(task Task) string {
	if strings.TrimSpace(task.Subject) != "Химия" {
		return ""
	}
	// Can be overridden per-task via task.Theory.
	return chemistryTheory(task.ExamTaskNumber)
}

func chemistryTheorySteps(examTaskNumber int) []string {
	// Build 3 steps from the existing single-block theory text.
	raw := strings.TrimSpace(chemistryTheory(examTaskNumber))
	if raw == "" {
		return nil
	}
	raw = strings.ReplaceAll(raw, "\r\n", "\n")
	title := raw
	rest := ""
	if idx := strings.Index(raw, "\n"); idx >= 0 {
		title = strings.TrimSpace(raw[:idx])
		rest = strings.TrimSpace(raw[idx+1:])
	}
	if rest == "" {
		rest = title
	}
	check := "Проверь себя: что именно просят; где типичные ошибки; всё ли сошлось по зарядам/коэффициентам/единицам."
	if examTaskNumber >= 29 {
		check = "Проверь себя: выписаны данные, единицы приведены, формулы подписаны, стехиометрия по коэффициентам верная."
	}
	if examTaskNumber >= 20 && examTaskNumber <= 28 {
		check = "Проверь себя: класс вещества определён верно, функциональная группа на месте, условия реакции и продукты согласованы."
	}
	out := []string{title, rest, check}
	normalized := make([]string, 0, 3)
	for _, s := range out {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		normalized = append(normalized, s)
	}
	return normalized
}

func splitTheoryTextToSteps(theory string) []string {
	theory = strings.TrimSpace(strings.ReplaceAll(theory, "\r\n", "\n"))
	if theory == "" {
		return nil
	}
	// Prefer explicit delimiter if present.
	if strings.Contains(theory, "\n---\n") {
		parts := strings.Split(theory, "\n---\n")
		out := make([]string, 0, len(parts))
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			out = append(out, p)
		}
		return out
	}
	// Otherwise split by non-empty lines.
	lines := strings.Split(theory, "\n")
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		out = append(out, line)
	}
	if len(out) == 0 {
		return []string{theory}
	}
	return out
}

func buildTheorySteps(task Task) []TextStep {
	// Highest priority: explicit theorySteps in DB.
	if len(task.TheorySteps) > 0 {
		out := make([]TextStep, 0, len(task.TheorySteps))
		for i, s := range task.TheorySteps {
			s = strings.TrimSpace(strings.ReplaceAll(s, "\r\n", "\n"))
			if s == "" {
				continue
			}
			out = append(out, TextStep{Step: i + 1, Text: s})
		}
		if len(out) > 0 {
			return out
		}
	}

	// Next: derive from theory text (task.Theory or default).
	theory := strings.TrimSpace(task.Theory)
	if theory == "" {
		theory = defaultTheory(task)
	}
	steps := splitTheoryTextToSteps(theory)
	if len(steps) == 0 && strings.TrimSpace(task.Subject) == "Химия" {
		steps = chemistryTheorySteps(task.ExamTaskNumber)
	}
	if len(steps) == 0 {
		return []TextStep{{Step: 1, Text: "Теория пока не добавлена."}}
	}
	out := make([]TextStep, 0, len(steps))
	for i, s := range steps {
		out = append(out, TextStep{Step: i + 1, Text: s})
	}
	return out
}

func ensureHintSteps(task *Task) bool {
	if task == nil {
		return false
	}
	// If steps are present (even empty strings), assume it's intentional and keep them.
	if len(task.HintSteps) > 0 {
		return false
	}
	if steps, ok := generateHintStepsWithAI(*task); ok {
		task.HintSteps = steps
		return true
	}
	task.HintSteps = deriveHintSteps(task.Solution)
	return true
}

func aiStepsServiceURL() string {
	raw := strings.TrimSpace(os.Getenv("AI_STEPS_SERVICE_URL"))
	if raw == "" {
		return ""
	}
	return strings.TrimRight(raw, "/")
}

func generateHintStepsWithAISvc(task Task) ([]string, bool) {
	base := aiStepsServiceURL()
	if base == "" {
		return nil, false
	}

	payload := map[string]interface{}{
		"task": map[string]interface{}{
			"id":             task.ID,
			"subject":        task.Subject,
			"examType":       task.ExamType,
			"examTaskNumber": task.ExamTaskNumber,
			"question":       task.Question,
		},
		"solution": task.Solution,
		"policy": map[string]interface{}{
			"language":        "ru",
			"maxSteps":        12,
			"noFinalAnswer":   true,
			"keepMathLatex":   true,
			"preferShortStep": false,
		},
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return nil, false
	}

	client := &http.Client{Timeout: 25 * time.Second}
	req, err := http.NewRequest(http.MethodPost, base+"/v1/steps/generate", bytes.NewReader(data))
	if err != nil {
		return nil, false
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, false
	}

	var parsed struct {
		HintSteps []string `json:"hintSteps"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, false
	}
	out := make([]string, 0, len(parsed.HintSteps))
	for _, s := range parsed.HintSteps {
		s = strings.TrimSpace(strings.ReplaceAll(s, "\r\n", "\n"))
		if s == "" {
			continue
		}
		if strings.HasPrefix(strings.ToLower(s), "ответ") {
			continue
		}
		out = append(out, s)
	}
	if len(out) == 0 {
		return nil, false
	}
	return out, true
}

func openAIBaseURL() string {
	raw := strings.TrimSpace(os.Getenv("OPENAI_BASE_URL"))
	if raw == "" {
		raw = "https://api.openai.com/v1"
	}
	return strings.TrimRight(raw, "/")
}

func openAIModel() string {
	raw := strings.TrimSpace(os.Getenv("OPENAI_MODEL"))
	if raw == "" {
		raw = "gpt-4o-mini"
	}
	return raw
}

func openAIKey() string {
	return strings.TrimSpace(os.Getenv("OPENAI_API_KEY"))
}

func aiHintsEnabled() bool {
	raw := strings.TrimSpace(os.Getenv("AI_HINTS_ENABLED"))
	if raw == "" {
		return openAIKey() != "" || aiStepsServiceURL() != ""
	}
	return raw == "1" || strings.EqualFold(raw, "true") || strings.EqualFold(raw, "yes")
}

func buildOpenAIPrompt(task Task, maxSteps int, noFinalAnswer bool) (string, string) {
	if maxSteps <= 0 {
		maxSteps = 12
	}
	noAnswer := "Можно довести до финального ответа."
	if noFinalAnswer {
		noAnswer = "Не пиши строку «Ответ: …» и не раскрывай финальный числовой/текстовый ответ."
	}
	system := strings.TrimSpace(fmt.Sprintf(`Ты — сервис, который превращает школьную задачу в понятные шаги решения.
Верни ТОЛЬКО валидный JSON по схеме:
{"hintSteps":["...","..."]}

Требования:
- Язык: русский
- Не добавляй «контекст», не задавай вопросы, не добавляй чек-листы.
- Каждый элемент hintSteps — это текст одного шага решения.
- Максимум шагов: %d (если нужно — объединяй).
- %s
- Допускается LaTeX (как в исходнике).
`, maxSteps, noAnswer))

	user := strings.TrimSpace(fmt.Sprintf("Задача:\n%s\n\nРешение (для опоры):\n%s\n",
		strings.TrimSpace(task.Question),
		strings.TrimSpace(task.Solution),
	))
	return system, user
}

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

func generateHintStepsWithOpenAI(task Task) ([]string, bool) {
	if openAIKey() == "" {
		return nil, false
	}
	if strings.TrimSpace(task.Question) == "" {
		return nil, false
	}

	system, user := buildOpenAIPrompt(task, 12, true)
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
		return nil, false
	}

	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequest(http.MethodPost, openAIBaseURL()+"/chat/completions", bytes.NewReader(data))
	if err != nil {
		return nil, false
	}
	req.Header.Set("Authorization", "Bearer "+openAIKey())
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, false
	}

	var parsed openAIChatResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, false
	}
	if len(parsed.Choices) == 0 {
		return nil, false
	}
	content := strings.TrimSpace(parsed.Choices[0].Message.Content)
	if content == "" {
		return nil, false
	}

	var out struct {
		HintSteps []string `json:"hintSteps"`
	}
	if err := json.Unmarshal([]byte(content), &out); err != nil {
		start := strings.Index(content, "{")
		end := strings.LastIndex(content, "}")
		if start >= 0 && end > start {
			if err2 := json.Unmarshal([]byte(content[start:end+1]), &out); err2 != nil {
				return nil, false
			}
		} else {
			return nil, false
		}
	}

	normalized := make([]string, 0, len(out.HintSteps))
	for _, s := range out.HintSteps {
		s = strings.TrimSpace(strings.ReplaceAll(s, "\r\n", "\n"))
		if s == "" {
			continue
		}
		if strings.HasPrefix(strings.ToLower(s), "ответ") {
			continue
		}
		normalized = append(normalized, s)
	}
	if len(normalized) == 0 {
		return nil, false
	}
	return normalized, true
}

func generateHintStepsWithAI(task Task) ([]string, bool) {
	if !aiHintsEnabled() {
		return nil, false
	}
	// Prefer local AI microservice if configured, otherwise call OpenAI directly.
	if steps, ok := generateHintStepsWithAISvc(task); ok {
		return steps, true
	}
	if steps, ok := generateHintStepsWithOpenAI(task); ok {
		return steps, true
	}
	return nil, false
}

func adminToken() string {
	return strings.TrimSpace(os.Getenv("ADMIN_TOKEN"))
}

func requireAdmin(w http.ResponseWriter, r *http.Request) bool {
	token := adminToken()
	if token == "" {
		http.Error(w, "admin token is not configured", http.StatusForbidden)
		return false
	}
	got := strings.TrimSpace(r.Header.Get("X-Admin-Token"))
	if got == "" {
		got = strings.TrimSpace(r.URL.Query().Get("token"))
	}
	if got != token {
		http.Error(w, "forbidden", http.StatusForbidden)
		return false
	}
	return true
}

type BackfillJob struct {
	ID         string    `json:"id"`
	Status     string    `json:"status"` // running|done|failed
	StartedAt  time.Time `json:"startedAt"`
	FinishedAt time.Time `json:"finishedAt,omitempty"`
	Total      int       `json:"total"`
	Updated    int       `json:"updated"`
	Skipped    int       `json:"skipped"`
	Failed     int       `json:"failed"`
	LastError  string    `json:"lastError,omitempty"`
}

var backfillMu sync.Mutex
var backfillJobs = map[string]*BackfillJob{}

func newJobID() string {
	// short-ish ID without external deps
	n := big.NewInt(time.Now().UnixNano())
	return fmt.Sprintf("job-%s-%d", n.Text(36), rand.Intn(10000))
}

func buildHintSteps(task Task) []HintStep {
	if len(task.HintSteps) > 0 {
		out := make([]HintStep, 0, len(task.HintSteps))
		for i, s := range task.HintSteps {
			s = strings.TrimSpace(s)
			if s == "" {
				continue
			}
			out = append(out, HintStep{Step: i + 1, Hint: s})
		}
		if len(out) > 0 {
			return out
		}
	}

	chunks := splitIntoHintChunks(task.Solution)
	if len(chunks) == 0 {
		return []HintStep{{Step: 1, Hint: "Нет текста решения для подсказки."}}
	}
	out := make([]HintStep, 0, len(chunks))
	for i, c := range chunks {
		out = append(out, HintStep{Step: i + 1, Hint: c})
	}
	return out
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

	// Optional autogeneration on start (disabled by default on prod).
	if strings.TrimSpace(os.Getenv("AUTO_HINTS_ON_START")) == "1" {
		changed := false
		for i := range loadedTasks {
			if ensureHintSteps(&loadedTasks[i]) {
				changed = true
			}
		}
		if changed {
			if err := saveTasks(tasksPath, loadedTasks); err != nil {
				log.Printf("failed to persist generated hintSteps: %v", err)
			}
		}
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

		var variant *int
		if rawVariant := strings.TrimSpace(query.Get("variant")); rawVariant != "" {
			parsed, err := strconv.Atoi(rawVariant)
			if err != nil {
				http.Error(w, "bad variant", http.StatusBadRequest)
				return
			}
			variant = &parsed
		}

		available := filterTasks(tasks, examType, subject, subtopic, examTaskNumber, variant)
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
			"solution":         task.Solution,
			"solutionImageUrl": task.SolutionImage,
		})
	})

	// API: показать теорию (опорный блок)
	http.HandleFunc("/api/theory", func(w http.ResponseWriter, r *http.Request) {
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

		theory := strings.TrimSpace(task.Theory)
		if theory == "" && len(task.TheorySteps) > 0 {
			parts := make([]string, 0, len(task.TheorySteps))
			for _, s := range task.TheorySteps {
				s = strings.TrimSpace(strings.ReplaceAll(s, "\r\n", "\n"))
				if s == "" {
					continue
				}
				parts = append(parts, s)
			}
			theory = strings.TrimSpace(strings.Join(parts, "\n\n"))
		}
		if theory == "" {
			theory = defaultTheory(task)
		}
		json.NewEncoder(w).Encode(map[string]string{
			"theory": theory,
		})
	})

	// API: теория по шагам (для UI "дальше")
	http.HandleFunc("/api/theory-steps", func(w http.ResponseWriter, r *http.Request) {
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
		if req.ID <= 0 {
			http.Error(w, "id required", http.StatusBadRequest)
			return
		}

		tasksMu.Lock()
		task, ok := findTask(req.ID)
		tasksMu.Unlock()
		if !ok {
			http.Error(w, "task not found", http.StatusNotFound)
			return
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"taskId": task.ID,
			"steps":  buildTheorySteps(task),
		})
	})

	// API: подсказка (короткий фрагмент решения)
	http.HandleFunc("/api/hint", func(w http.ResponseWriter, r *http.Request) {
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

		steps := buildHintSteps(task)
		if len(steps) == 0 || strings.TrimSpace(steps[0].Hint) == "" {
			json.NewEncoder(w).Encode(map[string]string{"hint": ""})
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"hint": steps[0].Hint})
	})

	// API: ступенчатые подсказки (для UI "дальше")
	http.HandleFunc("/api/hints", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req struct {
			ID    int   `json:"id"`
			Steps []int `json:"steps,omitempty"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if req.ID <= 0 {
			http.Error(w, "id required", http.StatusBadRequest)
			return
		}

		tasksMu.Lock()
		task, ok := findTask(req.ID)
		tasksMu.Unlock()
		if !ok {
			http.Error(w, "task not found", http.StatusNotFound)
			return
		}

		_ = req.Steps // reserved for future (client may send preferred steps)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"taskId": task.ID,
			"steps":  buildHintSteps(task),
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

		var variant *int
		if rawVariant := strings.TrimSpace(query.Get("variant")); rawVariant != "" {
			parsed, err := strconv.Atoi(rawVariant)
			if err != nil {
				http.Error(w, "bad variant", http.StatusBadRequest)
				return
			}
			variant = &parsed
		}

		tasksMu.Lock()
		available := filterTasks(tasks, examType, subject, subtopic, examTaskNumber, variant)
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

			// If hintSteps were not provided, autogenerate from solution.
			for i := range payload {
				ensureHintSteps(&payload[i])
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

	// Admin: backfill hintSteps via AI in background
	http.HandleFunc("/api/admin/backfill-hintsteps", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			if !requireAdmin(w, r) {
				return
			}
			id := strings.TrimSpace(r.URL.Query().Get("id"))
			if id == "" {
				http.Error(w, "id required", http.StatusBadRequest)
				return
			}
			backfillMu.Lock()
			job := backfillJobs[id]
			backfillMu.Unlock()
			if job == nil {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			json.NewEncoder(w).Encode(job)
			return
		}

		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !requireAdmin(w, r) {
			return
		}

		var req struct {
			Subject     string `json:"subject,omitempty"`
			OnlyMissing bool   `json:"onlyMissing,omitempty"`
			Overwrite   bool   `json:"overwrite,omitempty"`
			MaxTasks    int    `json:"maxTasks,omitempty"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if req.MaxTasks <= 0 {
			req.MaxTasks = 50
		}
		// Empty or "*" subject means "all subjects".
		subjectFilter := strings.TrimSpace(req.Subject)
		if subjectFilter == "*" {
			subjectFilter = ""
		}

		if openAIKey() == "" && aiStepsServiceURL() == "" {
			http.Error(w, "AI is not configured (set OPENAI_API_KEY or AI_STEPS_SERVICE_URL)", http.StatusBadRequest)
			return
		}

		job := &BackfillJob{
			ID:        newJobID(),
			Status:    "running",
			StartedAt: time.Now(),
		}
		backfillMu.Lock()
		backfillJobs[job.ID] = job
		backfillMu.Unlock()

		go func() {
			defer func() {
				backfillMu.Lock()
				if job.Status == "running" {
					job.Status = "done"
				}
				job.FinishedAt = time.Now()
				backfillMu.Unlock()
			}()

			updated := 0
			skipped := 0
			failed := 0
			total := 0

			tasksMu.Lock()
			local := make([]Task, len(tasks))
			copy(local, tasks)
			tasksMu.Unlock()

			for i := range local {
				t := &local[i]
				if subjectFilter != "" && strings.TrimSpace(t.Subject) != subjectFilter {
					continue
				}
				total++

				if req.OnlyMissing && len(t.HintSteps) > 0 {
					skipped++
					continue
				}
				if !req.Overwrite && len(t.HintSteps) > 0 {
					skipped++
					continue
				}
				if updated+failed >= req.MaxTasks {
					break
				}

				steps, ok := generateHintStepsWithAI(*t)
				if !ok {
					failed++
					backfillMu.Lock()
					job.LastError = fmt.Sprintf("failed to generate for task id=%d", t.ID)
					backfillMu.Unlock()
					continue
				}
				t.HintSteps = steps
				updated++

				backfillMu.Lock()
				job.Total = total
				job.Updated = updated
				job.Skipped = skipped
				job.Failed = failed
				backfillMu.Unlock()
			}

			backfillMu.Lock()
			job.Total = total
			job.Updated = updated
			job.Skipped = skipped
			job.Failed = failed
			backfillMu.Unlock()

			// Persist and swap in-memory tasks.
			if err := saveTasks(tasksPath, local); err != nil {
				backfillMu.Lock()
				job.Status = "failed"
				job.LastError = "failed to save tasks.json"
				backfillMu.Unlock()
				return
			}
			tasksMu.Lock()
			tasks = local
			tasksMu.Unlock()
		}()

		json.NewEncoder(w).Encode(map[string]string{"jobId": job.ID})
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
