package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
)

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

func load(path string) ([]Task, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var items []Task
	if err := json.Unmarshal(data, &items); err != nil {
		return nil, err
	}
	if len(items) == 0 {
		return nil, errors.New("tasks file is empty")
	}
	return items, nil
}

func save(path string, items []Task) error {
	data, err := json.MarshalIndent(items, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0o644)
}

func chemistryTheory(examTaskNumber int) string {
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
		return "Ароматика (бензол и производные).\nЭлектрофильное замещение (нитрование, галогенирование, алкилирование/ацилирование), ориентанты в упрощённом виде."
	case 24:
		return "Спирты и фенолы.\nСпирты: окисление, дегидратация, замещение OH (через HX). Фенолы: более кислотны, реакции с Br2(водн), NaOH, комплекс с FeCl3."
	case 25:
		return "Альдегиды/кетоны.\nКарбонильная группа, окисление альдегидов (реакции «серебряного зеркала», Cu(OH)2), восстановление до спиртов."
	case 26:
		return "Карбоновые кислоты и сложные эфиры.\nКислотность, взаимодействие с основаниями/металлами/карбонатами. Эстерификация (кислота + спирт ⇄ эфир + вода, H2SO4(конц))."
	case 27:
		return "Амины, аминокислоты, белки.\nАмины — основания; аминокислоты амфотерны. Пептидная связь, качественные реакции (если нужны)."
	case 28:
		return "Полимеры и пластмассы.\nПовторяющееся звено, мономер, тип реакции (полимеризация/поликонденсация). Связь между строением и свойствами."
	case 29:
		return "Задача с расчётами по растворам/массовой доле.\nИспользуй: ω = m(в-ва)/m(р-ра), c = n/V, n = m/M. Проверяй единицы (г, л, моль) и промежуточные данные."
	case 30:
		return "Расчёты по уравнению реакции.\nСоставь уравнение, найди количество вещества (n) из данных, используй стехиометрические коэффициенты. Не забывай про выход/примеси, если указаны."
	case 31:
		return "ОВР/ионные уравнения повышенной сложности.\nСначала определись со средой, уравняй электронным балансом, затем переходи к ионному/молекулярному виду. Контроль: заряды и атомы сходятся."
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

func chemistryTheorySteps(examTaskNumber int) []string {
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

func main() {
	var (
		path      = flag.String("path", "tasks.json", "path to tasks.json")
		subject   = flag.String("subject", "Химия", "subject to fill theory for")
		overwrite = flag.Bool("overwrite", false, "overwrite existing non-empty theory")
		fillSteps = flag.Bool("fill-steps", false, "also fill theorySteps for matching tasks")
		dryRun    = flag.Bool("dry-run", false, "do not write file, just print stats")
	)
	flag.Parse()

	items, err := load(*path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "load:", err)
		os.Exit(1)
	}

	subj := strings.TrimSpace(*subject)
	changed := 0
	skipped := 0
	noMapping := 0
	stepsChanged := 0

	for i := range items {
		t := &items[i]
		if strings.TrimSpace(t.Subject) != subj {
			continue
		}
		if strings.TrimSpace(t.Theory) != "" && !*overwrite {
			skipped++
		} else {
			var theory string
			if subj == "Химия" {
				theory = chemistryTheory(t.ExamTaskNumber)
			}
			theory = strings.TrimSpace(theory)
			if theory == "" {
				noMapping++
				continue
			}
			t.Theory = theory
			changed++
		}

		if *fillSteps {
			if len(t.TheorySteps) > 0 && !*overwrite {
				continue
			}
			var steps []string
			if subj == "Химия" {
				steps = chemistryTheorySteps(t.ExamTaskNumber)
			}
			if len(steps) > 0 {
				t.TheorySteps = steps
				stepsChanged++
			}
		}
	}

	fmt.Printf("subject=%q changed=%d steps_changed=%d skipped=%d no_mapping=%d total=%d\n", subj, changed, stepsChanged, skipped, noMapping, len(items))
	if *dryRun {
		return
	}
	if changed == 0 && stepsChanged == 0 {
		fmt.Println("nothing to do")
		return
	}
	if err := save(*path, items); err != nil {
		fmt.Fprintln(os.Stderr, "save:", err)
		os.Exit(1)
	}
}

