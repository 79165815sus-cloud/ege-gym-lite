#!/usr/bin/env python3
import json
import re
import sys
from pathlib import Path

VENDOR_DIR = Path(__file__).resolve().parent / "_vendor"
if VENDOR_DIR.exists():
    sys.path.insert(0, str(VENDOR_DIR))

from pypdf import PdfReader


def extract_text(pdf_path: Path) -> str:
    reader = PdfReader(str(pdf_path))
    chunks = []
    for page in reader.pages:
        text = page.extract_text() or ""
        chunks.append(text)
    raw = "\n".join(chunks)
    return raw.replace("\r\n", "\n").replace("\x0c", "\n")


SOLUTION_STARTERS = (
    "Так ",
    "Найдем",
    "Найдём",
    "Пусть",
    "Воспользуем",
    "Решим",
    "Обозначим",
    "Составим",
    "По ",
    "Тогда ",
    "Возьмем",
    "Возьмём",
    "Заметим",
    "Отметим",
)


def split_question_solution(block: str) -> tuple[str, str, str]:
    answer = ""
    answer_match = re.search(r"(?m)^\s*Ответ:\s*(.+)$", block)
    if answer_match:
        answer = answer_match.group(1).strip()
        block = block[: answer_match.start()].strip()

    lines = [line.strip() for line in block.splitlines()]
    lines = [line for line in lines if line]

    question_lines = []
    solution_lines = []
    found_solution = False

    for line in lines:
        if line.startswith("$$") or line.startswith("\\["):
            found_solution = True
        if not found_solution and line.startswith(SOLUTION_STARTERS):
            found_solution = True
        if found_solution:
            solution_lines.append(line)
        else:
            question_lines.append(line)

    if not question_lines and lines:
        question_lines = [lines[0]]
        solution_lines = lines[1:]

    question = "\n".join(question_lines).strip()
    solution = "\n".join(solution_lines).strip()
    return question, solution, answer


def parse_tasks(text: str) -> list[dict]:
    tasks = []
    matches = []

    inline_pattern = re.compile(r"(?m)^\s*(\d+)\.\s*")
    for m in inline_pattern.finditer(text):
        matches.append((int(m.group(1)), m.end()))

    lines = text.splitlines(keepends=True)
    offset = 0
    for line in lines:
        num_match = re.match(r"^\s*(\d+)\.?\s*$", line)
        if num_match:
            matches.append((int(num_match.group(1)), offset + len(line)))
        offset += len(line)

    matches = sorted({(num, pos) for num, pos in matches}, key=lambda x: x[1])
    filtered = []
    prev_pos = -1
    for target in range(1, 20):
        found = None
        for idx, (number, start) in enumerate(matches):
            if number != target or start <= prev_pos:
                continue
            end = matches[idx + 1][1] if idx + 1 < len(matches) else len(text)
            block = text[start:end].strip()
            if len(block) < 20:
                continue
            found = (number, start)
            prev_pos = start
            break
        if found:
            filtered.append(found)

    for idx, (number, start) in enumerate(filtered):
        end = filtered[idx + 1][1] if idx + 1 < len(filtered) else len(text)
        block = text[start:end].strip()
        question, solution, answer = split_question_solution(block)
        tasks.append(
            {
                "id": number,
                "question": question,
                "imageUrl": "",
                "subject": "Математика профиль",
                "examTaskNumber": number,
                "subtopic": "Пробник",
                "examType": "ЕГЭ",
                "answer": answer,
                "solution": solution,
            }
        )
    return tasks


def main() -> int:
    if len(sys.argv) < 3:
        print("Usage: pdf_to_tasks.py <input.pdf> <output.json>")
        return 1
    pdf_path = Path(sys.argv[1])
    out_path = Path(sys.argv[2])
    if not pdf_path.exists():
        print(f"PDF not found: {pdf_path}")
        return 1

    text = extract_text(pdf_path)
    tasks = parse_tasks(text)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(tasks, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {len(tasks)} tasks to {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
