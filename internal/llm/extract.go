package llm

import (
	"encoding/json"
	"errors"
	"strings"
)

const (
	thinkOpen  = "<think>"
	thinkClose = "</think>"
)

func SplitThink(content string) (answer, thought string) {
	var thoughts []string
	for {
		open := strings.Index(content, thinkOpen)
		if open < 0 {
			break
		}
		rest := content[open+len(thinkOpen):]
		end := strings.Index(rest, thinkClose)
		if end < 0 {
			thoughts = append(thoughts, rest)
			content = content[:open]
			break
		}
		thoughts = append(thoughts, rest[:end])
		content = content[:open] + rest[end+len(thinkClose):]
	}
	if close := strings.Index(content, thinkClose); close >= 0 && !strings.Contains(content[:close], "{") {
		thoughts = append(thoughts, content[:close])
		content = content[close+len(thinkClose):]
	}
	return strings.TrimSpace(content), strings.TrimSpace(strings.Join(thoughts, "\n"))
}

var ErrNoJSON = errors.New("no JSON object in the model answer")

func ExtractJSON(content string) ([]byte, error) {
	answer, _ := SplitThink(content)
	var candidates [][]byte
	for i := 0; i < len(answer); i++ {
		if answer[i] != '{' {
			continue
		}
		end := matchBrace(answer, i)
		if end < 0 {
			continue
		}
		obj := []byte(answer[i : end+1])
		if json.Valid(obj) {
			candidates = append(candidates, obj)
			i = end
		}
	}
	if len(candidates) == 0 {
		return nil, ErrNoJSON
	}
	best := candidates[0]
	for _, c := range candidates[1:] {
		if len(c) > len(best) {
			best = c
		}
	}
	return best, nil
}

func matchBrace(s string, start int) int {
	depth := 0
	inString, escaped := false, false
	for i := start; i < len(s); i++ {
		ch := s[i]
		switch {
		case inString && escaped:
			escaped = false
		case inString && ch == '\\':
			escaped = true
		case inString && ch == '"':
			inString = false
		case inString:
		case ch == '"':
			inString = true
		case ch == '{':
			depth++
		case ch == '}':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}
