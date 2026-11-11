package sqltext

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

const (
	MaxLength = 1500
	Truncated = " …"
)

var (
	placeholder    = regexp.MustCompile(`\$(\d+)`)
	safeIdentifier = regexp.MustCompile(`^[A-Za-z0-9_ .$-]{1,63}$`)
	typedLiteral   = map[string]bool{"interval": true, "date": true, "time": true, "timestamp": true, "timestamptz": true}
	modifiedType   = map[string]bool{"numeric": true, "decimal": true, "varchar": true, "char": true, "character": true, "varying": true,
		"bit": true, "varbit": true, "time": true, "timestamp": true, "timestamptz": true, "interval": true, "float": true}
	listEnd = map[string]bool{"limit": true, "offset": true, "having": true, "fetch": true, "for": true, "union": true,
		"intersect": true, "except": true, "window": true, "returning": true}
)

type normalizer struct {
	src         []rune
	i           int
	out         strings.Builder
	space       bool
	next        int
	last        string
	depth       int
	ordinals    int
	modifiers   int
	backslashes bool
}

func Normalize(sql string) string {
	standard, escaped := normalize(sql, false), normalize(sql, true)
	if standard != escaped {
		return ""
	}
	return standard
}

func normalize(sql string, backslashes bool) string {
	n := &normalizer{src: []rune(sql), next: 1, backslashes: backslashes}
	for _, m := range placeholder.FindAllStringSubmatch(sql, -1) {
		if v, err := strconv.Atoi(m[1]); err == nil && v >= n.next {
			n.next = v + 1
		}
	}
	n.run()
	text := strings.TrimSpace(n.out.String())
	if r := []rune(text); len(r) > MaxLength {
		text = string(r[:MaxLength]) + Truncated
	}
	return text
}

func Explainable(text string) bool {
	fields := strings.Fields(text)
	if len(fields) == 0 || strings.HasSuffix(text, Truncated) || strings.Contains(strings.TrimSuffix(text, ";"), ";") {
		return false
	}
	first := strings.ToLower(strings.TrimLeft(fields[0], "("))
	return first == "select" || first == "with" || first == "values" || first == "table"
}

func (n *normalizer) peek(k int) rune {
	if n.i+k < len(n.src) {
		return n.src[n.i+k]
	}
	return 0
}

func (n *normalizer) emit(token, kind string) {
	if n.space && n.out.Len() > 0 {
		n.out.WriteByte(' ')
	}
	n.space = false
	n.out.WriteString(token)
	n.last = kind
}

func (n *normalizer) literal(cast string) {
	token := fmt.Sprintf("$%d", n.next)
	n.next++
	if cast != "" {
		token += "::" + cast
	}
	n.emit(token, "$")
}

func (n *normalizer) run() {
	for n.i < len(n.src) {
		c := n.src[n.i]
		switch {
		case unicode.IsSpace(c):
			n.space = true
			n.i++
		case c == '-' && n.peek(1) == '-':
			for n.i < len(n.src) && n.src[n.i] != '\n' && n.src[n.i] != '\r' {
				n.i++
			}
			n.space = true
		case c == '/' && n.peek(1) == '*':
			n.comment()
		case c == '\'':
			n.quoted(n.backslashes)
			n.literal("")
		case c == '"':
			n.identifier()
		case c == '$':
			n.dollar("")
		case unicode.IsDigit(c) || c == '.' && unicode.IsDigit(n.peek(1)):
			n.number()
		case unicode.IsLetter(c) || c == '_':
			n.word()
		default:
			n.symbol(c)
		}
	}
}

func (n *normalizer) comment() {
	depth := 0
	for n.i < len(n.src) {
		switch {
		case n.src[n.i] == '/' && n.peek(1) == '*':
			depth++
			n.i += 2
		case n.src[n.i] == '*' && n.peek(1) == '/':
			depth--
			n.i += 2
			if depth == 0 {
				n.space = true
				return
			}
		default:
			n.i++
		}
	}
	n.space = true
}

func (n *normalizer) quoted(backslash bool) {
	n.i++
	for n.i < len(n.src) {
		c := n.src[n.i]
		switch {
		case backslash && c == '\\':
			n.i += 2
		case c == '\'' && n.peek(1) == '\'':
			n.i += 2
		case c == '\'':
			n.i++
			return
		default:
			n.i++
		}
	}
}

func (n *normalizer) identifier() {
	start := n.i
	n.i++
	var name strings.Builder
	for n.i < len(n.src) {
		c := n.src[n.i]
		if c == '"' && n.peek(1) == '"' {
			name.WriteRune(c)
			n.i += 2
			continue
		}
		n.i++
		if c == '"' {
			break
		}
		name.WriteRune(c)
	}
	if n.i-start >= 2 && n.src[n.i-1] == '"' && safeIdentifier.MatchString(name.String()) {
		n.emit(`"`+name.String()+`"`, "ident")
	} else {
		n.emit(`"identifier"`, "ident")
	}
}

func (n *normalizer) dollar(cast string) {
	j := n.i + 1
	for j < len(n.src) && unicode.IsDigit(n.src[j]) {
		j++
	}
	if j > n.i+1 {
		token := string(n.src[n.i:j])
		n.i = j
		if cast != "" {
			token += "::" + cast
		}
		n.emit(token, "$")
		return
	}
	j = n.i + 1
	for j < len(n.src) && (unicode.IsLetter(n.src[j]) || unicode.IsDigit(n.src[j]) || n.src[j] == '_') {
		j++
	}
	if j >= len(n.src) || n.src[j] != '$' {
		n.symbol('$')
		return
	}
	tag := string(n.src[n.i : j+1])
	rest := string(n.src[j+1:])
	if end := strings.Index(rest, tag); end >= 0 {
		n.i = j + 1 + len([]rune(rest[:end])) + len([]rune(tag))
	} else {
		n.i = len(n.src)
	}
	n.literal(cast)
}

func (n *normalizer) number() {
	start := n.i
	for n.i < len(n.src) {
		c := n.src[n.i]
		if !unicode.IsDigit(c) && !unicode.IsLetter(c) && c != '_' && c != '.' {
			break
		}
		n.i++
		if (c == 'e' || c == 'E') && (n.peek(0) == '+' || n.peek(0) == '-') && unicode.IsDigit(n.peek(1)) {
			n.i++
		}
	}
	digits := string(n.src[start:n.i])
	small := len(digits) <= 4 && strings.Trim(digits, "0123456789") == ""
	listed := n.modifiers > 0 || n.ordinals == n.depth+1 && (n.last == "by" || n.last == ",")
	if small && listed && n.standsAlone() {
		n.emit(digits, "0")
		return
	}
	n.literal("")
}

func (n *normalizer) standsAlone() bool {
	j := n.i
	for j < len(n.src) && unicode.IsSpace(n.src[j]) {
		j++
	}
	return j == len(n.src) || strings.ContainsRune(",);", n.src[j]) || unicode.IsLetter(n.src[j])
}

func (n *normalizer) word() {
	start := n.i
	for n.i < len(n.src) && (unicode.IsLetter(n.src[n.i]) || unicode.IsDigit(n.src[n.i]) || n.src[n.i] == '_' || n.src[n.i] == '$') {
		n.i++
	}
	w := string(n.src[start:n.i])
	lower := strings.ToLower(w)
	switch {
	case lower == "e" && n.peek(0) == '\'':
		n.quoted(true)
		n.literal("")
		return
	case (lower == "b" || lower == "x" || lower == "n") && n.peek(0) == '\'':
		n.quoted(lower == "n" && n.backslashes)
		n.literal("")
		return
	case lower == "u" && n.peek(0) == '&' && n.peek(1) == '\'':
		n.i++
		n.quoted(false)
		n.literal("")
		return
	case typedLiteral[lower]:
		j := n.i
		for j < len(n.src) && unicode.IsSpace(n.src[j]) {
			j++
		}
		if j < len(n.src) && (n.src[j] == '\'' || n.src[j] == '$' && j+1 < len(n.src) && unicode.IsDigit(n.src[j+1])) {
			n.i = j
			if n.src[j] == '\'' {
				n.quoted(n.backslashes)
				n.literal(lower)
			} else {
				n.dollar(lower)
			}
			return
		}
	}
	if lower == "by" && (n.last == "order" || n.last == "group") {
		n.ordinals = n.depth + 1
	} else if listEnd[lower] && n.ordinals == n.depth+1 {
		n.ordinals = 0
	}
	n.emit(w, lower)
}

func (n *normalizer) symbol(c rune) {
	n.i++
	switch c {
	case '(':
		if n.modifiers > 0 || modifiedType[n.last] && !n.space {
			n.modifiers++
		}
		n.depth++
	case ')':
		if n.modifiers > 0 {
			n.modifiers--
		}
		if n.ordinals > n.depth {
			n.ordinals = 0
		}
		n.depth = max(0, n.depth-1)
	case ';':
		n.ordinals = 0
	}
	n.emit(string(c), string(c))
}
