package redact

import (
	"regexp"
	"strings"
)

var alias = regexp.MustCompile(`\bid_[0-9]+\b`)

// Restore is local-only: no reverse dictionary is serialized into the prompt.
func (a Context) Restore(s string) string {
	reverse := make(map[string]string, len(a))
	for name, id := range a {
		reverse[id] = name
	}
	return alias.ReplaceAllStringFunc(s, func(id string) string {
		if name, ok := reverse[id]; ok {
			return name
		}
		return id
	})
}

// RestoreSQL substitutes identifier tokens, never values or comments. It keeps
// the model's literals unchanged; original literal values are never reconstructed.
func (a Context) RestoreSQL(s string) string {
	reverse := make(map[string]string, len(a))
	for name, id := range a {
		reverse[id] = name
	}
	var out strings.Builder
	for i := 0; i < len(s); {
		if s[i] == '\'' {
			j := i + 1
			for j < len(s) {
				if s[j] == '\\' {
					return s
				}
				if s[j] == '\'' {
					if j+1 < len(s) && s[j+1] == '\'' {
						j += 2
						continue
					}
					j++
					break
				}
				j++
			}
			if j == len(s) && s[j-1] != '\'' {
				return s
			}
			out.WriteString(s[i:j])
			i = j
			continue
		}
		if strings.HasPrefix(s[i:], "--") || strings.HasPrefix(s[i:], "/*") || s[i] == '$' {
			// Model SQL with ambiguous quoting is left as a template. Raw local SQL
			// is available separately in the attached evidence.
			return s
		}
		if s[i] == '"' {
			j := i + 1
			for j < len(s) && s[j] != '"' {
				j++
			}
			if j == len(s) {
				return s
			}
			if name, ok := reverse[s[i+1:j]]; ok {
				out.WriteString(`"` + strings.ReplaceAll(name, `"`, `""`) + `"`)
			} else {
				out.WriteString(s[i : j+1])
			}
			i = j + 1
			continue
		}
		if loc := alias.FindStringIndex(s[i:]); loc != nil && loc[0] == 0 && (i == 0 || !identifierByte(s[i-1])) {
			id := s[i : i+loc[1]]
			if name, ok := reverse[id]; ok {
				out.WriteString(`"` + strings.ReplaceAll(name, `"`, `""`) + `"`)
			} else {
				out.WriteString(id)
			}
			i += loc[1]
			continue
		}
		out.WriteByte(s[i])
		i++
	}
	return out.String()
}

func identifierByte(b byte) bool {
	return b == '_' || b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || b >= 128
}
