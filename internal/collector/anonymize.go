package collector

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// One dictionary per investigation keeps SQL, plan and catalog names aligned.
// Neither the dictionary nor original text leaves the collector.
type anonymizer map[string]string

func (a anonymizer) name(s string) string {
	if v, ok := a[s]; ok {
		return v
	}
	v := fmt.Sprintf("id_%d", len(a)+1)
	a[s] = v
	return v
}

const sqlWords = " select from where join inner outer left right full cross natural on using as and or not null true false is distinct all any some exists in between like ilike escape case when then else end with recursive union intersect except order by group having limit offset fetch first next rows row only asc desc nulls last over partition range preceding following current unbounded filter within lateral materialized values insert into update set delete returning conflict do nothing for of skip locked nowait cast collate window grouping sets rollup cube variadic both leading trailing placing extract interval at time zone array table tablesample repeatable integer bigint smallint int int2 int4 int8 numeric decimal real float float4 float8 double precision boolean bool text varchar character varying char date timestamp timestamptz timetz without json jsonb uuid bytea oid record void count sum avg min max coalesce nullif greatest least abs round ceil floor length lower upper substring trim btrim ltrim rtrim concat concat_ws replace split_part md5 now date_trunc date_part generate_series unnest pg_sleep pg_catalog btree hash gist gin spgist brin unique primary key references check constraint exclude include match simple partial cascade restrict action deferrable initially deferred immediate no valid nulls respect ignore "

// Lex SQL rather than applying regexes: comments, escaped strings, quoted names
// and dollar quotes can all contain secrets and SQL-looking text.
func (a anonymizer) sql(s string) (string, error) {
	return a.tokens(s, true)
}

func (a anonymizer) tokens(s string, redactNumbers bool) (string, error) {
	if !utf8.ValidString(s) || len(s) > 64*1024 {
		return "", fmt.Errorf("unsupported_sql")
	}
	var out []string
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case strings.ContainsRune(" \r\n\t\f", rune(c)):
			i++
		case strings.HasPrefix(s[i:], "--"):
			for i < len(s) && s[i] != '\n' {
				i++
			}
		case strings.HasPrefix(s[i:], "/*"):
			i += 2
			depth := 1
			for i < len(s) && depth > 0 {
				if strings.HasPrefix(s[i:], "/*") {
					depth++
					i += 2
				} else if strings.HasPrefix(s[i:], "*/") {
					depth--
					i += 2
				} else {
					i++
				}
			}
			if depth != 0 {
				return "", fmt.Errorf("unsupported_sql")
			}
		case c == '\'' || c == '"':
			i++
			var value strings.Builder
			closed := false
			for i < len(s) {
				if s[i] == c {
					if i+1 < len(s) && s[i+1] == c {
						value.WriteByte(c)
						i += 2
						continue
					}
					i++
					closed = true
					break
				}
				if s[i] == '\\' {
					// Ambiguous standard_conforming_strings and U& syntax fail closed.
					return "", fmt.Errorf("unsupported_sql")
				}
				value.WriteByte(s[i])
				i++
			}
			if !closed {
				return "", fmt.Errorf("unsupported_sql")
			}
			if c == '"' {
				out = append(out, `"`+a.name(value.String())+`"`)
			} else {
				out = append(out, "'<redacted>'")
			}
		case c == '$':
			j := i + 1
			for j < len(s) && s[j] >= '0' && s[j] <= '9' {
				j++
			}
			if j > i+1 {
				out = append(out, s[i:j])
				i = j
				continue
			}
			for j < len(s) && (s[j] == '_' || s[j] >= 'a' && s[j] <= 'z' || s[j] >= 'A' && s[j] <= 'Z' || s[j] >= '0' && s[j] <= '9') {
				j++
			}
			if j == len(s) || s[j] != '$' {
				return "", fmt.Errorf("unsupported_sql")
			}
			tag := s[i : j+1]
			end := strings.Index(s[j+1:], tag)
			if end < 0 {
				return "", fmt.Errorf("unsupported_sql")
			}
			i = j + 1 + end + len(tag)
			out = append(out, "'<redacted>'")
		case c >= '0' && c <= '9':
			// Numeric constants (including hex and exponents) are data too.
			start := i
			i++
			for i < len(s) && strings.ContainsRune("0123456789abcdefABCDEFxXoObB._eE", rune(s[i])) {
				i++
			}
			if redactNumbers {
				out = append(out, "0")
			} else {
				out = append(out, s[start:i])
			}
		case c == ';':
			// A single trailing semicolon is harmless; no stacked statements.
			if strings.TrimSpace(s[i+1:]) != "" {
				return "", fmt.Errorf("unsupported_sql")
			}
			i++
		default:
			r, size := utf8.DecodeRuneInString(s[i:])
			if unicode.IsLetter(r) || r == '_' {
				j := i + size
				for j < len(s) {
					r, size = utf8.DecodeRuneInString(s[j:])
					if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '_' && r != '$' {
						break
					}
					j += size
				}
				word := strings.ToLower(s[i:j])
				if j < len(s) && s[j] == '\'' && strings.Contains(" e b x n ", " "+word+" ") {
					i = j
					continue
				}
				if strings.Contains(sqlWords+" create index lock access exclusive share mode ", " "+word+" ") {
					out = append(out, word)
				} else {
					out = append(out, `"`+a.name(word)+`"`)
				}
				i = j
			} else if strings.ContainsRune("+-/%<>=!~^|&:#?", r) {
				j := i + size
				for j < len(s) && strings.ContainsRune("+-/%<>=!~^|&:#?", rune(s[j])) {
					j++
				}
				out = append(out, s[i:j])
				i = j
			} else if strings.ContainsRune("(),.*+-/%<>=!~^|&:#?[]", r) {
				out = append(out, string(r))
				i += size
			} else {
				return "", fmt.Errorf("unsupported_sql")
			}
		}
	}
	return strings.Join(out, " "), nil
}
