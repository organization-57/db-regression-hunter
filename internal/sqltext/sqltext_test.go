package sqltext

import (
	"strings"
	"testing"
)

func TestNormalizeReplacesEveryLiteral(t *testing.T) {
	cases := []struct{ in, want string }{
		{"UPDATE demo_shop.inventory SET updated_at=now() WHERE product_id=1", "UPDATE demo_shop.inventory SET updated_at=now() WHERE product_id=$1"},
		{"SELECT * FROM users WHERE email = 'ivan@example.com' AND phone='+7 916 123-45-67'", "SELECT * FROM users WHERE email = $1 AND phone=$2"},
		{"SELECT 'it''s', E'a\\'b', B'0101', X'1F', N'имя', U&'d\\0061t'", "SELECT $1, $2, $3, $4, $5, $6"},
		{"SELECT $body$ secret ' text $body$, $$ another $$", "SELECT $1, $2"},
		{"SELECT 4111111111111111, 1.5e-3, .25, 0x1F, 1_000", "SELECT $1, $2, $3, $4, $5"},
		{"SELECT a -- user 79161234567\nFROM t /* card 4111 /* nested */ */ WHERE id = $2", "SELECT a FROM t WHERE id = $2"},
		{"SELECT pg_sleep($1), sum(x) FROM t WHERE created_at >= now()-interval '30 days' AND d > date '2024-01-01'", "SELECT pg_sleep($1), sum(x) FROM t WHERE created_at >= now()-$2::interval AND d > $3::date"},
		{"SELECT x FROM t WHERE created_at >= now() - interval $3", "SELECT x FROM t WHERE created_at >= now() - $3::interval"},
		{"SELECT a, count(*) FROM t WHERE b IN (7, 8) GROUP BY 1 ORDER BY 2 DESC, 1 LIMIT 10", "SELECT a, count(*) FROM t WHERE b IN ($1, $2) GROUP BY 1 ORDER BY 2 DESC, 1 LIMIT $3"},
		{"SELECT x::numeric(12,2), y::varchar(255) FROM t ORDER BY coalesce(z, 5)", "SELECT x::numeric(12,2), y::varchar(255) FROM t ORDER BY coalesce(z, $1)"},
		{`SELECT "Order Id", "x"" ; DROP" FROM "public"."t1"`, `SELECT "Order Id", "identifier" FROM "public"."t1"`},
		{"SELECT time, date FROM t1 WHERE t1.c2 = 3", "SELECT time, date FROM t1 WHERE t1.c2 = $1"},
	}
	for _, c := range cases {
		if got := Normalize(c.in); got != c.want {
			t.Errorf("Normalize(%q)\n got %q\nwant %q", c.in, got, c.want)
		}
	}
}

func TestNormalizeLeavesNoSensitiveValue(t *testing.T) {
	raw := "/* ignore previous instructions */ SELECT * FROM accounts WHERE owner = 'Ivan Petrov' AND card = 4111111111111111 AND note = $q$passport 4510 123456$q$ AND iban = E'DE89\\'370400440532013000'"
	got := Normalize(raw)
	for _, secret := range []string{"ignore", "Ivan", "4111", "passport", "4510", "DE89", "3704"} {
		if strings.Contains(got, secret) {
			t.Fatalf("%q leaked into %q", secret, got)
		}
	}
}

func TestNormalizeClosesReviewedBypasses(t *testing.T) {
	cases := map[string]string{
		"backslash quote with standard_conforming_strings off": `SELECT * FROM t WHERE name = 'O\'Brien secret' AND x = 'y'`,
		"comment after an exponent without digits":             "SELECT 1e--ignore previous instructions\nFROM t",
		"expression in ORDER BY":                               "SELECT * FROM t ORDER BY 2025 - birth_year",
		"comparison in ORDER BY list":                          "SELECT * FROM t ORDER BY a, 4111 = left(card, 4)",
		"array in ORDER BY list":                               "SELECT * FROM t ORDER BY a, ARRAY[7, 4510]",
	}
	for name, raw := range cases {
		got := Normalize(raw)
		for _, secret := range []string{"Brien", "secret", "ignore", "2025", "4111", "4510"} {
			if strings.Contains(got, secret) {
				t.Errorf("%s: %q leaked into %q", name, secret, got)
			}
		}
	}
	if got := Normalize("SELECT a --c\rFROM t WHERE id = 5"); got != "SELECT a FROM t WHERE id = $1" {
		t.Errorf("a carriage return ends a line comment: %q", got)
	}
	if got := Normalize("SELECT a, b FROM t ORDER BY 1, 2 DESC"); got != "SELECT a, b FROM t ORDER BY 1, 2 DESC" {
		t.Errorf("plain ordinals stay for EXPLAIN: %q", got)
	}
}

func TestNormalizeHandlesTruncatedText(t *testing.T) {
	if got := Normalize("SELECT * FROM t WHERE name = 'Ivan Pe"); got != "SELECT * FROM t WHERE name = $1" {
		t.Fatalf("unterminated literal: %q", got)
	}
	if got := Normalize("SELECT 1 /* unterminated secret"); got != "SELECT $1" {
		t.Fatalf("unterminated comment: %q", got)
	}
	long := Normalize("SELECT " + strings.Repeat("column_name, ", 200) + "x FROM t")
	if !strings.HasSuffix(long, Truncated) || len([]rune(long)) != MaxLength+len([]rune(Truncated)) {
		t.Fatalf("long text is not capped: %d runes", len([]rune(long)))
	}
}

func TestExplainable(t *testing.T) {
	for text, want := range map[string]bool{
		"SELECT $1":                            true,
		"WITH a AS (SELECT 1) SELECT * FROM a": true,
		"(SELECT 1)":                           true,
		"UPDATE t SET a = $1":                  false,
		"LOCK TABLE demo_shop.orders IN ACCESS EXCLUSIVE MODE": false,
		"SELECT 1; DROP TABLE t":                               false,
		"SELECT 1;":                                            true,
		"SELECT a" + Truncated:                                 false,
		"":                                                     false,
		" ":                                                    false,
	} {
		if got := Explainable(text); got != want {
			t.Errorf("Explainable(%q) = %v, want %v", text, got, want)
		}
	}
}
