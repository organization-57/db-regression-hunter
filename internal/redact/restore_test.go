package redact

import (
	"strings"
	"testing"
)

func TestRestoreUsesOnlyKnownIdentifierTokens(t *testing.T) {
	a := New()
	id := a.Name(`private"table`)
	if got := a.Restore("Таблица " + id); got != `Таблица private"table` {
		t.Fatal(got)
	}
	input := `SELECT ` + id + `, '` + id + `', prefix_` + id + ` FROM "` + id + `"`
	want := `SELECT "private""table", '` + id + `', prefix_` + id + ` FROM "private""table"`
	if got := a.RestoreSQL(input); got != want {
		t.Fatalf("%s != %s", got, want)
	}
	// A known builtin-looking column/table still shares its alias with the schema.
	count := a.Name("count")
	safe, err := a.SQL("SELECT count, count(*) FROM count")
	if err != nil || strings.Count(safe, `"`+count+`"`) != 2 || !strings.Contains(safe, "count (") {
		t.Fatal(safe, err)
	}
}
