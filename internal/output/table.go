package output

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/lipgloss/table"

	"github.com/lazhari/jwt/internal/timeparse"
	"github.com/lazhari/jwt/internal/token"
)

// Options controls table rendering.
type Options struct {
	// Color enables ANSI styling. When false the output has no escape codes.
	Color bool
	// Width caps table width. Zero means 100.
	Width int
	// Now is used for relative time annotations. Zero means time.Now().
	Now time.Time
}

const defaultWidth = 100

// sanitize replaces control runes (and invalid UTF-8 bytes) with a visible
// escaped form so hostile claim text cannot inject ANSI escape sequences,
// stray newlines, or invisible bidi overrides into table output. \n, \r,
// and \t get their familiar two-character escapes; other runes below 0x80
// become \xNN; anything else in the control (Cc), format (Cf), line
// separator (Zl), or paragraph separator (Zp) categories becomes \uNNNN.
// Everything else, including all printable Unicode, passes through
// unchanged.
func sanitize(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			// Invalid byte, not a real U+FFFD from the source text.
			_, _ = fmt.Fprintf(&b, `\x%02x`, s[i])
			i++
			continue
		}
		switch {
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case unicode.IsControl(r), unicode.Is(unicode.Cf, r), unicode.Is(unicode.Zl, r), unicode.Is(unicode.Zp, r):
			if r < 0x80 {
				_, _ = fmt.Fprintf(&b, `\x%02x`, r)
			} else {
				_, _ = fmt.Fprintf(&b, `\u%04x`, r)
			}
		default:
			b.WriteRune(r)
		}
		i += size
	}
	return b.String()
}

type styles struct {
	section, key, dim, ok, bad, valid, invalid, border lipgloss.Style
}

func newStyles(color bool) styles {
	plain := lipgloss.NewStyle()
	s := styles{section: plain, key: plain, dim: plain, ok: plain, bad: plain, valid: plain, invalid: plain, border: plain}
	if !color {
		return s
	}
	s.section = plain.Bold(true).Foreground(lipgloss.Color("99"))
	s.key = plain.Foreground(lipgloss.Color("39"))
	s.dim = plain.Foreground(lipgloss.Color("245"))
	s.ok = plain.Foreground(lipgloss.Color("2"))
	s.bad = plain.Foreground(lipgloss.Color("1"))
	s.valid = plain.Bold(true).Foreground(lipgloss.Color("2"))
	s.invalid = plain.Bold(true).Foreground(lipgloss.Color("1"))
	s.border = plain.Foreground(lipgloss.Color("99"))
	return s
}

// Table renders header, payload, signature, and (when present) the
// verification report.
func Table(w io.Writer, r *token.Result, o Options) error {
	if o.Width <= 0 {
		o.Width = defaultWidth
	}
	if o.Now.IsZero() {
		o.Now = time.Now()
	}
	st := newStyles(o.Color)

	var b strings.Builder
	b.WriteString(st.section.Render("Header") + "\n")
	b.WriteString(kvTable(r.Header, o, st) + "\n")
	b.WriteString(st.section.Render("Payload") + "\n")
	b.WriteString(kvTable(r.Payload, o, st) + "\n")
	b.WriteString(st.section.Render("Signature") + "\n")
	if r.Signature == "" {
		b.WriteString("  " + st.dim.Render("(none)") + "\n")
	} else {
		b.WriteString("  " + sanitize(r.Signature) + "\n")
	}
	if r.Verification != nil {
		b.WriteString("\n")
		b.WriteString(checks(r.Verification, st))
	}
	_, err := io.WriteString(w, b.String())
	return err
}

func kvTable(m map[string]any, o Options, st styles) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	rows := make([][]string, 0, len(keys))
	keyW, valW := 3, 5 // "KEY", "VALUE"
	for _, k := range keys {
		displayKey := sanitize(k)
		v := formatValue(k, m[k], o, st)
		rows = append(rows, []string{displayKey, v})
		keyW = max(keyW, lipgloss.Width(displayKey))
		valW = max(valW, lipgloss.Width(v))
	}
	if len(rows) == 0 {
		rows = append(rows, []string{st.dim.Render("(empty)"), ""})
		keyW = 7
	}
	// Borders (3) plus cell padding (4) plus content.
	natural := keyW + valW + 7
	width := min(natural, o.Width)

	t := table.New().
		Border(lipgloss.RoundedBorder()).
		BorderStyle(st.border).
		Headers("KEY", "VALUE").
		Width(width).
		Wrap(true).
		StyleFunc(func(row, col int) lipgloss.Style {
			base := lipgloss.NewStyle().Padding(0, 1)
			if col == 0 && row != table.HeaderRow {
				return base.Inherit(st.key)
			}
			return base
		}).
		Rows(rows...)
	return t.Render()
}

var timeClaims = map[string]bool{"exp": true, "nbf": true, "iat": true}

func formatValue(key string, v any, o Options, st styles) string {
	if timeClaims[key] {
		if t, present, err := token.NumericDate(v); present && err == nil {
			return formatTime(key, t, o, st)
		}
	}
	return plain(v)
}

// plain renders any claim value on one line. Objects and arrays become
// compact JSON.
func plain(v any) string {
	switch x := v.(type) {
	case nil:
		return "null"
	case string:
		return sanitize(x)
	case json.Number:
		return x.String()
	case bool:
		return strconv.FormatBool(x)
	}
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprintf("%v", v)
	}
	return sanitize(string(b))
}

func formatTime(key string, t time.Time, o Options, st styles) string {
	abs := t.UTC().Format("2006-01-02 15:04:05 UTC")
	rel := timeparse.Relative(t, o.Now)
	note, style := "", st.dim
	switch key {
	case "exp":
		if t.Before(o.Now) {
			note, style = "expired "+rel, st.bad
		} else {
			note = "expires " + rel
		}
	case "nbf":
		if t.After(o.Now) {
			note, style = "not valid for "+timeparse.Short(t.Sub(o.Now)), st.bad
		} else {
			note = "valid since " + rel
		}
	case "iat":
		if t.After(o.Now) {
			note, style = "issued "+rel+", clock skew?", st.bad
		} else {
			note = "issued " + rel
		}
	}
	return fmt.Sprintf("%d  %s  %s", t.Unix(), abs, style.Render("("+note+")"))
}

func checks(v *token.Verification, st styles) string {
	var b strings.Builder
	b.WriteString(st.section.Render("Verification") + "\n")
	names := make([]string, len(v.Checks))
	details := make([]string, len(v.Checks))
	nameW := 0
	for i, c := range v.Checks {
		names[i] = sanitize(c.Name)
		details[i] = sanitize(c.Detail)
		nameW = max(nameW, len([]rune(names[i])))
	}
	for i, c := range v.Checks {
		mark := st.ok.Render("✓")
		switch {
		case c.Skipped:
			mark = st.dim.Render("-")
		case !c.Passed:
			mark = st.bad.Render("✗")
		}
		_, _ = fmt.Fprintf(&b, "  %s %-*s  %s\n", mark, nameW, names[i], details[i])
	}
	b.WriteString("\n")
	if v.Valid {
		b.WriteString(st.valid.Render("VALID") + "\n")
	} else {
		b.WriteString(st.invalid.Render("INVALID") + "\n")
	}
	return b.String()
}
