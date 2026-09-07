// Package output renders decode and verify results as tables or JSON.
package output

import (
	"encoding/json"
	"io"

	"github.com/lazhari/jwt/internal/token"
)

// WriteJSON writes v as an indented JSON document followed by a newline.
// HTML escaping is off so URLs in claims stay readable.
func WriteJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(v)
}

// JSON writes a result as one JSON document. Map keys are sorted by
// encoding/json; json.Number values are emitted verbatim.
func JSON(w io.Writer, r *token.Result) error {
	return WriteJSON(w, r)
}
