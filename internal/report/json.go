package report

import (
	"encoding/json"
	"io"

	"github.com/Jehudavd/gitwasp/internal/model"
)

// WriteJSON encodes res as formatted JSON to w.
func WriteJSON(w io.Writer, res model.ScanResult) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(res)
}
