// Package fixture records a real review to disk and replays it later, so the
// GitHub half of the pipeline — comment upsert, sticky updates, check runs,
// outputs — can be exercised repeatedly without paying for inference every
// time.
//
// A replayed run is never allowed to pass for a real one. The player reports
// what it did, and whether the recording still matches the diff being
// reviewed, so a comment posted from a stale fixture says so on its face.
package fixture

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/threatcl/drift-action/internal/findings"
	"github.com/threatcl/drift-action/internal/llm"
)

// Recording is one captured provider response.
type Recording struct {
	// RecordedAt and Source are provenance: a recording is only meaningful
	// against the diff it was made from, and both fields make a stale one
	// recognisable rather than silently wrong.
	RecordedAt string `json:"recorded_at"`
	Source     string `json:"source,omitempty"`
	Model      string `json:"model"`
	Fallback   bool   `json:"fallback,omitempty"`
	// RequestDigest fingerprints the prompt sections this was recorded from.
	// Empty means the recording predates the fingerprint or was written by
	// hand, and the match cannot be checked.
	RequestDigest string `json:"request_digest,omitempty"`
	// Report is the model's output, stored in the same schema the API forced
	// it into. It is re-validated on replay: a fixture is not trusted just
	// because it is on disk.
	Report json.RawMessage `json:"report"`
}

// Digest fingerprints a request by the data sections it carries.
func Digest(req llm.ReviewRequest) string {
	sum := sha256.Sum256([]byte(req.Sections()))
	return hex.EncodeToString(sum[:])
}

var (
	_ llm.Provider = (*Recorder)(nil)
	_ llm.Provider = (*Player)(nil)
)

// Recorder passes a review through to inner and writes the result to path.
type Recorder struct {
	inner  llm.Provider
	path   string
	source string
}

func NewRecorder(inner llm.Provider, path, source string) *Recorder {
	return &Recorder{inner: inner, path: path, source: source}
}

func (r *Recorder) Review(ctx context.Context, req llm.ReviewRequest) (*llm.ReviewResult, error) {
	result, err := r.inner.Review(ctx, req)
	if err != nil {
		return nil, err
	}
	if err := r.write(req, result); err != nil {
		// The review itself succeeded and has already been paid for. Losing
		// the recording is worth a warning, not the run.
		result.Notes = append(result.Notes,
			fmt.Sprintf("Recording: this review could not be saved to %s — %v",
				filepath.Base(r.path), err))
	}
	return result, nil
}

func (r *Recorder) write(req llm.ReviewRequest, result *llm.ReviewResult) error {
	report, err := json.Marshal(result.Report)
	if err != nil {
		return err
	}

	raw, err := json.MarshalIndent(Recording{
		RecordedAt:    time.Now().UTC().Format(time.RFC3339),
		Source:        r.source,
		Model:         result.Model,
		Fallback:      result.Fallback,
		RequestDigest: Digest(req),
		Report:        report,
	}, "", "  ")
	if err != nil {
		return err
	}

	if dir := filepath.Dir(r.path); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	return os.WriteFile(r.path, append(raw, '\n'), 0o644)
}

// Player replays a recording instead of calling a model.
type Player struct{ path string }

func NewPlayer(path string) *Player {
	return &Player{path: path}
}

func (p *Player) Review(_ context.Context, req llm.ReviewRequest) (*llm.ReviewResult, error) {
	raw, err := os.ReadFile(p.path)
	if err != nil {
		return nil, fmt.Errorf("reading the recording: %w", err)
	}

	var recording Recording
	if err := json.Unmarshal(raw, &recording); err != nil {
		return nil, fmt.Errorf("parsing the recording at %s: %w", p.path, err)
	}

	// Validate on the way out, exactly as a live response would be. A hand
	// edited fixture must not be able to put anything past the schema that a
	// model could not.
	report, err := findings.Parse(recording.Report)
	if err != nil {
		return nil, fmt.Errorf("the recording at %s holds an invalid report: %w", p.path, err)
	}

	result := &llm.ReviewResult{
		Report:   report,
		Model:    recording.Model,
		Fallback: recording.Fallback,
	}

	// The caller already discloses that this run was replayed. Notes here add
	// only what it cannot know: whether the recording still describes the diff
	// in front of it.
	switch {
	case recording.RequestDigest == "":
		result.Notes = append(result.Notes,
			"Recording: it carries no request fingerprint, so it could not be checked against this pull request")
	case recording.RequestDigest != Digest(req):
		result.Notes = append(result.Notes, fmt.Sprintf(
			"Recording: it was made from a different diff (%s), so the findings below describe that diff and not this one",
			or(recording.Source, "source unrecorded")))
	}
	return result, nil
}

func or(value, fallback string) string {
	if value != "" {
		return value
	}
	return fallback
}
