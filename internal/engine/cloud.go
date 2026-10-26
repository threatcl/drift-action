package engine

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sort"
	"strings"

	"github.com/threatcl/drift-action/internal/cloud"
	"github.com/threatcl/drift-action/internal/config"
	"github.com/threatcl/drift-action/internal/model"
)

// BaseFetcher returns the base-commit content of a repo-relative path, with
// found=false when the file did not exist there — a file the pull request
// adds has no base. main reads it from the GitHub contents API; the corpus
// serves it from the case directory.
type BaseFetcher func(ctx context.Context, path string) (content []byte, found bool, err error)

// CloudInput is what the context call needs beyond the config.
type CloudInput struct {
	// Client is nil when the run holds no token. CloudContext then degrades
	// without a request, with a note only if the repo configured cloud mode.
	Client     *cloud.Client
	Workspace  string
	Repository string
	Assertions *model.Assertions
	Base       BaseFetcher
}

// CloudOutcome is what the run learned from Threatcl Cloud, or why it did not.
type CloudOutcome struct {
	// Connected reports that the context call succeeded. When false, the
	// review is exactly the local-mode review: Library is empty, so no ORG
	// LIBRARY section, no prompt addendum and the v0 schema.
	Connected bool
	// Degraded is the "not connected" reason for the comment, worded by
	// cause and never from a response body. Empty when connected, and empty
	// when there was no token and the repo never configured cloud mode.
	Degraded string
	Response *cloud.ContextResponse
	Link     cloud.LinkResult
	// Library is the rendered ORG LIBRARY section; empty when not connected
	// or when the organisation's library has no referenceable entries.
	Library string
	// Index maps every reference id that was sent to its name. The renderer
	// prints names from here, never from the model's output, and
	// findings.PruneLibraryRefs drops any id outside it.
	Index map[string]string
}

// Degradation wording, by cause. Each is specific enough to act on and none
// quotes the server.
const (
	degradedNoToken     = "not connected — no API token in this run"
	degradedRejected    = "not connected — the API token was rejected"
	degradedUpgrade     = "not connected — cloud-connected mode needs the Team plan"
	degradedForbidden   = "not connected — the API token's organisation refused the request"
	degradedUnreachable = "not connected — Threatcl Cloud could not be reached"
	degradedRefused     = "not connected — Threatcl Cloud refused the request; see the action log"
	degradedBase        = "not connected — the base-commit threat model could not be read from GitHub"
)

// CloudLink maps the set's files onto cloud models under cfg's cloud.model
// override. A contradiction between the override and the files' backend
// blocks is a configuration error, returned here so the run fails before the
// diff is fetched — whether or not a token is present, as every other config
// contradiction does.
func CloudLink(cfg config.Config, assertions *model.Assertions) (cloud.LinkResult, error) {
	byFile := map[string]model.Backend{}
	for _, b := range assertions.Backends() {
		byFile[b.File] = b
	}
	files := make([]cloud.ModelFile, 0, len(assertions.Sources))
	for _, source := range assertions.Sources {
		b := byFile[source]
		files = append(files, cloud.ModelFile{Name: source, Org: b.Org, Model: b.Model})
	}
	link, err := cloud.Link(files, cfg.Cloud.Model)
	if err != nil {
		return link, fmt.Errorf("%s: %w", cfg.ConfigPath, err)
	}
	return link, nil
}

// CloudContext performs the one read of cloud-connected mode. It runs before
// the diff is fetched and never fails the run: every failure degrades to the
// local review with a note, and the caller treats a non-connected outcome
// exactly as it treats having no token.
//
// It lives here for the reason AssembleRequest does: main and the corpus must
// build the same request, and the library section this returns is part of
// the request the corpus measures.
func CloudContext(ctx context.Context, cfg config.Config, in CloudInput) CloudOutcome {
	if in.Client == nil {
		if cfg.Cloud.Declared {
			return CloudOutcome{Degraded: degradedNoToken}
		}
		return CloudOutcome{}
	}

	link, err := CloudLink(cfg, in.Assertions)
	if err != nil {
		// Unreachable from main, which calls CloudLink first and fails on
		// it; kept so a caller that skipped that step degrades instead of
		// sending a request built on a contradiction.
		log.Printf("cloud: %v", err)
		return CloudOutcome{Degraded: degradedRefused}
	}

	req, err := buildContextRequest(ctx, in, link)
	if err != nil {
		log.Printf("cloud: %v", err)
		if errors.Is(err, errBaseUnavailable) {
			return CloudOutcome{Degraded: degradedBase, Link: link}
		}
		return CloudOutcome{Degraded: degradedRefused, Link: link}
	}

	resp, err := in.Client.Context(ctx, req)
	if err != nil {
		log.Printf("cloud: %v", err)
		return CloudOutcome{Degraded: degradation(err), Link: link}
	}

	library, index := renderLibrary(resp.Library)
	return CloudOutcome{
		Connected: true,
		Response:  resp,
		Link:      link,
		Library:   library,
		Index:     index,
	}
}

var errBaseUnavailable = errors.New("base content unavailable")

// buildContextRequest reads each linked file's head from the checkout, under
// the same confinement as loading it, and its base from the fetcher. The
// request carries model HCL and nothing else; the type cannot express a diff.
func buildContextRequest(ctx context.Context, in CloudInput, link cloud.LinkResult) (cloud.ContextRequest, error) {
	req := cloud.ContextRequest{
		Repository: in.Repository,
		// Non-nil even when empty: a run with no linked model still asks
		// for the library, and the server refuses a null models array.
		Models: []cloud.RequestModel{},
	}
	for _, linked := range link.Models {
		heads, err := model.ReadFiles(in.Workspace, linked.Files)
		if err != nil {
			return req, err
		}
		rm := cloud.RequestModel{Slug: linked.Slug}
		if linked.Org != "" {
			org := linked.Org
			rm.BackendOrg = &org
		}
		for i, name := range linked.Files {
			head := string(heads[i])
			file := cloud.RequestFile{Name: name, Head: &head}
			if in.Base != nil {
				content, found, err := in.Base(ctx, name)
				if err != nil {
					return req, fmt.Errorf("%w: %v", errBaseUnavailable, err)
				}
				if found {
					base := string(content)
					file.Base = &base
				}
			}
			rm.Files = append(rm.Files, file)
		}
		req.Models = append(req.Models, rm)
	}
	return req, nil
}

// degradation words a failed context call for the comment. Only the status
// and code are read; the server's message stays in the run log.
func degradation(err error) string {
	var apiErr *cloud.APIError
	if !errors.As(err, &apiErr) {
		return degradedUnreachable
	}
	switch {
	case apiErr.Unauthorized():
		return degradedRejected
	case apiErr.UpgradeRequired():
		return degradedUpgrade
	case apiErr.Forbidden():
		return degradedForbidden
	case apiErr.Status >= 500 || apiErr.Status == 429:
		return degradedUnreachable
	default:
		return degradedRefused
	}
}

// renderLibrary writes the ORG LIBRARY section and the id→name index behind
// it. Entries are sorted by id so the section is stable across runs, and an
// entry without an id is skipped: the model could not cite it.
func renderLibrary(lib cloud.ContextLibrary) (string, map[string]string) {
	index := map[string]string{}
	write := func(b *strings.Builder, heading string, entries []cloud.LibraryEntry) {
		var lines []string
		for _, e := range entries {
			if e.ReferenceID == "" {
				continue
			}
			index[e.ReferenceID] = e.Name
			lines = append(lines, fmt.Sprintf("%s | %s", e.ReferenceID, oneLine(e.Name)))
		}
		if len(lines) == 0 {
			return
		}
		sort.Strings(lines)
		fmt.Fprintf(b, "%s:\n%s\n\n", heading, strings.Join(lines, "\n"))
	}

	var b strings.Builder
	write(&b, "Threats", lib.Threats)
	write(&b, "Controls", lib.Controls)
	if b.Len() == 0 {
		return "", index
	}
	return strings.TrimSpace(b.String()) + "\n", index
}

// oneLine keeps a library name on its line: a name is org-authored data, and
// a newline in it could start a counterfeit section marker.
func oneLine(s string) string {
	return strings.Join(strings.Fields(s), " ")
}
