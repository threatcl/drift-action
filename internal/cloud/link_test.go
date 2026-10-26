package cloud

import (
	"reflect"
	"strings"
	"testing"
)

// The §3 table of the design, row by row. Contradictions are errors; nothing
// is silently resolved.
func TestLink(t *testing.T) {
	addressed := func(name, slug string) ModelFile { return ModelFile{Name: name, Org: "acme", Model: slug} }
	bare := func(name string) ModelFile { return ModelFile{Name: name} }

	tests := []struct {
		name     string
		files    []ModelFile
		override string
		want     LinkResult
		wantErr  string
	}{
		{
			name:  "no address, override set: every file links to it",
			files: []ModelFile{bare("a.tm.hcl"), bare("b.tm.hcl")}, override: "payments",
			want: LinkResult{Models: []Linked{{Slug: "payments", Files: []string{"a.tm.hcl", "b.tm.hcl"}}}},
		},
		{
			name:  "no address, no override: nothing links",
			files: []ModelFile{bare("a.tm.hcl")},
			want:  LinkResult{Unlinked: []string{"a.tm.hcl"}},
		},
		{
			name:  "one address, no override: links, unaddressed files follow",
			files: []ModelFile{addressed("parent.tm.hcl", "payments"), bare("child.tm.hcl")},
			want:  LinkResult{Models: []Linked{{Slug: "payments", Org: "acme", Files: []string{"parent.tm.hcl", "child.tm.hcl"}}}},
		},
		{
			name:  "one address, same override: links",
			files: []ModelFile{addressed("p.tm.hcl", "payments")}, override: "payments",
			want: LinkResult{Models: []Linked{{Slug: "payments", Org: "acme", Files: []string{"p.tm.hcl"}}}},
		},
		{
			name:  "one address, different override: error",
			files: []ModelFile{addressed("p.tm.hcl", "payments")}, override: "ledger",
			wantErr: "remove cloud.model",
		},
		{
			name:  "several addresses, override set: ambiguous",
			files: []ModelFile{addressed("p.tm.hcl", "payments"), addressed("l.tm.hcl", "ledger")}, override: "payments",
			wantErr: "ambiguous",
		},
		{
			name:  "several addresses, no override: each links itself, unaddressed noted",
			files: []ModelFile{addressed("p.tm.hcl", "payments"), bare("stray.tm.hcl"), addressed("l.tm.hcl", "ledger"), addressed("p2.tm.hcl", "payments")},
			want: LinkResult{
				Models: []Linked{
					{Slug: "payments", Org: "acme", Files: []string{"p.tm.hcl", "p2.tm.hcl"}},
					{Slug: "ledger", Org: "acme", Files: []string{"l.tm.hcl"}},
				},
				Unlinked: []string{"stray.tm.hcl"},
			},
		},
		{
			// A block naming an organisation but no slug — never pushed — is
			// not an address.
			name:  "org-only block is unaddressed",
			files: []ModelFile{{Name: "new.tm.hcl", Org: "acme"}},
			want:  LinkResult{Unlinked: []string{"new.tm.hcl"}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Link(tt.files, tt.override)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want it to mention %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Link: %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Link = %+v, want %+v", got, tt.want)
			}
		})
	}
}
