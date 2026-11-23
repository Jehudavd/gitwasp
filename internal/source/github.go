package source

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Jehudavd/gitwasp/internal/model"
)

const (
	defaultGitHubAPIBase   = "https://api.github.com"
	defaultMaxRemoteFiles  = 40
	defaultRemoteWorkers   = 6
	defaultHTTPTimeout     = 20 * time.Second
	maxGitHubErrorBodySize = 4096
)

var reGitHubIdent = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)

// GitHubRepo identifies a parsed GitHub repository target.
type GitHubRepo struct {
	Owner    string
	Repo     string
	Ref      string
	CloneURL string
}

// GitHubOptions configures remote pre-clone scanning via the GitHub REST API.
type GitHubOptions struct {
	APIBaseURL     string
	Token          string
	Ref            string
	HTTPClient     *http.Client
	Concurrency    int
	MaxRemoteFiles int
}

// LooksLikeRemoteTarget reports whether raw appears to be a remote repository URL
// or an owner/repo shorthand (when not referring to an existing local path).
func LooksLikeRemoteTarget(raw string) bool {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return false
	}
	lower := strings.ToLower(trimmed)
	if strings.HasPrefix(lower, "http://") ||
		strings.HasPrefix(lower, "https://") ||
		strings.HasPrefix(lower, "ssh://") ||
		strings.HasPrefix(lower, "git@") {
		return true
	}
	if _, err := os.Stat(trimmed); err == nil {
		return false
	}
	if strings.HasPrefix(trimmed, ".") || strings.HasPrefix(trimmed, "/") || strings.Contains(trimmed, `\`) {
		return false
	}
	parts := strings.Split(trimmed, "/")
	if len(parts) != 2 {
		return false
	}
	return isValidGitHubSegment(parts[0]) && isValidGitHubSegment(strings.TrimSuffix(parts[1], ".git"))
}

// ParseGitHubTarget parses HTTPS, SSH, or owner/repo GitHub references into a validated GitHubRepo.
func ParseGitHubTarget(raw string) (GitHubRepo, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return GitHubRepo{}, fmt.Errorf("empty repository target")
	}
	if strings.ContainsAny(trimmed, "\r\n\x00") || strings.HasPrefix(trimmed, "-") {
		return GitHubRepo{}, fmt.Errorf("invalid repository target %q", raw)
	}

	var owner, repo, ref string

	switch {
	case strings.HasPrefix(strings.ToLower(trimmed), "git@"):
		rest := trimmed[4:]
		colon := strings.IndexByte(rest, ':')
		if colon < 0 {
			return GitHubRepo{}, fmt.Errorf("invalid SSH git URL %q", raw)
		}
		host := strings.ToLower(rest[:colon])
		if host != "github.com" {
			return GitHubRepo{}, fmt.Errorf("unsupported remote host %q: gitwasp currently supports github.com repositories", host)
		}
		parts := strings.Split(strings.Trim(rest[colon+1:], "/"), "/")
		if len(parts) != 2 {
			return GitHubRepo{}, fmt.Errorf("invalid GitHub SSH path in %q", raw)
		}
		owner = parts[0]
		repo = strings.TrimSuffix(parts[1], ".git")

	case strings.Contains(trimmed, "://"):
		u, err := url.Parse(trimmed)
		if err != nil {
			return GitHubRepo{}, fmt.Errorf("invalid repository URL %q: %w", raw, err)
		}
		scheme := strings.ToLower(u.Scheme)
		if scheme != "https" && scheme != "http" && scheme != "ssh" {
			return GitHubRepo{}, fmt.Errorf("unsupported URL scheme %q", u.Scheme)
		}
		host := strings.ToLower(u.Hostname())
		if host != "github.com" {
			return GitHubRepo{}, fmt.Errorf("unsupported remote host %q: gitwasp currently supports github.com repositories", host)
		}
		pathTrimmed := strings.Trim(u.Path, "/")
		parts := strings.Split(pathTrimmed, "/")
		if len(parts) < 2 {
			return GitHubRepo{}, fmt.Errorf("invalid GitHub URL %q: expected https://github.com/<owner>/<repo>", raw)
		}
		owner = parts[0]
		repo = strings.TrimSuffix(parts[1], ".git")
		if len(parts) >= 4 && parts[2] == "tree" {
			ref = strings.Join(parts[3:], "/")
		} else if len(parts) > 2 {
			return GitHubRepo{}, fmt.Errorf("unsupported GitHub URL path %q: pass repository root or /tree/<ref>", raw)
		}

	default:
		parts := strings.Split(strings.Trim(trimmed, "/"), "/")
		if len(parts) != 2 {
			return GitHubRepo{}, fmt.Errorf("invalid GitHub target %q: expected owner/repo or https://github.com/owner/repo", raw)
		}
		owner = parts[0]
		repo = strings.TrimSuffix(parts[1], ".git")
	}

	if !isValidGitHubSegment(owner) || !isValidGitHubSegment(repo) {
		return GitHubRepo{}, fmt.Errorf("invalid GitHub owner or repository name in %q", raw)
	}

	return GitHubRepo{
		Owner:    owner,
		Repo:     repo,
		Ref:      ref,
		CloneURL: fmt.Sprintf("https://github.com/%s/%s.git", owner, repo),
	}, nil
}

func isValidGitHubSegment(s string) bool {
	if s == "" || s == "." || s == ".." || strings.HasPrefix(s, "-") || strings.Contains(s, "..") {
		return false
	}
	return reGitHubIdent.MatchString(s)
}

type githubRepoMeta struct {
	DefaultBranch string `json:"default_branch"`
}

type githubTreeResp struct {
	Truncated bool             `json:"truncated"`
	Tree      []githubTreeItem `json:"tree"`
}

type githubTreeItem struct {
	Path string `json:"path"`
	Type string `json:"type"`
	SHA  string `json:"sha"`
	Size int64  `json:"size"`
}

type githubBlobResp struct {
	Content  string `json:"content"`
	Encoding string `json:"encoding"`
	Size     int64  `json:"size"`
}

// CollectGitHub inspects a remote GitHub repository via the GitHub REST API without
// cloning or writing any files to local disk.
func CollectGitHub(ctx context.Context, repo GitHubRepo, opts GitHubOptions) ([]model.FileEntry, int, string, error) {
	apiBase := strings.TrimRight(opts.APIBaseURL, "/")
	if apiBase == "" {
		apiBase = defaultGitHubAPIBase
	}
	token := strings.TrimSpace(opts.Token)
	if token == "" {
		token = strings.TrimSpace(os.Getenv("GITHUB_TOKEN"))
	}
	if token == "" {
		token = strings.TrimSpace(os.Getenv("GH_TOKEN"))
	}
	client := opts.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: defaultHTTPTimeout}
	}
	workers := opts.Concurrency
	if workers <= 0 {
		workers = defaultRemoteWorkers
	}
	maxFiles := opts.MaxRemoteFiles
	if maxFiles <= 0 {
		maxFiles = defaultMaxRemoteFiles
	}

	ref := strings.TrimSpace(opts.Ref)
	if ref == "" {
		ref = strings.TrimSpace(repo.Ref)
	}
	if ref == "" {
		metaURL := fmt.Sprintf("%s/repos/%s/%s", apiBase, url.PathEscape(repo.Owner), url.PathEscape(repo.Repo))
		var meta githubRepoMeta
		if err := fetchGitHubJSON(ctx, client, metaURL, token, repo, "", &meta); err != nil {
			return nil, 0, "", err
		}
		if strings.TrimSpace(meta.DefaultBranch) == "" {
			return nil, 0, "", fmt.Errorf("GitHub API did not return a default branch for %s/%s", repo.Owner, repo.Repo)
		}
		ref = meta.DefaultBranch
	}

	treeURL := fmt.Sprintf("%s/repos/%s/%s/git/trees/%s?recursive=1",
		apiBase, url.PathEscape(repo.Owner), url.PathEscape(repo.Repo), url.PathEscape(ref))
	var tree githubTreeResp
	if err := fetchGitHubJSON(ctx, client, treeURL, token, repo, ref, &tree); err != nil {
		return nil, 0, "", err
	}

	type candidate struct {
		item     githubTreeItem
		priority int
	}

	var candidates []candidate
	skipped := 0
	for _, item := range tree.Tree {
		if item.Type != "blob" {
			continue
		}
		if IsSkippedPath(item.Path) {
			continue
		}
		prio := RemotePriority(item.Path)
		if prio == 0 {
			continue
		}
		if item.Size > MaxFileSize {
			skipped++
			continue
		}
		candidates = append(candidates, candidate{item: item, priority: prio})
	}

	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].priority != candidates[j].priority {
			return candidates[i].priority < candidates[j].priority
		}
		return candidates[i].item.Path < candidates[j].item.Path
	})

	if len(candidates) > maxFiles {
		skipped += len(candidates) - maxFiles
		candidates = candidates[:maxFiles]
	}

	if len(candidates) == 0 {
		return []model.FileEntry{}, skipped, ref, nil
	}

	jobs := make(chan candidate, len(candidates))
	for _, c := range candidates {
		jobs <- c
	}
	close(jobs)

	var (
		mu       sync.Mutex
		wg       sync.WaitGroup
		files    = make([]model.FileEntry, 0, len(candidates))
		firstErr error
	)

	workerCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	if workers > len(candidates) {
		workers = len(candidates)
	}

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for c := range jobs {
				if workerCtx.Err() != nil {
					return
				}
				blobURL := fmt.Sprintf("%s/repos/%s/%s/git/blobs/%s",
					apiBase, url.PathEscape(repo.Owner), url.PathEscape(repo.Repo), url.PathEscape(c.item.SHA))
				var blob githubBlobResp
				if err := fetchGitHubJSON(workerCtx, client, blobURL, token, repo, ref, &blob); err != nil {
					mu.Lock()
					if firstErr == nil {
						firstErr = err
						cancel()
					}
					mu.Unlock()
					return
				}

				if !strings.EqualFold(blob.Encoding, "base64") {
					mu.Lock()
					skipped++
					mu.Unlock()
					continue
				}

				data, err := base64.StdEncoding.DecodeString(blob.Content)
				if err != nil || len(data) > MaxFileSize {
					mu.Lock()
					skipped++
					mu.Unlock()
					continue
				}
				headLen := len(data)
				if headLen > 512 {
					headLen = 512
				}
				if bytes.IndexByte(data[:headLen], 0) >= 0 {
					mu.Lock()
					skipped++
					mu.Unlock()
					continue
				}

				mu.Lock()
				files = append(files, model.FileEntry{
					Path:    c.item.Path,
					Content: data,
					Size:    int64(len(data)),
				})
				mu.Unlock()
			}
		}()
	}

	wg.Wait()
	if firstErr != nil {
		return nil, skipped, ref, firstErr
	}

	sort.Slice(files, func(i, j int) bool {
		return files[i].Path < files[j].Path
	})

	return files, skipped, ref, nil
}

func fetchGitHubJSON(ctx context.Context, client *http.Client, endpoint, token string, repo GitHubRepo, ref string, dest any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "gitwasp")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("requesting GitHub API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		if err := json.NewDecoder(resp.Body).Decode(dest); err != nil {
			return fmt.Errorf("decoding GitHub API response: %w", err)
		}
		return nil
	}

	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, maxGitHubErrorBodySize))
	bodyLower := strings.ToLower(string(bodyBytes))

	switch resp.StatusCode {
	case http.StatusUnauthorized:
		return fmt.Errorf("GitHub API authentication failed (401): check GITHUB_TOKEN or --token")
	case http.StatusForbidden, http.StatusTooManyRequests:
		if resp.Header.Get("X-RateLimit-Remaining") == "0" || strings.Contains(bodyLower, "rate limit") {
			return fmt.Errorf("GitHub API rate limit exceeded: set GITHUB_TOKEN or pass --token to increase limit")
		}
		return fmt.Errorf("GitHub API access denied (%d) for %s/%s", resp.StatusCode, repo.Owner, repo.Repo)
	case http.StatusNotFound:
		if ref != "" {
			return fmt.Errorf("repository %s/%s (ref %q) not found or private: set GITHUB_TOKEN or pass --token for private repos", repo.Owner, repo.Repo, ref)
		}
		return fmt.Errorf("repository %s/%s not found or private: set GITHUB_TOKEN or pass --token for private repos", repo.Owner, repo.Repo)
	default:
		return fmt.Errorf("GitHub API error (%d) for %s/%s", resp.StatusCode, repo.Owner, repo.Repo)
	}
}
