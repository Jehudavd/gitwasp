package source

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/Jehudavd/gitwasp/internal/model"
)

// MaxArchiveReadBytes caps total uncompressed bytes read across a ZIP archive
// to protect against zip-bomb resource exhaustion (32 MiB).
const MaxArchiveReadBytes = 32 * 1024 * 1024

// ZipMeta summarizes archive-level structural hazards observed while inspecting
// a ZIP file without extracting entries to disk.
type ZipMeta struct {
	HasEmbeddedGit   bool
	EmbeddedGitPaths []string
	HasZipSlip       bool
	ZipSlipPaths     []string
}

// IsZipFile reports whether p ends with a .zip extension.
func IsZipFile(p string) bool {
	return strings.EqualFold(filepath.Ext(strings.TrimSpace(p)), ".zip")
}

// CollectZip inspects entries inside zipPath purely in memory without writing
// any extracted files to disk, guarding against zip bombs, symlinks, and Zip Slip.
func CollectZip(zipPath string) ([]model.FileEntry, int, ZipMeta, error) {
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return nil, 0, ZipMeta{}, fmt.Errorf("opening zip %q: %w", zipPath, err)
	}
	defer r.Close()

	files := make([]model.FileEntry, 0)
	skipped := 0
	var meta ZipMeta
	var totalRead int64

	for _, zf := range r.File {
		rawSlash := strings.ReplaceAll(zf.Name, `\`, "/")
		if isZipSlipPath(rawSlash) {
			meta.HasZipSlip = true
			if len(meta.ZipSlipPaths) < 5 {
				meta.ZipSlipPaths = append(meta.ZipSlipPaths, zf.Name)
			}
			skipped++
			continue
		}

		norm := path.Clean(strings.TrimSuffix(rawSlash, "/"))
		if norm == "." || norm == "" {
			continue
		}

		if hasGitSegment(norm) {
			meta.HasEmbeddedGit = true
			if len(meta.EmbeddedGitPaths) < 5 {
				meta.EmbeddedGitPaths = append(meta.EmbeddedGitPaths, norm)
			}
		}

		if zf.FileInfo().IsDir() || strings.HasSuffix(rawSlash, "/") {
			continue
		}

		if zf.Mode()&os.ModeSymlink != 0 {
			skipped++
			continue
		}

		if IsSkippedPath(norm) || !IsTargetFile(norm) {
			continue
		}

		if len(files) >= MaxFiles {
			skipped++
			continue
		}

		if zf.UncompressedSize64 > uint64(MaxFileSize) {
			skipped++
			continue
		}

		data, ok, err := readZipEntryBounded(zf, MaxFileSize)
		if err != nil || !ok {
			skipped++
			continue
		}

		if totalRead+int64(len(data)) > MaxArchiveReadBytes {
			skipped++
			continue
		}
		totalRead += int64(len(data))

		files = append(files, model.FileEntry{
			Path:    norm,
			Content: data,
			Size:    int64(len(data)),
		})
	}

	return files, skipped, meta, nil
}

func readZipEntryBounded(zf *zip.File, maxSize int64) ([]byte, bool, error) {
	rc, err := zf.Open()
	if err != nil {
		return nil, false, err
	}
	defer rc.Close()

	data, err := io.ReadAll(io.LimitReader(rc, maxSize+1))
	if err != nil {
		return nil, false, err
	}
	if int64(len(data)) > maxSize {
		return nil, false, nil
	}

	headLen := len(data)
	if headLen > 512 {
		headLen = 512
	}
	if bytes.IndexByte(data[:headLen], 0) >= 0 {
		return nil, false, nil
	}
	return data, true, nil
}

func isZipSlipPath(rawSlash string) bool {
	if strings.HasPrefix(rawSlash, "/") {
		return true
	}
	if len(rawSlash) >= 2 && rawSlash[1] == ':' {
		return true
	}
	for _, seg := range strings.Split(rawSlash, "/") {
		if seg == ".." {
			return true
		}
	}
	return false
}

func hasGitSegment(norm string) bool {
	for _, seg := range strings.Split(strings.ToLower(norm), "/") {
		if seg == ".git" {
			return true
		}
	}
	return false
}
