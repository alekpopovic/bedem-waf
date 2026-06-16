package rules

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const MetadataFile = "ruleset.json"

type Metadata struct {
	Name        string          `json:"name"`
	Provider    string          `json:"provider"`
	Source      string          `json:"source"`
	Version     string          `json:"version"`
	Description string          `json:"description,omitempty"`
	Enabled     bool            `json:"enabled"`
	Extra       json.RawMessage `json:"metadata,omitempty"`
}

type ManagedRuleSet struct {
	Name        string          `json:"name"`
	Provider    string          `json:"provider"`
	Source      string          `json:"source"`
	Description string          `json:"description,omitempty"`
	LocalPath   string          `json:"local_path"`
	Enabled     bool            `json:"enabled"`
	Metadata    json.RawMessage `json:"metadata,omitempty"`
	Version     ManagedVersion  `json:"version"`
}

type ManagedVersion struct {
	Version         string          `json:"version"`
	SourceURI       string          `json:"source_uri"`
	LocalPath       string          `json:"local_path"`
	ChecksumSHA256  string          `json:"checksum_sha256"`
	RulesetSnapshot json.RawMessage `json:"ruleset_snapshot"`
}

type Recorder interface {
	RecordManagedRuleSet(ctx context.Context, set ManagedRuleSet) error
}

func ScanAndRecord(ctx context.Context, root string, recorder Recorder) ([]ManagedRuleSet, error) {
	sets, err := ScanLocalDirectory(root)
	if err != nil {
		return nil, err
	}
	if recorder == nil {
		return sets, nil
	}
	for _, set := range sets {
		if err := recorder.RecordManagedRuleSet(ctx, set); err != nil {
			return nil, err
		}
	}
	return sets, nil
}

func ScanLocalDirectory(root string) ([]ManagedRuleSet, error) {
	root = strings.TrimSpace(root)
	if root == "" {
		return nil, errors.New("rules directory is required")
	}
	info, err := os.Stat(root)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, errors.New("rules directory must be a directory")
	}

	var dirs []string
	if _, err := os.Stat(filepath.Join(root, MetadataFile)); err == nil {
		dirs = append(dirs, root)
	} else {
		entries, err := os.ReadDir(root)
		if err != nil {
			return nil, err
		}
		for _, entry := range entries {
			if entry.IsDir() {
				dirs = append(dirs, filepath.Join(root, entry.Name()))
			}
		}
	}
	sort.Strings(dirs)

	sets := make([]ManagedRuleSet, 0, len(dirs))
	for _, dir := range dirs {
		set, err := scanRuleSet(dir)
		if err != nil {
			return nil, err
		}
		sets = append(sets, set)
	}
	return sets, nil
}

func scanRuleSet(dir string) (ManagedRuleSet, error) {
	metadata, err := readMetadata(dir)
	if err != nil {
		return ManagedRuleSet{}, err
	}
	files, checksum, err := checksumDirectory(dir)
	if err != nil {
		return ManagedRuleSet{}, err
	}
	snapshot, err := json.Marshal(map[string]any{
		"files":      files,
		"scanned_at": time.Now().UTC().Format(time.RFC3339),
	})
	if err != nil {
		return ManagedRuleSet{}, err
	}
	return ManagedRuleSet{
		Name:        metadata.Name,
		Provider:    metadata.Provider,
		Source:      metadata.Source,
		Description: metadata.Description,
		LocalPath:   dir,
		Enabled:     metadata.Enabled,
		Metadata:    defaultRaw(metadata.Extra, `{}`),
		Version: ManagedVersion{
			Version:         metadata.Version,
			SourceURI:       "local://" + filepath.ToSlash(dir),
			LocalPath:       dir,
			ChecksumSHA256:  checksum,
			RulesetSnapshot: snapshot,
		},
	}, nil
}

func readMetadata(dir string) (Metadata, error) {
	data, err := os.ReadFile(filepath.Join(dir, MetadataFile))
	if err != nil {
		return Metadata{}, err
	}
	var metadata Metadata
	if err := json.Unmarshal(data, &metadata); err != nil {
		return Metadata{}, err
	}
	metadata.Name = strings.TrimSpace(metadata.Name)
	metadata.Provider = strings.TrimSpace(metadata.Provider)
	metadata.Source = strings.TrimSpace(metadata.Source)
	metadata.Version = strings.TrimSpace(metadata.Version)
	if metadata.Name == "" {
		return Metadata{}, errors.New("managed rule set name is required")
	}
	if metadata.Provider == "" {
		metadata.Provider = "local"
	}
	if metadata.Source == "" {
		metadata.Source = "local"
	}
	if metadata.Version == "" {
		return Metadata{}, errors.New("managed rule set version is required")
	}
	return metadata, nil
}

func checksumDirectory(dir string) ([]string, string, error) {
	var files []string
	if err := filepath.WalkDir(dir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if rel == MetadataFile {
			return nil
		}
		if !strings.HasSuffix(rel, ".conf") && !strings.HasSuffix(rel, ".data") && !strings.HasSuffix(rel, ".txt") {
			return nil
		}
		files = append(files, rel)
		return nil
	}); err != nil {
		return nil, "", err
	}
	sort.Strings(files)

	hash := sha256.New()
	for _, rel := range files {
		hash.Write([]byte(rel))
		hash.Write([]byte{0})
		file, err := os.Open(filepath.Join(dir, filepath.FromSlash(rel)))
		if err != nil {
			return nil, "", err
		}
		if _, err := io.Copy(hash, file); err != nil {
			_ = file.Close()
			return nil, "", err
		}
		if err := file.Close(); err != nil {
			return nil, "", err
		}
		hash.Write([]byte{0})
	}
	return files, hex.EncodeToString(hash.Sum(nil)), nil
}

func defaultRaw(value json.RawMessage, fallback string) json.RawMessage {
	if len(value) == 0 {
		return json.RawMessage(fallback)
	}
	return value
}
