package rules

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestScanLocalDirectoryParsesMetadataAndChecksum(t *testing.T) {
	root := t.TempDir()
	ruleSetDir := filepath.Join(root, "owasp-crs")
	if err := os.Mkdir(ruleSetDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	writeFile(t, filepath.Join(ruleSetDir, MetadataFile), `{
		"name":"OWASP CRS Local",
		"provider":"owasp",
		"source":"local",
		"version":"4.0.0-local",
		"description":"Local CRS mirror",
		"enabled":true
	}`)
	writeFile(t, filepath.Join(ruleSetDir, "REQUEST-901.conf"), `SecRuleEngine DetectionOnly`)

	sets, err := ScanLocalDirectory(root)
	if err != nil {
		t.Fatalf("ScanLocalDirectory() error = %v", err)
	}
	if len(sets) != 1 {
		t.Fatalf("sets = %d, want 1", len(sets))
	}
	set := sets[0]
	if set.Name != "OWASP CRS Local" || set.Provider != "owasp" || set.Source != "local" || !set.Enabled {
		t.Fatalf("set metadata = %+v", set)
	}
	if set.Version.Version != "4.0.0-local" || set.Version.ChecksumSHA256 == "" {
		t.Fatalf("version metadata = %+v", set.Version)
	}
}

func TestChecksumChangesWhenRuleFileChanges(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, MetadataFile), `{"name":"Test Rules","version":"v1"}`)
	rulePath := filepath.Join(dir, "REQUEST-test.conf")
	writeFile(t, rulePath, `one`)

	first, err := ScanLocalDirectory(dir)
	if err != nil {
		t.Fatalf("first scan: %v", err)
	}
	writeFile(t, rulePath, `two`)
	second, err := ScanLocalDirectory(dir)
	if err != nil {
		t.Fatalf("second scan: %v", err)
	}
	if first[0].Version.ChecksumSHA256 == second[0].Version.ChecksumSHA256 {
		t.Fatal("checksum did not change after rule file update")
	}
}

func TestScanAndRecordCallsRecorder(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, MetadataFile), `{"name":"Test Rules","version":"v1"}`)
	writeFile(t, filepath.Join(dir, "REQUEST-test.conf"), `SecAction "id:1,pass"`)
	recorder := &memoryRecorder{}

	if _, err := ScanAndRecord(context.Background(), dir, recorder); err != nil {
		t.Fatalf("ScanAndRecord() error = %v", err)
	}
	if len(recorder.sets) != 1 || recorder.sets[0].Name != "Test Rules" {
		t.Fatalf("recorded sets = %+v", recorder.sets)
	}
}

type memoryRecorder struct {
	sets []ManagedRuleSet
}

func (m *memoryRecorder) RecordManagedRuleSet(_ context.Context, set ManagedRuleSet) error {
	m.sets = append(m.sets, set)
	return nil
}

func writeFile(t *testing.T, path string, data string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
