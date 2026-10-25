package releaseplan

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const testVersion = "1.2.3"

type gitFixture struct {
	env    []string
	origin string
	work   string
	sha    string
}

func TestReleasePlanner(t *testing.T) {
	t.Run("new tag", func(t *testing.T) {
		fixture := newGitFixture(t)

		outputs := fixture.plan(t, fixture.sha)

		assertOutputs(t, outputs, true, true)
	})

	for _, tagType := range []string{"lightweight", "annotated"} {
		t.Run("matching "+tagType+" tag", func(t *testing.T) {
			fixture := newGitFixture(t)
			fixture.publishTag(t, tagType, fixture.sha)

			outputs := fixture.plan(t, fixture.sha)

			assertOutputs(t, outputs, true, false)
		})
	}

	t.Run("tag on different commit", func(t *testing.T) {
		fixture := newGitFixture(t)
		fixture.publishTag(t, "lightweight", fixture.sha)
		laterSHA := fixture.commit(t, "later main commit")

		outputs := fixture.plan(t, laterSHA)

		assertOutputs(t, outputs, false, false)
	})

	t.Run("remote lookup failure", func(t *testing.T) {
		fixture := newGitFixture(t)
		missingOrigin := filepath.Join(t.TempDir(), "missing.git")
		fixture.git(t, "remote", "set-url", "origin", missingOrigin)
		outputFile := filepath.Join(t.TempDir(), "github-output")

		output, err := fixture.runPlanner(fixture.sha, outputFile)
		if err == nil {
			t.Fatalf("planner succeeded for unavailable remote:\n%s", output)
		}
		if !strings.Contains(output, "Unable to inspect remote tag") {
			t.Fatalf("planner did not report remote lookup failure:\n%s", output)
		}
		if data, readErr := os.ReadFile(outputFile); readErr == nil && len(data) != 0 {
			t.Fatalf("planner wrote outputs after remote lookup failure:\n%s", data)
		} else if readErr != nil && !os.IsNotExist(readErr) {
			t.Fatalf("read planner output: %v", readErr)
		}
	})
}

func newGitFixture(t *testing.T) *gitFixture {
	t.Helper()

	root := t.TempDir()
	fixture := &gitFixture{
		env:    isolatedGitEnvironment(t.TempDir()),
		origin: filepath.Join(root, "origin.git"),
		work:   filepath.Join(root, "work"),
	}

	fixture.command(t, root, "git", "init", "--bare", fixture.origin)
	fixture.command(t, root, "git", "init", "--initial-branch=main", fixture.work)
	fixture.git(t, "config", "user.name", "Release Plan Test")
	fixture.git(t, "config", "user.email", "release-plan@example.invalid")
	fixture.git(t, "config", "commit.gpgSign", "false")
	fixture.git(t, "config", "tag.gpgSign", "false")
	fixture.git(t, "remote", "add", "origin", fixture.origin)

	if err := os.WriteFile(filepath.Join(fixture.work, "VERSION"), []byte(testVersion+"\n"), 0o600); err != nil {
		t.Fatalf("write VERSION: %v", err)
	}
	if err := os.WriteFile(filepath.Join(fixture.work, "content.txt"), []byte("release content\n"), 0o600); err != nil {
		t.Fatalf("write content: %v", err)
	}
	fixture.git(t, "add", "VERSION", "content.txt")
	fixture.git(t, "commit", "-m", "release commit")
	fixture.sha = strings.TrimSpace(fixture.git(t, "rev-parse", "HEAD"))
	fixture.git(t, "push", "--set-upstream", "origin", "main")

	return fixture
}

func (f *gitFixture) publishTag(t *testing.T, tagType, sha string) {
	t.Helper()

	tag := "v" + testVersion
	switch tagType {
	case "lightweight":
		f.git(t, "tag", tag, sha)
	case "annotated":
		f.git(t, "tag", "-a", "-m", "release "+tag, tag, sha)
	default:
		t.Fatalf("unsupported tag type %q", tagType)
	}
	f.git(t, "push", "origin", "refs/tags/"+tag)
	f.git(t, "tag", "--delete", tag)
}

func (f *gitFixture) commit(t *testing.T, contents string) string {
	t.Helper()

	if err := os.WriteFile(filepath.Join(f.work, "content.txt"), []byte(contents+"\n"), 0o600); err != nil {
		t.Fatalf("update content: %v", err)
	}
	f.git(t, "add", "content.txt")
	f.git(t, "commit", "-m", contents)
	f.git(t, "push", "origin", "main")
	return strings.TrimSpace(f.git(t, "rev-parse", "HEAD"))
}

func (f *gitFixture) plan(t *testing.T, sha string) map[string]string {
	t.Helper()

	outputFile := filepath.Join(t.TempDir(), "github-output")
	output, err := f.runPlanner(sha, outputFile)
	if err != nil {
		t.Fatalf("planner failed: %v\n%s", err, output)
	}

	return readOutputs(t, outputFile)
}

func (f *gitFixture) runPlanner(sha, outputFile string) (string, error) {
	_, testFile, _, ok := runtime.Caller(0)
	if !ok {
		return "", fmt.Errorf("locate release planner test")
	}
	script := filepath.Join(filepath.Dir(testFile), "..", "..", "scripts", "plan-release.sh")
	cmd := exec.Command("/bin/bash", script)
	cmd.Dir = f.work
	cmd.Env = append(append([]string{}, f.env...),
		"GITHUB_SHA="+sha,
		"GITHUB_OUTPUT="+outputFile,
	)
	output, err := cmd.CombinedOutput()
	return string(output), err
}

func (f *gitFixture) git(t *testing.T, args ...string) string {
	t.Helper()
	return f.command(t, f.work, "git", args...)
}

func (f *gitFixture) command(t *testing.T, dir, name string, args ...string) string {
	t.Helper()

	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	cmd.Env = f.env
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s failed: %v\n%s", name, strings.Join(args, " "), err, output)
	}
	return string(output)
}

func isolatedGitEnvironment(home string) []string {
	blocked := map[string]bool{
		"GIT_CONFIG_GLOBAL":   true,
		"GIT_CONFIG_NOSYSTEM": true,
		"GIT_TERMINAL_PROMPT": true,
		"GITHUB_OUTPUT":       true,
		"GITHUB_SHA":          true,
		"HOME":                true,
		"XDG_CONFIG_HOME":     true,
	}

	env := make([]string, 0, len(os.Environ())+5)
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if !blocked[key] {
			env = append(env, entry)
		}
	}
	return append(env,
		"HOME="+home,
		"XDG_CONFIG_HOME="+filepath.Join(home, ".config"),
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_TERMINAL_PROMPT=0",
	)
}

func readOutputs(t *testing.T, path string) map[string]string {
	t.Helper()

	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("open planner output: %v", err)
	}
	defer file.Close()

	outputs := make(map[string]string)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		key, value, ok := strings.Cut(scanner.Text(), "=")
		if !ok {
			t.Fatalf("invalid planner output line %q", scanner.Text())
		}
		outputs[key] = value
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("read planner output: %v", err)
	}
	return outputs
}

func assertOutputs(t *testing.T, outputs map[string]string, shouldRelease, createTag bool) {
	t.Helper()

	want := map[string]string{
		"should_release": fmt.Sprint(shouldRelease),
		"create_tag":     fmt.Sprint(createTag),
		"version":        testVersion,
		"tag":            "v" + testVersion,
	}
	if len(outputs) != len(want) {
		t.Fatalf("planner outputs = %v, want %v", outputs, want)
	}
	for key, wantValue := range want {
		if got := outputs[key]; got != wantValue {
			t.Errorf("output %s = %q, want %q", key, got, wantValue)
		}
	}
}
