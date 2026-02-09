package version

import (
	"os/exec"
	"strings"
	"sync"
)

var buildName string
var buildVersion string

var gitOnce sync.Once
var gitVersion string

func detectGitVersion() {
	// Try tag-based version first
	if out, err := exec.Command("git", "describe", "--tags", "--match=v[0-9]*.[0-9]*.[0-9]*").Output(); err == nil {
		gitVersion = strings.TrimSpace(string(out))
		return
	}
	// Fall back to short SHA
	if out, err := exec.Command("git", "rev-parse", "--short", "HEAD").Output(); err == nil {
		gitVersion = "dev-" + strings.TrimSpace(string(out))
	}
}

// BuildName gets the current build name. This is usually injected if built
// from git, or returns "unknown" otherwise.
func BuildName() string {
	if buildName == "" {
		return "unknown"
	}
	return buildName
}

// BuildVersion gets the current build version. This is usually injected if
// built from git, or returns "unknown" otherwise. Falls back to git SHA.
func BuildVersion() string {
	if buildVersion != "" {
		return buildVersion
	}
	gitOnce.Do(detectGitVersion)
	if gitVersion != "" {
		return gitVersion
	}
	return "unknown"
}
