package arch

import (
	"encoding/json"
	"os/exec"
	"strings"
	"testing"
)

type listPkg struct {
	ImportPath string
	Deps       []string
}

func pkgInfo(t *testing.T, importPath string) listPkg {
	t.Helper()
	out, err := exec.Command("go", "list", "-json", importPath).Output()
	if err != nil {
		t.Fatalf("go list %s: %v", importPath, err)
	}
	var p listPkg
	if err := json.Unmarshal(out, &p); err != nil {
		t.Fatalf("decode go list output: %v", err)
	}
	return p
}

func TestCorePurity(t *testing.T) {
	targets := []string{
		mainModule + "/internal/ports",
		mainModule + "/internal/core",
		mainModule + "/internal/flagstore",
		mainModule + "/internal/detect/denylist",
		mainModule + "/internal/detect/honeypot",
		mainModule + "/internal/detect/browserhint",
		mainModule + "/internal/generate/labyrinth",
		mainModule + "/internal/generate/bomb",
		mainModule + "/internal/generate/poison",
		mainModule + "/internal/generate/poison/babble",
		mainModule + "/internal/generate/poison/article",
		mainModule + "/internal/generate/poison/canary",
		mainModule + "/internal/pow",
	}

	for _, target := range targets {
		info := pkgInfo(t, target)
		for _, dep := range info.Deps {
			switch {
			case dep == "net/http" || strings.HasPrefix(dep, "net/http/"):
				t.Errorf("%s illegally depends on transport package %s", target, dep)
			case strings.Contains(dep, "/internal/adapters"):
				t.Errorf("%s illegally depends on adapter package %s", target, dep)
			case strings.HasSuffix(dep, "/internal/config"):
				t.Errorf("%s illegally depends on config package %s", target, dep)
			case strings.HasSuffix(dep, "/internal/clientip"):
				t.Errorf("%s illegally depends on clientip package %s", target, dep)
			}
		}
	}
}
