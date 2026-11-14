package arch

import (
	"encoding/json"
	"os/exec"
	"strings"
	"testing"
)

// allowedModules is the dependency allowlist (Global Constraints).
// Add a module here ONLY when the design doc sanctions it.
var allowedModules = map[string]bool{
	"gopkg.in/yaml.v3": true,
	// "golang.org/x/crypto": true, // reserved for the autocert slice (not yet)
}

const mainModule = "github.com/datadir-lab/henbane"

type depPkg struct {
	Standard bool
	Module   *struct {
		Path string
	}
}

func TestDependencyAllowlist(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", "-json", mainModule+"/...").Output()
	if err != nil {
		t.Fatalf("go list -deps: %v", err)
	}
	dec := json.NewDecoder(strings.NewReader(string(out)))
	seen := map[string]bool{}
	for dec.More() {
		var p depPkg
		if err := dec.Decode(&p); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if p.Standard || p.Module == nil {
			continue
		}
		mp := p.Module.Path
		if mp == mainModule || allowedModules[mp] || seen[mp] {
			continue
		}
		seen[mp] = true
		t.Errorf("disallowed third-party dependency imported: %s (update allowlist only if sanctioned by the design doc)", mp)
	}
}
