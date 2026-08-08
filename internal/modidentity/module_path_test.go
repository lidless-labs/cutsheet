package modidentity_test

import (
	"bytes"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const canonicalModule = "github.com/lidless-labs/cutsheet"

// legacyModule is built from parts so a bulk path rewrite cannot neutralize the guard.
var legacyModule = strings.Join([]string{"github.com", "solomonneas", "cutsheet"}, "/")

func TestGoModDeclaresCanonicalModule(t *testing.T) {
	root := moduleRoot(t)
	data, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		t.Fatalf("read go.mod: %v", err)
	}
	mod, ok := modulePath(data)
	if !ok {
		t.Fatal("go.mod has no module declaration")
	}
	if mod != canonicalModule {
		t.Fatalf("go.mod module = %q, want %q", mod, canonicalModule)
	}
	if strings.Contains(string(data), legacyModule) {
		t.Fatalf("go.mod still mentions legacy module path %q", legacyModule)
	}
}

func TestGoSourcesDoNotImportLegacyModule(t *testing.T) {
	root := moduleRoot(t)
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			if name == "vendor" || name == "node_modules" || name == ".git" || name == "web" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		f, parseErr := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if parseErr != nil {
			t.Errorf("parse %s: %v", path, parseErr)
			return nil
		}
		for _, imp := range f.Imports {
			pathLit := strings.Trim(imp.Path.Value, `"`)
			if pathLit == legacyModule || strings.HasPrefix(pathLit, legacyModule+"/") {
				rel, _ := filepath.Rel(root, path)
				t.Errorf("%s imports legacy module path %q", rel, pathLit)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getcwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found from test working directory")
		}
		dir = parent
	}
}

func modulePath(goMod []byte) (string, bool) {
	for _, line := range bytes.Split(goMod, []byte("\n")) {
		line = bytes.TrimSpace(line)
		if !bytes.HasPrefix(line, []byte("module ")) {
			continue
		}
		return string(bytes.TrimSpace(bytes.TrimPrefix(line, []byte("module ")))), true
	}
	return "", false
}
