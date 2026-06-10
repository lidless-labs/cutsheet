package store

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestTokenLifecycle(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	n, err := s.CountTokens(ctx)
	if err != nil {
		t.Fatalf("CountTokens: %v", err)
	}
	if n != 0 {
		t.Fatalf("CountTokens on fresh store = %d, want 0", n)
	}

	tok, plaintext, err := s.CreateToken(ctx, "ci")
	if err != nil {
		t.Fatalf("CreateToken: %v", err)
	}
	if tok.ID == 0 || tok.Name != "ci" || tok.CreatedAt.IsZero() {
		t.Fatalf("token record: %+v", tok)
	}
	if !strings.HasPrefix(plaintext, "cst_") || len(plaintext) != len("cst_")+64 {
		t.Fatalf("plaintext shape: %q", plaintext)
	}

	tok2, plaintext2, err := s.CreateToken(ctx, "laptop")
	if err != nil {
		t.Fatalf("CreateToken second: %v", err)
	}
	if plaintext2 == plaintext {
		t.Fatal("two tokens with identical plaintext")
	}

	tokens, err := s.ListTokens(ctx)
	if err != nil {
		t.Fatalf("ListTokens: %v", err)
	}
	if len(tokens) != 2 || tokens[0].Name != "ci" || tokens[1].Name != "laptop" {
		t.Fatalf("ListTokens: %+v", tokens)
	}

	for _, tc := range []struct {
		token string
		want  bool
	}{
		{plaintext, true},
		{plaintext2, true},
		{"cst_" + strings.Repeat("0", 64), false},
		{"", false},
		{plaintext + "x", false},
	} {
		ok, err := s.ValidateToken(ctx, tc.token)
		if err != nil {
			t.Fatalf("ValidateToken(%q): %v", tc.token, err)
		}
		if ok != tc.want {
			t.Errorf("ValidateToken(%q) = %t, want %t", tc.token, ok, tc.want)
		}
	}

	if err := s.DeleteToken(ctx, tok.ID); err != nil {
		t.Fatalf("DeleteToken: %v", err)
	}
	if err := s.DeleteToken(ctx, tok.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("DeleteToken twice: err = %v, want ErrNotFound", err)
	}
	ok, err := s.ValidateToken(ctx, plaintext)
	if err != nil {
		t.Fatalf("ValidateToken after delete: %v", err)
	}
	if ok {
		t.Fatal("deleted token still validates")
	}

	n, err = s.CountTokens(ctx)
	if err != nil {
		t.Fatalf("CountTokens: %v", err)
	}
	if n != 1 {
		t.Fatalf("CountTokens after delete = %d, want 1", n)
	}
	_ = tok2
}

func TestListChangesMinSeverity(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	if err := s.CreateDevice(ctx, Device{ID: "gw1", Name: "gw1", Vendor: "auto", CollectorType: "file"}); err != nil {
		t.Fatalf("CreateDevice: %v", err)
	}
	for _, sev := range []string{"none", "low", "medium", "high", "low"} {
		if _, err := s.RecordChange(ctx, Change{DeviceID: "gw1", CommitHash: "c-" + sev, MaxSeverity: sev}); err != nil {
			t.Fatalf("RecordChange %s: %v", sev, err)
		}
	}

	tests := []struct {
		min  string
		want int
	}{
		{"", 5},
		{"none", 5},
		{"low", 4},
		{"medium", 2},
		{"high", 1},
		{"bogus", 5}, // unknown floor ranks as none: no filter
	}
	for _, tt := range tests {
		changes, err := s.ListChanges(ctx, ListChangesOptions{MinSeverity: tt.min})
		if err != nil {
			t.Fatalf("ListChanges(min=%q): %v", tt.min, err)
		}
		if len(changes) != tt.want {
			t.Errorf("ListChanges(min=%q) = %d changes, want %d", tt.min, len(changes), tt.want)
		}
	}

	// Filter composes with device + paging.
	changes, err := s.ListChanges(ctx, ListChangesOptions{DeviceID: "gw1", MinSeverity: "low", Limit: 2, Offset: 1})
	if err != nil {
		t.Fatalf("ListChanges combined: %v", err)
	}
	if len(changes) != 2 {
		t.Fatalf("combined filter = %d changes, want 2", len(changes))
	}
	for _, c := range changes {
		if SeverityRank(c.MaxSeverity) < SeverityRank("low") {
			t.Errorf("change %d severity %q below floor", c.ID, c.MaxSeverity)
		}
	}
}
