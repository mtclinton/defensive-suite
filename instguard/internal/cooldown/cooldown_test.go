package cooldown

import (
	"testing"
	"time"

	"github.com/mtclinton/defensive-suite/instguard/internal/report"
)

var now = time.Date(2026, 6, 19, 12, 0, 0, 0, time.UTC)

func TestTooFresh(t *testing.T) {
	tests := []struct {
		name      string
		published time.Time
		days      int
		want      bool
	}{
		{"published today, 3d window", now.Add(-1 * time.Hour), 3, true},
		{"published 2d ago, 3d window", now.Add(-48 * time.Hour), 3, true},
		{"published exactly 3d ago", now.Add(-72 * time.Hour), 3, false}, // boundary: age==window is NOT < window
		{"published 4d ago, 3d window", now.Add(-96 * time.Hour), 3, false},
		{"published in the future", now.Add(24 * time.Hour), 3, true},
		{"zero window disables", now.Add(-1 * time.Hour), 0, false},
		{"negative window disables", now.Add(-1 * time.Hour), -1, false},
		{"unknown publish date", time.Time{}, 3, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := TooFresh(tc.published, now, tc.days); got != tc.want {
				t.Errorf("TooFresh=%v want %v", got, tc.want)
			}
		})
	}
}

func TestAgeDays(t *testing.T) {
	if got := AgeDays(now.Add(-50*time.Hour), now); got != 2 {
		t.Errorf("AgeDays=%d want 2", got)
	}
	if got := AgeDays(now.Add(24*time.Hour), now); got != -1 {
		t.Errorf("future AgeDays=%d want -1", got)
	}
}

func TestCheckFreshProducesMedium(t *testing.T) {
	f := Check(Release{Package: "fresh-pkg", Version: "9.9.9", PublishedAt: now.Add(-12 * time.Hour)}, now, 3)
	if len(f) != 1 {
		t.Fatalf("want 1 finding, got %+v", f)
	}
	if f[0].Severity != report.SeverityMedium || f[0].Package != "fresh-pkg" {
		t.Errorf("finding=%+v", f[0])
	}
}

func TestCheckFutureDateDetail(t *testing.T) {
	f := Check(Release{Package: "skewed", Version: "1.0.0", PublishedAt: now.Add(48 * time.Hour)}, now, 3)
	if len(f) != 1 {
		t.Fatalf("future date should flag: %+v", f)
	}
	if want := "in the future"; !contains(f[0].Detail, want) {
		t.Errorf("detail %q missing %q", f[0].Detail, want)
	}
}

func TestCheckOldIsClean(t *testing.T) {
	if f := Check(Release{Package: "old", Version: "1", PublishedAt: now.Add(-30 * 24 * time.Hour)}, now, 3); len(f) != 0 {
		t.Errorf("old release should be clean: %+v", f)
	}
}

func TestCheckAllBatch(t *testing.T) {
	rels := []Release{
		{Package: "a", Version: "1", PublishedAt: now.Add(-1 * time.Hour)},   // fresh
		{Package: "b", Version: "1", PublishedAt: now.Add(-100 * time.Hour)}, // old
		{Package: "c", Version: "1", PublishedAt: now.Add(-2 * time.Hour)},   // fresh
	}
	f := CheckAll(rels, now, 3)
	if len(f) != 2 {
		t.Errorf("want 2 fresh findings, got %d: %+v", len(f), f)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
