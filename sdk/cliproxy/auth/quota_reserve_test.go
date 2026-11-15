package auth

import (
	"errors"
	"net/http"
	"testing"
	"time"
)

func quotaReserveTestAuth(id string, priority string, reserve map[string]any, usage map[string]QuotaReserveWindow) *Auth {
	auth := &Auth{
		ID:         id,
		Provider:   "claude",
		Status:     StatusActive,
		Attributes: map[string]string{},
		Metadata:   map[string]any{"type": "claude"},
	}
	if priority != "" {
		auth.Attributes["priority"] = priority
	}
	if reserve != nil {
		auth.Metadata[QuotaReserveMetadataKey] = reserve
	}
	if usage != nil {
		auth.quotaReserveUsage = &QuotaReserveUsage{Windows: usage}
	}
	return auth
}

func TestParseClaudeQuotaReserveUsage(t *testing.T) {
	body := []byte(`{
		"five_hour": {"utilization": 12.5, "resets_at": "2026-11-15T03:00:00+00:00"},
		"seven_day": {"utilization": 48, "resets_at": "2026-11-20T12:00:00Z"},
		"seven_day_opus": null,
		"limits": [
			{"kind": "weekly_scoped", "percent": 30, "is_active": false, "resets_at": "2026-11-19T00:00:00Z", "scope": {"model": {"display_name": "Fable 5"}}},
			{"kind": "weekly_scoped", "percent": 61, "is_active": true, "resets_at": "2026-11-20T12:00:00Z", "scope": {"model": {"display_name": "Fable"}}},
			{"kind": "weekly_scoped", "percent": 99, "is_active": true, "resets_at": "2026-11-20T12:00:00Z", "scope": {"model": {"display_name": "Sonnet"}}}
		]
	}`)
	usage, err := ParseClaudeQuotaReserveUsage(body, time.Unix(1, 0))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	cases := map[string]float64{
		QuotaReserveFiveHour:      12.5,
		QuotaReserveSevenDay:      48,
		QuotaReserveSevenDayFable: 61,
	}
	for window, want := range cases {
		got, ok := usage.Windows[window]
		if !ok || got.UsedPercent != want || got.ResetsAt.IsZero() {
			t.Fatalf("window %s = %+v (present %v), want used %v", window, got, ok, want)
		}
	}
	if _, err = ParseClaudeQuotaReserveUsage([]byte("not json"), time.Now()); err == nil {
		t.Fatal("expected invalid JSON error")
	}
}

func TestQuotaReserveBlockUntil(t *testing.T) {
	now := time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC)
	weeklyReset := now.Add(5 * 24 * time.Hour)
	fableReset := now.Add(4 * 24 * time.Hour)
	usage := map[string]QuotaReserveWindow{
		QuotaReserveSevenDay:      {UsedPercent: 40, ResetsAt: weeklyReset},
		QuotaReserveSevenDayFable: {UsedPercent: 50, ResetsAt: fableReset},
	}

	fableOnly := quotaReserveTestAuth("a", "", map[string]any{QuotaReserveSevenDayFable: 50.0}, usage)
	if got := quotaReserveBlockUntil(fableOnly, "claude-fable-5-1", now); !got.Equal(fableReset) {
		t.Fatalf("fable model at reserve: got %v, want %v", got, fableReset)
	}
	if got := quotaReserveBlockUntil(fableOnly, "claude-opus-5-5", now); !got.IsZero() {
		t.Fatalf("fable reserve must not gate other models, got %v", got)
	}

	weekly := quotaReserveTestAuth("b", "", map[string]any{QuotaReserveSevenDay: 50.0}, usage)
	if got := quotaReserveBlockUntil(weekly, "claude-opus-5-5", now); !got.IsZero() {
		t.Fatalf("60%% remaining above 50%% reserve must not block, got %v", got)
	}
	weekly.Metadata[QuotaReserveMetadataKey] = map[string]any{QuotaReserveSevenDay: 60.0}
	if got := quotaReserveBlockUntil(weekly, "claude-opus-5-5", now); !got.Equal(weeklyReset) {
		t.Fatalf("remaining at reserve must block until reset, got %v", got)
	}
	if got := quotaReserveBlockUntil(weekly, "claude-opus-5-5", weeklyReset); !got.IsZero() {
		t.Fatalf("elapsed window must not block, got %v", got)
	}

	codex := quotaReserveTestAuth("c", "", map[string]any{QuotaReserveSevenDay: 90.0}, usage)
	codex.Provider = "codex"
	if got := quotaReserveBlockUntil(codex, "gpt-6.1-sol", now); !got.IsZero() {
		t.Fatalf("reserves apply only to Claude OAuth credentials, got %v", got)
	}

	noUsage := quotaReserveTestAuth("d", "", map[string]any{QuotaReserveSevenDay: 90.0}, nil)
	if got := quotaReserveBlockUntil(noUsage, "claude-opus-5-5", now); !got.IsZero() {
		t.Fatalf("unknown usage must not block, got %v", got)
	}
}

func TestQuotaReserveFailsOverToBackupAndReturnsLimitError(t *testing.T) {
	now := time.Now()
	reset := now.Add(3 * time.Hour)
	primary := quotaReserveTestAuth("primary", "", map[string]any{QuotaReserveFiveHour: 10.0},
		map[string]QuotaReserveWindow{QuotaReserveFiveHour: {UsedPercent: 92, ResetsAt: reset}})
	backup := quotaReserveTestAuth("backup", "-10", nil, nil)

	manager := NewManager(nil, nil, nil)
	available, err := manager.availableAuthsForRouteModel([]*Auth{primary, backup}, "claude", "claude-opus-5-5", now)
	if err != nil {
		t.Fatalf("expected backup to be available: %v", err)
	}
	if len(available) != 1 || available[0].ID != "backup" {
		t.Fatalf("expected only backup credential, got %d candidates", len(available))
	}

	fableReset := now.Add(48 * time.Hour)
	fableAuth := quotaReserveTestAuth("fable", "-10", map[string]any{QuotaReserveSevenDayFable: 50.0},
		map[string]QuotaReserveWindow{QuotaReserveSevenDayFable: {UsedPercent: 55, ResetsAt: fableReset}})
	_, err = manager.availableAuthsForRouteModel([]*Auth{fableAuth}, "claude", "claude-fable-5-1", now)
	var cooldown *modelCooldownError
	if !errors.As(err, &cooldown) {
		t.Fatalf("expected model cooldown error, got %v", err)
	}
	if cooldown.StatusCode() != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", cooldown.StatusCode())
	}
	if cooldown.resetIn <= 47*time.Hour {
		t.Fatalf("reset hint %v should point at the Fable window reset", cooldown.resetIn)
	}
}

func TestSetQuotaReserveUsageSurvivesAuthUpdate(t *testing.T) {
	manager := NewManager(nil, nil, nil)
	auth := quotaReserveTestAuth("claude-x", "", map[string]any{QuotaReserveSevenDay: 50.0}, nil)
	if _, err := manager.Register(WithSkipPersist(t.Context()), auth); err != nil {
		t.Fatalf("register: %v", err)
	}
	usage := &QuotaReserveUsage{Windows: map[string]QuotaReserveWindow{
		QuotaReserveSevenDay: {UsedPercent: 70, ResetsAt: time.Now().Add(time.Hour)},
	}, ObservedAt: time.Now()}
	manager.SetQuotaReserveUsage(auth.ID, usage)

	updated := auth.Clone()
	updated.quotaReserveUsage = nil
	if _, err := manager.Update(WithSkipPersist(t.Context()), updated); err != nil {
		t.Fatalf("update: %v", err)
	}
	if got := manager.QuotaReserveUsageSnapshot(auth.ID); got != usage {
		t.Fatal("usage snapshot must be preserved across auth updates")
	}
	current, _ := manager.GetByID(auth.ID)
	if IsAuthAvailableForModel(current, "claude-opus-5-5", time.Now()) {
		t.Fatal("credential below its weekly reserve must be unavailable")
	}
}
