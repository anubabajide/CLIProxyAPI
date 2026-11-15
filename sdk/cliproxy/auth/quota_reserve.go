package auth

import (
	"context"
	"fmt"
	"io"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/MoeForge/moego/ojson"
	log "github.com/sirupsen/logrus"
)

// Quota reserves keep a credential out of rotation once a usage window's remaining
// percentage drops to a configured floor. The floor is stored per credential in the
// auth file metadata, for example:
//
//	"quota_reserve": {"five_hour": 10, "seven_day": 50, "seven_day_fable": 50}
//
// Each value is the minimum remaining percentage (0-100) to preserve. A credential at
// or below its floor is treated as cooling down until that window resets. The
// "seven_day_fable" window only gates Fable models; the others gate every model.
const (
	QuotaReserveMetadataKey   = "quota_reserve"
	QuotaReserveFiveHour      = "five_hour"
	QuotaReserveSevenDay      = "seven_day"
	QuotaReserveSevenDayFable = "seven_day_fable"

	claudeUsageURL = "https://api.anthropic.com/api/oauth/usage"

	quotaReserveTickInterval = 30 * time.Second
	quotaReservePollInterval = 2 * time.Minute
	// quotaReserveFetchTimeout bounds the standalone usage probe; it is not part of any
	// proxied request.
	quotaReserveFetchTimeout = 30 * time.Second
)

// QuotaReserveWindows lists the configurable reserve windows in display order.
var QuotaReserveWindows = []string{QuotaReserveFiveHour, QuotaReserveSevenDay, QuotaReserveSevenDayFable}

// QuotaReserveWindow is one observed usage window.
type QuotaReserveWindow struct {
	UsedPercent float64
	ResetsAt    time.Time
}

// QuotaReserveUsage is the latest usage snapshot observed for a credential.
// Snapshots are immutable once attached to an Auth.
type QuotaReserveUsage struct {
	Windows    map[string]QuotaReserveWindow
	ObservedAt time.Time
}

// IsQuotaReserveWindow reports whether name is a supported reserve window.
func IsQuotaReserveWindow(name string) bool {
	for _, window := range QuotaReserveWindows {
		if window == name {
			return true
		}
	}
	return false
}

// QuotaReserveLimits returns the configured reserves keyed by window. Invalid or
// non-positive entries are ignored.
func QuotaReserveLimits(auth *Auth) map[string]float64 {
	if auth == nil || auth.Metadata == nil {
		return nil
	}
	raw, ok := auth.Metadata[QuotaReserveMetadataKey].(map[string]any)
	if !ok || len(raw) == 0 {
		return nil
	}
	limits := make(map[string]float64, len(raw))
	for window, value := range raw {
		if !IsQuotaReserveWindow(window) {
			continue
		}
		reserve, okReserve := quotaReserveNumber(value)
		if !okReserve || reserve <= 0 || reserve > 100 {
			continue
		}
		limits[window] = reserve
	}
	if len(limits) == 0 {
		return nil
	}
	return limits
}

func quotaReserveNumber(value any) (float64, bool) {
	var parsed float64
	switch v := value.(type) {
	case float64:
		parsed = v
	case float32:
		parsed = float64(v)
	case int:
		parsed = float64(v)
	case int64:
		parsed = float64(v)
	case interface{ Float64() (float64, error) }:
		f, errFloat := v.Float64()
		if errFloat != nil {
			return 0, false
		}
		parsed = f
	case string:
		f, errParse := strconv.ParseFloat(strings.TrimSpace(v), 64)
		if errParse != nil {
			return 0, false
		}
		parsed = f
	default:
		return 0, false
	}
	if math.IsNaN(parsed) || math.IsInf(parsed, 0) {
		return 0, false
	}
	return parsed, true
}

func quotaReserveSupported(auth *Auth) bool {
	return auth != nil && strings.EqualFold(strings.TrimSpace(auth.Provider), "claude") && auth.AuthKind() != AuthKindAPIKey
}

func isFableModel(model string) bool {
	return strings.Contains(canonicalModelLookupKey(model), "fable")
}

// quotaReserveBlockUntil reports when the latest exhausted reserve window applicable to
// model resets, or the zero time when no reserve currently blocks the credential.
func quotaReserveBlockUntil(auth *Auth, model string, now time.Time) time.Time {
	if auth == nil || auth.quotaReserveUsage == nil || !quotaReserveSupported(auth) {
		return time.Time{}
	}
	limits := QuotaReserveLimits(auth)
	if len(limits) == 0 {
		return time.Time{}
	}
	var until time.Time
	for window, reserve := range limits {
		if window == QuotaReserveSevenDayFable && !isFableModel(model) {
			continue
		}
		observed, ok := auth.quotaReserveUsage.Windows[window]
		if !ok || !observed.ResetsAt.After(now) {
			continue
		}
		if 100-observed.UsedPercent <= reserve && observed.ResetsAt.After(until) {
			until = observed.ResetsAt
		}
	}
	return until
}

// QuotaReserveUsageSnapshot returns the latest usage snapshot recorded for authID.
func (m *Manager) QuotaReserveUsageSnapshot(authID string) *QuotaReserveUsage {
	if m == nil {
		return nil
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if auth := m.auths[authID]; auth != nil {
		return auth.quotaReserveUsage
	}
	return nil
}

// SetQuotaReserveUsage records a usage snapshot and re-evaluates scheduling for the auth.
func (m *Manager) SetQuotaReserveUsage(authID string, usage *QuotaReserveUsage) {
	if m == nil || authID == "" {
		return
	}
	m.mu.Lock()
	auth := m.auths[authID]
	if auth == nil {
		m.mu.Unlock()
		return
	}
	auth.quotaReserveUsage = usage
	snapshot := auth.Clone()
	m.mu.Unlock()
	if m.scheduler != nil {
		m.scheduler.upsertAuth(snapshot)
	}
}

// StartQuotaReservePoller periodically refreshes usage for credentials with reserves.
func (m *Manager) StartQuotaReservePoller(ctx context.Context) {
	if m == nil {
		return
	}
	go func() {
		ticker := time.NewTicker(quotaReserveTickInterval)
		defer ticker.Stop()
		m.pollQuotaReserves(ctx, time.Now())
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				m.pollQuotaReserves(ctx, time.Now())
			}
		}
	}()
}

func (m *Manager) pollQuotaReserves(ctx context.Context, now time.Time) {
	for _, auth := range m.List() {
		if ctx.Err() != nil {
			return
		}
		if auth == nil || auth.Disabled || !quotaReserveSupported(auth) || len(QuotaReserveLimits(auth)) == 0 {
			continue
		}
		if last := m.QuotaReserveUsageSnapshot(auth.ID); last != nil && now.Sub(last.ObservedAt) < quotaReservePollInterval {
			continue
		}
		usage, errFetch := m.fetchClaudeQuotaReserveUsage(ctx, auth)
		if errFetch != nil {
			log.WithField("auth", auth.ID).Warnf("quota reserve: usage refresh failed: %v", errFetch)
			continue
		}
		m.SetQuotaReserveUsage(auth.ID, usage)
		if until := quotaReserveBlockUntil(m.authSnapshot(auth.ID), "", now); !until.IsZero() {
			log.WithField("auth", auth.ID).Infof("quota reserve reached; credential paused until %s", until.Format(time.RFC3339))
		}
	}
}

func (m *Manager) authSnapshot(authID string) *Auth {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if auth := m.auths[authID]; auth != nil {
		return auth.Clone()
	}
	return nil
}

func (m *Manager) fetchClaudeQuotaReserveUsage(ctx context.Context, auth *Auth) (*QuotaReserveUsage, error) {
	reqCtx, cancel := context.WithTimeout(ctx, quotaReserveFetchTimeout)
	defer cancel()
	headers := http.Header{}
	headers.Set("Accept", "application/json")
	headers.Set("anthropic-beta", "oauth-2025-04-20")
	headers.Set("User-Agent", "claude-cli/2.1.280 (external, cli)")
	req, errReq := m.NewHttpRequest(reqCtx, auth, http.MethodGet, claudeUsageURL, nil, headers)
	if errReq != nil {
		return nil, errReq
	}
	resp, errDo := m.HttpRequest(reqCtx, auth, req)
	if errDo != nil {
		return nil, errDo
	}
	defer func() {
		if errClose := resp.Body.Close(); errClose != nil {
			log.Errorf("quota reserve: close usage response: %v", errClose)
		}
	}()
	body, errRead := io.ReadAll(resp.Body)
	if errRead != nil {
		return nil, fmt.Errorf("read usage response: %w", errRead)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("usage endpoint returned HTTP %d", resp.StatusCode)
	}
	return ParseClaudeQuotaReserveUsage(body, time.Now())
}

// ParseClaudeQuotaReserveUsage extracts reserve windows from an Anthropic OAuth usage payload.
func ParseClaudeQuotaReserveUsage(body []byte, observedAt time.Time) (*QuotaReserveUsage, error) {
	if !ojson.ValidBytes(body) {
		return nil, fmt.Errorf("usage response is not valid JSON")
	}
	usage := &QuotaReserveUsage{Windows: make(map[string]QuotaReserveWindow), ObservedAt: observedAt}
	for _, key := range []string{QuotaReserveFiveHour, QuotaReserveSevenDay} {
		window := ojson.GetBytesNoCopy(body, key)
		if window.IsObject() {
			if parsed, ok := parseQuotaReserveWindow(window.Get("utilization"), window.Get("resets_at")); ok {
				usage.Windows[key] = parsed
			}
		}
	}
	if fable, ok := claudeFableUsageLimit(ojson.GetBytesNoCopy(body, "limits")); ok {
		usage.Windows[QuotaReserveSevenDayFable] = fable
	}
	return usage, nil
}

// claudeFableUsageLimit mirrors the management panel: prefer the active weekly Fable
// scoped limit, otherwise the first one.
func claudeFableUsageLimit(limits ojson.Result) (QuotaReserveWindow, bool) {
	var first *QuotaReserveWindow
	for _, limit := range limits.Array() {
		if !strings.EqualFold(strings.TrimSpace(limit.Get("kind").String()), "weekly_scoped") {
			continue
		}
		name := strings.ToLower(strings.TrimSpace(limit.Get("scope.model.display_name").String()))
		if name != "fable" && name != "fable 5" {
			continue
		}
		parsed, ok := parseQuotaReserveWindow(limit.Get("percent"), limit.Get("resets_at"))
		if !ok {
			continue
		}
		if limit.Get("is_active").Bool() {
			return parsed, true
		}
		if first == nil {
			first = &parsed
		}
	}
	if first == nil {
		return QuotaReserveWindow{}, false
	}
	return *first, true
}

func parseQuotaReserveWindow(used, resetsAt ojson.Result) (QuotaReserveWindow, bool) {
	if !used.Exists() || used.Type == ojson.Null {
		return QuotaReserveWindow{}, false
	}
	percent := used.Float()
	if math.IsNaN(percent) || math.IsInf(percent, 0) {
		return QuotaReserveWindow{}, false
	}
	resetAt, errParse := time.Parse(time.RFC3339Nano, strings.TrimSpace(resetsAt.String()))
	if errParse != nil {
		return QuotaReserveWindow{}, false
	}
	return QuotaReserveWindow{UsedPercent: percent, ResetsAt: resetAt}, true
}
