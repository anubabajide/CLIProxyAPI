package management

import (
	"encoding/json"
	"testing"

	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

func TestApplyAuthFileFieldsPatchQuotaReserve(t *testing.T) {
	auth := &coreauth.Auth{ID: "claude.json", Provider: "claude", Metadata: map[string]any{"type": "claude"}}
	patch := map[string]json.RawMessage{
		"quota_reserve": json.RawMessage(`{"five_hour": 10, "seven_day": 50.5, "seven_day_fable": 0}`),
	}
	if err := applyAuthFileFieldsPatch(auth, patch, authFileRequestRetryPatch{}); err != nil {
		t.Fatalf("patch: %v", err)
	}
	limits := coreauth.QuotaReserveLimits(auth)
	if len(limits) != 2 || limits[coreauth.QuotaReserveFiveHour] != 10 || limits[coreauth.QuotaReserveSevenDay] != 50.5 {
		t.Fatalf("limits = %v", limits)
	}

	clear := map[string]json.RawMessage{"quota_reserve": json.RawMessage(`null`)}
	if err := applyAuthFileFieldsPatch(auth, clear, authFileRequestRetryPatch{}); err != nil {
		t.Fatalf("clear: %v", err)
	}
	if _, ok := auth.Metadata[coreauth.QuotaReserveMetadataKey]; ok {
		t.Fatal("null must remove quota_reserve")
	}

	for _, raw := range []string{`{"monthly": 5}`, `{"seven_day": 100}`, `{"seven_day": -1}`, `{"seven_day": "50"}`, `[1]`} {
		bad := map[string]json.RawMessage{"quota_reserve": json.RawMessage(raw)}
		if err := applyAuthFileFieldsPatch(auth, bad, authFileRequestRetryPatch{}); err == nil {
			t.Fatalf("expected %s to be rejected", raw)
		}
	}
	nested := map[string]json.RawMessage{"quota_reserve.seven_day": json.RawMessage(`50`)}
	if err := applyAuthFileFieldsPatch(auth, nested, authFileRequestRetryPatch{}); err == nil {
		t.Fatal("expected nested quota_reserve path to be rejected")
	}
}
