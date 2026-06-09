// internal/api/alerts_handlers.go
package api

import (
	"encoding/json"
	"net/http"
	"time"

	"waf-project/internal/notifier"
)

// handleAlertsConfig handles GET (read current config, passwords redacted)
// and PUT/POST (replace config). Mutation is gated by requireAdminForWrite
// in the route table.
//
// Per-destination passwords (email) are blank or "********" in the response.
// On save, blank/placeholder passwords are replaced by the saved value
// (look up by destination ID) so the dashboard can omit unchanged secrets.
func (s *APIServer) handleAlertsConfig(w http.ResponseWriter, r *http.Request) {
	if s.notifier == nil {
		http.Error(w, `{"error":"notifier not initialized"}`, http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		// Build "has_password" map keyed by destination ID for UI hints.
		current := s.notifier.GetConfig()
		hasPwd := map[string]bool{}
		for _, d := range current.Email {
			if d.Password != "" {
				hasPwd[d.ID] = true
			}
		}
		resp := map[string]interface{}{
			"config":            notifier.RedactConfig(current),
			"email_has_password": hasPwd,
		}
		json.NewEncoder(w).Encode(resp)
		return

	case http.MethodPut, http.MethodPost:
		var incoming notifier.Config
		if err := json.NewDecoder(r.Body).Decode(&incoming); err != nil {
			http.Error(w, `{"error":"invalid JSON: `+err.Error()+`"}`, http.StatusBadRequest)
			return
		}
		// Reattach passwords on a per-destination ID basis when client sent
		// blank/placeholder — lets the UI omit the field on subsequent saves.
		current := s.notifier.GetConfig()
		oldPwd := map[string]string{}
		for _, d := range current.Email {
			if d.Password != "" {
				oldPwd[d.ID] = d.Password
			}
		}
		for i := range incoming.Email {
			d := &incoming.Email[i]
			if (d.Password == "" || d.Password == "********") && d.ID != "" {
				if p, ok := oldPwd[d.ID]; ok {
					d.Password = p
				}
			}
		}
		s.notifier.SetConfig(incoming)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"config":  notifier.RedactConfig(s.notifier.GetConfig()),
		})
		return

	default:
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
	}
}

// handleAlertsStats returns lifetime counters (sent / failed / throttled).
func (s *APIServer) handleAlertsStats(w http.ResponseWriter, r *http.Request) {
	if s.notifier == nil {
		http.Error(w, `{"error":"notifier not initialized"}`, http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s.notifier.GetStats())
}

// handleAlertsTest fires a synthetic alert to a specific destination and
// returns the per-channel result. The destination object can be unsaved —
// the dashboard sends whatever the user typed in the form so the user
// doesn't need to Save before clicking Test.
//
// Body:
//
//	{
//	  "channel":     "slack" | "email" | "webhook",
//	  "destination": { <full SlackDestination / EmailDestination / WebhookDestination> }
//	}
//
// For email destinations, a blank/placeholder password is filled from the
// saved destination with the same ID (so users can test edits without
// re-typing the SMTP password each time).
func (s *APIServer) handleAlertsTest(w http.ResponseWriter, r *http.Request) {
	if s.notifier == nil {
		http.Error(w, `{"error":"notifier not initialized"}`, http.StatusServiceUnavailable)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"POST required"}`, http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")

	var body struct {
		Channel     string          `json:"channel"`
		Destination json.RawMessage `json:"destination"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, `{"error":"invalid JSON: `+err.Error()+`"}`, http.StatusBadRequest)
		return
	}

	current := s.notifier.GetConfig()
	var result string

	switch body.Channel {
	case "slack":
		var d notifier.SlackDestination
		if err := json.Unmarshal(body.Destination, &d); err != nil {
			result = "Bad destination JSON: " + err.Error()
			break
		}
		result = s.notifier.TestSlack(d)

	case "email":
		var d notifier.EmailDestination
		if err := json.Unmarshal(body.Destination, &d); err != nil {
			result = "Bad destination JSON: " + err.Error()
			break
		}
		// Re-attach saved password if blank/placeholder.
		if d.Password == "" || d.Password == "********" {
			for _, sd := range current.Email {
				if sd.ID != "" && sd.ID == d.ID && sd.Password != "" {
					d.Password = sd.Password
					break
				}
			}
		}
		result = s.notifier.TestEmail(d)

	case "webhook":
		var d notifier.WebhookDestination
		if err := json.Unmarshal(body.Destination, &d); err != nil {
			result = "Bad destination JSON: " + err.Error()
			break
		}
		result = s.notifier.TestWebhook(d)

	default:
		result = "Unknown channel: " + body.Channel
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"channel": body.Channel,
		"result":  result,
	})
}

// handleAlertsTestBroadcast fires a synthetic event through notifier.Send()
// so the operator can verify the FULL pipeline — kind toggle + severity gate
// + throttle + every enabled destination — without having to wait for a real
// block or config change.
//
// Body: {"kind": "request" | "system"}.
//
// We inspect the current config before firing so we can surface the actual
// reason the event got dropped (alerts disabled, kind toggle off, etc.)
// instead of leaving the user guessing why nothing arrived.
//
// The synthetic event uses Severity=HIGH and a unique RuleID per click so
// throttle dedup doesn't suppress repeated clicks during debugging.
func (s *APIServer) handleAlertsTestBroadcast(w http.ResponseWriter, r *http.Request) {
	if s.notifier == nil {
		http.Error(w, `{"error":"notifier not initialized"}`, http.StatusServiceUnavailable)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"POST required"}`, http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")

	var body struct {
		Kind string `json:"kind"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	kind := notifier.KindRequest
	switch body.Kind {
	case "system":
		kind = notifier.KindSystem
	case "request", "":
		kind = notifier.KindRequest
	default:
		json.NewEncoder(w).Encode(map[string]interface{}{
			"sent":   false,
			"reason": "unknown kind: " + body.Kind + " (use \"request\" or \"system\")",
		})
		return
	}

	cfg := s.notifier.GetConfig()
	reply := func(sent bool, reason string) {
		dests := 0
		switch kind {
		case notifier.KindRequest, notifier.KindSystem:
			for _, d := range cfg.Slack {
				if d.Enabled {
					dests++
				}
			}
			for _, d := range cfg.Email {
				if d.Enabled {
					dests++
				}
			}
			for _, d := range cfg.Webhook {
				if d.Enabled {
					dests++
				}
			}
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"sent":               sent,
			"reason":             reason,
			"kind":               string(kind),
			"severity":           "HIGH",
			"min_severity":       cfg.MinSeverity,
			"enabled_dests":      dests,
			"alerts_enabled":     cfg.Enabled,
			"send_request_events": cfg.SendRequestEvents,
			"send_system_events":  cfg.SendSystemEvents,
		})
	}

	if !cfg.Enabled {
		reply(false, "alerts are disabled globally — enable the master toggle first")
		return
	}
	if kind == notifier.KindRequest && !cfg.SendRequestEvents {
		reply(false, `"Send request events" toggle is OFF in General settings`)
		return
	}
	if kind == notifier.KindSystem && !cfg.SendSystemEvents {
		reply(false, `"Send system events" toggle is OFF in General settings`)
		return
	}

	now := time.Now()
	s.notifier.Send(notifier.Event{
		Kind:      kind,
		Timestamp: now,
		Decision:  "TEST",
		Severity:  "HIGH",
		ClientIP:  "127.0.0.1",
		Method:    "GET",
		Host:      "waf.local",
		Path:      "/__test_broadcast",
		Reason:    "Manual broadcast test from dashboard",
		RuleID:    "WAF-TEST-BROADCAST-" + now.Format("150405.000"),
		Score:     7.5,
		UserAgent: "WAF/test-broadcast",
		RequestID: "broadcast-" + now.Format("150405.000"),
	})
	reply(true, "")
}
