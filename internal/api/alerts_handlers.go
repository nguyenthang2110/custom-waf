// internal/api/alerts_handlers.go
package api

import (
	"encoding/json"
	"net/http"

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
