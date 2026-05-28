// internal/engine/ml_hook.go
//
// Bridge to the ML inference service for action.ml_confirm.
// We deliberately decouple from internal/ml package via a tiny interface so
// the engine package can be tested without the ML client.
package engine

import (
	"context"
	"strings"
	"time"
)

// MLPredictor — minimal surface engine needs.
// internal/ml.Client satisfies this (Predict(ctx, text) → response).
type MLPredictor interface {
	Predict(ctx context.Context, text string) (*MLVerdict, error)
	Enabled() bool
}

// MLVerdict — engine-side view of the ML response.
type MLVerdict struct {
	Label      string
	Confidence float64
	IsAttack   bool
}

// MLClientAdapter wraps any object with a Predict method returning the
// concrete ML response shape, exposing it as MLPredictor.
// Keeping the adapter in this package avoids an import cycle.
type MLClientAdapter struct {
	predictFn func(ctx context.Context, text string) (label string, confidence float64, isAttack bool, err error)
	enabledFn func() bool
}

// NewMLAdapter creates an adapter from raw functions (allows injection from main).
func NewMLAdapter(
	predict func(ctx context.Context, text string) (label string, confidence float64, isAttack bool, err error),
	enabled func() bool,
) *MLClientAdapter {
	return &MLClientAdapter{predictFn: predict, enabledFn: enabled}
}

func (a *MLClientAdapter) Predict(ctx context.Context, text string) (*MLVerdict, error) {
	label, conf, atk, err := a.predictFn(ctx, text)
	if err != nil {
		return nil, err
	}
	return &MLVerdict{Label: label, Confidence: conf, IsAttack: atk}, nil
}

func (a *MLClientAdapter) Enabled() bool {
	if a.enabledFn == nil {
		return false
	}
	return a.enabledFn()
}

// =========================================================================
// runMLConfirm — synchronous score adjustment.
// Returns delta to add to the rule's contribution (may be negative).
// =========================================================================

func runMLConfirm(
	pred MLPredictor,
	cfg *MLConfirm,
	req *ParsedRequest,
) (delta float64, addLabels []string) {
	if pred == nil || !pred.Enabled() || cfg == nil || !cfg.Enabled {
		return 0, nil
	}

	text := pickMLInput(cfg.Input, req)
	if text == "" {
		return 0, nil
	}

	// Hard cap (model max_length is 256 tokens; 4 KB chars is more than enough).
	const maxLen = 4096
	if len(text) > maxLen {
		text = text[:maxLen]
	}

	ctx, cancel := context.WithTimeout(context.Background(), 800*time.Millisecond)
	defer cancel()
	v, err := pred.Predict(ctx, text)
	if err != nil || v == nil {
		// Fail-open: ML unavailable → no adjustment.
		return 0, nil
	}
	if v.Confidence < cfg.MinConfidence {
		return 0, nil
	}

	if v.IsAttack {
		return cfg.OnAttackAdd, []string{"ml:confirmed", "ml:" + v.Label}
	}
	return -cfg.OnNormalSubtract, []string{"ml:cleared"}
}

func pickMLInput(name string, req *ParsedRequest) string {
	switch strings.ToLower(name) {
	case "", "body":
		return req.NormalizedBody
	case "args":
		return collectArgs(req)
	case "query":
		return req.NormalizedQuery
	case "uri":
		uri := req.NormalizedPath
		if req.NormalizedQuery != "" {
			uri += "?" + req.NormalizedQuery
		}
		return uri
	case "headers_all":
		return concatHeaders(req)
	}
	return req.NormalizedBody
}
