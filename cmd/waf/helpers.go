package main

import (
	"waf-project/internal/ratelimit"
	"waf-project/pkg/config"
)

func convertEndpointLimits(src map[string]config.LimitConfig) map[string]ratelimit.LimitConfig {
	dst := make(map[string]ratelimit.LimitConfig)
	for k, v := range src {
		dst[k] = ratelimit.LimitConfig{
			RequestsPerMin: v.RequestsPerMin,
			BurstSize:      v.BurstSize,
		}
	}
	return dst
}
