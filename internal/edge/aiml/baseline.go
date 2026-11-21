package aiml

import (
	"fmt"
	"math"
	"strings"
)

// AdaptiveBaseline tracks a vetted, per-sensor empirical distribution of event
// signatures. This is an anomaly score, NEVER proof of attack or benignness.
// Only training-label-confirmed normal events, human/central feedback, or
// previously established low-risk signatures may update it. Unknown signatures
// cannot train themselves into the baseline through mere repetition.
type AdaptiveBaseline struct {
	Version          int                `json:"version"`
	Counts           map[string]float64 `json:"counts"`
	Totals           map[string]float64 `json:"totals"`
	Updates          uint64             `json:"updates"`
	AutoUpdates      uint64             `json:"auto_updates"`
	ConfirmedUpdates uint64             `json:"confirmed_updates"`
}

func NewAdaptiveBaseline() *AdaptiveBaseline {
	return &AdaptiveBaseline{Version: 1, Counts: make(map[string]float64), Totals: make(map[string]float64)}
}

func baselineKey(e Event) string {
	// Exclude IP so we learn the sensor's normal service mix without learning
	// an attacker's host identity; preserve specific ports for novel exposure.
	return fmt.Sprintf("%s|%s|%d|%s", e.Type, e.Proto, e.Port, strings.ToLower(e.Source))
}

func (b *AdaptiveBaseline) Clone() *AdaptiveBaseline {
	n := NewAdaptiveBaseline()
	n.Updates, n.AutoUpdates, n.ConfirmedUpdates = b.Updates, b.AutoUpdates, b.ConfirmedUpdates
	for k, v := range b.Counts {
		n.Counts[k] = v
	}
	for k, v := range b.Totals {
		n.Totals[k] = v
	}
	return n
}

func (b *AdaptiveBaseline) Count(e Event) float64 { return b.Counts[baselineKey(e)] }

// Anomaly never updates the frozen baseline. Unknown signatures are
// surprising, but warm-up uncertainty is a reason for cautious escalation.
func (b *AdaptiveBaseline) Anomaly(e Event) float64 {
	count := b.Count(e)
	total := b.Totals[e.Type]
	if total < 30 {
		return .5
	}
	rarity := math.Log1p(total/(count+1.0)) / 8.0
	return Clamp(rarity)
}
