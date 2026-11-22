package aiml

import (
	"fmt"
	"math"
	"sort"
	"strings"
)

// WeightedECDF persists the validation distribution, including exact tie
// weights. It never learns from live observations or held-out labels.
type WeightedECDF struct {
	Values []float64 `json:"values"`
	Prefix []float64 `json:"cumulative_weights"`
}

func NewWeightedECDF(values, weights []float64) (WeightedECDF, error) {
	if len(values) == 0 || len(values) != len(weights) {
		return WeightedECDF{}, fmt.Errorf("empty/mismatched ECDF")
	}
	type point struct{ v, w float64 }
	ps := make([]point, len(values))
	for i, v := range values {
		if !ValidScore(v) || !finite(weights[i]) || weights[i] <= 0 {
			return WeightedECDF{}, fmt.Errorf("invalid ECDF point %d", i)
		}
		ps[i] = point{v, weights[i]}
	}
	sort.Slice(ps, func(i, j int) bool { return ps[i].v < ps[j].v })
	r := WeightedECDF{Values: make([]float64, len(ps)), Prefix: make([]float64, len(ps)+1)}
	for i, p := range ps {
		r.Values[i] = p.v
		r.Prefix[i+1] = r.Prefix[i] + p.w
	}
	return r, r.Validate()
}

func finite(v float64) bool     { return !math.IsNaN(v) && !math.IsInf(v, 0) }
func ValidScore(v float64) bool { return finite(v) && v >= 0 && v <= 1 }

func (r WeightedECDF) Validate() error {
	if len(r.Values) == 0 || len(r.Prefix) != len(r.Values)+1 || r.Prefix[0] != 0 {
		return fmt.Errorf("invalid ECDF dimensions")
	}
	for i, v := range r.Values {
		if !ValidScore(v) || (i > 0 && v < r.Values[i-1]) || !finite(r.Prefix[i+1]) || r.Prefix[i+1] <= r.Prefix[i] {
			return fmt.Errorf("invalid ECDF order/weight at %d", i)
		}
	}
	return nil
}

// Rank assumes Validate has succeeded at load time. Missing rankers are not
// accepted by RankCascade. Midranks match the screening benchmark exactly.
func (r WeightedECDF) Rank(v float64) float64 {
	lo := sort.Search(len(r.Values), func(i int) bool { return r.Values[i] >= v })
	hi := sort.Search(len(r.Values), func(i int) bool { return r.Values[i] > v })
	return (r.Prefix[lo] + r.Prefix[hi]) / (2 * r.Prefix[len(r.Values)])
}

type RankCascade struct {
	Fast            []string                `json:"fast_components"`
	Remote          []string                `json:"remote_components"`
	FastThreshold   float64                 `json:"fast_threshold"`
	RemoteThreshold float64                 `json:"remote_threshold"`
	RemoteStrategy  string                  `json:"remote_strategy"`
	Rankers         map[string]WeightedECDF `json:"rankers"`
}

type CascadeDecision struct {
	Forward    bool               `json:"forward"`
	Unresolved bool               `json:"unresolved"`
	Stage      string             `json:"stage"`
	Reason     string             `json:"reason"`
	Score      *float64           `json:"score"`
	Threshold  float64            `json:"threshold"`
	Ranks      map[string]float64 `json:"ranks,omitempty"`
}

func (c RankCascade) Validate() error {
	if len(c.Fast) == 0 || len(c.Remote) == 0 || !finite(c.FastThreshold) || !finite(c.RemoteThreshold) || c.FastThreshold < 0 || c.RemoteThreshold < 0 {
		return fmt.Errorf("invalid cascade thresholds/components")
	}
	switch c.RemoteStrategy {
	case "mean_raw", "max_raw", "rank_mean", "rank_max":
	default:
		return fmt.Errorf("unsupported remote aggregation %q", c.RemoteStrategy)
	}
	seen := map[string]bool{}
	for _, n := range append(append([]string{}, c.Fast...), c.Remote...) {
		if n == "" || seen[n] {
			return fmt.Errorf("duplicate/empty component %q", n)
		}
		seen[n] = true
		if err := c.Rankers[n].Validate(); err != nil {
			return fmt.Errorf("ranker %s: %w", n, err)
		}
	}
	return nil
}

func (c RankCascade) stage(scores map[string]float64, fast bool) CascadeDecision {
	names, strategy, threshold, stage := c.Remote, c.RemoteStrategy, c.RemoteThreshold, "remote"
	if fast {
		names, strategy, threshold, stage = c.Fast, "rank_mean", c.FastThreshold, "fast"
	}
	d := CascadeDecision{Stage: stage, Threshold: threshold, Ranks: map[string]float64{}}
	values := make([]float64, 0, len(names))
	for _, n := range names {
		v, ok := scores[n]
		r, exists := c.Rankers[n]
		if !ok || !ValidScore(v) || !exists || len(r.Values) == 0 {
			d.Forward, d.Unresolved, d.Reason = true, true, "fail_open_missing_or_invalid_signal:"+n
			return d
		}
		rank := r.Rank(v)
		d.Ranks[n] = rank
		if strings.HasPrefix(strategy, "rank_") {
			v = rank
		}
		values = append(values, v)
	}
	// Same addition order as fusionValue, important at an exact threshold.
	sort.Float64s(values)
	score := 0.
	if strategy == "max_raw" || strategy == "rank_max" {
		score = values[len(values)-1]
	} else {
		for _, v := range values {
			score += v
		}
		score /= float64(len(values))
	}
	d.Score = &score
	d.Forward = score >= threshold
	d.Reason = "cascade_" + stage + "_below_threshold"
	if d.Forward {
		d.Reason = "cascade_" + stage + "_escalate"
	}
	return d
}

func (c RankCascade) Early(scores map[string]float64) CascadeDecision { return c.stage(scores, true) }
func (c RankCascade) AfterRemote(scores map[string]float64) CascadeDecision {
	return c.stage(scores, false)
}
func (c RankCascade) Decide(scores map[string]float64) CascadeDecision {
	d := c.Early(scores)
	if d.Forward {
		return d
	}
	return c.AfterRemote(scores)
}
