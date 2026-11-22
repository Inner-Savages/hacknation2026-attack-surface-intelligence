package aiml

import (
	"encoding/json"
	"math"
	"testing"
)

func TestWeightedECDFPersistenceAndTies(t *testing.T) {
	r, err := NewWeightedECDF([]float64{.2, .8, .2}, []float64{3, 1, 6})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(r)
	var restored WeightedECDF
	if err = json.Unmarshal(b, &restored); err != nil {
		t.Fatal(err)
	}
	for _, v := range []struct{ x, want float64 }{{0, 0}, {.2, .45}, {.5, .9}, {.8, .95}, {1, 1}} {
		if got := restored.Rank(v.x); got != v.want {
			t.Fatalf("rank(%g)=%g want %g", v.x, got, v.want)
		}
	}
	for _, bad := range []WeightedECDF{{Values: []float64{.2}, Prefix: []float64{0, 0}}, {Values: []float64{.8, .2}, Prefix: []float64{0, 1, 2}}, {Values: []float64{.2}, Prefix: []float64{0, math.NaN()}}} {
		if bad.Validate() == nil {
			t.Fatal("accepted corrupt ECDF")
		}
	}
}

func TestRankCascadeMissingIsNeverBenignAndEarlyCannotBeVetoed(t *testing.T) {
	r, _ := NewWeightedECDF([]float64{0, .5, 1}, []float64{1, 1, 1})
	c := RankCascade{Fast: []string{"tree", "gnb"}, Remote: []string{"basal", "laya", "kev"}, FastThreshold: .6, RemoteThreshold: .6, RemoteStrategy: "rank_max", Rankers: map[string]WeightedECDF{}}
	for _, n := range []string{"tree", "gnb", "basal", "laya", "kev"} {
		c.Rankers[n] = r
	}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	d := c.Decide(map[string]float64{"tree": 1, "gnb": 1})
	if !d.Forward || d.Unresolved || d.Stage != "fast" {
		t.Fatalf("early escalation lost: %+v", d)
	}
	s := map[string]float64{"tree": 0, "gnb": 0, "basal": 0, "laya": 0}
	d = c.Decide(s)
	if !d.Forward || !d.Unresolved {
		t.Fatal("missing Kev became benign")
	}
	s["kev"] = math.NaN()
	if !c.Decide(s).Unresolved {
		t.Fatal("NaN accepted")
	}
	s["kev"] = 0
	d = c.Decide(s)
	if d.Forward || d.Unresolved {
		t.Fatal("valid low scores should reach below-threshold result")
	}
	s["laya"] = 1
	d = c.Decide(s)
	if !d.Forward || d.Unresolved || d.Stage != "remote" {
		t.Fatal("max rank failed")
	}
}
