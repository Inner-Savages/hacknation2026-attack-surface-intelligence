package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"reflect"
	"strings"

	"github.com/Inner-Savages/silence-on-the-wire/internal/edge/aiml"
)

const cascadePromptSHA = "21211fa19df6bbafe180d9e6a2151cedf7de48c5d6373a78cffc946993a227bd"
const cascadeFeaturesSHA = "f3c79d131704cdbc035c2b49b5d98ef5ad2a27d1682cb8d6be093a7aaa9e6a28"
const cascadeBaselineSHA = "5171acb14c24fc4744575ee9499fa7c4e7581a35a77a76f3666b5b931e87b1a1"

type cascadeBackendIdentity struct {
	Model   string `json:"model"`
	Routing string `json:"routing,omitempty"`
}
type cascadePolicy struct {
	Version      int                               `json:"version"`
	Kind         string                            `json:"kind"`
	Budget       float64                           `json:"validation_budget"`
	BudgetPolicy string                            `json:"budget_policy"`
	FeatureNames []string                          `json:"features"`
	PromptSHA    string                            `json:"prompt_source_sha256"`
	FeaturesSHA  string                            `json:"feature_source_sha256"`
	BaselineSHA  string                            `json:"baseline_source_sha256"`
	Cascade      aiml.RankCascade                  `json:"cascade"`
	Tree         aiml.Model                        `json:"tree"`
	GNB          aiml.Model                        `json:"gnb"`
	Baseline     *aiml.AdaptiveBaseline            `json:"frozen_baseline"`
	Backends     map[string]cascadeBackendIdentity `json:"backends"`
	Runtime      json.RawMessage                   `json:"runtime_manifest"`
	Inputs       map[string]string                 `json:"inputs_sha256"`
	Evidence     string                            `json:"evidence"`
}

func sourceDigest(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func finiteNumber(v float64) bool  { return !math.IsNaN(v) && !math.IsInf(v, 0) }
func (p *cascadePolicy) validate() error {
	if p.Version != 1 || p.Kind != "rank_cascade_50" || p.Budget != .5 || p.BudgetPolicy != "soft_fail_open" {
		return fmt.Errorf("unsupported cascade policy/budget")
	}
	if p.PromptSHA != cascadePromptSHA || p.FeaturesSHA != cascadeFeaturesSHA || p.BaselineSHA != cascadeBaselineSHA || !reflect.DeepEqual(p.FeatureNames, aiml.FeatureNames) {
		return fmt.Errorf("policy prompt/feature/baseline schema mismatch; recalibrate explicitly")
	}
	if !reflect.DeepEqual(p.Cascade.Fast, []string{"tree", "gnb"}) || !reflect.DeepEqual(p.Cascade.Remote, []string{"basal", "laya", "kev"}) || p.Cascade.RemoteStrategy != "rank_max" || !aiml.ValidScore(p.Cascade.FastThreshold) || !aiml.ValidScore(p.Cascade.RemoteThreshold) {
		return fmt.Errorf("expected Tree+GNB rank_mean then Basal+Laya+Kev rank_max")
	}
	if err := p.Cascade.Validate(); err != nil {
		return err
	}
	if p.Tree.Kind != "tree" || p.GNB.Kind != "gnb" || !reflect.DeepEqual(p.Tree.FeatureNames, p.FeatureNames) || !reflect.DeepEqual(p.GNB.FeatureNames, p.FeatureNames) {
		return fmt.Errorf("invalid Go model schema")
	}
	var node func(*aiml.Node, int) error
	node = func(n *aiml.Node, depth int) error {
		if n == nil || depth > 128 || !aiml.ValidScore(n.P) || !finiteNumber(n.Cut) {
			return fmt.Errorf("invalid tree node")
		}
		if n.Left == nil && n.Right == nil {
			return nil
		}
		if n.Feature < 0 || n.Feature >= aiml.Dimension || n.Left == nil || n.Right == nil {
			return fmt.Errorf("invalid tree branch")
		}
		if err := node(n.Left, depth+1); err != nil {
			return err
		}
		return node(n.Right, depth+1)
	}
	if err := node(p.Tree.Tree, 0); err != nil {
		return err
	}
	for c := 0; c < 2; c++ {
		if len(p.GNB.Mean[c]) != aiml.Dimension || len(p.GNB.Var[c]) != aiml.Dimension || !aiml.ValidScore(p.GNB.Prior[c]) || p.GNB.Prior[c] == 0 {
			return fmt.Errorf("invalid GNB dimensions/prior")
		}
		for i, v := range p.GNB.Var[c] {
			if !finiteNumber(v) || v <= 0 || !finiteNumber(p.GNB.Mean[c][i]) {
				return fmt.Errorf("invalid GNB moments")
			}
		}
	}
	if p.Baseline == nil || p.Baseline.Version != 1 || len(p.Baseline.Counts) == 0 || len(p.Baseline.Totals) == 0 || p.Baseline.AutoUpdates != 0 {
		return fmt.Errorf("requires a frozen, confirmed-training baseline")
	}
	for _, m := range []map[string]float64{p.Baseline.Counts, p.Baseline.Totals} {
		for _, v := range m {
			if !finiteNumber(v) || v < 0 {
				return fmt.Errorf("invalid baseline counts")
			}
		}
	}
	for _, name := range p.Cascade.Remote {
		if strings.TrimSpace(p.Backends[name].Model) == "" {
			return fmt.Errorf("missing model identity: %s", name)
		}
	}
	if p.Backends["laya"].Routing != "english" {
		return fmt.Errorf("policy requires Laya English routing")
	}
	return nil
}

func loadCascadePolicy(path string) (*cascadePolicy, string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, "", err
	}
	if len(raw) > 8*1024*1024 {
		return nil, "", fmt.Errorf("policy exceeds 8 MiB")
	}
	var p cascadePolicy
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err = d.Decode(&p); err != nil {
		return nil, "", err
	}
	if err = d.Decode(new(interface{})); err != io.EOF {
		return nil, "", fmt.Errorf("trailing policy data")
	}
	if err = p.validate(); err != nil {
		return nil, "", err
	}
	return &p, sourceDigest(raw), nil
}
