package main

import (
	"encoding/json"
	"fmt"
)

func validateSystemOneSafety(raw []byte) error {
	var r struct {
		Usage struct {
			Truncated bool     `json:"truncated"`
			Dropped   int      `json:"state_tokens_dropped"`
			Questions []string `json:"truncated_questions"`
		} `json:"usage"`
		Answers map[string]struct {
			Abstain bool   `json:"abstain"`
			Unbound bool   `json:"unbound"`
			Route   string `json:"route"`
		} `json:"answers"`
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		return err
	}
	a := r.Answers["attack"]
	if r.Usage.Truncated || r.Usage.Dropped > 0 || len(r.Usage.Questions) > 0 {
		return fmt.Errorf("input/question truncated")
	}
	if a.Abstain || a.Unbound || a.Route == "review" {
		return fmt.Errorf("model requests review/abstention")
	}
	return nil
}
