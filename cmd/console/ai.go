package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// AIClient talks to any OpenAI-compatible chat-completions API. The default
// configuration targets OpenAI, but ASI_AI_BASE_URL can point at any provider
// — a hosted API or a local server (Ollama, llama.cpp, vLLM, LM Studio) —
// without code changes. ASI_AI_API_KEY may stay empty for local servers that
// do not require authentication.
type AIClient struct {
	baseURL string
	apiKey  string
	model   string
	http    *http.Client
}

func aiFromEnv() *AIClient {
	base := strings.TrimRight(os.Getenv("ASI_AI_BASE_URL"), "/")
	key := os.Getenv("ASI_AI_API_KEY")
	if base == "" && key == "" {
		return nil // AI analysis disabled unless explicitly configured
	}
	if base == "" {
		base = "https://api.openai.com/v1"
	}
	model := os.Getenv("ASI_AI_MODEL")
	if model == "" {
		model = "gpt-4o-mini"
	}
	return newAIClient(base, key, model)
}

func newAIClient(base, key, model string) *AIClient {
	return &AIClient{baseURL: strings.TrimRight(base, "/"), apiKey: key, model: model, http: &http.Client{Timeout: 90 * time.Second}}
}

func (a *AIClient) modelName() string {
	if a == nil {
		return ""
	}
	return a.model
}

func (a *AIClient) baseName() string {
	if a == nil {
		return ""
	}
	return a.baseURL
}

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// analyze asks the model for an operator-oriented assessment of one case:
// what likely happened, how confident it is, and the recommended next step.
// The reply is plain Polish text; the model is explicitly told it advises a
// human and never executes anything.
func (a *AIClient) analyze(ctx context.Context, envelope json.RawMessage, logs []LogEntry) (string, error) {
	var sb strings.Builder
	sb.WriteString("Koperta eskalacji (cascadeEnvelope):\n")
	env := envelope
	if len(env) > 12000 {
		env = env[:12000]
	}
	sb.Write(env)
	if len(logs) > 0 {
		sb.WriteString("\n\nOstatnie logi z sensora (najstarsze → najnowsze):\n")
		for _, e := range logs {
			fmt.Fprintf(&sb, "%s %s\n", e.At.Format(time.RFC3339), e.Text)
		}
	}
	reqBody, _ := json.Marshal(map[string]interface{}{
		"model": a.model,
		"messages": []chatMessage{
			{
				Role: "system",
				Content: "Jesteś analitykiem SOC wspierającym operatora konsoli 'Silence on the Wire', która monitoruje pasywnie sieć. " +
					"Analizujesz eskalacje z bramki edge (oceny modeli lokalnych, cechy zdarzenia, logi sensora). " +
					"Odpowiadasz zwięźle po polsku, w trzech sekcjach: OCENA (co prawdopodobnie się stało, 1-3 zdania), " +
					"PEWNOŚĆ (niska/średnia/wysoka + dlaczego), REKOMENDACJA (konkretny następny krok dla operatora: obserwacja, skan aktywny, odcięcie hosta, zamknięcie jako fałszywy alarm). " +
					"Nie wykonujesz żadnych akcji — decyzję zawsze podejmuje człowiek. Nie wymyślaj faktów spoza danych wejściowych.",
			},
			{Role: "user", Content: sb.String()},
		},
		// No explicit temperature: several current models accept only the
		// provider default and reject the parameter outright.
	})
	return a.chat(ctx, reqBody)
}

// chat posts one prepared chat-completions request and returns the first
// message's text.
func (a *AIClient) chat(ctx context.Context, reqBody []byte) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", a.baseURL+"/chat/completions", bytes.NewReader(reqBody))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	if a.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+a.apiKey)
	}
	resp, err := a.http.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4*1024*1024))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != 200 {
		snippet := string(body)
		if len(snippet) > 300 {
			snippet = snippet[:300]
		}
		return "", fmt.Errorf("AI API odpowiedziało %d: %s", resp.StatusCode, snippet)
	}
	var out struct {
		Choices []struct {
			Message chatMessage `json:"message"`
		} `json:"choices"`
	}
	if json.Unmarshal(body, &out) != nil || len(out.Choices) == 0 || strings.TrimSpace(out.Choices[0].Message.Content) == "" {
		return "", fmt.Errorf("pusta odpowiedź AI API")
	}
	return strings.TrimSpace(out.Choices[0].Message.Content), nil
}
