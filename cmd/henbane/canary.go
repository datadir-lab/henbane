package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/datadir-lab/henbane/internal/config"
	"github.com/datadir-lab/henbane/internal/generate/poison/canary"
)

// canaryUsage is printed when `henbane canary` is run without a valid subcommand.
const canaryUsage = `usage: henbane canary <list|check|probe> [flags]

Provable-poison tooling for the "canary" poison strategy. Canary phrases are coined
deterministically from the deployment salt with HMAC-SHA256, so they are stable for
a deployment yet unguessable without the salt.

  list    print this deployment's canary phrases (search for them in an AI assistant)
  check   report whether a canary from this deployment appears in text (stdin or args)
  probe   query a configured AI endpoint for each canary and report which surface

Common flags:
  -salt string     canary salt (overrides the config file's poison.salt)
  -config string   path to henbane.yaml (reads poison.salt and, for probe, canary.probe)

A hit proves text reached and reproduced Henbane's planted content (live retrieval
and repetition reach). It does NOT prove the content entered any model's training set.
`

// runCanary implements the `henbane canary` subcommand. It returns a process exit
// code: 0 on success, 1 when a check finds no canary (so it is scriptable), 2 on
// usage or configuration errors.
func runCanary(args []string, stdout, stderr io.Writer, stdin io.Reader) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, canaryUsage)
		return 2
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "list":
		return canaryList(rest, stdout, stderr)
	case "check":
		return canaryCheck(rest, stdout, stderr, stdin)
	case "probe":
		return canaryProbe(rest, stdout, stderr)
	case "-h", "--help", "help":
		fmt.Fprint(stdout, canaryUsage)
		return 0
	default:
		fmt.Fprintf(stderr, "henbane canary: unknown subcommand %q\n\n%s", sub, canaryUsage)
		return 2
	}
}

// resolveSalt returns the canary salt from the -salt flag, else the config file's
// poison.salt. Exactly one source must supply a non-empty salt.
func resolveSalt(configPath, saltFlag string) (string, error) {
	if saltFlag != "" {
		return saltFlag, nil
	}
	if configPath == "" {
		return "", errors.New("no salt: pass -salt, or -config pointing at a file with poison.salt set")
	}
	cfg, err := config.LoadFile(configPath)
	if err != nil {
		return "", err
	}
	if cfg.Poison.Salt == "" {
		return "", fmt.Errorf("config %q has no poison.salt", configPath)
	}
	return cfg.Poison.Salt, nil
}

func canaryList(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("canary list", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var configPath, salt string
	fs.StringVar(&configPath, "config", "", "path to henbane.yaml (reads poison.salt)")
	fs.StringVar(&salt, "salt", "", "canary salt (overrides config poison.salt)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	s, err := resolveSalt(configPath, salt)
	if err != nil {
		fmt.Fprintf(stderr, "henbane canary list: %v\n", err)
		return 2
	}
	for _, c := range canary.New(s).Canaries() {
		fmt.Fprintln(stdout, c)
	}
	return 0
}

func canaryCheck(args []string, stdout, stderr io.Writer, stdin io.Reader) int {
	fs := flag.NewFlagSet("canary check", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var configPath, salt string
	fs.StringVar(&configPath, "config", "", "path to henbane.yaml (reads poison.salt)")
	fs.StringVar(&salt, "salt", "", "canary salt (overrides config poison.salt)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	s, err := resolveSalt(configPath, salt)
	if err != nil {
		fmt.Fprintf(stderr, "henbane canary check: %v\n", err)
		return 2
	}

	var text string
	if rem := fs.Args(); len(rem) > 0 {
		text = strings.Join(rem, " ")
	} else {
		// Read the text to check from stdin (e.g. an AI assistant's answer piped in),
		// bounded so an unbounded pipe cannot exhaust memory.
		b, err := io.ReadAll(io.LimitReader(stdin, 8<<20)) // 8 MiB cap
		if err != nil {
			fmt.Fprintf(stderr, "henbane canary check: read stdin: %v\n", err)
			return 2
		}
		text = string(b)
	}

	if tok, ok := canary.New(s).Find(text); ok {
		fmt.Fprintf(stdout, "ATTRIBUTED: found this deployment's canary %q\n", tok)
		return 0
	}
	fmt.Fprintln(stdout, "no canary from this deployment found in the input")
	return 1
}

func canaryProbe(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("canary probe", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var configPath, salt string
	fs.StringVar(&configPath, "config", "", "path to henbane.yaml (reads poison.salt and canary.probe)")
	fs.StringVar(&salt, "salt", "", "canary salt (overrides config poison.salt)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if configPath == "" {
		fmt.Fprintln(stderr, "henbane canary probe: -config is required (it carries canary.probe.endpoint)")
		return 2
	}
	cfg, err := config.LoadFile(configPath)
	if err != nil {
		fmt.Fprintf(stderr, "henbane canary probe: %v\n", err)
		return 2
	}
	s := salt
	if s == "" {
		s = cfg.Poison.Salt
	}
	if s == "" {
		fmt.Fprintln(stderr, "henbane canary probe: no salt (set poison.salt or pass -salt)")
		return 2
	}
	pc := cfg.Canary.Probe
	if pc.Endpoint == "" {
		fmt.Fprintln(stderr, "henbane canary probe: canary.probe.endpoint is not set")
		return 2
	}
	if u, err := url.Parse(pc.Endpoint); err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		fmt.Fprintf(stderr, "henbane canary probe: endpoint %q must be an http(s) URL\n", pc.Endpoint)
		return 2
	}
	var token string
	if pc.AuthEnv != "" {
		token = os.Getenv(pc.AuthEnv)
		if token == "" {
			fmt.Fprintf(stderr, "henbane canary probe: auth_env %q is empty in the environment\n", pc.AuthEnv)
			return 2
		}
	}

	client := &http.Client{Timeout: 30 * time.Second}
	canaries := canary.New(s).Canaries()
	return probeCanaries(context.Background(), client, pc, token, canaries, stdout, stderr, 30*time.Second)
}

// probeResult is the outcome of probing one canary.
type probeResult int

const (
	probeAbsent   probeResult = iota // neither the phrase nor its planted number came back
	probeWeak                        // the planted number surfaced but not the full phrase
	probeSurfaced                    // the full planted phrase surfaced verbatim
)

// probeCanaries asks the endpoint about each canary's coined name (NOT the full
// phrase, so a match cannot be a mere echo of the prompt) and reports whether the
// response reproduced the full planted phrase — including the reference number that
// exists only on Henbane's planted pages. It returns 0 if any canary surfaced, else
// 1. Per-canary errors are reported and do not abort the run.
func probeCanaries(ctx context.Context, client *http.Client, pc config.CanaryProbe, token string, canaries []string, stdout, stderr io.Writer, timeout time.Duration) int {
	query := pc.Query
	if query == "" {
		query = `What is the "{{canary}}" specification? State its full reference designation.`
	}
	field := pc.BodyField
	if field == "" {
		field = "query"
	}

	surfaced := 0
	for _, phrase := range canaries {
		name, number := splitCanary(phrase)
		q := strings.ReplaceAll(query, "{{canary}}", name)
		res, err := probeOne(ctx, client, pc.Endpoint, field, q, token, phrase, number, timeout)
		if err != nil {
			fmt.Fprintf(stderr, "  error  %-28s %v\n", name, err)
			continue
		}
		switch res {
		case probeSurfaced:
			surfaced++
			fmt.Fprintf(stdout, "  HIT    %s\n", phrase)
		case probeWeak:
			fmt.Fprintf(stdout, "  weak   %-28s (reference number %s surfaced; full phrase did not)\n", name, number)
		default:
			fmt.Fprintf(stdout, "  -      %s\n", name)
		}
	}
	fmt.Fprintf(stdout, "%d/%d canaries surfaced\n", surfaced, len(canaries))
	if surfaced > 0 {
		return 0
	}
	return 1
}

// probeOne POSTs one query and classifies the response. The response body is read
// under a hard cap so a hostile or oversized endpoint cannot exhaust memory.
func probeOne(ctx context.Context, client *http.Client, endpoint, field, query, token, phrase, number string, timeout time.Duration) (probeResult, error) {
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	body, err := json.Marshal(map[string]string{field: query})
	if err != nil {
		return probeAbsent, err
	}
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return probeAbsent, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := client.Do(req)
	if err != nil {
		return probeAbsent, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1 MiB cap
	if err != nil {
		return probeAbsent, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return probeAbsent, fmt.Errorf("endpoint returned HTTP %d", resp.StatusCode)
	}
	text := string(raw)
	switch {
	case strings.Contains(text, phrase):
		return probeSurfaced, nil
	case number != "" && strings.Contains(text, number):
		return probeWeak, nil
	default:
		return probeAbsent, nil
	}
}

// splitCanary splits a canary phrase into its coined name and planted reference
// number. "Velthu Casmarvel 9017 standard" => ("Velthu Casmarvel", "9017"). If no
// numeric field is present it returns the whole phrase as the name and an empty
// number (the probe then falls back to full-phrase matching only).
func splitCanary(phrase string) (name, number string) {
	fields := strings.Fields(phrase)
	for i := len(fields) - 1; i >= 0; i-- {
		if isAllDigits(fields[i]) {
			return strings.Join(fields[:i], " "), fields[i]
		}
	}
	return phrase, ""
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
