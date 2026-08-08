package main

import (
	"fmt"
	"os"

	"github.com/threatcl/drift-action/internal/config"
)

var version = "dev"

func main() {
	cfg := config.FromEnv()
	fmt.Printf("threatcl drift-action %s — skeleton build, drift engine not implemented yet\n", version)
	fmt.Printf("config: path=%s fail-mode=%s model=%s\n", cfg.ConfigPath, cfg.FailMode, cfg.Model)

	if err := writeOutputs(map[string]string{
		"findings-count":        "0",
		"action-required-count": "0",
		"verdict":               "skipped",
	}); err != nil {
		fmt.Fprintf(os.Stderr, "writing outputs: %v\n", err)
		os.Exit(1)
	}
}

// writeOutputs appends key=value pairs to $GITHUB_OUTPUT when running under
// Actions; outside a runner it is a no-op.
func writeOutputs(outputs map[string]string) error {
	path := os.Getenv("GITHUB_OUTPUT")
	if path == "" {
		return nil
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	for k, v := range outputs {
		if _, err := fmt.Fprintf(f, "%s=%s\n", k, v); err != nil {
			f.Close()
			return err
		}
	}
	return f.Close()
}
