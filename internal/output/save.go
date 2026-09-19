package output

import (
	"fmt"
	"inspect/internal/models"
	"os"
	"strings"
)

func Save() (string, error) {
	filename := models.INFO.TargetName + ".md"

	var b strings.Builder

	fmt.Fprintf(&b, "# Inspect Results\n\n")
	fmt.Fprintf(&b, "**Target:** %s\n\n", models.INFO.TargetName)

	b.WriteString("| Port | State | Service | Banner | Latency |\n")
	b.WriteString("|------|-------|---------|--------|---------|\n")

	for _, d := range models.LOOT.Details {
		fmt.Fprintf(
			&b,
			"| %d | %s | %s | %s | %s |\n",
			d.Port,
			escapeMarkdown(d.State),
			escapeMarkdown(d.Service),
			escapeMarkdown(d.Banner),
			escapeMarkdown(d.Latency.String()))
	}

	err := os.WriteFile(filename, []byte(b.String()), 0644)
	if err != nil {
		return "", err
	}

	return filename, nil
}

func escapeMarkdown(value string) string {
	value = strings.ReplaceAll(value, "|", "\\|")
	value = strings.ReplaceAll(value, "\n", " ")
	value = strings.ReplaceAll(value, "\r", "")

	return value
}
