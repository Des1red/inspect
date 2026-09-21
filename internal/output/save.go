package output

import (
	"fmt"
	"ipspect/internal/models"
	"os"
	"strconv"
	"strings"
	"unicode/utf8"
)

type tableRow struct {
	Port    string
	State   string
	Service string
	Banner  string
	Latency string
}

type tableWidths struct {
	Port    int
	State   int
	Service int
	Banner  int
	Latency int
}

func Save() (string, error) {
	filename := safeFilename(models.INFO.TargetName) + ".md"

	var b strings.Builder

	b.WriteString("# ipspect Results\n\n")

	fmt.Fprintf(
		&b,
		"**Target:** %s\n\n",
		escapeMarkdown(models.INFO.TargetName),
	)

	if models.INFO.PortStart == models.INFO.PortEnd {
		fmt.Fprintf(
			&b,
			"**Port:** %d\n\n",
			models.INFO.PortStart,
		)
	} else {
		fmt.Fprintf(
			&b,
			"**Ports:** %d-%d\n\n",
			models.INFO.PortStart,
			models.INFO.PortEnd,
		)
	}

	for _, host := range models.LOOT.Hosts {
		if len(host.Details) == 0 {
			continue
		}

		fmt.Fprintf(
			&b,
			"## %s\n\n",
			escapeMarkdown(host.Target),
		)

		rows := make([]tableRow, 0, len(host.Details))

		for _, d := range host.Details {
			rows = append(rows, tableRow{
				Port:    strconv.Itoa(d.Port),
				State:   escapeMarkdown(d.State),
				Service: escapeMarkdown(d.Service),
				Banner:  escapeMarkdown(d.Banner),
				Latency: escapeMarkdown(d.Latency.String()),
			})
		}

		widths := calcWidths(rows)

		writeHeader(&b, widths)

		for _, row := range rows {
			writeRow(&b, row, widths)
		}

		b.WriteString("\n")
	}

	err := os.WriteFile(
		filename,
		[]byte(b.String()),
		0644,
	)
	if err != nil {
		return "", err
	}

	return filename, nil
}

func calcWidths(rows []tableRow) tableWidths {
	widths := tableWidths{
		Port:    len("Port"),
		State:   len("State"),
		Service: len("Service"),
		Banner:  len("Banner"),
		Latency: len("Latency"),
	}

	for _, row := range rows {
		widths.Port = max(widths.Port, stringWidth(row.Port))
		widths.State = max(widths.State, stringWidth(row.State))
		widths.Service = max(widths.Service, stringWidth(row.Service))
		widths.Banner = max(widths.Banner, stringWidth(row.Banner))
		widths.Latency = max(widths.Latency, stringWidth(row.Latency))
	}

	return widths
}

func writeHeader(
	b *strings.Builder,
	widths tableWidths,
) {
	fmt.Fprintf(
		b,
		"| %s | %s | %s | %s | %s |\n",
		padRight("Port", widths.Port),
		padRight("State", widths.State),
		padRight("Service", widths.Service),
		padRight("Banner", widths.Banner),
		padRight("Latency", widths.Latency),
	)

	fmt.Fprintf(
		b,
		"|-%s-|-%s-|-%s-|-%s-|-%s-|\n",
		strings.Repeat("-", widths.Port),
		strings.Repeat("-", widths.State),
		strings.Repeat("-", widths.Service),
		strings.Repeat("-", widths.Banner),
		strings.Repeat("-", widths.Latency),
	)
}

func writeRow(
	b *strings.Builder,
	row tableRow,
	widths tableWidths,
) {
	fmt.Fprintf(
		b,
		"| %s | %s | %s | %s | %s |\n",
		padRight(row.Port, widths.Port),
		padRight(row.State, widths.State),
		padRight(row.Service, widths.Service),
		padRight(row.Banner, widths.Banner),
		padRight(row.Latency, widths.Latency),
	)
}

func padRight(value string, width int) string {
	padding := width - stringWidth(value)

	if padding <= 0 {
		return value
	}

	return value + strings.Repeat(" ", padding)
}

func stringWidth(value string) int {
	return utf8.RuneCountInString(value)
}

func escapeMarkdown(value string) string {
	value = strings.ReplaceAll(value, "|", "\\|")
	value = strings.ReplaceAll(value, "\n", " ")
	value = strings.ReplaceAll(value, "\r", "")

	return value
}

func safeFilename(value string) string {
	value = strings.TrimSpace(value)

	replacer := strings.NewReplacer(
		"/", "-",
		"\\", "-",
		":", "-",
		"*", "-",
		"?", "-",
		"\"", "-",
		"<", "-",
		">", "-",
		"|", "-",
	)

	return replacer.Replace(value)
}
