package output

import (
	"fmt"
	"ipspect/internal/models"
	"os"
	"sort"
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
	filename :=
		safeFilename(
			models.INFO.TargetName,
		) + ".md"

	var b strings.Builder

	b.WriteString(
		"# ipspect Results\n\n",
	)

	fmt.Fprintf(
		&b,
		"**Target:** %s\n\n",
		escapeMarkdown(
			models.INFO.TargetName,
		),
	)

	writePortSelection(
		&b,
	)

	writeICMPResults(
		&b,
	)

	for _, host := range models.LOOT.Hosts {

		if len(host.Details) == 0 {
			continue
		}

		fmt.Fprintf(
			&b,
			"## %s\n\n",
			escapeMarkdown(
				host.Target,
			),
		)

		rows := make(
			[]tableRow,
			0,
			len(host.Details),
		)

		for _, detail := range host.Details {

			rows = append(
				rows,
				tableRow{
					Port: strconv.Itoa(
						detail.Port,
					),

					State: escapeMarkdown(
						detail.State,
					),

					Service: escapeMarkdown(
						detail.Service,
					),

					Banner: escapeMarkdown(
						detail.Banner,
					),

					Latency: escapeMarkdown(
						detail.
							Latency.
							String(),
					),
				},
			)
		}

		widths :=
			calcWidths(rows)

		writeHeader(
			&b,
			widths,
		)

		for _, row := range rows {
			writeRow(
				&b,
				row,
				widths,
			)
		}

		b.WriteString("\n")

		writeHeaders(
			&b,
			host.Details,
		)
	}

	err := os.WriteFile(
		filename,
		[]byte(
			b.String(),
		),
		0644,
	)

	if err != nil {
		return "", err
	}

	return filename, nil
}

func writePortSelection(
	b *strings.Builder,
) {
	portSpec :=
		strings.TrimSpace(
			models.INFO.PortSpec,
		)

	if portSpec == "" {
		portSpec = fmt.Sprintf(
			"%d-%d",
			models.INFO.PortStart,
			models.INFO.PortEnd,
		)
	}

	fmt.Fprintf(
		b,
		"**Ports:** %s\n\n",
		escapeMarkdown(
			portSpec,
		),
	)
}

func writeICMPResults(
	b *strings.Builder,
) {
	b.WriteString(
		"## ICMP Reachable\n\n",
	)

	if len(
		models.LOOT.ICMPReachable,
	) == 0 {

		b.WriteString(
			"No targets responded to ICMP echo.\n\n",
		)

		return
	}

	for _, host := range models.LOOT.ICMPReachable {

		fmt.Fprintf(
			b,
			"- %s\n",
			escapeMarkdown(host),
		)
	}

	b.WriteString("\n")
}

func writeHeaders(
	b *strings.Builder,
	details []models.PortDetail,
) {
	for _, detail := range details {
		if len(detail.Headers) == 0 {
			continue
		}

		fmt.Fprintf(
			b,
			"### HTTP Headers — Port %d\n\n",
			detail.Port,
		)

		keys := make(
			[]string,
			0,
			len(detail.Headers),
		)

		for key := range detail.Headers {

			keys = append(
				keys,
				key,
			)
		}

		sort.Strings(keys)

		for _, key := range keys {
			values :=
				detail.Headers[key]

			for _, value := range values {

				fmt.Fprintf(
					b,
					"- **%s:** %s\n",
					escapeMarkdown(
						key,
					),
					escapeMarkdown(
						value,
					),
				)
			}
		}

		b.WriteString("\n")
	}
}

func calcWidths(
	rows []tableRow,
) tableWidths {
	widths := tableWidths{
		Port:    len("Port"),
		State:   len("State"),
		Service: len("Service"),
		Banner:  len("Banner"),
		Latency: len("Latency"),
	}

	for _, row := range rows {
		widths.Port = max(
			widths.Port,
			stringWidth(row.Port),
		)

		widths.State = max(
			widths.State,
			stringWidth(row.State),
		)

		widths.Service = max(
			widths.Service,
			stringWidth(row.Service),
		)

		widths.Banner = max(
			widths.Banner,
			stringWidth(row.Banner),
		)

		widths.Latency = max(
			widths.Latency,
			stringWidth(row.Latency),
		)
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
		padRight(
			"Port",
			widths.Port,
		),
		padRight(
			"State",
			widths.State,
		),
		padRight(
			"Service",
			widths.Service,
		),
		padRight(
			"Banner",
			widths.Banner,
		),
		padRight(
			"Latency",
			widths.Latency,
		),
	)

	fmt.Fprintf(
		b,
		"|-%s-|-%s-|-%s-|-%s-|-%s-|\n",
		strings.Repeat(
			"-",
			widths.Port,
		),
		strings.Repeat(
			"-",
			widths.State,
		),
		strings.Repeat(
			"-",
			widths.Service,
		),
		strings.Repeat(
			"-",
			widths.Banner,
		),
		strings.Repeat(
			"-",
			widths.Latency,
		),
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
		padRight(
			row.Port,
			widths.Port,
		),
		padRight(
			row.State,
			widths.State,
		),
		padRight(
			row.Service,
			widths.Service,
		),
		padRight(
			row.Banner,
			widths.Banner,
		),
		padRight(
			row.Latency,
			widths.Latency,
		),
	)
}

func padRight(
	value string,
	width int,
) string {
	padding :=
		width -
			stringWidth(value)

	if padding <= 0 {
		return value
	}

	return value +
		strings.Repeat(
			" ",
			padding,
		)
}

func stringWidth(
	value string,
) int {
	return utf8.RuneCountInString(
		value,
	)
}

func escapeMarkdown(
	value string,
) string {
	value = strings.ReplaceAll(
		value,
		"|",
		"\\|",
	)

	value = strings.ReplaceAll(
		value,
		"\n",
		" ",
	)

	value = strings.ReplaceAll(
		value,
		"\r",
		"",
	)

	return value
}

func safeFilename(
	value string,
) string {
	value =
		strings.TrimSpace(value)

	replacer :=
		strings.NewReplacer(
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

	return replacer.Replace(
		value,
	)
}
