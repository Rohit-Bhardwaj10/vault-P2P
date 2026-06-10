package main

import (
	"fmt"
	"strings"
)

const barWidth = 30

// progressBar renders a single-line progress bar and overwrites the previous
// line using a carriage return (works on any ANSI terminal).
//
// Example output:
//
//	Sending  [===========>          ]  45%  4.5 MB / 10.0 MB
func progressBar(label string, sent, total int64) {
	if total <= 0 {
		fmt.Printf("\r%s  %s sent", label, fmtBytes(sent))
		return
	}
	pct := float64(sent) / float64(total)
	filled := int(pct * barWidth)
	if filled > barWidth {
		filled = barWidth
	}
	bar := strings.Repeat("=", filled)
	if filled < barWidth {
		bar += ">"
		bar += strings.Repeat(" ", barWidth-filled-1)
	}
	fmt.Printf("\r%-10s [%s] %3.0f%%  %s / %s",
		label, bar, pct*100, fmtBytes(sent), fmtBytes(total))
}

// progressDone prints the final "done" line after a transfer completes.
func progressDone(label string, total int64) {
	bar := strings.Repeat("=", barWidth)
	fmt.Printf("\r%-10s [%s] 100%%  %s\n", label, bar, fmtBytes(total))
}

// fmtBytes formats a byte count as a human-readable string.
func fmtBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}
