package builder

import (
	"github.com/EvilBit-Labs/opnDossier/internal/converter/formatters"
	"github.com/nao1215/markdown"
)

// renderMarkdown returns the accumulated markdown with line endings normalized
// to LF. It is the only sanctioned way to take output out of this package;
// calling md.String() directly reintroduces the platform-dependent line endings
// described on formatters.NormalizeToLF.
func renderMarkdown(md *markdown.Markdown) string {
	return formatters.NormalizeToLF(md.String())
}
