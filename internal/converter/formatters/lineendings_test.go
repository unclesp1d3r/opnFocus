package formatters_test

import (
	"testing"

	"github.com/EvilBit-Labs/opnDossier/internal/converter/formatters"
)

func TestNormalizeToLF(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "crlf", input: "a\r\nb", want: "a\nb"},
		{name: "bare cr", input: "a\rb", want: "a\nb"},
		{name: "mixed", input: "a\r\nb\rc\nd", want: "a\nb\nc\nd"},
		{name: "trailing crlf", input: "a\r\n", want: "a\n"},
		{name: "consecutive crlf", input: "a\r\n\r\nb", want: "a\n\nb"},
		{name: "already lf", input: "a\nb", want: "a\nb"},
		{name: "no line endings", input: "abc", want: "abc"},
		{name: "empty", input: "", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := formatters.NormalizeToLF(tt.input); got != tt.want {
				t.Errorf("NormalizeToLF(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
