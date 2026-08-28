package sanitizer

import (
	"bytes"
	"encoding/xml"
	"errors"
	"io"
	"strings"
	"testing"
)

// assertReparses fails the test when s is not a well-formed XML document.
// The sanitizer's contract is that a config.xml in produces a config.xml out.
func assertReparses(t *testing.T, s string) {
	t.Helper()

	decoder := xml.NewDecoder(strings.NewReader(s))
	for {
		_, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			return
		}
		if err != nil {
			t.Fatalf("sanitized output is not well-formed XML: %v (output: %s)", err, s)
		}
	}
}

// TestSanitizeXML_AcceptsDeclaredCharsets guards a hard failure of the sanitize
// command. sanitizeXMLContent built a decoder with no CharsetReader, so
// encoding/xml refused any declaration other than UTF-8 with "encoding %q
// declared but Decoder.CharsetReader is nil". A real OPNsense config.xml
// declares us-ascii, and two of the fixtures in testdata/ do, so the flagship
// "make this safe to share" command failed outright on its most common input.
func TestSanitizeXML_AcceptsDeclaredCharsets(t *testing.T) {
	t.Parallel()

	body := `<opnsense><system><hostname>fw</hostname></system></opnsense>`

	tests := []struct {
		name string
		decl string
	}{
		{"no declaration", ""},
		{"utf-8", `<?xml version="1.0" encoding="UTF-8"?>`},
		{"utf-8 single quoted", `<?xml version='1.0' encoding='UTF-8'?>`},
		{"us-ascii", `<?xml version='1.0' encoding='us-ascii'?>`},
		{"iso-8859-1", `<?xml version="1.0" encoding="ISO-8859-1"?>`},
		{"windows-1252", `<?xml version="1.0" encoding="Windows-1252"?>`},
		{"no encoding attribute", `<?xml version="1.0"?>`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			s := NewSanitizer(ModeMinimal)
			var out bytes.Buffer
			if err := s.SanitizeXML(strings.NewReader(tt.decl+body), &out); err != nil {
				t.Fatalf("SanitizeXML() error = %v", err)
			}

			assertReparses(t, out.String())

			if !strings.Contains(out.String(), "<hostname>") {
				t.Errorf("document body was lost: %s", out.String())
			}
		})
	}
}

// TestSanitizeXML_RelabelsNonUTF8Declaration checks that the emitted
// declaration matches the bytes actually written. CharsetReader decodes the
// input to UTF-8, so echoing the original "us-ascii" or "iso-8859-1" would
// label the output with an encoding it is not in.
func TestSanitizeXML_RelabelsNonUTF8Declaration(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		decl     string
		wantDecl string
	}{
		// Rewritten: the output is UTF-8, whatever the input declared.
		{"us-ascii", `<?xml version='1.0' encoding='us-ascii'?>`, canonicalXMLDeclaration},
		{"iso-8859-1", `<?xml version="1.0" encoding="ISO-8859-1"?>`, canonicalXMLDeclaration},
		// Preserved byte for byte: already UTF-8, or no encoding named.
		{"utf-8 double quoted", `<?xml version="1.0" encoding="UTF-8"?>`, `<?xml version="1.0" encoding="UTF-8"?>`},
		{"utf-8 single quoted", `<?xml version='1.0' encoding='UTF-8'?>`, `<?xml version='1.0' encoding='UTF-8'?>`},
		// CharsetReader normalizes "_" to "-", so this is UTF-8 and its bytes
		// are passed through untouched; relabelling it would be wrong.
		{"utf_8 underscore alias", `<?xml version="1.0" encoding="UTF_8"?>`, `<?xml version="1.0" encoding="UTF_8"?>`},
		{"version only", `<?xml version="1.0"?>`, `<?xml version="1.0"?>`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			s := NewSanitizer(ModeMinimal)
			var out bytes.Buffer
			if err := s.SanitizeXML(strings.NewReader(tt.decl+`<opnsense><a>x</a></opnsense>`), &out); err != nil {
				t.Fatalf("SanitizeXML() error = %v", err)
			}

			got, _, _ := strings.Cut(out.String(), "\n")
			if got != tt.wantDecl {
				t.Errorf("declaration = %q, want %q", got, tt.wantDecl)
			}
		})
	}
}

// TestSanitizeXML_DecodesHighBytes asserts the charset table is applied rather
// than the bytes being passed through. 0x93 and 0x94 are the Windows-1252 curly
// quotes and are undefined in ISO-8859-1.
func TestSanitizeXML_DecodesHighBytes(t *testing.T) {
	t.Parallel()

	var in bytes.Buffer
	in.WriteString(`<?xml version="1.0" encoding="Windows-1252"?><opnsense><descr>caf`)
	in.WriteByte(0xE9)
	in.WriteByte(0x20)
	in.WriteByte(0x93)
	in.WriteString("crew")
	in.WriteByte(0x94)
	in.WriteString(`</descr></opnsense>`)

	s := NewSanitizer(ModeMinimal)
	var out bytes.Buffer
	if err := s.SanitizeXML(bytes.NewReader(in.Bytes()), &out); err != nil {
		t.Fatalf("SanitizeXML() error = %v", err)
	}

	result := out.String()
	assertReparses(t, result)

	if !strings.Contains(result, "caf\u00e9 \u201ccrew\u201d") {
		t.Errorf("Windows-1252 high bytes were not decoded: %q", result)
	}
	if !strings.Contains(result, canonicalXMLDeclaration) {
		t.Errorf("output still declares a non-UTF-8 charset: %q", result)
	}
}

func TestDeclaresNonUTF8Charset(t *testing.T) {
	t.Parallel()

	tests := []struct {
		decl string
		want bool
	}{
		{`<?xml version="1.0"?>`, false},
		{`<?xml version="1.0" encoding="UTF-8"?>`, false},
		{`<?xml version="1.0" encoding="utf-8"?>`, false},
		{`<?xml version='1.0' encoding='utf8'?>`, false},
		{`<?xml version="1.0" encoding="UTF_8"?>`, false},
		{`<?xml version="1.0" encoding="ISO_8859_1"?>`, true},
		{`<?xml version='1.0' encoding='us-ascii'?>`, true},
		{`<?xml version="1.0" encoding="ISO-8859-1"?>`, true},
		{`<?xml version="1.0" encoding="Windows-1252"?>`, true},
		{`<?xml version="1.0" encoding=""?>`, false},
	}

	for _, tt := range tests {
		t.Run(tt.decl, func(t *testing.T) {
			t.Parallel()

			if got := declaresNonUTF8Charset([]byte(tt.decl)); got != tt.want {
				t.Errorf("declaresNonUTF8Charset(%q) = %v, want %v", tt.decl, got, tt.want)
			}
		})
	}
}
