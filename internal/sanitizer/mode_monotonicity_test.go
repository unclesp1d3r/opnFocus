package sanitizer

import (
	"bytes"
	"encoding/xml"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/pkg/parser"
)

// Mode monotonicity: whatever moderate redacts, aggressive must redact too.
//
// This is the invariant that FieldGuard restores. A rule matched on field name
// alone used to consume the match and then decline inside its Redactor,
// returning the value untouched, which stopped every later rule and the
// value-detector pass from ever seeing it. Because the two rules that did this
// (ip_address_field, subnet_field) are aggressive-only, the effect was that
// aggressive leaked values moderate redacted -- the higher-privacy mode being
// the leaky one. See GOTCHAS.md section 19.2.
//
// Asserting the whole invariant rather than the two known fields is deliberate:
// any future rule that consumes a match without transforming reintroduces the
// class, and the two-field version of this test would not notice.

// leafValues returns every non-empty leaf value in doc, keyed by the dotted
// element path plus an occurrence index, so the same path appearing twice is
// compared position-wise rather than collapsing.
func leafValues(t *testing.T, doc string) map[string]string {
	t.Helper()

	out := map[string]string{}
	seen := map[string]int{}
	var stack []string

	dec := xml.NewDecoder(strings.NewReader(doc))
	dec.Strict = false
	// Fixtures declare us-ascii; without this the walk fails on them and the
	// invariant would go unchecked on exactly the real-world-shaped inputs.
	dec.CharsetReader = parser.CharsetReader

	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			return out
		}
		if err != nil {
			t.Fatalf("parsing sanitized output: %v", err)
		}

		switch tok := tok.(type) {
		case xml.StartElement:
			stack = append(stack, tok.Name.Local)
		case xml.EndElement:
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
		case xml.CharData:
			text := strings.TrimSpace(string(tok))
			if text == "" || len(stack) == 0 {
				continue
			}
			path := strings.Join(stack, ".")
			key := path + "#" + strconv.Itoa(seen[path])
			seen[path]++
			out[key] = text
		}
	}
}

func sanitizeToString(t *testing.T, mode Mode, raw []byte) string {
	t.Helper()

	var buf bytes.Buffer
	if err := NewSanitizer(mode).SanitizeXML(bytes.NewReader(raw), &buf); err != nil {
		t.Fatalf("sanitizing in %v mode: %v", mode, err)
	}

	return buf.String()
}

func TestModes_AggressiveRedactsEverythingModerateDoes(t *testing.T) {
	t.Parallel()

	fixtures, err := filepath.Glob(filepath.Join("..", "..", "testdata", "*.xml"))
	if err != nil {
		t.Fatalf("globbing fixtures: %v", err)
	}
	pf, err := filepath.Glob(filepath.Join("..", "..", "testdata", "pfsense", "*.xml"))
	if err != nil {
		t.Fatalf("globbing pfSense fixtures: %v", err)
	}
	fixtures = append(fixtures, pf...)
	if len(fixtures) == 0 {
		t.Fatal("no fixtures found; the invariant would pass vacuously")
	}

	for _, path := range fixtures {
		t.Run(filepath.Base(path), func(t *testing.T) {
			t.Parallel()

			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("reading fixture: %v", err)
			}

			original := leafValues(t, string(raw))
			moderate := leafValues(t, sanitizeToString(t, ModeModerate, raw))
			aggressive := leafValues(t, sanitizeToString(t, ModeAggressive, raw))

			// path#index keys only line up while every leaf survives in all three
			// documents. If a redaction ever emptied a value its CharData would be
			// skipped, shifting every later index for that path and silently
			// comparing unrelated pairs. Verified true for all shipped fixtures;
			// assert it so a future change fails here instead of passing wrongly.
			if len(moderate) != len(original) || len(aggressive) != len(original) {
				t.Fatalf(
					"leaf counts diverged, so path#index keys no longer align: original=%d moderate=%d aggressive=%d",
					len(original), len(moderate), len(aggressive),
				)
			}

			for key, before := range original {
				modAfter, ok := moderate[key]
				if !ok || modAfter == before {
					continue // moderate left it alone; aggressive is unconstrained
				}

				aggAfter, ok := aggressive[key]
				if !ok {
					continue // element dropped entirely, which is not a leak
				}
				if aggAfter == before {
					t.Errorf(
						"mode monotonicity violated at %s\n  original:   %q\n  moderate:   %q (redacted)\n"+
							"  aggressive: %q (UNCHANGED -- the higher-privacy mode leaked it)",
						key, before, modAfter, aggAfter,
					)
				}
			}
		})
	}
}

// TestModes_AggressiveRedactsEverythingModerateDoes_Synthetic carries the
// invariant on inputs built to trigger it. The fixture sweep above is the
// regression net for real-world-shaped configs, but no shipped fixture puts an
// email address in a <subnet> or <from> element, so on its own it passes
// against the unfixed code and proves nothing. These probes fail without
// FieldGuard.
func TestModes_AggressiveRedactsEverythingModerateDoes_Synthetic(t *testing.T) {
	t.Parallel()

	// Each case is a field whose name matches an aggressive-only rule with a
	// generic pattern, holding a value that rule does not handle but another
	// rule does.
	const probe = `<?xml version="1.0"?>
<pfsense>
  <a><subnet>frank@realcompany.net</subnet></a>
  <b><from>grace@realcompany.net</from></b>
  <c><to>henry@realcompany.net</to></c>
  <d><ipaddr>irene@realcompany.net</ipaddr></d>
  <e><subnet>255.255.255.0</subnet></e>
</pfsense>`

	raw := []byte(probe)
	original := leafValues(t, probe)
	moderate := leafValues(t, sanitizeToString(t, ModeModerate, raw))
	aggressive := leafValues(t, sanitizeToString(t, ModeAggressive, raw))

	if len(moderate) != len(original) || len(aggressive) != len(original) {
		t.Fatalf(
			"leaf counts diverged, so path#index keys no longer align: original=%d moderate=%d aggressive=%d",
			len(original), len(moderate), len(aggressive),
		)
	}

	checked := 0

	for key, before := range original {
		modAfter, ok := moderate[key]
		if !ok || modAfter == before {
			continue
		}

		checked++

		aggAfter, ok := aggressive[key]
		if !ok {
			continue
		}
		if aggAfter == before {
			t.Errorf(
				"mode monotonicity violated at %s\n  original:   %q\n  moderate:   %q (redacted)\n"+
					"  aggressive: %q (UNCHANGED -- the higher-privacy mode leaked it)",
				key, before, modAfter, aggAfter,
			)
		}
	}

	// Guard the guard: if moderate stops redacting these, every assertion above
	// turns into a no-op and the test would pass while checking nothing.
	if checked < 5 {
		t.Fatalf("expected moderate to redact all 5 probe values, it redacted %d", checked)
	}
}
