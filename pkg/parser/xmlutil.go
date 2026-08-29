package parser

import (
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/text/encoding/charmap"
	"golang.org/x/text/transform"
)

// ErrUnsupportedCharset reports that an XML declaration named an encoding the
// decoder cannot read. Callers wrap decode failures with their own context, so
// this lets them tell an encoding problem apart from a malformed document
// rather than reporting the first as the second.
//
// Check for it with [errors.Is]. It is returned by [CharsetReader], and reaches
// callers wrapped by any decoder that installs it — including
// [NewSecureXMLDecoder] and the auto-detect path of [Factory.CreateDevice].
var ErrUnsupportedCharset = errors.New("unsupported charset")

// NewSecureXMLDecoder returns an *xml.Decoder configured with security hardening:
//   - Input size limited to maxSize bytes (prevents XML bomb attacks)
//   - Entity expansion disabled (prevents XXE attacks)
//   - Charset reader for UTF-8, US-ASCII, ISO-8859-1, and Windows-1252
//
// Both the OPNsense and pfSense parsers delegate to this function to avoid
// duplicating security hardening logic.
func NewSecureXMLDecoder(r io.Reader, maxSize int64) *xml.Decoder {
	dec, _ := NewSecureXMLDecoderTracked(r, maxSize)

	return dec
}

// ErrInputTooLarge reports that the input exceeded the configured maximum size
// and was truncated before the decoder saw the end of the document.
var ErrInputTooLarge = errors.New("input exceeds maximum allowed size")

// TruncationTracker reports whether input remained beyond a reader's size cap. A decode error alone cannot distinguish an oversized document from a
// corrupt one: both surface from encoding/xml as "unexpected EOF", because the
// cap simply ends the stream early. Callers consult this to say which happened.
type TruncationTracker interface {
	// Truncated reports whether input remained beyond the cap. A document
	// that ends exactly at the cap is not truncated: nothing was lost.
	Truncated() bool
}

// truncatingReader caps reads at limit bytes and records whether the cap
// actually cut the input short.
//
// The cap is exact: at most limit bytes reach the decoder, so the documented
// size limit is enforced to the byte. Distinguishing "the document ended
// exactly at the cap" from "the cap cut it short" needs one look past the
// boundary, so when the budget is spent the reader probes the underlying
// stream once. Data there means the input really was truncated; EOF means the
// document simply ended.
type truncatingReader struct {
	r         io.Reader
	remaining int64
	truncated bool
	probed    bool
}

func (t *truncatingReader) Read(p []byte) (int, error) {
	if t.remaining <= 0 {
		t.probeForMore()

		return 0, io.EOF
	}

	if int64(len(p)) > t.remaining {
		p = p[:t.remaining]
	}

	n, err := t.r.Read(p)
	t.remaining -= int64(n)

	return n, err
}

// probeForMore reads a single byte past the cap, once, to decide whether the
// input was truncated. The byte is discarded: the reader is already returning
// EOF to the decoder either way.
func (t *truncatingReader) probeForMore() {
	if t.probed {
		return
	}

	t.probed = true

	var probe [1]byte

	// The read error is deliberately discarded: any outcome other than "a byte
	// was available" means the input ended at or before the cap, which is
	// exactly the not-truncated case. The byte itself is dropped because the
	// reader is already returning EOF to the decoder.
	n, _ := t.r.Read(probe[:]) //nolint:errcheck // see above
	if n > 0 {
		t.truncated = true
	}
}

// Truncated reports whether input remained beyond the cap.
//
// A decoder that stops on the closing root tag never asks for another byte, so
// the budget can be spent without anything having looked past it. The first
// call probes the source once in that state, which makes the answer
// authoritative wherever decoding happened to stop rather than only after the
// reader was driven to EOF.
func (t *truncatingReader) Truncated() bool {
	if t.remaining <= 0 {
		t.probeForMore()
	}

	return t.truncated
}

// NewSecureXMLDecoderTracked is [NewSecureXMLDecoder] plus a tracker reporting
// whether the size cap truncated the input.
//
// Without it an oversized config is indistinguishable from a corrupt one: the
// cap ends the stream mid-document and encoding/xml reports "unexpected EOF",
// so an operator handed an 11 MB config.xml is told their file is malformed and
// goes looking for the wrong problem. Pair the tracker with
// [WrapSizeLimitedDecodeError] to name the real cause.
func NewSecureXMLDecoderTracked(r io.Reader, maxSize int64) (*xml.Decoder, TruncationTracker) {
	tracked := &truncatingReader{r: r, remaining: maxSize}

	dec := xml.NewDecoder(tracked)
	dec.Entity = map[string]string{}
	dec.CharsetReader = CharsetReader

	return dec, tracked
}

// WrapSizeLimitedDecodeError annotates err like [WrapDecodeError], but reports
// the size cap as the cause when the tracker shows the input was truncated.
// Returns nil when err is nil.
func WrapSizeLimitedDecodeError(err error, elementPath string, tracker TruncationTracker, maxSize int64) error {
	if err == nil {
		return nil
	}

	if tracker != nil && tracker.Truncated() {
		return fmt.Errorf("field %q: %w (limit %d bytes): %w", elementPath, ErrInputTooLarge, maxSize, err)
	}

	return WrapDecodeError(err, elementPath)
}

// WrapDecodeError annotates an encoding/xml decode error with the element
// path of the failing node so operators can identify the exact field that
// failed to parse. The path is caller-supplied (e.g., "/opnsense/system"
// or "/pfsense") because XML decoding does not expose the full element
// stack once control is inside encoding/xml. Callers that decode
// section-by-section can build deep paths; callers that decode the entire
// document at once can at least supply the root name.
//
// Returns nil when err is nil so it is safe to call unconditionally.
//
// Both the OPNsense and pfSense parsers delegate to this function to avoid
// duplicating error-wrapping logic. Future device parsers registered with
// [Register] should do the same.
func WrapDecodeError(err error, elementPath string) error {
	if err == nil {
		return nil
	}

	return fmt.Errorf("field %q: %w", elementPath, err)
}

// CharsetReader creates a reader for the specified XML charset declaration.
// Supported encodings: UTF-8, US-ASCII, ISO-8859-1 (Latin1), and Windows-1252.
// Names are matched case-insensitively after trimming space, folding "_" to "-"
// and dropping an IANA ":1987" suffix, so registered spellings such as
// "ISO-8859-1:1987", "latin1" and "cp1252" resolve to the same entry.
//
// UTF-8 and US-ASCII pass through untouched; ISO-8859-1 and Windows-1252 are
// transcoded through golang.org/x/text/encoding/charmap, so the returned reader
// always yields valid UTF-8 rather than merely ASCII-compatible bytes. Anything
// else returns [ErrUnsupportedCharset].
func CharsetReader(charset string, input io.Reader) (io.Reader, error) {
	normalized := strings.ToLower(strings.TrimSpace(charset))
	normalized = strings.ReplaceAll(normalized, "_", "-")
	normalized = strings.TrimSuffix(normalized, ":1987")

	switch normalized {
	case "us-ascii", "ascii":
		return input, nil
	case "utf-8", "utf8":
		return input, nil
	case "iso-8859-1", "iso8859-1", "latin1", "latin-1":
		return transform.NewReader(input, charmap.ISO8859_1.NewDecoder()), nil
	case "windows-1252", "windows1252", "cp1252":
		return transform.NewReader(input, charmap.Windows1252.NewDecoder()), nil
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedCharset, charset)
	}
}
