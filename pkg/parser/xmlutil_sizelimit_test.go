package parser_test

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/EvilBit-Labs/opnDossier/pkg/parser"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestTruncationTracker_ReportsCapReached covers the boundary: a document that
// exactly fills the cap is legal and must not be reported as truncated, while
// one byte more must be.
func TestTruncationTracker_ReportsCapReached(t *testing.T) {
	t.Parallel()

	const body = "<a>0123456789</a>"

	tests := []struct {
		name      string
		maxSize   int64
		truncated bool
	}{
		{"under the cap", int64(len(body)) + 10, false},
		{"exactly at the cap", int64(len(body)), false},
		{"one byte over", int64(len(body)) - 1, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			dec, tracker := parser.NewSecureXMLDecoderTracked(strings.NewReader(body), tt.maxSize)
			for {
				if _, err := dec.Token(); err != nil {
					break
				}
			}

			assert.Equal(t, tt.truncated, tracker.Truncated())
		})
	}
}

// countingReader records how many bytes the reader under test actually
// consumed from the source.
type countingReader struct {
	r    io.Reader
	read int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.read += int64(n)

	return n, err
}

// TestTruncationTracker_CapIsExact pins the byte budget. An earlier version of
// the reader admitted maxSize+1 bytes so it could see past the boundary, which
// quietly made NewSecureXMLDecoder's documented "limited to maxSize bytes" off
// by one. The probe now looks past the cap without spending budget on it, so
// the decoder still receives at most maxSize bytes.
func TestTruncationTracker_CapIsExact(t *testing.T) {
	t.Parallel()

	const limit = 64

	src := &countingReader{r: bytes.NewReader(bytes.Repeat([]byte("x"), limit*8))}

	dec, tracker := parser.NewSecureXMLDecoderTracked(src, limit)
	for {
		if _, err := dec.Token(); err != nil {
			break
		}
	}

	assert.True(t, tracker.Truncated(), "input well over the cap must report truncated")
	assert.LessOrEqual(t, src.read, int64(limit)+1,
		"the decoder must be fed at most maxSize bytes; only the one-byte probe may read past it")
}

// TestTruncationTracker_UnreadIsNotTruncated confirms a fresh tracker reports
// nothing before the reader has been driven.
func TestTruncationTracker_UnreadIsNotTruncated(t *testing.T) {
	t.Parallel()

	_, tracker := parser.NewSecureXMLDecoderTracked(bytes.NewReader([]byte("<a/>")), 4)

	assert.False(t, tracker.Truncated())
}

// TestWrapSizeLimitedDecodeError_NamesTheCap guards a misleading error. The size
// cap ends the stream mid-document, so encoding/xml reports "unexpected EOF" --
// indistinguishable from a corrupt file. An operator handed an 11 MB config.xml
// was told it was malformed and went looking for the wrong problem.
func TestWrapSizeLimitedDecodeError_NamesTheCap(t *testing.T) {
	t.Parallel()

	decodeErr := errors.New("unexpected EOF")

	t.Run("nil error stays nil", func(t *testing.T) {
		t.Parallel()

		assert.NoError(t, parser.WrapSizeLimitedDecodeError(nil, "/opnsense", nil, 10))
	})

	t.Run("not truncated keeps the original wrapping", func(t *testing.T) {
		t.Parallel()

		dec, tracker := parser.NewSecureXMLDecoderTracked(strings.NewReader("<a/>"), 1024)
		for {
			if _, err := dec.Token(); err != nil {
				break
			}
		}

		err := parser.WrapSizeLimitedDecodeError(decodeErr, "/opnsense", tracker, 1024)
		require.Error(t, err)
		require.NotErrorIs(t, err, parser.ErrInputTooLarge)
		require.ErrorIs(t, err, decodeErr)
	})

	t.Run("truncated names the cap", func(t *testing.T) {
		t.Parallel()

		dec, tracker := parser.NewSecureXMLDecoderTracked(strings.NewReader("<a>0123456789</a>"), 4)
		for {
			if _, err := dec.Token(); err != nil {
				break
			}
		}

		err := parser.WrapSizeLimitedDecodeError(decodeErr, "/opnsense", tracker, 4)
		require.Error(t, err)
		require.ErrorIs(t, err, parser.ErrInputTooLarge, "the size cap must be named as the cause")
		require.ErrorIs(t, err, decodeErr, "the underlying decode error must be preserved")
	})
}
