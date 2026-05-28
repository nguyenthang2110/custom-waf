// internal/engine/transforms.go
//
// Transform chain functions. Names are lowercase v2; the loader normalises
// v1 UPPERCASE names to lowercase. Unknown transforms are skipped silently
// (logged once at load via validator).
package engine

import (
	"encoding/base64"
	"encoding/hex"
	"html"
	"net/url"
	"path"
	"regexp"
	"strings"
)

// TransformFunc — input/output normalisation step.
type TransformFunc func(string) string

// Built-in transforms registry.
var builtinTransforms = map[string]TransformFunc{
	"url_decode":          transformURLDecode,
	"lowercase":           strings.ToLower,
	"uppercase":           strings.ToUpper,
	"html_decode":         transformHTMLDecode,
	"base64_decode":       transformBase64Decode,
	"hex_decode":          transformHexDecode,
	"remove_nulls":        transformRemoveNulls,
	"remove_whitespace":   transformRemoveWhitespace,
	"compress_whitespace": transformCompressWhitespace,
	"replace_comments":    transformReplaceComments,
	"cmd_normalize":       transformCmdNormalize,
	"normalize_path":      transformNormalizePath,
	"trim":                strings.TrimSpace,
	// v1 legacy aliases — loader emits lowercase; these handle direct callers.
	"URL_DECODE":          transformURLDecode,
	"LOWERCASE":           strings.ToLower,
	"HTML_DECODE":         transformHTMLDecode,
	"BASE64_DECODE":       transformBase64Decode,
	"REMOVE_NULLS":        transformRemoveNulls,
	"REMOVE_WHITESPACE":   transformRemoveWhitespace,
	"COMPRESS_WHITESPACE": transformCompressWhitespace,
}

// applyTransforms — chain runner. Empty chain → identity.
func applyTransforms(value string, chain []string, registry map[string]TransformFunc) string {
	out := value
	for _, name := range chain {
		fn := registry[name]
		if fn == nil {
			// Lowercase fallback (handles "UrlDecode" etc.)
			fn = registry[strings.ToLower(name)]
		}
		if fn == nil {
			continue
		}
		out = fn(out)
	}
	return out
}

// =========================================================================
// Implementations
// =========================================================================

func transformURLDecode(in string) string {
	out := in
	for i := 0; i < 3; i++ { // up to 3 layers of percent-encoding
		next, err := url.QueryUnescape(out)
		if err != nil {
			break
		}
		if next == out {
			break
		}
		out = next
	}
	return out
}

func transformHTMLDecode(in string) string { return html.UnescapeString(in) }

func transformBase64Decode(in string) string {
	if dec, err := base64.StdEncoding.DecodeString(in); err == nil {
		return string(dec)
	}
	if dec, err := base64.URLEncoding.DecodeString(in); err == nil {
		return string(dec)
	}
	if dec, err := base64.RawStdEncoding.DecodeString(in); err == nil {
		return string(dec)
	}
	return in
}

func transformHexDecode(in string) string {
	dec, err := hex.DecodeString(in)
	if err != nil {
		return in
	}
	return string(dec)
}

func transformRemoveNulls(in string) string {
	out := in
	for _, marker := range []string{"\x00", "%00", "\\x00", "\\0"} {
		out = strings.ReplaceAll(out, marker, "")
	}
	return out
}

var (
	reWhitespace         = regexp.MustCompile(`\s+`)
	reMultiWhitespace    = regexp.MustCompile(`\s+`)
	reSqlBlockComment    = regexp.MustCompile(`/\*.*?\*/`)
	reSqlLineComment     = regexp.MustCompile(`(?m)(--|#).*$`)
	reCmdQuoteCarets     = regexp.MustCompile(`["'\^\\]`)
	reCmdQuotesQuote     = regexp.MustCompile(`["']`)
	reCmdBackslashSpace  = regexp.MustCompile(`\\(\s)`)
)

func transformRemoveWhitespace(in string) string {
	return reWhitespace.ReplaceAllString(in, "")
}

func transformCompressWhitespace(in string) string {
	return reMultiWhitespace.ReplaceAllString(in, " ")
}

// transformReplaceComments — strip SQL-style comments (anti-evasion).
func transformReplaceComments(in string) string {
	out := reSqlBlockComment.ReplaceAllString(in, " ")
	out = reSqlLineComment.ReplaceAllString(out, " ")
	return out
}

// transformCmdNormalize — strip cmd-injection evasion chars: c"m"d → cmd,
// c^md → cmd, cmd\<tab> → cmd<tab>.
func transformCmdNormalize(in string) string {
	out := in
	out = reCmdBackslashSpace.ReplaceAllString(out, "$1")
	out = reCmdQuoteCarets.ReplaceAllString(out, "")
	return out
}

// transformNormalizePath — collapse `..`, `//`, `./`.
func transformNormalizePath(in string) string {
	if in == "" {
		return in
	}
	// path.Clean handles . and .. and //; preserve leading slash if any.
	cleaned := path.Clean(in)
	return cleaned
}
