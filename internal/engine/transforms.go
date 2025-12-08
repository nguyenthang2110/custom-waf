package engine

import (
	"encoding/base64"
	"html"
	"net/url"
	"regexp"
	"strings"
)

// TransformFunc transforms a string value.
type TransformFunc func(string) string

// registerTransforms registers built-in transform functions.
func (re *RuleEngine) registerTransforms() {
	re.transformFuncs["URL_DECODE"] = transformURLDecode
	re.transformFuncs["LOWERCASE"] = transformLowercase
	re.transformFuncs["REMOVE_WHITESPACE"] = transformRemoveWhitespace
	re.transformFuncs["COMPRESS_WHITESPACE"] = transformCompressWhitespace
	re.transformFuncs["BASE64_DECODE"] = transformBase64Decode
	re.transformFuncs["HTML_DECODE"] = transformHTMLDecode
	re.transformFuncs["REMOVE_NULLS"] = transformRemoveNulls
}

func transformURLDecode(input string) string {
	decoded := input
	for i := 0; i < 3; i++ {
		prev := decoded
		unescaped, err := url.QueryUnescape(decoded)
		if err != nil {
			break
		}
		decoded = unescaped
		if decoded == prev {
			break
		}
	}
	return decoded
}

func transformLowercase(input string) string {
	return strings.ToLower(input)
}

func transformRemoveWhitespace(input string) string {
	return regexp.MustCompile(`\s+`).ReplaceAllString(input, "")
}

func transformCompressWhitespace(input string) string {
	return regexp.MustCompile(`\s+`).ReplaceAllString(input, " ")
}

func transformBase64Decode(input string) string {
	decoded, err := base64.StdEncoding.DecodeString(input)
	if err != nil {
		decoded, err = base64.URLEncoding.DecodeString(input)
		if err != nil {
			return input
		}
	}
	return string(decoded)
}

func transformHTMLDecode(input string) string {
	return html.UnescapeString(input)
}

func transformRemoveNulls(input string) string {
	result := input
	result = strings.ReplaceAll(result, "\x00", "")
	result = strings.ReplaceAll(result, "%00", "")
	result = strings.ReplaceAll(result, "\\x00", "")
	result = strings.ReplaceAll(result, "\\0", "")
	return result
}
