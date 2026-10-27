package parser

import (
	"strconv"
	"strings"
)

func isDigit(c byte) bool { return c >= '0' && c <= '9' }
func isAlpha(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }
func toLowerB(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + 32
	}
	return c
}

func pad2(n int) string {
	if n < 0 {
		n = 0
	}
	if n > 99 {
		n = 99
	}
	return string([]byte{byte('0' + n/10), byte('0' + n%10)})
}

func pad4(n int) string {
	if n < 0 {
		n = 0
	}
	s := strconv.Itoa(n)
	for len(s) < 4 {
		s = "0" + s
	}
	return s
}

// atoi parses an integer prefix, skipping leading whitespace like C atoi.
func atoi(s string) int {
	i := 0
	for i < len(s) && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r') {
		i++
	}
	neg := false
	if i < len(s) && (s[i] == '-' || s[i] == '+') {
		neg = s[i] == '-'
		i++
	}
	n := 0
	for ; i < len(s) && isDigit(s[i]); i++ {
		n = n*10 + int(s[i]-'0')
	}
	if neg {
		return -n
	}
	return n
}

// take returns up to n bytes from p, clamped to the string end.
func take(s string, p, n int) string {
	if p >= len(s) {
		return ""
	}
	if p+n > len(s) {
		n = len(s) - p
	}
	return s[p : p+n]
}

// takeInt parses a run of digits at p.
func takeInt(s string, p int) (int, int, bool) {
	start := p
	for p < len(s) && isDigit(s[p]) {
		p++
	}
	if p == start {
		return 0, p, false
	}
	return atoi(s[start:p]), p, true
}

// asciiLower lowercases the whole string.
func asciiLower(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		b.WriteByte(toLowerB(s[i]))
	}
	return b.String()
}

// containsWord matches a whole word so "accept" does not match "cp".
func containsWord(low, word string) bool {
	if word == "" {
		return false
	}
	for i := 0; ; {
		j := strings.Index(low[i:], word)
		if j < 0 {
			return false
		}
		at := i + j
		before := at == 0 || !isWordByte(low[at-1])
		afterIdx := at + len(word)
		after := afterIdx >= len(low) || !isWordByte(low[afterIdx])
		if before && after {
			return true
		}
		i = at + 1
		if i >= len(low) {
			return false
		}
	}
}

func isWordByte(c byte) bool {
	return isAlpha(c) || isDigit(c) || c == '_'
}

// findKVKey locates "key=" case-insensitively and returns the value start.
func findKVKey(msg, key string) (int, bool) {
	klen := len(key)
	if klen == 0 {
		return 0, false
	}
	for i := 0; i+klen < len(msg); i++ {
		ok := true
		for j := 0; j < klen; j++ {
			if toLowerB(msg[i+j]) != toLowerB(key[j]) {
				ok = false
				break
			}
		}
		if ok && msg[i+klen] == '=' {
			return i + klen + 1, true
		}
	}
	return 0, false
}

func isValueEnd(c byte) bool {
	switch c {
	case '\x00', ' ', '\n', '\r', '\t', ',', ';', ']', ')', '"', '\'':
		return true
	}
	return false
}

// extractKV returns the value for key, stopping at a value terminator.
func extractKV(msg, key string) (string, bool) {
	start, ok := findKVKey(msg, key)
	if !ok {
		return "", false
	}
	end := start
	for end < len(msg) && !isValueEnd(msg[end]) {
		end++
	}
	if end == start {
		return "", false
	}
	return msg[start:end], true
}

// extractKVInt returns the integer value for key, or -1 when absent.
func extractKVInt(msg, key string) int {
	if v, ok := extractKV(msg, key); ok {
		return atoi(v)
	}
	return -1
}

// intPtr converts the C "-1 means unset" sentinel into a nullable pointer.
func intPtr(v int) *int {
	if v < 0 {
		return nil
	}
	return &v
}
