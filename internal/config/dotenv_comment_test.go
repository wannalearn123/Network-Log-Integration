package config

import "testing"

// TestUnquoteStripsInlineComment pins the bug that broke the Telegram API
// base: an unquoted value must end before a trailing " # comment".
func TestUnquoteStripsInlineComment(t *testing.T) {
	cases := map[string]string{
		"https://api.telegram.org   # optional override": "https://api.telegram.org",
		"5\t# tab comment":  "5",
		"plain":             "plain",
		"http://a#fragment": "http://a#fragment",
		`"quoted # kept"`:   "quoted # kept",
		`'single # kept'`:   "single # kept",
		"":                  "",
	}
	for in, want := range cases {
		if got := unquote(in); got != want {
			t.Errorf("unquote(%q) = %q, want %q", in, got, want)
		}
	}
}
