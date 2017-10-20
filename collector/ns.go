package collector

import "strings"

var notAllowedChars = map[string][]string{
	//"brackets":     {"(", ")", "[", "]", "{", "}"},
	//"spaces":       {" "},
	//"punctuations": {".", ",", ";", "?", "!"},
	"slashes":      {"|", "\\", "/"},
	//"carets":       {"^"},
	//"quotations":   {"\"", "`", "'"},
}

//ReplaceNotAllowedCharsInNamespacePart replaces not allowed characters in namespace part  by '_'
func ReplaceNotAllowedCharsInNamespacePart(ns string) string {
	for _, chars := range notAllowedChars {
		for _, ch := range chars {
			ns = strings.Replace(ns, ch, "_", -1)
			ns = strings.Replace(ns, "__", "_", -1)
		}
	}
	ns = strings.Trim(ns, "_")
	return ns
}
