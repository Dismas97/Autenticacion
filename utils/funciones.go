package utils

import (
	"unicode"
)

func IndiceMayuscula(s string, i int) string {
	aux := []rune(s)
	if i < 0 || i >= len(aux) {
		return s
	}
	aux[i] = unicode.ToUpper(aux[i])
	return string(aux)
}
