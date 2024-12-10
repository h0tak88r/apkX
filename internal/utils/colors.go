package utils

const (
	ColorHeader  = "\033[95m"
	ColorBlue    = "\033[94m"
	ColorGreen   = "\033[92m"
	ColorWarning = "\033[93m"
	ColorFail    = "\033[91m"
	ColorEnd     = "\033[0m"
)

func Colorize(text string, color string) string {
	return color + text + ColorEnd
}
