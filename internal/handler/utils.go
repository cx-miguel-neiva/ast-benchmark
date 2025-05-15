package handler

import "fmt"

func ToStr(value interface{}) string {
	if value == nil {
		return ""
	}
	str, ok := value.(string)
	if !ok {
		return fmt.Sprintf("%v", value)
	}
	return str
}
