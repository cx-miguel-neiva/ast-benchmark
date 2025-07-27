package handler

import (
	"crypto/sha256"
	"fmt"
)

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

func GenerateResultID(resourceType, resource, category, value string) string {
	uniqueString := fmt.Sprintf("%s|%s|%s|%s", resourceType, resource, category, value)

	hash := sha256.Sum256([]byte(uniqueString))
	return fmt.Sprintf("%x", hash)[:32]
}
