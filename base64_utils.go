package shad0w

import "encoding/base64"

func toBase64(byt []byte) string {
	return base64.StdEncoding.EncodeToString(byt)
}

func fromBase64(str string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(str)
}