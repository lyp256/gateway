package sconv

import "unsafe"

func String(s []byte) string {
	return unsafe.String(unsafe.SliceData(s), len(s))
}

func ByteSlice(s string) []byte {
	return unsafe.Slice(unsafe.StringData(s), len(s))
}
