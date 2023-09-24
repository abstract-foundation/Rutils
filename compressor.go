package rutils

import (
	"bytes"

	"github.com/pierrec/lz4"
)

func compressString(input string) ([]byte, error) {
	var b bytes.Buffer
	writer := lz4.NewWriter(&b)

	_, err := writer.Write([]byte(input))
	if err != nil {
		return nil, err
	}

	err = writer.Close()
	if err != nil {
		return nil, err
	}

	return b.Bytes(), nil
}

func decompressString(input []byte) (string, error) {
	reader := lz4.NewReader(bytes.NewReader(input))

	decompressed := make([]byte, len(input)*3) // Make a buffer large enough to hold the decompressed data
	n, err := reader.Read(decompressed)
	if err != nil {
		return "", err
	}

	return string(decompressed[:n]), nil
}
