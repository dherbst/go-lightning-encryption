package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"reflect"
)

var (
	i          [1]int
	intSize    = int(reflect.TypeOf(i).Elem().Size())
	block_size = aes.BlockSize
)

func main() {
	// START OMIT1
	// prep the plaintext by taking your string, and returning a byte array
	plain := "Hello there"
	plainbytes := []byte(plain)
	paddedplainbytes := pad(plainbytes)

	fmt.Printf("plain=%v\n", plain)
	fmt.Printf("paddedplainbytes=%v\n", paddedplainbytes)

	// byte array to hold the encrypted bytes
	ciphertext := make([]byte, len(paddedplainbytes))

	key, _ := hex.DecodeString("4242424242424242424242424242424242424242424242424242424242424242")
	iv, _ := hex.DecodeString("42424242424242424242424242424242")
	// your key needs to be the right size
	block, err := aes.NewCipher(key)
	if err != nil {
		fmt.Printf("Error getting NewCipher %v\n", err)
	}
	// END OMIT1

	// START OMIT2
	// if you use the same iv every time that is considered non-optimal
	// better to generate one randomly and encode it into the data
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, paddedplainbytes)

	fmt.Printf("encrypted=%v\n", base64.StdEncoding.EncodeToString(ciphertext))
	// END OMIT2
}

// Pad with the standard repeating bytes to block size 16 as PKCS#5 does
func pad(src []byte) []byte {
	oversize := block_size - (len(src) % block_size)
	newsize := len(src) + oversize
	result := make([]byte, newsize, newsize)
	copy(result, src)
	b := make([]byte, intSize)
	switch intSize {
	case 64 / 8:
		binary.BigEndian.PutUint64(b, uint64(oversize))
	case 32 / 8:
		binary.BigEndian.PutUint32(b, uint32(oversize))
	default:
		panic("unknown intSize")
	}
	for i := len(src); i < (len(src) + oversize); i++ {
		result[i] = b[intSize-1]
	}
	return result
}
