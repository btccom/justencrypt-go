package justencrypt

import (
	"github.com/stretchr/testify/assert"
	"log"
	"testing"
)

func TestEncryptionAndMySanity(t *testing.T) {
	pw := []byte(`hey there good password!`)
	header := Header{}
	err := header.Generate()
	assert.NoError(t, err)

	sensitive := []byte(`topsecret - or key material`)
	_, iv, cipherText, err := header.EncryptInner(sensitive, pw)
	assert.NoError(t, err)

	plainText, err := header.DecryptInner(cipherText, iv, pw)
	assert.NoError(t, err)
	log.Println(cipherText)
	log.Println(string(plainText))

}
