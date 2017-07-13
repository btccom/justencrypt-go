package justencrypt

import (
	"github.com/stretchr/testify/assert"
	"testing"
	"bytes"
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

	assert.True(t, bytes.Equal(sensitive, plainText))
}


func TestEncryptionHighLevelSanity(t *testing.T) {
	pw := []byte(`hey there good password!`)
	sensitive := []byte(`topsecret - or key material`)
	cipherText, err := Encrypt(sensitive, pw)
	assert.NoError(t, err)

	plainText, err := Decrypt(cipherText, pw)
	assert.NoError(t, err)

	assert.True(t, bytes.Equal(sensitive, plainText))
}
