package justencrypt

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestHeader_DeriveKey(t *testing.T) {
	header := Header{}
	err := header.Generate()
	assert.NoError(t, err)

	assert.Equal(t, DefaultIterations, header.Iterations)
	assert.Equal(t, DefaultSaltLen, header.SaltLen)
	assert.Equal(t, int(DefaultSaltLen), len(header.Salt))
}
