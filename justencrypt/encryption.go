package justencrypt

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"log"
)

func Encrypt(plainText []byte, passphrase []byte) ([]byte, error) {

	header := &Header{}
	err := header.Generate()
	if err != nil {
		return emptyArray, err
	}

	headerBytes, iv, ct, err := header.EncryptInner(plainText, passphrase)
	if err != nil {
		return emptyArray, err
	}

	serialized := make([]byte, 0, len(headerBytes)+IvLen+len(ct))
	serialized = append(serialized, headerBytes...)
	serialized = append(serialized, iv...)
	serialized = append(serialized, ct...)

	hex2 := hex.EncodeToString(serialized)
	log.Println(hex2)

	return serialized, nil
}

func Decrypt(cipherText []byte, passphrase []byte) ([]byte, error) {

	log.Println(cipherText)
	buffer := bytes.NewBuffer(cipherText)
	header := &Header{}
	err := header.Parse(buffer)
	if err != nil {
		return emptyArray, err
	}
	log.Printf("%+v", header)
	iv := make([]byte, IvLen)
	err = binary.Read(buffer, binary.BigEndian, iv)

	inner := bytes.NewBuffer(make([]byte, 0))
	_, err = inner.ReadFrom(buffer)
	if err != nil {
		return emptyArray, err
	}

	pt, err := header.DecryptInner(inner.Bytes(), iv, passphrase)
	if err != nil {
		return emptyArray, err
	}

	return pt, nil
}
