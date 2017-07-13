package justencrypt

import (
	"fmt"
	"io/ioutil"
)

const (
	TestCaseFmt = "Test case %d"
)

func desc(i int) string {
	return fmt.Sprintf(TestCaseFmt, i)
}
func readFile(filename string) []byte {
	source, err := ioutil.ReadFile(filename)
	if err != nil {
		panic(err)
	}
	return source
}
