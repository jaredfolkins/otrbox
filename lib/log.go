package src

import (
	"fmt"
	"os"
)

func Logl(s string) {
	fmt.Println(s)
}

func Errl(err error) {
	fmt.Println(err)
}

func Fatall(err error) {
	fmt.Println(err)
	os.Exit(3)
}
