package main

import (
	cr "github.com/dreddick-home/certrenew/pkg/kcertrenew"
)

const (
	root string = "testdata"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func main() {
	cr.Renew("controller-manager.conf", "testdata", "controller-manager.conf", 1)
}
