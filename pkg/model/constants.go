package model

import (
	"strings"

	randomdata "github.com/Pallinder/go-randomdata"
)

var lexicon []string
var sizes []string

func NewConstants() {
	lexicon = []string{}
	for i := 0; i < 1000; i++ {
		lexicon[i] = strings.ToUpper(randomdata.SillyName())
	}

}
