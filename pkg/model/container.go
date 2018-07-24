package model

import (
	"math/rand"
)

type Container struct {
	exposed bool
	image   *Image
}

func randApp() []*Container {
	c := []*Container{}
	// max containers per NS = 12
	l := rand.Int() % 12
	for i := 0; i < l; i++ {
		c[i] = randContainer()
	}
	return c
}

func randContainer() *Container {
	cnj := &Container{
		image:   randImage(),
		exposed: rand.Int()%2 == 0,
	}

	return cnj
}
