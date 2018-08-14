package model3

import (
	"fmt"
	"math/rand"

	randomdata "github.com/Pallinder/go-randomdata"
)

type Registry struct {
	Images        map[string]*Image
	ImagesByIndex []*Image
}

func (c *Registry) RandImageFrom() *Image {
	index := rand.Intn(len(c.Images))
	return c.ImagesByIndex[index]
}

func NewRegistry(maxBaseNames int, maxImages int) *Registry {
	r := &Registry{}
	r.Images = make(map[string]*Image)
	// make a bunch of base images...
	for i := 0; i < maxBaseNames; i++ {
		//fmt.Printf(fmt.Sprintf("making new image %v", i))
		i := NewImage(randomdata.SillyName(), []string{"latest"})
		r.Images[i.SHA] = i
	}

	done := func() bool {
		return len(r.Images) >= maxImages
	}

	version := 0.0
	for !done() {
		version = version + 1
		for _, v := range r.Images {
			if !done() {
				i := NewImage(v.Name, []string{fmt.Sprintf("%v", version)})
				fmt.Printf(fmt.Sprintf("making new image %v / %v \n", len(r.Images), maxImages))
				r.Images[i.SHA] = i
			} else {
				return r
			}
		}
	}
	r.ImagesByIndex = []*Image{}
	// build random image index...
	i := 0
	for _, img := range r.Images {
		r.ImagesByIndex = append(r.ImagesByIndex, img)
		i++
	}

	return r
}
