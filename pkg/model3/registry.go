package model3

import (
	"fmt"
	"math/rand"

	randomdata "github.com/Pallinder/go-randomdata"
	"github.com/sirupsen/logrus"
)

type Registry struct {
	Images        map[string]*Image
	ImagesByIndex []*Image
}

func (r *Registry) RandImageFrom() *Image {
	if len(r.Images) != len(r.ImagesByIndex) {
		panic(fmt.Sprintf("Something is wrong with the index of images!!! %v %v", len(r.Images), len(r.ImagesByIndex)))
	}
	index := rand.Intn(len(r.Images))
	return r.ImagesByIndex[index]
}

// internal function only call me once, when initing.
func (r *Registry) createIndex() {
	r.ImagesByIndex = []*Image{}
	// build random image index...
	i := 0
	for _, img := range r.Images {
		r.ImagesByIndex = append(r.ImagesByIndex, img)
		i++
	}

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
				// omg ya i did it. i used a goto for no reason.
				goto returnnow
			}
		}
	}

returnnow:
	r.createIndex()
	for _, i := range r.Images {
		logrus.Infof("New reg: image %v", i)
	}
	return r
}
