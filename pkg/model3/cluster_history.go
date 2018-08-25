package model3

type History struct {
	State         []map[string]map[string]*Image
	ImageDeletes  []map[string]int
	ImageAdds     []map[string]int
	ImagesAtCache []map[string]int
}

func (h *History) currentIndex() int {
	h.init()
	return len(h.State) - 1
}

func (h *History) currentState() map[string]map[string]*Image {
	h.init()
	return h.State[h.currentIndex()]
}

func (h *History) ImagesAt(i int) map[string]int {
	total := map[string]int{}
	for before := 0; before <= i; before++ {
		for sha, count := range h.ImageAdds[before] {
			total[sha] += count
		}
		for sha, count := range h.ImageDeletes[before] {
			total[sha] -= count
		}
	}
	for k, m := range total {
		if m == 0 {
			delete(total, k)
		}
	}
	return total
}

func (h *History) init() {
	if h.State == nil {
		h.State = []map[string]map[string]*Image{}
		h.State = append(h.State, map[string]map[string]*Image{})
		h.ImageAdds = []map[string]int{map[string]int{}}
		h.ImageDeletes = []map[string]int{map[string]int{}}
		h.ImagesAtCache = []map[string]int{map[string]int{}}
	}
}

func (h *History) Next() {
	h.init()
	h.State = append(h.State, map[string]map[string]*Image{})
	h.ImageAdds = append(h.ImageAdds, map[string]int{})
	h.ImageDeletes = append(h.ImageDeletes, map[string]int{})

}

func (h *History) ApplyCreate(ns string, images []*Image) {
	h.init()
	c := h.currentIndex()
	if h.State[c] == nil {
		panic("There is no value at this index. bye.")
	}
	h.State[c][ns] = map[string]*Image{}
	for _, img := range images {
		h.State[c][ns][img.SHA] = img
		h.ImageAdds[c][img.SHA] += 1
	}

}

func (h *History) ApplyDestroy(ns string, images []*Image) {
	h.init()
	c := h.currentIndex()
	// delete all of the  vulns that may have been created in that namespace.
	for _, img := range images {
		h.ImageDeletes[c][img.SHA] += 1
	}
}
