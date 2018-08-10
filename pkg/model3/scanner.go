package model3

// Scan Tool

type ScanTool struct {
	Queue   map[string]*Image
	Scanned map[string]*Image
}

func (s *ScanTool) init() {
	if s.Queue == nil {
		s.Queue = map[string]*Image{}
		s.Scanned = map[string]*Image{}
	}
}
func (s *ScanTool) Enqueue(i *Image) {
	s.init()
	s.Queue[i.SHA] = i
}

// ScanNewImage takes an image from the queue and 'scans' it, i.e.,
// adds its contents to the scanned queue.  Theres no 'work' done here,
// b/c each image has a fundamental 'truth' associated with it.
func (s *ScanTool) ScanNewImage() {
	s.init()
	for k, v := range s.Queue {
		_, scanned := s.Scanned[k]
		if !scanned {
			s.Scanned[k] = v
			return
		}
	}
}
