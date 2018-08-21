package model3

// Scan Tool

type ScanTool struct {
	Queue      map[string]*Image
	Scanned    map[string]*Image
	Importance map[string]int
}

func (s *ScanTool) init() {
	if s.Queue == nil {
		s.Queue = make(map[string]*Image, 10000)
		s.Scanned = make(map[string]*Image, 10000)
		s.Importance = make(map[string]int, 10000)
	}
}

// Some images, after being queued, again become unimportant.
func (s *ScanTool) DeprioritizeBy1(i *Image) {
	s.init()
	s.Importance[i.SHA]--
}

// Add an image to the scan Queue.  If it exists, only importance changes.
func (s *ScanTool) Enqueue(i *Image) {
	s.init()
	s.Queue[i.SHA] = i
	s.Importance[i.SHA]++
}

// ScanNewImage takes an image from the queue and 'scans' it, i.e.,
// adds its contents to the scanned queue.  Theres no 'work' done here,
// b/c each image has a fundamental 'truth' associated with it.
func (s *ScanTool) ScanNewImage() {
	s.init()

	for k, v := range s.Queue {
		_, scanned := s.Scanned[k]
		if !scanned {
			delete(s.Queue, k)
			s.Scanned[k] = v
			//logrus.Infof("Scanned: H %v M %v L %v", v.HasHighVulns, v.HasMedVulns, v.HasLowVulns)
			return
		}
	}
}
