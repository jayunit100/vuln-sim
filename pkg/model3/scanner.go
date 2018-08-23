package model3

import "fmt"

// Scan Tool

type ScanTool struct {
	scans      int
	Queue      map[string]*Image
	Scanned    map[string]*Image
	Importance map[string]int

	// map of SHA to scan time, for historical lookup.
	History map[string]int
}

func (s *ScanTool) Debug() string {
	x := fmt.Sprintf("%v --- ", len(s.History))
	for scan, h := range s.History {
		x += fmt.Sprintf("(image:%v time:%v)", scan, h)
	}
	return x
}

func (s *ScanTool) init() {
	if s.Queue == nil {
		s.Queue = make(map[string]*Image, 10000)
		s.Scanned = make(map[string]*Image, 10000)
		s.Importance = make(map[string]int, 10000)
		s.History = make(map[string]int, 1000)
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
func (s *ScanTool) ScanNewImage(time int) string {
	s.init()
	s.scans++
	for k, v := range s.Queue {
		delete(s.Queue, k)
		s.History[k] = time // use this to determine when the scan happened.
		s.Scanned[k] = v
		//logrus.Infof("Scanned: H %v M %v L %v", v.HasHighVulns, v.HasMedVulns, v.HasLowVulns)
		return k
	}
	return ""
}
