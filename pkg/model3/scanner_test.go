package model3

import (
	"testing"

	"github.com/sirupsen/logrus"
)

func TestScanQ(t *testing.T) {
	st := &ScanTool{}
	i1 := &Image{
		SHA:  "asdf",
		Name: "jay1",
	}
	i2 := &Image{
		SHA:  "asd",
		Name: "jay1",
	}

	st.Enqueue(i1)
	st.Enqueue(i2)

	v1 := st.ScanNewImage(0)
	v2 := st.ScanNewImage(0)
	st.ScanNewImage(0)
	st.ScanNewImage(0)

	// make sure we see the SHA in the return values...
	if v1 != "asdf" && v2 != "asdf" {
		logrus.Infof("Didnt get scanned image SHA back: %v", v1)
		t.Fail()
	}

	if len(st.Scanned) != 2 {
		logrus.Infof("failing b/c scanned != 2, %v", st.Scanned)
		t.Fail()
	}
	if len(st.Queue) != 0 {
		logrus.Infof("failing b/c Queue still exitsts, %v", st.Queue)
		t.Fail()
	}
}
