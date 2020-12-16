package queue

import (
	"fmt"
	"testing"
)

func TestAddElement(t *testing.T) {
	size := 5
	bq := NewBounded(size)

	// Should be able to add more element that size
	for i := 0; i < size+1; i++ {
		bq.Add(i)
	}
}

func TestContains(t *testing.T) {
	bq := NewBounded(2)

	elem := "A"
	bq.Add(elem)
	if !bq.Contains(elem) {
		t.Errorf("Expected queue to contain %q", elem)
	}

	elem = "B"
	bq.Add(elem)
	if !bq.Contains(elem) {
		t.Errorf("Expected queue to contain %q", elem)
	}

	if bq.Contains("Ö") {
		t.Errorf("Expected queue to not contain %q", elem)
	}

	elem = "C"
	bq.Add(elem)
	if !bq.Contains(elem) {
		t.Errorf("Expected queue to contain %q", elem)
	}

	// Since size is 2, A should not be in the queue (pushed out by "C")
	if bq.Contains("A") {
		t.Errorf("Expected queue to not contain %q", "A")
	}
}

// TestOrderInQueue tests that contains should not affect the order to which elements are added
func TestOrderInQueue(t *testing.T) {
	bq := NewBounded(6)
	for i := 1; i <= 5; i++ {
		bq.Add(i)
	}

	want := true
	got := bq.Contains(3)
	if got != want {
		t.Error("Expected element to exists within queue")
	}

	// This should add the element at the end (sixth element out of a size of 6)
	bq.Add(10)
	// This should remove the first element, i.e. remove 1 and add 100 since
	// the queue is "full"
	bq.Add(100)

	tests := []struct {
		in   int
		want bool
	}{
		{99, false},
		{1, false},
		{2, true},
		{3, true},
		{4, true},
		{5, true},
		{10, true},
		{100, true},
	}

	for _, tt := range tests {
		name := fmt.Sprintf("Testing with %d", tt.in)
		t.Run(name, func(t *testing.T) {
			got := bq.Contains(tt.in)
			if got != tt.want {
				t.Errorf("\ngot:\n\t%t\nwant:\n\t%t\nfor element %d", got, tt.want, tt.in)
			}
		})
	}
}
