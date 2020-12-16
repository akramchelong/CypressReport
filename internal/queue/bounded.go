package queue

import (
	"container/ring"
)

// Bounded is a queue with a fixed size that will replace the oldest item if
// more items than size are added.
type Bounded struct {
	data *ring.Ring
}

// NewBounded returns a new bounded queue.
func NewBounded(size int) *Bounded {
	return &Bounded{
		data: ring.New(size),
	}
}

// Add will add an element to the end of the queue. If the queue is full, the
// first item inserted will be replaced by the new element.
func (b *Bounded) Add(value interface{}) {
	b.data.Value = value
	b.data = b.data.Next()
}

// Contains will return true if the value is in the queue.
func (b *Bounded) Contains(value interface{}) bool {
	for i := 0; i < b.data.Len(); i++ {
		if b.data.Value == value {
			// reset ring element to that at the start
			b.data = b.data.Move(-1 * i)
			return true
		}
		b.data = b.data.Next()
	}

	return false
}
