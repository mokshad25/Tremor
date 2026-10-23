package pipeline

import "sync"

// Handler processes one batch. Its return value becomes the batch's ack.
type Handler func(*Batch) error

// Run starts workers goroutines that consume q until it is closed and
// drained, acking every batch with the handler's result. It returns a wait
// function that blocks until all workers have exited.
//
// Run deliberately takes no context: shutdown is signalled by q.Close so that
// everything already admitted is processed and acked, never dropped.
func Run(q *Queue, workers int, h Handler) (wait func()) {
	if workers < 1 {
		workers = 1
	}
	var wg sync.WaitGroup
	for range workers {
		wg.Go(func() {
			for b := range q.Batches() {
				b.Ack(h(b))
			}
		})
	}
	return wg.Wait
}
