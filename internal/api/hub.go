package api

import (
	"sync"
	"sync/atomic"
)

// Hub broadcasts Server-Sent Events to all connected subscribers.
// All methods are safe for concurrent use.
type Hub struct {
	sub       chan chan []byte
	unsub     chan chan []byte
	pub       chan []byte
	quit      chan struct{}
	done      chan struct{}
	closeOnce sync.Once
	clients   atomic.Int64 // current subscriber count, for /metrics
}

func newHub() *Hub {
	h := &Hub{
		sub:   make(chan chan []byte, 16),
		unsub: make(chan chan []byte, 16),
		pub:   make(chan []byte, 256),
		quit:  make(chan struct{}),
		done:  make(chan struct{}),
	}
	go h.run()
	return h
}

func (h *Hub) run() {
	defer close(h.done)
	clients := map[chan []byte]struct{}{}
	for {
		select {
		case <-h.quit:
			for c := range clients {
				close(c)
			}
			h.clients.Store(0)
			return
		case c := <-h.sub:
			clients[c] = struct{}{}
			h.clients.Store(int64(len(clients)))
		case c := <-h.unsub:
			if _, ok := clients[c]; ok {
				delete(clients, c)
				close(c)
			}
			h.clients.Store(int64(len(clients)))
		case msg := <-h.pub:
			for c := range clients {
				select {
				case c <- msg:
				default: // slow client: skip rather than block
				}
			}
		}
	}
}

func (h *Hub) subscribe() chan []byte {
	c := make(chan []byte, 32)
	h.sub <- c
	return c
}

func (h *Hub) unsubscribe(c chan []byte) {
	select {
	case h.unsub <- c:
	case <-h.quit:
	}
}

func (h *Hub) publish(msg []byte) {
	select {
	case h.pub <- msg:
	case <-h.quit:
	}
}

// clientCount returns the current number of connected subscribers.
func (h *Hub) clientCount() int64 { return h.clients.Load() }

// close shuts the hub down and disconnects all subscribers. Idempotent:
// it is called from both Server.Shutdown (to unblock SSE handlers before
// http.Server.Shutdown) and Server.Close.
func (h *Hub) close() {
	h.closeOnce.Do(func() { close(h.quit) })
	<-h.done
}
