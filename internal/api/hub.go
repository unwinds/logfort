package api

// Hub broadcasts Server-Sent Events to all connected subscribers.
// All methods are safe for concurrent use.
type Hub struct {
	sub   chan chan []byte
	unsub chan chan []byte
	pub   chan []byte
	quit  chan struct{}
	done  chan struct{}
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
			return
		case c := <-h.sub:
			clients[c] = struct{}{}
		case c := <-h.unsub:
			if _, ok := clients[c]; ok {
				delete(clients, c)
				close(c)
			}
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

func (h *Hub) close() {
	close(h.quit)
	<-h.done
}
