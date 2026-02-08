package core

import (
	"sync"
	"time"
)

// Fragment header layout (4 bytes):
//   [msg_id: 2B][frag_index: 1B][frag_total: 1B]
//
// When frag_total == 1, the sender OMITS the header entirely (zero overhead
// for small datagrams). The receiver distinguishes fragmented from unfragmented
// datagrams via a 1-byte flag prepended by SendDatagramFragmented /
// datagramReceiver:
//   0x00 = unfragmented (payload follows directly)
//   0x01 = fragmented  (4-byte header + payload)

const (
	fragHeaderSize = 4
	fragFlagSize   = 1
	fragFlagRaw    = 0x00
	fragFlagFrag   = 0x01

	// Conservative max size for each datagram passed to quic.Conn.SendDatagram().
	// QUIC minimum UDP payload is 1200 bytes. After short header (~25B), AEAD (16B),
	// and DATAGRAM frame header (~3B), ~1156 bytes remain for data. We use 1100 to
	// leave comfortable margin regardless of connection ID length or PMTU state.
	maxSafeDatagramSize = 1100

	// Maximum in-flight incomplete messages per peer before oldest is evicted.
	maxReassemblyPerPeer = 32
	// Time after which incomplete messages are discarded.
	reassemblyTimeout = 100 * time.Millisecond
)

// dgFragmenter handles outbound fragmentation for a single peer connection.
type dgFragmenter struct {
	mu    sync.Mutex
	msgID uint16
}

func (f *dgFragmenter) nextMsgID() uint16 {
	f.mu.Lock()
	id := f.msgID
	f.msgID++
	f.mu.Unlock()
	return id
}

// fragment splits payload into chunks that each fit in maxDatagramSize.
// Returns nil if payload is empty.
func (f *dgFragmenter) fragment(payload []byte, maxDatagramSize int) [][]byte {
	if len(payload) == 0 {
		return nil
	}

	// Account for the flag byte that wraps every datagram on the wire.
	maxWireSize := maxDatagramSize - fragFlagSize

	// If it fits in one datagram (no header needed), send as raw.
	if len(payload) <= maxWireSize {
		buf := make([]byte, fragFlagSize+len(payload))
		buf[0] = fragFlagRaw
		copy(buf[1:], payload)
		return [][]byte{buf}
	}

	// Fragmented: each chunk gets flag + 4-byte header + payload slice.
	chunkSize := maxWireSize - fragHeaderSize
	if chunkSize <= 0 {
		// MTU too small for even one fragment — shouldn't happen in practice.
		return nil
	}
	numFrags := (len(payload) + chunkSize - 1) / chunkSize
	if numFrags > 255 {
		return nil // Can't represent >255 fragments in 1 byte.
	}

	msgID := f.nextMsgID()
	frags := make([][]byte, numFrags)
	for i := 0; i < numFrags; i++ {
		start := i * chunkSize
		end := start + chunkSize
		if end > len(payload) {
			end = len(payload)
		}
		chunk := payload[start:end]
		buf := make([]byte, fragFlagSize+fragHeaderSize+len(chunk))
		buf[0] = fragFlagFrag
		buf[1] = byte(msgID >> 8)
		buf[2] = byte(msgID)
		buf[3] = byte(i)
		buf[4] = byte(numFrags)
		copy(buf[5:], chunk)
		frags[i] = buf
	}
	return frags
}

// dgReassembler handles inbound reassembly for datagrams from all peers.
type dgReassembler struct {
	mu       sync.Mutex
	peers    map[keyArray]*peerReassembly
	stopOnce sync.Once
	stopCh   chan struct{}
}

type peerReassembly struct {
	// ring of in-flight messages, keyed by msgID
	msgs    map[uint16]*pendingMsg
	ordered []uint16 // insertion order for eviction
}

type pendingMsg struct {
	fragments [][]byte
	received  int
	total     int
	created   time.Time
}

func newDgReassembler() *dgReassembler {
	r := &dgReassembler{
		peers:  make(map[keyArray]*peerReassembly),
		stopCh: make(chan struct{}),
	}
	go r.cleanupLoop()
	return r
}

func (r *dgReassembler) stop() {
	r.stopOnce.Do(func() { close(r.stopCh) })
}

// process takes a raw wire datagram (with flag byte) and returns a complete
// reassembled payload, or nil if the datagram is a fragment of an incomplete message.
func (r *dgReassembler) process(from keyArray, wire []byte) []byte {
	if len(wire) < fragFlagSize {
		return nil
	}

	flag := wire[0]
	if flag == fragFlagRaw {
		// Unfragmented: return payload directly (strip flag byte).
		return wire[1:]
	}
	if flag != fragFlagFrag || len(wire) < fragFlagSize+fragHeaderSize {
		return nil // Malformed
	}

	msgID := uint16(wire[1])<<8 | uint16(wire[2])
	fragIndex := int(wire[3])
	fragTotal := int(wire[4])
	fragData := wire[5:]

	if fragTotal == 0 || fragIndex >= fragTotal {
		return nil // Malformed
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	pr, ok := r.peers[from]
	if !ok {
		pr = &peerReassembly{msgs: make(map[uint16]*pendingMsg)}
		r.peers[from] = pr
	}

	pm, ok := pr.msgs[msgID]
	if !ok {
		// Evict oldest if too many in-flight messages.
		for len(pr.ordered) >= maxReassemblyPerPeer {
			oldest := pr.ordered[0]
			pr.ordered = pr.ordered[1:]
			delete(pr.msgs, oldest)
		}
		pm = &pendingMsg{
			fragments: make([][]byte, fragTotal),
			total:     fragTotal,
			created:   time.Now(),
		}
		pr.msgs[msgID] = pm
		pr.ordered = append(pr.ordered, msgID)
	}

	if pm.total != fragTotal || fragIndex >= len(pm.fragments) {
		return nil // Mismatched total — discard
	}

	if pm.fragments[fragIndex] == nil {
		pm.fragments[fragIndex] = append([]byte(nil), fragData...)
		pm.received++
	}

	if pm.received < pm.total {
		return nil // Not yet complete
	}

	// Reassemble
	totalLen := 0
	for _, f := range pm.fragments {
		totalLen += len(f)
	}
	result := make([]byte, 0, totalLen)
	for _, f := range pm.fragments {
		result = append(result, f...)
	}

	// Clean up
	delete(pr.msgs, msgID)
	for i, id := range pr.ordered {
		if id == msgID {
			pr.ordered = append(pr.ordered[:i], pr.ordered[i+1:]...)
			break
		}
	}

	return result
}

func (r *dgReassembler) cleanupLoop() {
	ticker := time.NewTicker(reassemblyTimeout)
	defer ticker.Stop()
	for {
		select {
		case <-r.stopCh:
			return
		case now := <-ticker.C:
			r.mu.Lock()
			for pk, pr := range r.peers {
				var remaining []uint16
				for _, id := range pr.ordered {
					pm, ok := pr.msgs[id]
					if !ok {
						continue
					}
					if now.Sub(pm.created) > reassemblyTimeout {
						delete(pr.msgs, id)
					} else {
						remaining = append(remaining, id)
					}
				}
				pr.ordered = remaining
				if len(pr.msgs) == 0 {
					delete(r.peers, pk)
				}
			}
			r.mu.Unlock()
		}
	}
}
