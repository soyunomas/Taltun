package engine

import (
	"encoding/binary"
	"fmt"
	"log"
	"sync/atomic"

	"github.com/Soyunomas/taltun/pkg/netutil"
	"github.com/Soyunomas/taltun/pkg/pool"
	"github.com/Soyunomas/taltun/pkg/protocol"
	
	"golang.org/x/net/ipv4"
)

func (e *Engine) loopTunReadAndEncrypt() error {
	const TunBatchSize = BatchSize 
	
	buffsPtrs := make([]*pool.Buff, TunBatchSize)
	buffs := make([][]byte, TunBatchSize)
	sizes := make([]int, TunBatchSize)

	for i := 0; i < TunBatchSize; i++ {
		buffsPtrs[i] = pool.Get()
		buffs[i] = buffsPtrs[i][:]
	}
	
	offset := protocol.HeaderSize
	var lastDstIP uint32
	var lastPeer *PeerInfo

	currentBatch := txBatchPool.Get().(*TxBatch)
	currentBatch.Len = 0

	for {
		n, err := e.ifce.Read(buffs, sizes, offset)
		if err != nil {
			if e.closed.Load() {
				return nil
			}
			return fmt.Errorf("tun read error: %v", err)
		}

		for i := 0; i < n; i++ {
			size := sizes[i]
			if size == 0 {
				continue
			}
			
			packetData := buffs[i][offset : offset+size]
			dstIP := netutil.ExtractDstIP(packetData)
			
			if dstIP == 0 {
				continue
			}
			
			var peer *PeerInfo
			
			if lastPeer != nil && lastDstIP == dstIP {
				peer = lastPeer
			} else {
				peer = e.router.Lookup(dstIP)

				if peer != nil {
					lastDstIP = dstIP
					lastPeer = peer
				} else {
					if e.cfg.Debug {
						// log.Printf("❌ DROP TX: No ruta para %s", netutil.Uint32ToIP(dstIP))
					}
				}
			}

			if peer == nil {
				continue
			}

			endpoint := peer.GetEndpoint()
			aead := peer.GetAEAD()

			if endpoint == nil || aead == nil {
				continue
			}

			outBufPtr := pool.Get()
			outBuf := outBufPtr[:]
			copy(outBuf[offset:], packetData)

			// OPTIMIZACION (STACK): Nonce en stack. Vital para hot-path.
			var nonceArr [protocol.NonceSize]byte
			nonceBuf := nonceArr[:]
			
			copy(nonceBuf[0:4], []byte{0xCA, 0xFE, 0xBA, 0xBE})

			ctr := atomic.AddUint64(&e.txCounter, 1)
			binary.BigEndian.PutUint64(nonceBuf[4:], ctr)
			protocol.EncodeDataHeader(outBuf[:offset], e.localVIP, nonceBuf)

			encrypted := aead.Seal(outBuf[offset:offset], nonceBuf, outBuf[offset:offset+size], nil)
			totalLen := offset + len(encrypted)

			atomic.AddUint64(&peer.BytesTx, uint64(len(encrypted)))
			peer.UpdateTimestamps(false) 

			req := txRequest{
				Data: outBuf[:totalLen],
				Buff: outBufPtr,
				Addr: endpoint,
			}
			
			currentBatch.Reqs[currentBatch.Len] = req
			currentBatch.Len++

			if currentBatch.Len == BatchSize {
				e.sendBatchSafe(currentBatch)
				currentBatch = txBatchPool.Get().(*TxBatch)
				currentBatch.Len = 0
			}
		}

		if currentBatch.Len > 0 {
			e.sendBatchSafe(currentBatch)
			currentBatch = txBatchPool.Get().(*TxBatch)
			currentBatch.Len = 0
		}
	}
}

func (e *Engine) sendBatchSafe(batch *TxBatch) {
	select {
	case e.txCh <- batch:
		// OK
	default:
		for i := 0; i < batch.Len; i++ {
			pool.Put(batch.Reqs[i].Buff)
		}
		txBatchPool.Put(batch)
		if e.cfg.Debug {
			log.Println("⚠️ DROP TX: Channel Full")
		}
	}
}

func (e *Engine) loopUdpBatchWrite() error {
	msgs := make([]ipv4.Message, BatchSize)
	var connIdx int

	for {
		batch := <-e.txCh
		
		count := batch.Len
		if count == 0 {
			txBatchPool.Put(batch)
			continue
		}

		for i := 0; i < count; i++ {
			msgs[i].Buffers = [][]byte{batch.Reqs[i].Data}
			msgs[i].Addr = batch.Reqs[i].Addr
		}

		conn := e.pconns[connIdx]
		connIdx = (connIdx + 1) % len(e.pconns)

		n, err := conn.WriteBatch(msgs[:count], 0)
		if err != nil {
			if e.cfg.Debug {
				log.Printf("writebatch error: %v", err)
			}
			if e.closed.Load() {
				return nil
			}
		} else if n < count && e.cfg.Debug {
			log.Printf("⚠️ WriteBatch Parcial: %d/%d enviados", n, count)
		}

		for i := 0; i < count; i++ {
			pool.Put(batch.Reqs[i].Buff)
			batch.Reqs[i].Buff = nil
			batch.Reqs[i].Data = nil
			msgs[i].Buffers = nil
		}

		txBatchPool.Put(batch)
	}
}
