package dht

import (
	"encoding/hex"
	"bytes"
	"crypto/sha1"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	dhtStorePrefix = "NATBYPASS:DHT:STORE:"
	dhtFindPrefix  = "NATBYPASS:DHT:FIND:"
	dhtFoundPrefix = "NATBYPASS:DHT:FOUND:"
)

// NodeInfo представляет информацию об узле в сети Kademlia DHT.
type NodeInfo struct {
	ID       [20]byte
	Address  string
	LastSeen time.Time
}

// Node представляет автономный DHT-узел для децентрализованной сигнализации.
type Node struct {
	NodeID       [20]byte
	Address      string
	RoutingTable [160][]*NodeInfo
	Store        map[[20]byte][]byte
	conn         *net.UDPConn
	mu           sync.RWMutex
	ctxDone      chan struct{}
}

// NewNode создаёт новый DHT-узел с хэшем DeviceID.
func NewNode(deviceID string, address string) *Node {
	hash := sha1.Sum([]byte(deviceID))
	n := &Node{
		NodeID:  hash,
		Address: address,
		Store:   make(map[[20]byte][]byte),
		ctxDone: make(chan struct{}),
	}

	if address != "" {
		if lAddr, err := net.ResolveUDPAddr("udp", address); err == nil {
			if conn, err := net.ListenUDP("udp", lAddr); err == nil {
				n.conn = conn
				go n.listenLoop()
			}
		}
	}
	return n
}

// Close останавливает сетевой сокет DHT-узла.
func (n *Node) Close() {
	n.mu.Lock()
	defer n.mu.Unlock()
	select {
	case <-n.ctxDone:
	default:
		close(n.ctxDone)
	}
	if n.conn != nil {
		_ = n.conn.Close()
	}
}

// Bootstrap подключается к начальным узлам DHT-сети.
func (n *Node) Bootstrap(bootstrapAddrs []string) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	for _, addr := range bootstrapAddrs {
		if addr == "" || addr == n.Address {
			continue
		}
		bootID := sha1.Sum([]byte(addr))
		bucketIdx := n.getBucketIndex(bootID)
		n.RoutingTable[bucketIdx] = append(n.RoutingTable[bucketIdx], &NodeInfo{
			ID:       bootID,
			Address:  addr,
			LastSeen: time.Now(),
		})
	}
	return nil
}

// PublishEndpoint сохраняет endpoint в локальном хранилище и реплицирует его на K ближайших узлов.
func (n *Node) PublishEndpoint(deviceID string, endpoint string) error {
	n.mu.Lock()
	key := sha1.Sum([]byte(deviceID))
	n.Store[key] = []byte(endpoint)
	n.mu.Unlock()

	_ = n.ReplicateToPeers(deviceID, endpoint, 8)
	return nil
}

// ReplicateToPeers реплицирует endpoint на K ближайших узлов из routing table.
func (n *Node) ReplicateToPeers(deviceID string, endpoint string, k int) error {
	n.mu.RLock()
	defer n.mu.RUnlock()

	key := sha1.Sum([]byte(deviceID))
	closest := n.findClosestNodes(key, k)

	for _, peer := range closest {
		if peer.Address == n.Address {
			continue
		}
		go n.sendStoreRequest(peer.Address, key, []byte(endpoint))
	}
	return nil
}

// LookupEndpoint ищет endpoint пира в DHT: сначала локально, затем опрашивает K ближайших узлов.
func (n *Node) LookupEndpoint(deviceID string) (string, error) {
	key := sha1.Sum([]byte(deviceID))

	n.mu.RLock()
	val, ok := n.Store[key]
	n.mu.RUnlock()

	if ok {
		return string(val), nil
	}

	n.mu.RLock()
	closest := n.findClosestNodes(key, 8)
	n.mu.RUnlock()

	for _, peer := range closest {
		if peer.Address == n.Address {
			continue
		}
		if res, err := n.queryRemotePeer(peer.Address, key); err == nil && res != "" {
			n.mu.Lock()
			n.Store[key] = []byte(res)
			n.mu.Unlock()
			return res, nil
		}
	}

	return "", fmt.Errorf("endpoint not found in DHT for device: %s", deviceID)
}

// findClosestNodes возвращает K ближайших узлов по XOR-метрике.
func (n *Node) findClosestNodes(target [20]byte, k int) []*NodeInfo {
	var all []*NodeInfo
	for _, bucket := range n.RoutingTable {
		all = append(all, bucket...)
	}

	// Сортировка по XOR-расстоянию
	sort.Slice(all, func(i, j int) bool {
		distI := xorDistance(n.NodeID, all[i].ID)
		distJ := xorDistance(n.NodeID, all[j].ID)
		return bytes.Compare(distI[:], distJ[:]) < 0
	})

	if len(all) > k {
		return all[:k]
	}
	return all
}

func xorDistance(a, b [20]byte) [20]byte {
	var dist [20]byte
	for i := 0; i < 20; i++ {
		dist[i] = a[i] ^ b[i]
	}
	return dist
}

func (n *Node) getBucketIndex(target [20]byte) int {
	for i := 0; i < 20; i++ {
		diff := n.NodeID[i] ^ target[i]
		if diff != 0 {
			for bit := 7; bit >= 0; bit-- {
				if (diff & (1 << bit)) != 0 {
					idx := (19-i)*8 + bit
					if idx >= 160 {
						idx = 159
					}
					return idx
				}
			}
		}
	}
	return 0
}

func (n *Node) sendStoreRequest(addr string, key [20]byte, val []byte) {
	if rAddr, err := net.ResolveUDPAddr("udp", addr); err == nil {
		msg := fmt.Sprintf("%s%x:%s", dhtStorePrefix, key, string(val))
		if n.conn != nil {
			_, _ = n.conn.WriteToUDP([]byte(msg), rAddr)
		} else {
			if c, err := net.DialUDP("udp", nil, rAddr); err == nil {
				defer c.Close()
				_, _ = c.Write([]byte(msg))
			}
		}
	}
}

func (n *Node) queryRemotePeer(addr string, key [20]byte) (string, error) {
	rAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return "", err
	}
	c, err := net.DialUDP("udp", nil, rAddr)
	if err != nil {
		return "", err
	}
	defer c.Close()

	_ = c.SetDeadline(time.Now().Add(500 * time.Millisecond))
	msg := fmt.Sprintf("%s%x", dhtFindPrefix, key)
	if _, err := c.Write([]byte(msg)); err != nil {
		return "", err
	}

	buf := make([]byte, 2048)
	readN, _, err := c.ReadFromUDP(buf)
	if err != nil {
		return "", err
	}

	resp := string(buf[:readN])
	if strings.HasPrefix(resp, dhtFoundPrefix) {
		parts := strings.SplitN(resp, ":", 4)
		if len(parts) >= 4 {
			return parts[3], nil
		}
	}
	return "", fmt.Errorf("not found on peer")
}

func (n *Node) listenLoop() {
	buf := make([]byte, 4096)
	for {
		select {
		case <-n.ctxDone:
			return
		default:
		}

		_ = n.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		nRead, rAddr, err := n.conn.ReadFromUDP(buf)
		if err != nil {
			if strings.Contains(err.Error(), "closed") {
				return
			}
			continue
		}
		if nRead <= 0 {
			continue
		}

		data := string(buf[:nRead])
		if strings.HasPrefix(data, dhtStorePrefix) {
			payload := strings.TrimPrefix(data, dhtStorePrefix)
			parts := strings.SplitN(payload, ":", 2)
			if len(parts) == 2 {
				keyBytes, err := hex.DecodeString(parts[0])
				if err == nil && len(keyBytes) == 20 {
					var k [20]byte
					copy(k[:], keyBytes)
					n.mu.Lock()
					n.Store[k] = []byte(parts[1])
					n.mu.Unlock()
				}
			}
		} else if strings.HasPrefix(data, dhtFindPrefix) {
			keyHex := strings.TrimPrefix(data, dhtFindPrefix)
			keyBytes, err := hex.DecodeString(keyHex)
			if err == nil && len(keyBytes) == 20 {
				var k [20]byte
				copy(k[:], keyBytes)
				n.mu.RLock()
				val, found := n.Store[k]
				n.mu.RUnlock()
				if found {
					resp := fmt.Sprintf("%s%x:%s", dhtFoundPrefix, k, string(val))
					_, _ = n.conn.WriteToUDP([]byte(resp), rAddr)
				}
			}
		}
	}
}
