package dht

import (
	"crypto/sha1"
	"fmt"
	"sync"
	"time"
)

// NodeInfo представляет информацию об узле в сети Kademlia DHT.
type NodeInfo struct {
	ID        [20]byte
	Address   string
	LastSeen  time.Time
}

// Node представляет автономный DHT-узел для децентрализованной сигнализации.
type Node struct {
	NodeID       [20]byte
	Address      string
	RoutingTable [160][]*NodeInfo
	Store        map[[20]byte][]byte
	mu           sync.RWMutex
}

// NewNode создаёт новый DHT-узел с хэшем DeviceID.
func NewNode(deviceID string, address string) *Node {
	hash := sha1.Sum([]byte(deviceID))
	return &Node{
		NodeID:  hash,
		Address: address,
		Store:   make(map[[20]byte][]byte),
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

// PublishEndpoint сохраняет endpoint в локальном хранилище и реплицирует его.
func (n *Node) PublishEndpoint(deviceID string, endpoint string) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	key := sha1.Sum([]byte(deviceID))
	n.Store[key] = []byte(endpoint)
	return nil
}

// LookupEndpoint ищет endpoint пира в DHT хранилище.
func (n *Node) LookupEndpoint(deviceID string) (string, error) {
	n.mu.RLock()
	defer n.mu.RUnlock()

	key := sha1.Sum([]byte(deviceID))
	if val, ok := n.Store[key]; ok {
		return string(val), nil
	}
	return "", fmt.Errorf("endpoint not found in DHT for device: %s", deviceID)
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
