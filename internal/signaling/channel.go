package signaling

import (
	"context"
	"encoding/json"
	"time"

	"github.com/natbypass/natbypass/internal/crypto"
)

type Payload struct {
	DeviceID  string    // unique device identifier
	PublicKey string    // NaCl public key hex
	PublicIP  string    // external IP
	STUNAddr  string    // STUN-derived addr:port
	WGPubKey  string    // WireGuard public key
	WGPort    int       // WireGuard listen port
	Timestamp time.Time
	Encrypted []byte    // full encrypted blob (optional)
}

type SignalingChannel interface {
	Name() string
	Send(ctx context.Context, payload *Payload) error
	Receive(ctx context.Context) (<-chan *Payload, error)
	IsAvailable(ctx context.Context) bool
	Close() error
}

func EncryptPayload(p *Payload, pubKey, privKey [32]byte) (*Payload, error) {
	data, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	
	enc, err := crypto.Encrypt(data, pubKey, privKey)
	if err != nil {
		return nil, err
	}

	return &Payload{
		Encrypted: enc,
	}, nil
}

func DecryptPayload(p *Payload, senderPub, recipientPriv [32]byte) (*Payload, error) {
	if len(p.Encrypted) == 0 {
		return p, nil
	}

	data, err := crypto.Decrypt(p.Encrypted, senderPub, recipientPriv)
	if err != nil {
		return nil, err
	}

	var res Payload
	if err := json.Unmarshal(data, &res); err != nil {
		return nil, err
	}

	return &res, nil
}
