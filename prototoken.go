//go:generate protoc --go_out=Mgoogle/protobuf/any.proto=github.com/golang/protobuf/ptypes/any:pb token.proto

package prototoken

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"

	"github.com/ThatsMrTalbot/prototoken/pb"
	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes"
	"github.com/pkg/errors"
)

// PrivateKey is used to sign tokens
type PrivateKey interface {
	Generate(data []byte) ([]byte, error)
}

// PublicKey is used to validate tokens
type PublicKey interface {
	Validate(data []byte, signature []byte) error
}

// GenerateBytes generates token bytes
func GenerateBytes(object proto.Message, key PrivateKey) ([]byte, error) {
	token, err := GenerateToken(object, key)
	if err != nil {
		return nil, errors.Wrap(err, "Token could not be generated")
	}

	data, err := proto.Marshal(token)
	return data, errors.Wrap(err, "Token could not be marshaled")
}

// GenerateString generates token string
func GenerateString(object proto.Message, key PrivateKey) (string, error) {
	token, err := GenerateToken(object, key)

	return proto.CompactTextString(token), errors.Wrap(err, "Token could not be generated")
}

// GenerateToken generates a token object
func GenerateToken(object proto.Message, key PrivateKey) (*pb.Token, error) {
	value, err := ptypes.MarshalAny(object)
	if err != nil {
		return nil, errors.Wrap(err, "Value could not be marshaled")
	}

	if key == nil {
		return nil, errors.New("Cannot sign using nil key")
	}

	signature, err := key.Generate(value.Value)
	return &pb.Token{
		Value:     value,
		Signature: signature,
	}, errors.Wrap(err, "Value could not be signed")
}

// ValidateBytes validates token bytes
func ValidateBytes(data []byte, key PublicKey, result proto.Message) (*pb.Token, error) {
	token, err := UnpackBytes(data)
	if err != nil {
		return nil, err
	}

	return token, ValidateToken(token, key, result)
}

// UnpackBytes unpacks token bytes without validation
func UnpackBytes(data []byte) (*pb.Token, error) {
	var token pb.Token
	err := proto.Unmarshal(data, &token)
	return &token, errors.Wrap(err, "Token could not be unmarshaled")
}

// ValidateString validates token string
func ValidateString(data string, key PublicKey, result proto.Message) (*pb.Token, error) {
	token, err := UnpackString(data)
	if err != nil {
		return nil, err
	}

	return token, ValidateToken(token, key, result)
}

// UnpackString unpacks a token string without validation
func UnpackString(data string) (*pb.Token, error) {
	var token pb.Token
	err := proto.UnmarshalText(data, &token)
	return &token, errors.Wrap(err, "Token could not be unmarshaled")
}

// ValidateToken validates token object
func ValidateToken(token *pb.Token, key PublicKey, result proto.Message) error {
	if key == nil {
		return errors.New("Cannot verify using nil key")
	}

	if err := key.Validate(token.Value.Value, token.Signature); err != nil {
		return errors.Wrap(err, "Token could not be validated")
	}

	return ExtractMessage(token, result)
}

// ExtractMessage extracts a tokens value without validation
func ExtractMessage(token *pb.Token, result proto.Message) error {
	err := ptypes.UnmarshalAny(token.Value, result)
	return errors.Wrap(err, "Could not unmarshal token mesasge")
}

type hmacKey struct {
	secret []byte
}

// NewHMACPublicKey creates a new public key
func NewHMACPublicKey(secret []byte) PublicKey {
	key := &hmacKey{secret: secret}
	return key
}

// NewHMACPrivateKey creates a new private key
func NewHMACPrivateKey(secret []byte) PrivateKey {
	key := &hmacKey{secret: secret}
	return key
}

func (h *hmacKey) compareSlice(b1 []byte, b2 []byte) bool {
	if len(b1) != len(b2) {
		return false
	}

	for i := 0; i < len(b1); i++ {
		if b1[i] != b2[i] {
			return false
		}
	}

	return true
}

func (h *hmacKey) Generate(data []byte) ([]byte, error) {
	mac := hmac.New(sha256.New, h.secret)
	_, err := mac.Write(data)
	return mac.Sum(nil), errors.Wrap(err, "Could not generate signature")
}

func (h *hmacKey) Validate(data []byte, signature []byte) error {
	expected, err := h.Generate(data)
	if err != nil {
		return errors.Wrap(err, "Could not generate comparison signature")
	}

	if !h.compareSlice(expected, signature) {
		return errors.New("Invalid signature")
	}

	return nil
}

type rsaPrivateKey struct {
	pk *rsa.PrivateKey
}

// NewRSAPrivateKey creates a private key from an RSA private key
func NewRSAPrivateKey(key *rsa.PrivateKey) PrivateKey {
	return &rsaPrivateKey{
		pk: key,
	}
}

func (r *rsaPrivateKey) Generate(data []byte) ([]byte, error) {
	hash := sha256.Sum256(data)

	// rsa/pss.go panics if it calculates a negative salt size. Catch here.
	salt := (r.pk.N.BitLen()+7)/8 - 2 - crypto.SHA256.Size()
	if salt < 0 {
		return nil, errors.New("Private key must have a bit length of at least 266")
	}

	sig, err := rsa.SignPSS(rand.Reader, r.pk, crypto.SHA256, hash[:], nil)
	return sig, errors.Wrap(err, "Could not sign token")
}

type rsaPublicKey struct {
	pk *rsa.PublicKey
}

// NewRSAPublicKey creates a public key from an RSA public key
func NewRSAPublicKey(key *rsa.PublicKey) PublicKey {
	return &rsaPublicKey{
		pk: key,
	}
}

func (r *rsaPublicKey) Validate(data []byte, signature []byte) error {
	hash := sha256.Sum256(data)
	err := rsa.VerifyPSS(r.pk, crypto.SHA256, hash[:], signature, nil)
	return errors.Wrap(err, "Could not validate signature")
}
