package proto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// NewPairingKey 生成 32 字节随机配对密钥，并给出便于抄写的展示形式（OCL-XXXX-...）。
func NewPairingKey() ([]byte, string, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, "", err
	}
	return key, FormatPairingKey(key), nil
}

// FormatPairingKey 把 32 字节密钥格式化为展示形式（OCL-XXXX-...）。
func FormatPairingKey(key []byte) string {
	enc := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(key)
	var sb strings.Builder
	for i, r := range enc {
		if i > 0 && i%4 == 0 {
			sb.WriteByte('-')
		}
		sb.WriteRune(r)
	}
	return "OCL-" + sb.String()
}

// ParsePairingKey 解析用户输入的密钥（容忍空格、连字符、大小写）。
func ParsePairingKey(s string) ([]byte, error) {
	s = strings.ToUpper(strings.TrimSpace(s))
	s = strings.TrimPrefix(s, "OCL-")
	s = strings.NewReplacer("-", "", " ", "", "\t", "").Replace(s)
	raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(s)
	if err != nil {
		return nil, errors.New("密钥格式不对")
	}
	if len(raw) != 32 {
		return nil, errors.New("密钥长度不对")
	}
	return raw, nil
}

// derive 用 HKDF-SHA256 从主密钥派生用途隔离的子密钥。
// 关键点：知道子密钥（如 authKey）反推不出主密钥，也推不出其它子密钥（如 encKey）。
func derive(secret []byte, info string, n int) []byte {
	out, err := hkdf.Key(sha256.New, secret, nil, info, n)
	if err != nil {
		panic(err)
	}
	return out
}

// DeviceID 是中继可见的公开标识（不可逆），用来定位设备。
func DeviceID(key []byte) string {
	h := sha256.Sum256(append([]byte("ocl-link:device:"), key...))
	return fmt.Sprintf("%x", h[:8])
}

// AuthKey 用于向中继证明身份。中继会保存它以便校验 HMAC 应答，
// 但它与 EncKey 是 HKDF 派生的两个独立分支，中继拿不到 EncKey。
func AuthKey(key []byte) []byte { return derive(key, "ocl-link:auth", 32) }

// EncKey 是端到端加密密钥，只存在于 A、B 两端，中继永远得不到。
func EncKey(key []byte) []byte { return derive(key, "ocl-link:e2ee", 32) }

// ClientKey 由设备密钥派生某个控制端的独立密钥：
//
//	clientKey = HKDF(deviceKey, "ocl-link:client:"+clientId)
//
// B 端可以随时推导（可吊销：忘记 clientId 即可）；A 端只能通过 B 生成的邀请码拿到。
// 每个 A 端一把，互不相同，吊销某一个不影响其它。
func ClientKey(deviceKey []byte, clientID string) []byte {
	return derive(deviceKey, "ocl-link:client:"+clientID, 32)
}

// NewClientID 生成一个公开的客户端凭证 ID。
func NewClientID() (string, error) {
	raw := make([]byte, 8)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

// Proof 计算挑战应答：HMAC(authKey, nonce|role|deviceId)。
// 中继用保存的 authKey 校验，不通过网络传输 authKey 本身。
func Proof(authKey, nonce []byte, role, deviceID string) []byte {
	return ProofFor(authKey, nonce, role, deviceID, "")
}

// ProofFor 在角色/设备之外再绑定客户端凭证 ID（A 端用），
// 防止不同客户端之间的应答被交叉重放。
func ProofFor(authKey, nonce []byte, role, deviceID, clientID string) []byte {
	m := hmac.New(sha256.New, authKey)
	m.Write(nonce)
	m.Write([]byte("|" + role + "|" + deviceID))
	if clientID != "" {
		m.Write([]byte("|" + clientID))
	}
	return m.Sum(nil)
}

// Session 是一条连接上的端到端加密会话（AES-256-GCM，序号防重放/重排）。
type Session struct {
	aead        cipher.AEAD
	sendSeq     uint64
	lastRecvSeq uint64
}

// NewEphemeral 生成临时 X25519 密钥对，返回私钥和公钥字节。
func NewEphemeral() (*ecdh.PrivateKey, []byte, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return priv, priv.PublicKey().Bytes(), nil
}

// DeriveSession 用「ECDH 共享密钥 + 配对密钥派生的 encKey」混合出会话密钥。
//
// 为什么要混 encKey：ECDH 本身不认人，中继若做中间人替换双方公钥，
// 双方算出的 shared 会不一致；把只有 A、B 知道的 encKey 混进去后，
// 中间人无法得到相同会话密钥 → 握手直接失败。这是防“中继监听/冒充”的关键。
func DeriveSession(priv *ecdh.PrivateKey, peerPub, encKey []byte) (*Session, error) {
	pub, err := ecdh.X25519().NewPublicKey(peerPub)
	if err != nil {
		return nil, err
	}
	shared, err := priv.ECDH(pub)
	if err != nil {
		return nil, err
	}
	material := make([]byte, 0, len(shared)+len(encKey)+16)
	material = append(material, shared...)
	material = append(material, encKey...)
	key := derive(material, "ocl-link:session", 32)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Session{aead: aead}, nil
}

var errReplay = errors.New("序号异常（重放或乱序）")

// Seal 加密一条消息，返回序号、随机 nonce 和密文。序号作为 AAD 参与认证。
func (s *Session) Seal(plain []byte) (uint64, []byte, []byte, error) {
	s.sendSeq++
	seq := s.sendSeq
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return 0, nil, nil, err
	}
	ct := s.aead.Seal(nil, nonce, plain, seqAAD(seq))
	return seq, nonce, ct, nil
}

// Open 解密并校验序号（只接受严格递增，挡住重放）。
func (s *Session) Open(seq uint64, nonce, ct []byte) ([]byte, error) {
	if seq <= s.lastRecvSeq {
		return nil, errReplay
	}
	pt, err := s.aead.Open(nil, nonce, ct, seqAAD(seq))
	if err != nil {
		return nil, err
	}
	s.lastRecvSeq = seq
	return pt, nil
}

func seqAAD(seq uint64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, seq)
	return b
}
