package hub

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"oclink/internal/proto"
)

// Client 是一台设备的某个控制端凭证（全盲：中继只存校验子键）。
type Client struct {
	ID        string    `json:"id"`
	Label     string    `json:"label,omitempty"`
	AuthKey   string    `json:"authKey"`
	Disabled  bool      `json:"disabled,omitempty"`
	CreatedAt time.Time `json:"createdAt"`
	LastSeen  time.Time `json:"lastSeen,omitempty"`
}

// Device 是中继保存的一台设备（全盲：只存校验信息，永远不存任何密钥）。
//
//	deviceId  —— 设备密钥的不可逆哈希
//	authKey   —— B 端挑战应答的校验子键（HMAC 用）
//	clients   —— 每个控制端（A）一把独立凭证，可单独吊销
type Device struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	AuthKey   string    `json:"authKey"`
	Clients   []Client  `json:"clients,omitempty"`
	SelfReg   bool      `json:"selfReg,omitempty"`
	CreatedAt time.Time `json:"createdAt"`
	LastSeen  time.Time `json:"lastSeen,omitempty"`
}

// Store 是设备库，落盘为一个 JSON 文件。
type Store struct {
	path       string
	bannedPath string
	mu         sync.Mutex
	devices    map[string]*Device
	banned     map[string]bool // deviceId -> 已拉黑（拒绝登记/连接）
}

// OpenStore 打开（或创建）设备库。
func OpenStore(path string) (*Store, error) {
	s := &Store{
		path:       path,
		bannedPath: filepath.Join(filepath.Dir(path), "banned.json"),
		devices:    map[string]*Device{},
		banned:     map[string]bool{},
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, err
		}
	}
	if data, err := os.ReadFile(path); err == nil {
		var list []*Device
		if json.Unmarshal(data, &list) == nil {
			for _, d := range list {
				if d != nil && d.ID != "" {
					s.devices[d.ID] = d
				}
			}
		}
	}
	if data, err := os.ReadFile(s.bannedPath); err == nil {
		var ids []string
		if json.Unmarshal(data, &ids) == nil {
			for _, id := range ids {
				if id != "" {
					s.banned[id] = true
				}
			}
		}
	}
	return s, nil
}

func (s *Store) saveBannedLocked() error {
	ids := make([]string, 0, len(s.banned))
	for id := range s.banned {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	data, err := json.MarshalIndent(ids, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.bannedPath + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.bannedPath)
}

// Ban 拉黑一个 deviceId（中继拒绝其登记与连接）；Unban 解禁；IsBanned 查询。
func (s *Store) Ban(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.banned[id] = true
	return s.saveBannedLocked()
}

func (s *Store) Unban(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.banned, id)
	return s.saveBannedLocked()
}

func (s *Store) IsBanned(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.banned[id]
}

// BannedList 返回全部被拉黑的 deviceId（排序）。
func (s *Store) BannedList() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.banned))
	for id := range s.banned {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

func (s *Store) saveLocked() error {
	list := make([]*Device, 0, len(s.devices))
	for _, d := range s.devices {
		list = append(list, d)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].CreatedAt.Before(list[j].CreatedAt) })
	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// List 返回全部设备（按创建时间排序）。
func (s *Store) List() []*Device {
	s.mu.Lock()
	defer s.mu.Unlock()
	list := make([]*Device, 0, len(s.devices))
	for _, d := range s.devices {
		list = append(list, d)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].CreatedAt.Before(list[j].CreatedAt) })
	return list
}

// Get 按 deviceId 取设备。
func (s *Store) Get(id string) *Device {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.devices[id]
}

// RegisterSelf 自助登记：设备自己生成密钥，只把 deviceId + authKey 校验子键交给中继。
// 中继不保存配对密钥本身，因此无法解密，也无法事后恢复密钥——全盲。
// 已存在的设备必须 authKey 一致才允许更新名字，避免被冒名顶掉。
func (s *Store) RegisterSelf(id string, authKey []byte, name string) (*Device, error) {
	if id == "" || len(authKey) != 32 {
		return nil, errors.New("注册信息不完整")
	}
	enc := base64.StdEncoding.EncodeToString(authKey)
	s.mu.Lock()
	defer s.mu.Unlock()
	if d := s.devices[id]; d != nil {
		if subtle.ConstantTimeCompare([]byte(d.AuthKey), []byte(enc)) != 1 {
			return nil, errors.New("设备已存在（校验子键不匹配）")
		}
		if name != "" && d.Name != name {
			d.Name = name
			_ = s.saveLocked()
		}
		return d, nil
	}
	d := &Device{ID: id, Name: name, AuthKey: enc, SelfReg: true, CreatedAt: time.Now()}
	s.devices[id] = d
	if err := s.saveLocked(); err != nil {
		delete(s.devices, id)
		return nil, err
	}
	return d, nil
}

// Delete 删除设备（断了它以后也无法再连）。
func (s *Store) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.devices[id]; !ok {
		return errors.New("设备不存在")
	}
	delete(s.devices, id)
	return s.saveLocked()
}

// MarkSeen 记录最近一次握手时间。
func (s *Store) MarkSeen(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if d := s.devices[id]; d != nil {
		d.LastSeen = time.Now()
		_ = s.saveLocked()
	}
}

// Rename 由设备自报改名（agent 连接时上报 hello.Name）。
func (s *Store) Rename(id, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.devices[id]
	if d == nil {
		return errors.New("设备不存在")
	}
	if name == "" || d.Name == name {
		return nil
	}
	d.Name = name
	return s.saveLocked()
}

// VerifyProof 校验挑战应答。用 constant-time 比较，避免时序侧信道泄漏。
func (s *Store) VerifyProof(id, role string, nonce, proof []byte) bool {
	s.mu.Lock()
	d := s.devices[id]
	s.mu.Unlock()
	if d == nil {
		return false
	}
	authKey, err := base64.StdEncoding.DecodeString(d.AuthKey)
	if err != nil {
		return false
	}
	want := proto.Proof(authKey, nonce, role, id)
	return subtle.ConstantTimeCompare(want, proof) == 1
}

// ---- 控制端凭证（每台设备可挂多个，每个 A 端一把，可单独吊销）----

// AddClient 登记/更新一个控制端凭证（由已鉴权的 B 端发起）。
func (s *Store) AddClient(deviceID, clientID, authKeyB64, label string) error {
	if deviceID == "" || clientID == "" {
		return errors.New("缺少参数")
	}
	raw, err := base64.StdEncoding.DecodeString(authKeyB64)
	if err != nil || len(raw) != 32 {
		return errors.New("authKey 无效")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.devices[deviceID]
	if d == nil {
		return errors.New("设备不存在")
	}
	for i := range d.Clients {
		if d.Clients[i].ID == clientID {
			d.Clients[i].AuthKey = authKeyB64
			if label != "" {
				d.Clients[i].Label = label
			}
			return s.saveLocked()
		}
	}
	if len(d.Clients) >= 50 {
		return errors.New("控制端数量达到上限")
	}
	d.Clients = append(d.Clients, Client{ID: clientID, Label: label, AuthKey: authKeyB64, CreatedAt: time.Now()})
	return s.saveLocked()
}

// RemoveClient 吊销一个控制端凭证。
func (s *Store) RemoveClient(deviceID, clientID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.devices[deviceID]
	if d == nil {
		return errors.New("设备不存在")
	}
	for i := range d.Clients {
		if d.Clients[i].ID == clientID {
			d.Clients = append(d.Clients[:i], d.Clients[i+1:]...)
			return s.saveLocked()
		}
	}
	return errors.New("控制端不存在")
}

// HasClient 判断某设备是否有该客户端凭证。
func (s *Store) HasClient(deviceID, clientID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.devices[deviceID]
	if d == nil {
		return false
	}
	for i := range d.Clients {
		if d.Clients[i].ID == clientID {
			return true
		}
	}
	return false
}

// VerifyClientProof 校验 A 端的挑战应答（用该客户端自己的校验子键）。
func (s *Store) VerifyClientProof(deviceID, clientID string, nonce, proof []byte) bool {
	s.mu.Lock()
	d := s.devices[deviceID]
	s.mu.Unlock()
	if d == nil {
		return false
	}
	for i := range d.Clients {
		if d.Clients[i].ID != clientID {
			continue
		}
		if d.Clients[i].Disabled {
			return false
		}
		authKey, err := base64.StdEncoding.DecodeString(d.Clients[i].AuthKey)
		if err != nil {
			return false
		}
		want := proto.ProofFor(authKey, nonce, "client", deviceID, clientID)
		return subtle.ConstantTimeCompare(want, proof) == 1
	}
	return false
}

// IsClientDisabled 判断某控制端凭证是否被中继禁用。
func (s *Store) IsClientDisabled(deviceID, clientID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.devices[deviceID]
	if d == nil {
		return false
	}
	for i := range d.Clients {
		if d.Clients[i].ID == clientID {
			return d.Clients[i].Disabled
		}
	}
	return false
}

// SetClientDisabled 禁用/启用某个控制端凭证；被禁用的凭证无法再通过握手。
func (s *Store) SetClientDisabled(deviceID, clientID string, disabled bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.devices[deviceID]
	if d == nil {
		return errors.New("设备不存在")
	}
	for i := range d.Clients {
		if d.Clients[i].ID == clientID {
			d.Clients[i].Disabled = disabled
			return s.saveLocked()
		}
	}
	return errors.New("控制端凭证不存在")
}

// MarkClientSeen 记录某客户端最近握手时间；如果它还没有备注名，就用它自报的名字补上。
func (s *Store) MarkClientSeen(deviceID, clientID, name string) {
	name = strings.TrimSpace(name)
	if rs := []rune(name); len(rs) > 24 {
		name = string(rs[:24])
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.devices[deviceID]
	if d == nil {
		return
	}
	for i := range d.Clients {
		if d.Clients[i].ID == clientID {
			d.Clients[i].LastSeen = time.Now()
			if d.Clients[i].Label == "" && name != "" {
				d.Clients[i].Label = name
			}
			_ = s.saveLocked()
			return
		}
	}
}
