// Package proto 定义 oc-link 的消息协议与端到端加密。
//
// 设计原则（安全第一）：
//  1. 中继只接触两类东西：控制信封（身份/路由，明文）和密文（Data 字段）。
//     它看不懂业务内容，也无法执行任何命令。
//  2. 业务载荷（exec/read/write/list）由 A 和 B 端到端加密，中继全程不参与加解密。
//  3. 配对密钥只在 A、B 各存一份。中继只知道：
//     - deviceId：密钥的不可逆哈希，用来定位设备；
//     - authKey：用来验证连接方确实持有密钥（HMAC 挑战应答）。
//     中继永远拿不到 encKey（加密密钥），所以就算中继被攻破，
//     攻击者只能“占坑/捣乱”（可用性问题），无法解密内容，也无法冒充你向 B 下命令。
package proto

// Version 是协议版本，握手时互相校验。
const Version = "0.1.0"

// Envelope 是中继与端点（A/B）之间的控制消息（明文，中继可见）。
// 真正的业务内容放在 Data（base64 密文）里。
type Envelope struct {
	Type     string `json:"type"`               // hello|challenge|auth|ready|peer|msg|ping|pong|error|ctrl|register|client-*|enroll*
	Role     string `json:"role,omitempty"`     // agent(B) | client(A)
	Presence bool   `json:"presence,omitempty"` // true=控制端在线待命（不占用控制通道，仅表示 A 引擎在线）
	DeviceID string `json:"deviceId,omitempty"` // 公开标识，中继据此定位设备
	ClientID string `json:"clientId,omitempty"` // 客户端凭证 ID（每个 A 端一把钥匙，公开）
	Version  string `json:"version,omitempty"`
	Name     string `json:"name,omitempty"`  // 设备显示名（hello 时上报，可改名）
	Cmd      string `json:"cmd,omitempty"`   // ctrl 指令：kick-client|unregister
	Token    string `json:"token,omitempty"` // A 端可选：用户令牌（托管设备鉴权用）
	Nonce    string `json:"nonce,omitempty"` // base64，挑战随机数
	Proof    string `json:"proof,omitempty"` // base64，HMAC 应答（证明持有 authKey）
	OK       bool   `json:"ok,omitempty"`
	Error    string `json:"error,omitempty"`
	Peer     string `json:"peer,omitempty"` // up|down：对端是否在线
	Seq      uint64 `json:"seq,omitempty"`  // 密文序号（防重放）
	Data     string `json:"data,omitempty"` // base64 密文；中继只转发不理解
}

// ---- 以下为端到端业务载荷（中继不可见，加密后放在 Envelope.Data 里）----

// Request 是 A 发给 B 的请求。
type Request struct {
	Op         string `json:"op"` // exec|read|write|list|ping
	ID         string `json:"id"` // 请求号，用于对齐响应
	Cmd        string `json:"cmd,omitempty"`
	Cwd        string `json:"cwd,omitempty"`
	Shell      string `json:"shell,omitempty"`
	TimeoutMs  int    `json:"timeoutMs,omitempty"`
	Path       string `json:"path,omitempty"`
	MaxBytes   int64  `json:"maxBytes,omitempty"`
	DataB64    string `json:"dataB64,omitempty"`
	CreateDirs bool   `json:"createDirs,omitempty"`

	// 扩展操作（edit / grep / glob）
	Pattern    string `json:"pattern,omitempty"`    // grep 正则 / glob 通配
	OldString  string `json:"oldString,omitempty"`  // edit 查找内容
	NewString  string `json:"newString,omitempty"`  // edit 替换内容
	ReplaceAll bool   `json:"replaceAll,omitempty"` // edit 全部替换
	MaxResults int    `json:"maxResults,omitempty"` // grep/glob 条数上限
}

// Response 是 B 回给 A 的结果。
type Response struct {
	Op         string   `json:"op"`
	ID         string   `json:"id"`
	OK         bool     `json:"ok"`
	Error      string   `json:"error,omitempty"`
	ExitCode   int      `json:"exitCode,omitempty"`
	Stdout     string   `json:"stdout,omitempty"`
	Stderr     string   `json:"stderr,omitempty"`
	DurationMs int64    `json:"durationMs,omitempty"`
	Truncated  bool     `json:"truncated,omitempty"`
	Path       string   `json:"path,omitempty"`
	Size       int64    `json:"size,omitempty"`
	Encoding   string   `json:"encoding,omitempty"` // utf8|base64
	Content    string   `json:"content,omitempty"`
	Bytes      int      `json:"bytes,omitempty"`
	Entries    []Entry  `json:"entries,omitempty"`
	Matches    []string `json:"matches,omitempty"` // grep/glob 结果
	Count      int      `json:"count,omitempty"`   // 替换/匹配数量
}

// Entry 是列目录中的一项。
type Entry struct {
	Name    string `json:"name"`
	Dir     bool   `json:"dir"`
	Size    int64  `json:"size"`
	ModTime string `json:"modTime,omitempty"`
}
