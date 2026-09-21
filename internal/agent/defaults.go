package agent

// 内置默认中继：B 端双击即可激活/接入，无需携带任何配置文件。
//
// 换中继时改这里重新编译即可；命令行 -hub/-fingerprint、enroll.json 可覆盖。
// 地址与指纹只在程序内部使用，不展示在界面上（配置/日志里可见）。
const (
	// DefaultHub 是默认中继（隧道地址，公网可达）。
	DefaultHub = "124.93.28.120:21122"
	// DefaultFingerprint 是默认中继的证书 SHA-256 指纹（防中间人）。
	DefaultFingerprint = "26:A9:7F:44:EE:C0:77:25:AA:8A:8D:5B:3F:0F:00:E3:ED:6A:0E:C0:79:81:40:35:ED:4C:3E:06:80:A3:7D:7E"
)
