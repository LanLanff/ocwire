package agent

import (
	"fmt"

	"oclink/internal/proto"
)

// handleRequestSafe 包一层 recover：
// 任何请求处理中的 panic 都不会带崩 agent，只会变成一条错误返回给 A 端。
func handleRequestSafe(cfg Config, req proto.Request) (resp proto.Response) {
	defer func() {
		if r := recover(); r != nil {
			resp = proto.Response{Op: req.Op, ID: req.ID, Error: fmt.Sprintf("请求处理异常: %v", r)}
		}
	}()
	return HandleRequest(cfg, req)
}
