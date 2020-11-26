package CORE

import (
	"fmt"

	v2core "v2ray.com/core"
)

func libVersion() string {
	return "1.0.3"
}

func coreVersion() string {
	return v2core.Version()
}

func Version() string {
	return fmt.Sprintf("Libv2ray v%s, v2ray-core v%s", libVersion(), coreVersion())
}
