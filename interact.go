package libv2ray

import (
	"github.com/rurirei/go-libv2ray/CORE"
)

// V2RayPointer is a public type
type V2RayPointer struct {
}

// VPNServiceSupportsSet is the interface of platform Android
type VPNServiceSupportsSet interface {
	Setup() int
	Prepare() int
	Shutdown() int
	Protect(int) int
	OnEmitStatus(int, string) int
}

// Tun2socksServiceSupportsSet is the interface of platform Android
type Tun2socksServiceSupportsSet interface {
	UseIPv6() bool
	LogLevel() string
	FakeIPRange() string
	SocksAddress() string
	HandlePackets() []byte
	PacketFlow(data []byte)
}

// V2RayServiceSupportsSet is the interface of platform Android
type V2RayServiceSupportsSet interface {
	ProxyOnly() bool
	ResolveDnsNext() bool
	ConfigFile() string
}

// NewV2RayPointer returns an instance of V2RayPoint
func NewV2RayPointer(s VPNServiceSupportsSet, t Tun2socksServiceSupportsSet, r V2RayServiceSupportsSet) *V2RayPointer {
	CORE.GetV2RayPoint(s, t, r)
	return &V2RayPointer{}
}

// Start runs V2Ray
func (v *V2RayPointer) Start() error {
	return CORE.Start()
}

// Stop stops V2Ray
func (v *V2RayPointer) Stop() error {
	return CORE.Stop()
}

// GetIsRunning returns of Instance.isRunning
func GetIsRunning() bool {
	return CORE.GetIsRunning()
}

// Version returns string of version (libv2ray + v2ray-core)
func Version() string {
	return CORE.Version()
}

// QueryStats returns traffic usage of given point
func QueryStats(title string, tag string, direct string) (int64, error) {
	return CORE.QueryStats(title, tag, direct)
}
