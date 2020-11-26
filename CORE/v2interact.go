package CORE

var (
	pv *V2RayPoint
)

func GetV2RayPoint(s VPNServiceSupportsSet, t Tun2socksServiceSupportsSet, r V2RayServiceSupportsSet) {
	pv = NewV2RayPoint(s, t, r)
}

func Start() error {
	return pv.Start()
}

func Stop() error {
	return pv.Stop()
}

func GetIsRunning() bool {
	return pv.GetIsRunning()
}

func QueryStats(title string, tag string, direct string) (int64, error) {
	return pv.QueryStats(title, tag, direct)
}
