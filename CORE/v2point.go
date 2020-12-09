package CORE

import (
	"fmt"
	"io"
	"os"
	"strings"

	mobasset "golang.org/x/mobile/asset"

	"github.com/rurirei/go-libv2ray/TUN"
	"github.com/rurirei/go-libv2ray/UTIL/logprint"
	"github.com/rurirei/go-libv2ray/VPN"

	v2core "v2ray.com/core"
	v2applog "v2ray.com/core/app/log"
	v2commlog "v2ray.com/core/common/log"
	v2filesystem "v2ray.com/core/common/platform/filesystem"
	v2stats "v2ray.com/core/features/stats"
	v2serial "v2ray.com/core/infra/conf/serial"
	v2internet "v2ray.com/core/transport/internet"
)

const (
	v2asset     = "v2ray.location.asset"
	assetperfix = "/dev/libv2rayfs0/asset"
	separator   = ";;;"
)

type V2RayPoint struct {
	V2RaySupportSet     V2RayServiceSupportsStruct
	Tun2socksSupportSet Tun2socksServiceSupportsSet
	VPNSupportSet       VPNServiceSupportsSet

	statsManager v2stats.Manager
	vpoint       v2core.Server
	isRunning    bool

	tun2task  *tun2socks.Tun2socksTask
	dialer    *VPN.ProtectedDialer
	closeChan chan struct{}
}

type VPNServiceSupportsSet interface {
	Setup() int
	Prepare() int
	Shutdown() int
	Protect(int) int
	OnEmitStatus(int, string) int
}

type Tun2socksServiceSupportsSet interface {
	UseIPv6() bool
	LogLevel() string
	FakeIPRange() string
	SocksAddress() string
	HandlePackets() []byte
	PacketFlow(data []byte)
}

type V2RayServiceSupportsSet interface {
	ProxyOnly() bool
	ResolveDnsNext() bool
	ConfigFile() string
}

type V2RayServiceSupportsStruct struct {
	proxyOnly         bool
	resolveDnsNext    bool
	domainName        string
	configFileContent string
}

func NewV2RayPoint(s VPNServiceSupportsSet, t Tun2socksServiceSupportsSet, r V2RayServiceSupportsSet) *V2RayPoint {
	// inject our own log writer
	v2applog.RegisterHandlerCreator(v2applog.LogType_Console,
		func(lt v2applog.LogType,
			options v2applog.HandlerCreatorOptions) (v2commlog.Handler, error) {
			return v2commlog.NewLogger(createStdoutLogWriter()), nil
		})

	configFile := strings.Split(r.ConfigFile(), separator)
	domainName := configFile[0]
	configFileContent := configFile[1]
	rv := V2RayServiceSupportsStruct{
		proxyOnly:         r.ProxyOnly(),
		resolveDnsNext:    r.ResolveDnsNext(),
		domainName:        domainName,
		configFileContent: configFileContent,
	}

	dialer := VPN.NewProtectedDialer(s)
	v2internet.UseAlternativeSystemDialer(dialer)

	tun2task := tun2socks.NewTun2socksTask()

	v := &V2RayPoint{
		VPNSupportSet:       s,
		Tun2socksSupportSet: t,
		V2RaySupportSet:     rv,
		dialer:              dialer,
		tun2task:            tun2task,
	}

	return v
}

func (v *V2RayPoint) Start() (err error) {
	v.dialer.ResolveDnsNext = v.V2RaySupportSet.resolveDnsNext

	if !v.isRunning {
		v.closeChan = make(chan struct{})
		v.dialer.PrepareResolveChan()
		go func() {
			v.dialer.PrepareDomain(v.V2RaySupportSet.domainName, v.closeChan)
			close(v.dialer.ResolveChan())
		}()
		go func() {
			select {
			// wait until resolved
			case <-v.dialer.ResolveChan():
				// shutdown VPNService if server name can not reolved
				if !v.dialer.IsVServerReady() {
					logprint.Infof("vServer cannot resolved, shutdown")
					v.Stop()
				}
			// stop waiting if manually closed
			case <-v.closeChan:
			}
		}()

		err = v.startLoop()
	}
	return
}

func (v *V2RayPoint) Stop() (err error) {
	if v.isRunning {
		err = v.stopLoop()
	}

	return
}

func (v *V2RayPoint) stopLoop() error {
	close(v.closeChan)
	v.vpoint.Close()
	v.vpoint = nil
	v.statsManager = nil
	v.dialer = nil
	v.isRunning = false

	v.tun2task.Stop()
	v.VPNSupportSet.Shutdown()
	v.VPNSupportSet.OnEmitStatus(0, "Closed")

	return nil
}

func (v *V2RayPoint) startLoop() error {
	logprint.Infof("loading v2ray config")
	config, err := TestConfig(v.V2RaySupportSet.configFileContent)
	if err != nil {
		return err
	}

	logprint.Infof("new v2ray core")
	inst, err := v2core.New(config)
	if err != nil {
		return err
	}
	v.vpoint = inst
	v.statsManager = inst.GetFeature(v2stats.ManagerType()).(v2stats.Manager)

	logprint.Infof("start v2ray core")
	v.isRunning = true
	if err := v.vpoint.Start(); err != nil {
		v.isRunning = false
		return err
	}

	v.VPNSupportSet.Prepare()
	v.VPNSupportSet.Setup()
	v.VPNSupportSet.OnEmitStatus(0, "Running")

	// Tun2socks started after VPN prepared
	if !v.V2RaySupportSet.proxyOnly {
		v.tun2task.Start(v.Tun2socksSupportSet.HandlePackets, v.Tun2socksSupportSet.PacketFlow, v.Tun2socksSupportSet.UseIPv6(), v.Tun2socksSupportSet.FakeIPRange(), v.Tun2socksSupportSet.SocksAddress())
	}

	return nil
}

func initV2Env() {
	//Initialize asset API, Since Raymond Will not let notify the asset location inside Process,
	//We need to set location outside V2Ray
	os.Setenv(v2asset, assetperfix)

	//Now we handle read
	v2filesystem.NewFileReader = func(path string) (io.ReadCloser, error) {
		if strings.HasPrefix(path, assetperfix) {
			p := path[len(assetperfix)+1:]
			//is it overridden?
			//by, ok := overridedAssets[p]
			//if ok {
			//	return os.Open(by)
			//}
			return mobasset.Open(p)
		}
		return os.Open(path)
	}
}

func (v *V2RayPoint) GetIsRunning() bool {
	if v.V2RaySupportSet.proxyOnly {
		return v.isRunning
	}
	return v.isRunning && v.tun2task.GetIsRunning()
}

func TestConfig(configFileContent string) (*v2core.Config, error) {
	initV2Env()
	return v2serial.LoadJSONConfig(strings.NewReader(configFileContent))
}

func (v *V2RayPoint) QueryStats(title string, tag string, direct string) (int64, error) {
	if v.statsManager == nil {
		return 0, nil
	}
	if title != "user" && title != "inbound" && title != "outbound" {
		return 0, nil
	}
	counter := v.statsManager.GetCounter(fmt.Sprintf("%s>>>%s>>>traffic>>>%s", title, tag, direct))
	if counter == nil {
		return 0, nil
	}
	return counter.Set(0), nil
}
