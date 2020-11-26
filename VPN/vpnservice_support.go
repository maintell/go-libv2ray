package VPN

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/rurirei/go-libv2ray/UTIL/logprint"

	"golang.org/x/sys/unix"

	v2net "v2ray.com/core/common/net"
	v2internet "v2ray.com/core/transport/internet"
)

type protectSet interface {
	Protect(int) int
}

type resolved struct {
	domain       string
	IPs          []net.IP
	Port         int
	ipIdx        uint8
	ipLock       sync.Mutex
	lastSwitched time.Time
}

// NextIP switch to another resolved result.
// there still be race-condition here if multiple err concurently occurred
// may cause idx keep switching,
// but that's an outside error can hardly handled here
func (r *resolved) NextIP() {
	r.ipLock.Lock()
	defer r.ipLock.Unlock()

	if len(r.IPs) <= 1 {
		return
	}

	// throttle, don't switch too quickly
	now := time.Now()
	if now.Sub(r.lastSwitched) < 3*time.Second {
		logprint.Infof("switch too quickly")
		return
	}
	r.lastSwitched = now
	r.ipIdx++

	if r.ipIdx >= uint8(len(r.IPs)) {
		r.ipIdx = 0
	}

	curIP := r.currentIP()
	logprint.Infof("switched to next IP: %s", curIP)
}

func (r *resolved) currentIP() net.IP {
	if len(r.IPs) > 0 {
		return r.IPs[r.ipIdx]
	}
	return nil
}

func NewProtectedDialer(p protectSet) *ProtectedDialer {
	return &ProtectedDialer{
		// prefer native lookup on Android
		resolver:   &net.Resolver{PreferGo: false},
		protectSet: p,
	}
}

type ProtectedDialer struct {
	currentServer string
	resolveChan   chan struct{}

	ResolveDnsNext bool

	vServer  *resolved
	resolver *net.Resolver

	protectSet
}

func (d *ProtectedDialer) IsVServerReady() bool {
	return d.vServer != nil
}

func (d *ProtectedDialer) PrepareResolveChan() {
	d.resolveChan = make(chan struct{})
}

func (d *ProtectedDialer) ResolveChan() chan struct{} {
	return d.resolveChan
}

// simplicated version of golang: internetAddrList in src/net/ipsock.go
func (d *ProtectedDialer) lookupAddr(addr string) (*resolved, error) {
	var (
		err        error
		host, port string
		portnum    int
	)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if host, port, err = net.SplitHostPort(addr); err != nil {
		logprint.Infof("PrepareDomain SplitHostPort Err: %v", err)
		return nil, err
	}

	if portnum, err = d.resolver.LookupPort(ctx, "tcp", port); err != nil {
		logprint.Infof("PrepareDomain LookupPort Err: %v", err)
		return nil, err
	}

	addrs, err := d.resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("domain %s Failed to resolve", addr)
	}

	IPs := make([]net.IP, len(addrs))
	for i, ia := range addrs {
		IPs[i] = ia.IP
	}

	rs := &resolved{
		domain: host,
		IPs:    IPs,
		Port:   portnum,
	}

	return rs, nil
}

// PrepareDomain caches direct v2ray server host
func (d *ProtectedDialer) PrepareDomain(domainName string, closeCh <-chan struct{}) {
	logprint.Infof("Preparing Domain: %s", domainName)
	d.currentServer = domainName

	maxRetry := 10
	for {
		if maxRetry == 0 {
			logprint.Infof("PrepareDomain maxRetry reached. exiting.")
			return
		}

		resolved, err := d.lookupAddr(domainName)
		if err != nil {
			maxRetry--
			logprint.Errorf("PrepareDomain err: %v", err)
			select {
			case <-closeCh:
				logprint.Fatalf("PrepareDomain exit due to v2ray closed")
				return
			case <-time.After(time.Second * 2):
			}
			continue
		}

		d.vServer = resolved
		logprint.Infof("[VPNPrepare] Prepare Result:\n Domain: %s\n Port: %d\n IPs: %v", resolved.domain, resolved.Port, resolved.IPs)
		return
	}
}

func (d *ProtectedDialer) getFd(network v2net.Network) (int, error) {
	switch network {
	case v2net.Network_TCP:
		return unix.Socket(unix.AF_INET6, unix.SOCK_STREAM, unix.IPPROTO_TCP)
	case v2net.Network_UDP:
		return unix.Socket(unix.AF_INET6, unix.SOCK_DGRAM, unix.IPPROTO_UDP)
	default:
		return -1, fmt.Errorf("unknown network")
	}
}

// Dial exported as the protected dial method
func (d *ProtectedDialer) Dial(ctx context.Context, src v2net.Address, dest v2net.Destination, sockopt *v2internet.SocketConfig) (net.Conn, error) {

	network := dest.Network.SystemString()
	address := dest.NetAddr()

	// v2ray server address,
	// try to connect fixed IP if multiple IP parsed from domain,
	// and switch to next IP if error occurred
	if strings.Compare(address, d.currentServer) == 0 {
		if d.vServer == nil {
			logprint.Infof("[VPNPrepare] Dial pending prepare %s", address)
			<-d.resolveChan

			// user may close connection during PrepareDomain,
			// fast return release resources.
			if d.vServer == nil {
				return nil, fmt.Errorf("fail to prepare domain %s", d.currentServer)
			}
		}

		if d.ResolveDnsNext {
			d.PrepareDomain(address, nil)
		}

		fd, err := d.getFd(dest.Network)
		if err != nil {
			return nil, err
		}

		curIP := d.vServer.currentIP()
		conn, err := d.fdConn(ctx, curIP, d.vServer.Port, fd)
		if err != nil {
			d.vServer.NextIP()
			return nil, err
		}
		logprint.Infof("Using Prepared: %s %s", address, curIP)
		return conn, nil
	}

	// v2ray connecting to "domestic" servers, no caching results
	resolved, err := d.lookupAddr(address)
	if err != nil {
		return nil, err
	}

	fd, err := d.getFd(dest.Network)
	if err != nil {
		return nil, err
	}

	// use the first resolved address.
	// the result IP may vary, eg: IPv6 addrs comes first if client has ipv6 address
	logprint.Infof("Using Not Prepared: %s %s %v", network, address, resolved.IPs[0])
	return d.fdConn(ctx, resolved.IPs[0], resolved.Port, fd)
}

func (d *ProtectedDialer) fdConn(ctx context.Context, ip net.IP, port int, fd int) (net.Conn, error) {
	defer unix.Close(fd)

	// call disallowedApplication
	// call android VPN service to "protect" the fd connecting straight out
	// d.Protect(fd)

	sa := &unix.SockaddrInet6{
		Port: port,
	}
	copy(sa.Addr[:], ip)

	if err := unix.Connect(fd, sa); err != nil {
		return nil, fmt.Errorf("[VPNPrepare] fdConn unix.Connect err, Close Fd: %d, Err: %v", fd, err)
	}

	file := os.NewFile(uintptr(fd), "Socket")
	if file == nil {
		// returned value will be nil if fd is not a valid file descriptor
		return nil, fmt.Errorf("fdConn fd invalid")
	}

	defer file.Close()
	//Closing conn does not affect file, and closing file does not affect conn.
	conn, err := net.FileConn(file)
	if err != nil {
		return nil, fmt.Errorf("[VPNPrepare] fdConn FileConn Close Fd: %d, Err: %v", fd, err)
	}

	return conn, nil
}
