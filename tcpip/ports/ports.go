// Copyright 2018 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package ports provides PortManager that manages allocating, reserving and releasing ports.
package ports

import (
	"math"
	"math/rand"
	"sync"
	"sync/atomic"

	"github.com/blastbao/netstack/tcpip"
)

const (
	// FirstEphemeral is the first ephemeral port.
	//
	// FirstEphemeral 是第一个临时端口。
	FirstEphemeral = 16000

	// numEphemeralPorts it the mnumber of available ephemeral ports to Netstack.
	//
	// numEphemeralPorts 指 Netstack 可用的临时端口的数量，65535 - 16000 + 1 == 49536 。
	numEphemeralPorts = math.MaxUint16 - FirstEphemeral + 1

	// 任播地址
	anyIPAddress tcpip.Address = ""
)


// 端口描述符：<网络层、传输层、端口号> 唯一标识一个端口号
type portDescriptor struct {
	network   tcpip.NetworkProtocolNumber	// 网络层协议号
	transport tcpip.TransportProtocolNumber // 传输层协议号
	port      uint16						// 端口号
}


// PortManager manages allocating, reserving and releasing ports.
//
// 端口管理器管理端口的分配、保留和释放。
type PortManager struct {
	mu             sync.RWMutex

	// 组织结构
	//
	//    port  -> addr1 -> dev0 -> {reuse(重用), refs(引用计数)}
	//					 -> dev1 -> {reuse, refs}
	//					 ...
	//			-> addr2 -> dev0 -> {reuse, refs}
	//					 -> dev1 -> {reuse, refs}
	//					 ...
	//			...
	//			-> addrN -> dev0 -> {reuse, refs}
	//					 -> dev1 -> {reuse, refs}
	//					 ...
	//
	allocatedPorts map[portDescriptor]bindAddresses // 已分配端口号



	// hint is used to pick ports ephemeral ports in a stable order for
	// a given port offset.
	//
	// hint must be accessed using the portHint/incPortHint helpers.
	// TODO(gvisor.dev/issue/940): S/R this field.
	//
	hint uint32
}

type portNode struct {
	reuse bool	// 是否允许重复绑定
	refs  int	// 引用计数，决定何时释放
}

// deviceNode is never empty.
// When it has no elements, it is removed from the map that references it.
//
// deviceNode 代表一个 addr 对应的一组设备。
type deviceNode map[tcpip.NICID]portNode


// isAvailable checks whether binding is possible by device.
// If not binding to a device, check against all portNodes.
// If binding to a specific device, check against the unspecified device and the provided device.
//
//
//
//
func (d deviceNode) isAvailable(reuse bool, bindToDevice tcpip.NICID) bool {

	// 如果 bindToDevice 为 0 ，则需要绑定到所有设备，这要求所有已绑定的 device 必须配置成 reuse ，不然就报错。
	if bindToDevice == 0 {

		// Trying to binding all devices.
		// 如果需要绑定所有 Device 但是还不许 reuse ，就报错。
		if !reuse {
			// Can't bind because the (addr,port) is already bound.
			return false
		}

		// 遍历 d 中所有设备，如果其中某个 device 不许被 reuse ，则也要报错。
		for _, p := range d {
			if !p.reuse {
				// Can't bind because the (addr,port) was previously bound without reuse.
				return false
			}
		}

		return true
	}

	// 至此，bindToDevice 不为 0 ，即明确指定了要绑定的设备。


	// ???
	if p, ok := d[0]; ok {
		if !reuse || !p.reuse {
			return false
		}
	}

	// 如果要绑定的 device 尚未绑定，或者已绑定但可以重用，就返回 true，否则 false 。
	if p, ok := d[bindToDevice]; ok {
		if !reuse || !p.reuse {
			return false
		}
	}

	return true
}

// bindAddresses is a set of IP addresses.
//
// bindAddresses 保存一组 addrs 及其对应的一组设备。
type bindAddresses map[tcpip.Address]deviceNode

// isAvailable checks whether an IP address is available to bind to.
// If the address is the "any" address, check all other addresses.
// Otherwise, just check against the "any" address and the provided address.
//
//
//
// isAvailable 检查一个 IP 地址是否可以绑定。
// 如果该地址是 "any" 地址，则检查所有其他地址。
// 否则，只需检查 "any "地址和提供的地址。
//
//
func (b bindAddresses) isAvailable(addr tcpip.Address, reuse bool, bindToDevice tcpip.NICID) bool {

	if addr == anyIPAddress {
		// If binding to the "any" address then check that there are no conflicts with all addresses.
		//
		// 若要绑定到 "any" 地址，则需遍历当前 port 关联的所有地址，检查有无冲突。
		for _, d := range b {
			// 检查地址 d 上关联的所有设备，是否允许绑定
			if !d.isAvailable(reuse, bindToDevice) {
				return false
			}
		}
		return true
	}

	// 至此，当前需绑定 port 到非 any 地址。

	// Check that there is no conflict with the "any" address.
	//
	// 如果此前 port 已绑定到 any 地址，那么意味已经绑定到任意地址，
	// 因此需要检查它绑定到 any 地址上的设备是否和 bindToDevice 有冲突。
	if d, ok := b[anyIPAddress]; ok {
		if !d.isAvailable(reuse, bindToDevice) {
			return false
		}
	}

	// Check that this is no conflict with the provided address.
	if d, ok := b[addr]; ok {
		if !d.isAvailable(reuse, bindToDevice) {
			return false
		}
	}

	return true
}

// NewPortManager creates new PortManager.
func NewPortManager() *PortManager {
	return &PortManager{allocatedPorts: make(map[portDescriptor]bindAddresses)}
}

// PickEphemeralPort randomly chooses a starting point and iterates over all
// possible ephemeral ports, allowing the caller to decide whether a given port
// is suitable for its needs, and stopping when a port is found or an error occurs.
//
//
// PickEphemeralPort 随机选择一个起始位置，遍历所有可能的临时端口，
// 让调用者通过 testPort 决定被遍历的端口是否符合要求，当找到一个端口或发生错误时，就会停止遍历。
//
//
//
func (s *PortManager) PickEphemeralPort(testPort func(p uint16) (bool, *tcpip.Error)) (port uint16, err *tcpip.Error) {
	// 随即选择遍历的起始点
	offset := uint32(rand.Int31n(numEphemeralPorts))
	//
	return s.pickEphemeralPort(offset, numEphemeralPorts, testPort)
}

// portHint atomically reads and returns the s.hint value.
func (s *PortManager) portHint() uint32 {
	return atomic.LoadUint32(&s.hint)
}

// incPortHint atomically increments s.hint by 1.
func (s *PortManager) incPortHint() {
	atomic.AddUint32(&s.hint, 1)
}

// PickEphemeralPortStable starts at the specified offset + s.portHint and
// iterates over all ephemeral ports, allowing the caller to decide whether a
// given port is suitable for its needs and stopping when a port is found or an
// error occurs.
func (s *PortManager) PickEphemeralPortStable(offset uint32, testPort func(p uint16) (bool, *tcpip.Error)) (port uint16, err *tcpip.Error) {
	p, err := s.pickEphemeralPort(s.portHint()+offset, numEphemeralPorts, testPort)
	if err == nil {
		s.incPortHint()
	}
	return p, err

}

// pickEphemeralPort starts at the offset specified from the FirstEphemeral port
// and iterates over the number of ports specified by count and allows the
// caller to decide whether a given port is suitable for its needs, and stopping
// when a port is found or an error occurs.
func (s *PortManager) pickEphemeralPort(offset, count uint32, testPort func(p uint16) (bool, *tcpip.Error)) (port uint16, err *tcpip.Error) {

	for i := uint32(0); i < count; i++ {
		port = uint16(FirstEphemeral + (offset+i)%count)
		ok, err := testPort(port)
		if err != nil {
			return 0, err
		}

		if ok {
			return port, nil
		}
	}

	return 0, tcpip.ErrNoPortAvailable
}

// IsPortAvailable tests if the given port is available on all given protocols.
func (s *PortManager) IsPortAvailable(networks []tcpip.NetworkProtocolNumber, transport tcpip.TransportProtocolNumber, addr tcpip.Address, port uint16, reuse bool, bindToDevice tcpip.NICID) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.isPortAvailableLocked(networks, transport, addr, port, reuse, bindToDevice)
}

func (s *PortManager) isPortAvailableLocked(
	networks []tcpip.NetworkProtocolNumber,		// 网络层协议
	transport tcpip.TransportProtocolNumber,	// 传输层协议
	addr tcpip.Address,							// IP 地址
	port uint16,								// 端口号
	reuse bool,									// 端口重用
	bindToDevice tcpip.NICID,					// 绑定网卡
) bool {

	// 遍历 networks 中指定的网络层协议
	for _, network := range networks {
		// 构造端口描述符：network + transport + port 唯一标识端口
		desc := portDescriptor{network, transport, port}
		// 检查端口是否已被分配
		if addrs, ok := s.allocatedPorts[desc]; ok {
			// 如果已被分配，检查端口已绑定的 addrs 上是否允许新的绑定，不允许则返回 false 。
			if !addrs.isAvailable(addr, reuse, bindToDevice) {
				return false
			}
		}
	}
	return true
}

// ReservePort marks a port/IP combination as reserved so that it cannot be
// reserved by another endpoint. If port is zero, ReservePort will search for
// an unreserved ephemeral port and reserve it, returning its value in the
// "port" return value.
//
// ReservePort 将一个 端口/IP 组合 标记为保留，这样它就不能被其他端点保留。
// 如果 port 为零，ReservePort() 将搜索一个未保留的短暂端口并保留它，
// 并在返回值 "reservedPort" 中返回它的值。
//
func (s *PortManager) ReservePort(
	networks []tcpip.NetworkProtocolNumber,
	transport tcpip.TransportProtocolNumber,
	addr tcpip.Address,
	port uint16,
	reuse bool,
	bindToDevice tcpip.NICID,
) (reservedPort uint16, err *tcpip.Error) {

	s.mu.Lock()
	defer s.mu.Unlock()


	// If a port is specified, just try to reserve it for all network protocols.
	// 如果指定了端口，就为 networks 指定的所有网络协议保留该端口。
	if port != 0 {
		if !s.reserveSpecificPort(networks, transport, addr, port, reuse, bindToDevice) {
			return 0, tcpip.ErrPortInUse
		}
		return port, nil
	}


	// A port wasn't specified, so try to find one.


	// 至此，port 为 0 ，即未指定端口号，需要分配临时端口号。
	return s.PickEphemeralPort(
		// 检查当前被选择的端口是否可以绑定到 {networks, transport, addr, bindToDevice} 上。
		func(p uint16) (bool, *tcpip.Error) {
			return s.reserveSpecificPort(networks, transport, addr, p, reuse, bindToDevice), nil
		},
	)
}

// reserveSpecificPort tries to reserve the given port on all given protocols.
func (s *PortManager) reserveSpecificPort(networks []tcpip.NetworkProtocolNumber, transport tcpip.TransportProtocolNumber, addr tcpip.Address, port uint16, reuse bool, bindToDevice tcpip.NICID) bool {



	if !s.isPortAvailableLocked(networks, transport, addr, port, reuse, bindToDevice) {
		return false
	}

	// Reserve port on all network protocols.
	for _, network := range networks {

		// 构造端口描述符
		desc := portDescriptor{network, transport, port}

		// 检查端口是否已分配，若尚未分配，则初始化一下
		m, ok := s.allocatedPorts[desc]
		if !ok {
			m = make(bindAddresses)
			s.allocatedPorts[desc] = m
		}

		// 检查端口是否绑定到 addr 上，若尚未绑定，则初始化一下
		d, ok := m[addr]
		if !ok {
			d = make(deviceNode)
			m[addr] = d
		}

		// 检查端口是否已绑定到 addr 的 bindToDevice 设备上
		if n, ok := d[bindToDevice]; ok {
			// 若已经绑定，则增加引用计数
			n.refs++
			d[bindToDevice] = n
		} else {
			// 若尚未绑定，则绑定一下
			d[bindToDevice] = portNode{reuse: reuse, refs: 1}
		}
	}

	return true
}

// ReleasePort releases the reservation on a port/IP combination so that it can
// be reserved by other endpoints.
func (s *PortManager) ReleasePort(
	networks []tcpip.NetworkProtocolNumber,		// 网络层协议号
	transport tcpip.TransportProtocolNumber,	// 传输层协议层
	addr tcpip.Address,							// 绑定地址
	port uint16,								// 绑定端口
	bindToDevice tcpip.NICID,					// 绑定设备
) {

	s.mu.Lock()
	defer s.mu.Unlock()

	for _, network := range networks {

		desc := portDescriptor{network, transport, port}

		if m, ok := s.allocatedPorts[desc]; ok {

			// 尚未绑定到 addr 上，无需释放
			d, ok := m[addr]
			if !ok {
				continue
			}

			// 尚未绑定到 bindToDevice 上，无需释放
			n, ok := d[bindToDevice]
			if !ok {
				continue
			}

			// 将设备 bindToDevice 的引用计数 -1
			n.refs--
			d[bindToDevice] = n //更新引用计数


			// 如果设备 bindToDevice 上已无引用，则释放掉 device
			if n.refs == 0 {
				delete(d, bindToDevice)
			}

			// 如果 addr 上已无绑定设备，则释放掉 addr
			if len(d) == 0 {
				delete(m, addr)
			}

			// 如果 port 上已无绑定地址，则释放掉 port
			if len(m) == 0 {
				delete(s.allocatedPorts, desc)
			}

		}
	}
}
