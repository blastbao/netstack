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

package udp

import (
	"sync"

	"github.com/blastbao/netstack/tcpip"
	"github.com/blastbao/netstack/tcpip/buffer"
	"github.com/blastbao/netstack/tcpip/header"
	"github.com/blastbao/netstack/tcpip/iptables"
	"github.com/blastbao/netstack/tcpip/stack"
	"github.com/blastbao/netstack/waiter"
)

// +stateify savable
type udpPacket struct {
	udpPacketEntry
	senderAddress tcpip.FullAddress
	data          buffer.VectorisedView
	timestamp     int64
}

// EndpointState represents the state of a UDP endpoint.
type EndpointState uint32

// Endpoint states. Note that are represented in a netstack-specific manner and
// may not be meaningful externally. Specifically, they need to be translated to
// Linux's representation for these states if presented to userspace.
//
// 端点状态。
// 请注意，这些状态是以 netstack 特有的方式来表示的，在外部可能没有意义。
// 具体来说，如果向用户空间展示这些状态，需要翻译成 Linux 的表示方式。
const (
	StateInitial EndpointState = iota	// 初始化
	StateBound 							// 已绑定
	StateConnected						// 已连接
	StateClosed							// 已关闭
)

// String implements fmt.Stringer.String.
func (s EndpointState) String() string {
	switch s {
	case StateInitial:
		return "INITIAL"
	case StateBound:
		return "BOUND"
	case StateConnected:
		return "CONNECTING"
	case StateClosed:
		return "CLOSED"
	default:
		return "UNKNOWN"
	}
}

// endpoint represents a UDP endpoint. This struct serves as the interface
// between users of the endpoint and the protocol implementation; it is legal to
// have concurrent goroutines make calls into the endpoint, they are properly
// synchronized.
//
// endpoint 代表一个 UDP 端点。
//
// It implements tcpip.Endpoint.
//
// +stateify savable
type endpoint struct {
	stack.TransportEndpointInfo

	// The following fields are initialized at creation time and do not
	// change throughout the lifetime of the endpoint.
	stack       *stack.Stack
	waiterQueue *waiter.Queue
	uniqueID    uint64

	// The following fields are used to manage the receive queue,
	// and are protected by rcvMu.
	rcvMu         sync.Mutex
	rcvReady      bool
	rcvList       udpPacketList
	rcvBufSizeMax int
	rcvBufSize    int
	rcvClosed     bool

	// The following fields are protected by the mu mutex.
	mu             sync.RWMutex
	sndBufSize     int
	state          EndpointState
	route          stack.Route
	dstPort        uint16
	v6only         bool
	ttl            uint8

	multicastTTL   uint8
	multicastAddr  tcpip.Address
	multicastNICID tcpip.NICID
	multicastLoop  bool

	reusePort      bool
	bindToDevice   tcpip.NICID
	broadcast      bool


	// sendTOS represents IPv4 TOS or IPv6 TrafficClass, applied while sending packets.
	// Defaults to 0 as on Linux.
	//
	// sendTOS 代表 IPv4 TOS 或 IPv6 TrafficClass，在发送数据包时应用。
	// 默认值为 0，同在 Linux 上一样。
	sendTOS uint8

	// shutdownFlags represent the current shutdown state of the endpoint.
	shutdownFlags tcpip.ShutdownFlags

	// multicastMemberships that need to be remvoed when the endpoint is closed.
	// Protected by the mu mutex.
	//
	// 当端点关闭时，需要移除 multicastMembership 。
	// 由 mu mutex 保护。
	multicastMemberships []multicastMembership

	// effectiveNetProtos contains the network protocols actually in use.
	// In most cases it will only contain "netProto", but in cases like IPv6
	// endpoints with v6only set to false, this could include multiple
	// protocols (e.g., IPv6 and IPv4) or a single different protocol (e.g.,
	// IPv4 when IPv6 endpoint is bound or connected to an IPv4 mapped
	// address).
	//
	// effectiveNetProtos 包含了使用的网络层协议(号)。
	// 在大多数情况下，它只包含 "netProto"，但在 IPv6 端点 v6only 设置为 false 的情况下，
	// 它可能包含多个协议（如 IPv6 和 IPv4 ）或单个不同的协议（如绑定到 IPv6 端点或连接到 IPv4 映射地址时的 IPv4 ）。
	//
	effectiveNetProtos []tcpip.NetworkProtocolNumber

	// TODO(b/142022063): Add ability to save and restore per endpoint stats.
	stats tcpip.TransportEndpointStats
}



// +stateify savable
type multicastMembership struct {
	nicID         tcpip.NICID 		// 网卡 ID
	multicastAddr tcpip.Address		// 多播地址
}

func newEndpoint(s *stack.Stack, netProto tcpip.NetworkProtocolNumber, waiterQueue *waiter.Queue) *endpoint {

	return &endpoint{
		stack: s,
		TransportEndpointInfo: stack.TransportEndpointInfo{
			NetProto:   netProto,					// 网络层协议号
			TransProto: header.UDPProtocolNumber,	// 传输层协议号
		},
		waiterQueue: waiterQueue,					// 等待队列


		// RFC 1075 section 5.4 recommends a TTL of 1 for membership requests.
		//
		// RFC 5135 4.2.1 appears to assume that IGMP messages have a TTL of 1.
		//
		// RFC 5135 Appendix A defines TTL=1: A multicast source that wants its
		// traffic to not traverse a router (e.g., leave a home network) may find
		// it useful to send traffic with IP TTL=1.
		//
		// Linux defaults to TTL=1.
		multicastTTL:  1,				// 多播 - 报文最大生存时间
		multicastLoop: true,			// 多播 -
		rcvBufSizeMax: 32 * 1024,		// 32 KB
		sndBufSize:    32 * 1024,		// 32 KB
		state:         StateInitial,	// 初始化状态
		uniqueID:      s.UniqueID(), 	// 唯一标识符
	}
}

// UniqueID implements stack.TransportEndpoint.UniqueID.
func (e *endpoint) UniqueID() uint64 {
	return e.uniqueID
}

// Close puts the endpoint in a closed state and frees all resources
// associated with it.
func (e *endpoint) Close() {
	e.mu.Lock()
	e.shutdownFlags = tcpip.ShutdownRead | tcpip.ShutdownWrite

	switch e.state {
	case StateBound, StateConnected:
		e.stack.UnregisterTransportEndpoint(e.RegisterNICID, e.effectiveNetProtos, ProtocolNumber, e.ID, e, e.bindToDevice)
		e.stack.ReleasePort(e.effectiveNetProtos, ProtocolNumber, e.ID.LocalAddress, e.ID.LocalPort, e.bindToDevice)
	}

	for _, mem := range e.multicastMemberships {
		e.stack.LeaveGroup(e.NetProto, mem.nicID, mem.multicastAddr)
	}
	e.multicastMemberships = nil

	// Close the receive list and drain it.
	e.rcvMu.Lock()
	e.rcvClosed = true
	e.rcvBufSize = 0
	for !e.rcvList.Empty() {
		p := e.rcvList.Front()
		e.rcvList.Remove(p)
	}
	e.rcvMu.Unlock()

	e.route.Release()

	// Update the state.
	e.state = StateClosed

	e.mu.Unlock()

	e.waiterQueue.Notify(waiter.EventHUp | waiter.EventErr | waiter.EventIn | waiter.EventOut)
}

// ModerateRecvBuf implements tcpip.Endpoint.ModerateRecvBuf.
func (e *endpoint) ModerateRecvBuf(copied int) {}

// IPTables implements tcpip.Endpoint.IPTables.
func (e *endpoint) IPTables() (iptables.IPTables, error) {
	return e.stack.IPTables(), nil
}

// Read reads data from the endpoint.
// This method does not block if there is no data pending.
func (e *endpoint) Read(addr *tcpip.FullAddress) (buffer.View, tcpip.ControlMessages, *tcpip.Error) {
	e.rcvMu.Lock()

	// 接收队列为空，报错返回
	if e.rcvList.Empty() {
		err := tcpip.ErrWouldBlock
		if e.rcvClosed {
			e.stats.ReadErrors.ReadClosed.Increment()
			err = tcpip.ErrClosedForReceive
		}
		e.rcvMu.Unlock()
		return buffer.View{}, tcpip.ControlMessages{}, err
	}

	// 取首个未读报文
	p := e.rcvList.Front()
	// 从接收队列中移除
	e.rcvList.Remove(p)
	// 释放接收缓存
	e.rcvBufSize -= p.data.Size()
	e.rcvMu.Unlock()

	// ???
	if addr != nil {
		*addr = p.senderAddress
	}

	// 返回该报文
	return p.data.ToView(), tcpip.ControlMessages{
		HasTimestamp: true,
		Timestamp: p.timestamp,
	}, nil
}

// prepareForWrite prepares the endpoint for sending data. In particular, it
// binds it if it's still in the initial state. To do so, it must first
// reacquire the mutex in exclusive mode.
//
// Returns true for retry if preparation should be retried.
//
// prepareForWrite 为发送数据的端点做准备。
// 特别是，如果端点还处于 init 状态，会对其进行绑定。
// 要做到这一点，必须先以独占模式重新获取 mutex 。
//
//
//
func (e *endpoint) prepareForWrite(to *tcpip.FullAddress) (retry bool, err *tcpip.Error) {


	// 状态检查
	// (1) 如果是 init 状态，需要重新绑定
	// (2) 如果是 connected 状态，则直接返回
	// (3) 如果是 bound 状态，则 ???
	switch e.state {
	case StateInitial:
	case StateConnected:
		return false, nil
	case StateBound:
		if to == nil {
			return false, tcpip.ErrDestinationRequired
		}
		return false, nil
	default:
		return false, tcpip.ErrInvalidEndpointState
	}

	// 至此，意味着 e 为 init 状态

	e.mu.RUnlock()
	defer e.mu.RLock()

	e.mu.Lock()
	defer e.mu.Unlock()

	// The state changed when we released the shared locked and re-acquired
	// it in exclusive mode. Try again.
	//
	// 加锁之后，再次检查一次，确保当前仍处于 init 状态。
	if e.state != StateInitial {
		return true, nil
	}

	// The state is still 'initial', so try to bind the endpoint.
	//
	// 状态仍然是 init ，尝试进行端点绑定。
	if err := e.bindLocked(tcpip.FullAddress{}); err != nil {
		return false, err
	}

	return true, nil
}

// connectRoute establishes a route to the specified interface or the
// configured multicast interface if no interface is specified and the
// specified address is a multicast address.
func (e *endpoint) connectRoute(
	nicID tcpip.NICID,
	addr tcpip.FullAddress,
	netProto tcpip.NetworkProtocolNumber,
) ( stack.Route, tcpip.NICID, *tcpip.Error ) {



	localAddr := e.ID.LocalAddress
	if isBroadcastOrMulticast(localAddr) {
		// A packet can only originate from a unicast address (i.e., an interface).
		localAddr = ""
	}

	if header.IsV4MulticastAddress(addr.Addr) || header.IsV6MulticastAddress(addr.Addr) {

		if nicID == 0 {
			nicID = e.multicastNICID
		}

		if localAddr == "" && nicID == 0 {
			localAddr = e.multicastAddr
		}

	}


	// Find a route to the desired destination.
	r, err := e.stack.FindRoute(nicID, localAddr, addr.Addr, netProto, e.multicastLoop)
	if err != nil {
		return stack.Route{}, 0, err
	}

	return r, nicID, nil
}

// Write writes data to the endpoint's peer.
// This method does not block if the data cannot be written.
func (e *endpoint) Write(p tcpip.Payloader, opts tcpip.WriteOptions) (int64, <-chan struct{}, *tcpip.Error) {
	n, ch, err := e.write(p, opts)
	switch err {
	case nil:
		e.stats.PacketsSent.Increment()
	case tcpip.ErrMessageTooLong, tcpip.ErrInvalidOptionValue:
		e.stats.WriteErrors.InvalidArgs.Increment()
	case tcpip.ErrClosedForSend:
		e.stats.WriteErrors.WriteClosed.Increment()
	case tcpip.ErrInvalidEndpointState:
		e.stats.WriteErrors.InvalidEndpointState.Increment()
	case tcpip.ErrNoLinkAddress:
		e.stats.SendErrors.NoLinkAddr.Increment()
	case tcpip.ErrNoRoute, tcpip.ErrBroadcastDisabled, tcpip.ErrNetworkUnreachable:
		// Errors indicating any problem with IP routing of the packet.
		e.stats.SendErrors.NoRoute.Increment()
	default:
		// For all other errors when writing to the network layer.
		e.stats.SendErrors.SendToNetworkFailed.Increment()
	}
	return n, ch, err
}

func (e *endpoint) write(p tcpip.Payloader, opts tcpip.WriteOptions) (int64, <-chan struct{}, *tcpip.Error) {

	// MSG_MORE is unimplemented. (This also means that MSG_EOR is a no-op.)
	if opts.More {
		return 0, nil, tcpip.ErrInvalidOptionValue
	}

	to := opts.To

	e.mu.RLock()
	defer e.mu.RUnlock()

	// If we've shutdown with SHUT_WR we are in an invalid state for sending.
	// 如果当前处于 ShutdownWrite 状态，则无法发送数据。
	if e.shutdownFlags&tcpip.ShutdownWrite != 0 {
		return 0, nil, tcpip.ErrClosedForSend
	}

	// Prepare for write.
	// 准备写数据。
	for {
		retry, err := e.prepareForWrite(to)
		if err != nil {
			return 0, nil, err
		}
		// 如果 retry == false ，则 break ，否则继续重试。
		if !retry {
			break
		}
	}

	var route *stack.Route
	var dstPort uint16
	if to == nil {

		route = &e.route
		dstPort = e.dstPort

		if route.IsResolutionRequired() {
			// Promote lock to exclusive if using a shared route,
			// given that it may need to change in Route.Resolve() call below.
			e.mu.RUnlock()
			defer e.mu.RLock()

			e.mu.Lock()
			defer e.mu.Unlock()

			// Recheck state after lock was re-acquired.
			if e.state != StateConnected {
				return 0, nil, tcpip.ErrInvalidEndpointState
			}
		}


	} else {

		// Reject destination address if it goes through a different
		// NIC than the endpoint was bound to.
		nicID := to.NIC
		if e.BindNICID != 0 {
			if nicID != 0 && nicID != e.BindNICID {
				return 0, nil, tcpip.ErrNoRoute
			}

			nicID = e.BindNICID
		}

		if to.Addr == header.IPv4Broadcast && !e.broadcast {
			return 0, nil, tcpip.ErrBroadcastDisabled
		}

		netProto, err := e.checkV4Mapped(to, false)
		if err != nil {
			return 0, nil, err
		}

		r, _, err := e.connectRoute(nicID, *to, netProto)
		if err != nil {
			return 0, nil, err
		}
		defer r.Release()

		route = &r
		dstPort = to.Port
	}


	// 如果必须调用 Resolve() 来解析链路层地址，IsResolutionRequired 会返回 true 。
	if route.IsResolutionRequired() {
		//
		if ch, err := route.Resolve(nil); err != nil {
			if err == tcpip.ErrWouldBlock {
				return 0, ch, tcpip.ErrNoLinkAddress
			}
			return 0, nil, err
		}
	}


	// 从 p 中读取所有可读字节。
	v, err := p.FullPayload()
	if err != nil {
		return 0, nil, err
	}

	// 如果可读数据大小超过 UDP 最大报文长度，则报错。
	if len(v) > header.UDPMaximumPacketSize {
		// Payload can't possibly fit in a packet.
		// 有效载荷太大了，不可能装在一个包里。
		return 0, nil, tcpip.ErrMessageTooLong
	}


	ttl := e.ttl
	useDefaultTTL := ttl == 0 // 若 ttl 为 0 则需要使用默认的 ttl

	// 如果是多播地址，则设置多播 ttl (默认为1)，且指明不使用默认 ttl 。
	if header.IsV4MulticastAddress(route.RemoteAddress) || header.IsV6MulticastAddress(route.RemoteAddress) {
		ttl = e.multicastTTL
		// Multicast allows a 0 TTL.
		useDefaultTTL = false
	}

	// 发送 UDP 报文
	if err := sendUDP(
		route,								// 路由信息
		buffer.View(v).ToVectorisedView(), 	// 数据
		e.ID.LocalPort,						// 本地端口
		dstPort,							// 目的端口
		ttl,								// 指定报文最大生存时间
		useDefaultTTL,						// 是否使用默认报文最大生存时间 true/false
		e.sendTOS, 							// 服务类型
	); err != nil {
		return 0, nil, err
	}

	return int64(len(v)), nil, nil
}

// Peek only returns data from a single datagram, so do nothing here.
func (e *endpoint) Peek([][]byte) (int64, tcpip.ControlMessages, *tcpip.Error) {
	return 0, tcpip.ControlMessages{}, nil
}

// SetSockOptInt implements tcpip.Endpoint.SetSockOptInt.
func (e *endpoint) SetSockOptInt(opt tcpip.SockOpt, v int) *tcpip.Error {
	return nil
}

// SetSockOpt implements tcpip.Endpoint.SetSockOpt.
func (e *endpoint) SetSockOpt(opt interface{}) *tcpip.Error {
	switch v := opt.(type) {
	case tcpip.V6OnlyOption:
		// We only recognize this option on v6 endpoints.
		if e.NetProto != header.IPv6ProtocolNumber {
			return tcpip.ErrInvalidEndpointState
		}

		e.mu.Lock()
		defer e.mu.Unlock()

		// We only allow this to be set when we're in the initial state.
		if e.state != StateInitial {
			return tcpip.ErrInvalidEndpointState
		}

		e.v6only = v != 0

	case tcpip.TTLOption:
		e.mu.Lock()
		e.ttl = uint8(v)
		e.mu.Unlock()

	case tcpip.MulticastTTLOption:
		e.mu.Lock()
		e.multicastTTL = uint8(v)
		e.mu.Unlock()

	case tcpip.MulticastInterfaceOption:
		e.mu.Lock()
		defer e.mu.Unlock()

		fa := tcpip.FullAddress{Addr: v.InterfaceAddr}
		netProto, err := e.checkV4Mapped(&fa, false)
		if err != nil {
			return err
		}
		nic := v.NIC
		addr := fa.Addr

		if nic == 0 && addr == "" {
			e.multicastAddr = ""
			e.multicastNICID = 0
			break
		}

		if nic != 0 {
			if !e.stack.CheckNIC(nic) {
				return tcpip.ErrBadLocalAddress
			}
		} else {
			nic = e.stack.CheckLocalAddress(0, netProto, addr)
			if nic == 0 {
				return tcpip.ErrBadLocalAddress
			}
		}

		if e.BindNICID != 0 && e.BindNICID != nic {
			return tcpip.ErrInvalidEndpointState
		}

		e.multicastNICID = nic
		e.multicastAddr = addr

	case tcpip.AddMembershipOption:
		if !header.IsV4MulticastAddress(v.MulticastAddr) && !header.IsV6MulticastAddress(v.MulticastAddr) {
			return tcpip.ErrInvalidOptionValue
		}

		nicID := v.NIC

		// The interface address is considered not-set if it is empty or contains
		// all-zeros. The former represent the zero-value in golang, the latter the
		// same in a setsockopt(IP_ADD_MEMBERSHIP, &ip_mreqn) syscall.
		allZeros := header.IPv4Any
		if len(v.InterfaceAddr) == 0 || v.InterfaceAddr == allZeros {
			if nicID == 0 {
				r, err := e.stack.FindRoute(0, "", v.MulticastAddr, header.IPv4ProtocolNumber, false /* multicastLoop */)
				if err == nil {
					nicID = r.NICID()
					r.Release()
				}
			}
		} else {
			nicID = e.stack.CheckLocalAddress(nicID, e.NetProto, v.InterfaceAddr)
		}
		if nicID == 0 {
			return tcpip.ErrUnknownDevice
		}

		memToInsert := multicastMembership{nicID: nicID, multicastAddr: v.MulticastAddr}

		e.mu.Lock()
		defer e.mu.Unlock()

		for _, mem := range e.multicastMemberships {
			if mem == memToInsert {
				return tcpip.ErrPortInUse
			}
		}

		if err := e.stack.JoinGroup(e.NetProto, nicID, v.MulticastAddr); err != nil {
			return err
		}

		e.multicastMemberships = append(e.multicastMemberships, memToInsert)

	case tcpip.RemoveMembershipOption:
		if !header.IsV4MulticastAddress(v.MulticastAddr) && !header.IsV6MulticastAddress(v.MulticastAddr) {
			return tcpip.ErrInvalidOptionValue
		}

		nicID := v.NIC
		if v.InterfaceAddr == header.IPv4Any {
			if nicID == 0 {
				r, err := e.stack.FindRoute(0, "", v.MulticastAddr, header.IPv4ProtocolNumber, false /* multicastLoop */)
				if err == nil {
					nicID = r.NICID()
					r.Release()
				}
			}
		} else {
			nicID = e.stack.CheckLocalAddress(nicID, e.NetProto, v.InterfaceAddr)
		}
		if nicID == 0 {
			return tcpip.ErrUnknownDevice
		}

		memToRemove := multicastMembership{nicID: nicID, multicastAddr: v.MulticastAddr}
		memToRemoveIndex := -1

		e.mu.Lock()
		defer e.mu.Unlock()

		for i, mem := range e.multicastMemberships {
			if mem == memToRemove {
				memToRemoveIndex = i
				break
			}
		}
		if memToRemoveIndex == -1 {
			return tcpip.ErrBadLocalAddress
		}

		if err := e.stack.LeaveGroup(e.NetProto, nicID, v.MulticastAddr); err != nil {
			return err
		}

		e.multicastMemberships[memToRemoveIndex] = e.multicastMemberships[len(e.multicastMemberships)-1]
		e.multicastMemberships = e.multicastMemberships[:len(e.multicastMemberships)-1]

	case tcpip.MulticastLoopOption:
		e.mu.Lock()
		e.multicastLoop = bool(v)
		e.mu.Unlock()

	case tcpip.ReusePortOption:
		e.mu.Lock()
		e.reusePort = v != 0
		e.mu.Unlock()

	case tcpip.BindToDeviceOption:
		e.mu.Lock()
		defer e.mu.Unlock()
		if v == "" {
			e.bindToDevice = 0
			return nil
		}
		for nicID, nic := range e.stack.NICInfo() {
			if nic.Name == string(v) {
				e.bindToDevice = nicID
				return nil
			}
		}
		return tcpip.ErrUnknownDevice

	case tcpip.BroadcastOption:
		e.mu.Lock()
		e.broadcast = v != 0
		e.mu.Unlock()

		return nil

	case tcpip.IPv4TOSOption:
		e.mu.Lock()
		e.sendTOS = uint8(v)
		e.mu.Unlock()
		return nil

	case tcpip.IPv6TrafficClassOption:
		e.mu.Lock()
		e.sendTOS = uint8(v)
		e.mu.Unlock()
		return nil
	}
	return nil
}

// GetSockOptInt implements tcpip.Endpoint.GetSockOptInt.
func (e *endpoint) GetSockOptInt(opt tcpip.SockOpt) (int, *tcpip.Error) {
	switch opt {

	// 返回接收报文队列中，首个报文的数据大小
	case tcpip.ReceiveQueueSizeOption:
		v := 0
		e.rcvMu.Lock()
		if !e.rcvList.Empty() {		// 接收队列非空（有数据可读）
			p := e.rcvList.Front()	// 接收队列首个 UDP 报文
			v = p.data.Size() 		// 该 UDP 报文的 Data 大小
		}
		e.rcvMu.Unlock()
		return v, nil

	// 返回发送缓冲区的大小
	case tcpip.SendBufferSizeOption:
		e.mu.Lock()
		v := e.sndBufSize
		e.mu.Unlock()
		return v, nil

	// 返回接收缓冲区的大小
	case tcpip.ReceiveBufferSizeOption:
		e.rcvMu.Lock()
		v := e.rcvBufSizeMax
		e.rcvMu.Unlock()
		return v, nil
	}

	return -1, tcpip.ErrUnknownProtocolOption
}

// GetSockOpt implements tcpip.Endpoint.GetSockOpt.
func (e *endpoint) GetSockOpt(opt interface{}) *tcpip.Error {
	switch o := opt.(type) {
	case tcpip.ErrorOption:
		return nil

	case *tcpip.V6OnlyOption:
		// We only recognize this option on v6 endpoints.
		if e.NetProto != header.IPv6ProtocolNumber {
			return tcpip.ErrUnknownProtocolOption
		}

		e.mu.Lock()
		v := e.v6only
		e.mu.Unlock()

		*o = 0
		if v {
			*o = 1
		}
		return nil

	case *tcpip.TTLOption:
		e.mu.Lock()
		*o = tcpip.TTLOption(e.ttl)
		e.mu.Unlock()
		return nil

	case *tcpip.MulticastTTLOption:
		e.mu.Lock()
		*o = tcpip.MulticastTTLOption(e.multicastTTL)
		e.mu.Unlock()
		return nil

	case *tcpip.MulticastInterfaceOption:
		e.mu.Lock()
		*o = tcpip.MulticastInterfaceOption{
			e.multicastNICID,
			e.multicastAddr,
		}
		e.mu.Unlock()
		return nil

	case *tcpip.MulticastLoopOption:
		e.mu.RLock()
		v := e.multicastLoop
		e.mu.RUnlock()

		*o = tcpip.MulticastLoopOption(v)
		return nil

	case *tcpip.ReuseAddressOption:
		*o = 0
		return nil

	case *tcpip.ReusePortOption:
		e.mu.RLock()
		v := e.reusePort
		e.mu.RUnlock()

		*o = 0
		if v {
			*o = 1
		}
		return nil

	case *tcpip.BindToDeviceOption:
		e.mu.RLock()
		defer e.mu.RUnlock()
		if nic, ok := e.stack.NICInfo()[e.bindToDevice]; ok {
			*o = tcpip.BindToDeviceOption(nic.Name)
			return nil
		}
		*o = tcpip.BindToDeviceOption("")
		return nil

	case *tcpip.KeepaliveEnabledOption:
		*o = 0
		return nil

	case *tcpip.BroadcastOption:
		e.mu.RLock()
		v := e.broadcast
		e.mu.RUnlock()

		*o = 0
		if v {
			*o = 1
		}
		return nil

	case *tcpip.IPv4TOSOption:
		e.mu.RLock()
		*o = tcpip.IPv4TOSOption(e.sendTOS)
		e.mu.RUnlock()
		return nil

	case *tcpip.IPv6TrafficClassOption:
		e.mu.RLock()
		*o = tcpip.IPv6TrafficClassOption(e.sendTOS)
		e.mu.RUnlock()
		return nil

	default:
		return tcpip.ErrUnknownProtocolOption
	}
}



// sendUDP sends a UDP segment via the provided network endpoint and under the provided identity.
func sendUDP(r *stack.Route, data buffer.VectorisedView, localPort, remotePort uint16, ttl uint8, useDefaultTTL bool, tos uint8) *tcpip.Error {

	// Allocate a buffer for the UDP header.
	// 先为头部准备出一个 buffer
	hdr := buffer.NewPrependable(header.UDPMinimumSize + int(r.MaxHeaderLength()))

	// Initialize the header.
	// 声明 udp 头部，其底层为刚刚创建的 hdr buffer
	udp := header.UDP(hdr.Prepend(header.UDPMinimumSize))

	// 报文长度 = 报头长度 + 数据长度
	length := uint16(hdr.UsedLength() + data.Size())

	// 将 udp 头部按照协议格式写入到 hdr 中
	udp.Encode(&header.UDPFields{	// 报头
		SrcPort: localPort,			// 源端口
		DstPort: remotePort,		// 目的端口
		Length:  length,			// 报文长度
	})

	// Only calculate the checksum if offloading isn't supported.
	// 在不支持 CheckSum Offloading 的情况下才需要计算校验和，否则会交由网卡负责。
	if r.Capabilities()&stack.CapabilityTXChecksumOffload == 0 {
		// UDP 校验和计算的三部分：UDP 头部、UDP 数据和 UDP 伪头部。（注意：UDP校验和是可选的。）
		// (1) 伪首部
		xsum := r.PseudoHeaderChecksum(ProtocolNumber, length)
		// (2) 数据
		for _, v := range data.Views() {
			xsum = header.Checksum(v, xsum)
		}
		// (3) 头部
		udp.SetChecksum(^udp.CalculateChecksum(xsum))
	}

	if useDefaultTTL {
		ttl = r.DefaultTTL()
	}

	// 发送网络层 IP Packet 报文
	if err := r.WritePacket(
		nil /* gso */,				// 通用分段策略
		stack.NetworkHeaderParams{		// 网络层 Header
			Protocol: ProtocolNumber,	// 传输层协议号
			TTL: ttl,					// 报文最大生存时间
			TOS: tos,					// 服务类型
		},
		tcpip.PacketBuffer{				// 包含网络包数据
			Header: hdr,				// Header 保存出栈数据包的头。当一个数据包从上向下层传递时，每一层都会向 Header 添加新头部。
			Data:   data,				// Data 存储着网络包的有效载荷。对于入栈数据包，它还保存着报头，报头在数据包向上移动时被逐层剔除。
		},
	); err != nil {
		r.Stats().UDP.PacketSendErrors.Increment()
		return err
	}

	// Track count of packets sent.
	r.Stats().UDP.PacketsSent.Increment()
	return nil
}


//
//
// 检查地址 addr 的有效性，返回关联的网络层协议号。
//
//
func (e *endpoint) checkV4Mapped(addr *tcpip.FullAddress, allowMismatch bool) (tcpip.NetworkProtocolNumber, *tcpip.Error) {

	// 获取本 endpoint 的网络层协议号
	netProto := e.NetProto
	// 如果待检查地址为空，则直接返回
	if len(addr.Addr) == 0 {
		return netProto, nil
	}

	// 检查 addr 是否是 IPv4 映射地址。（备注：IPv4 映射地址用于将 IPv4 节点表示为 IPv6 地址）
	if header.IsV4MappedAddress(addr.Addr) {

		// Fail if using a v4 mapped address on a v6only endpoint.
		// 如果本 endpoint 只支持 IPv6 ，则无法同 IPv4 端点通信，报错。
		if e.v6only {
			return 0, tcpip.ErrNoRoute
		}

		// 否则：
		// (1) 指定 IPv4 网络层协议号
		netProto = header.IPv4ProtocolNumber
		// (2) 从 IPv4 映射地址中取出 IPv4 地址
		addr.Addr = addr.Addr[header.IPv6AddressSize-header.IPv4AddressSize:]
		// (3) 如果该 IPv4 地址为 Anycast(任播) 地址，就重置它
		if addr.Addr == header.IPv4Any {
			addr.Addr = ""
		}

		// Fail if we are bound to an IPv6 address.
		//
		// 如果本 endpoint 绑定的是 IPv6 地址，则报错。
		// (备注：UDP 情况下，allowMismatch 默认 false，则两端网络层协议必须匹配)
		if !allowMismatch && len(e.ID.LocalAddress) == 16 {
			return 0, tcpip.ErrNetworkUnreachable
		}
	}

	// Fail if we're bound to an address length different from the one we're checking.
	//
	// 如果本 endpoint 绑定的地址长度与我们要检查的地址长度不同，则失败。
	if l := len(e.ID.LocalAddress); l != 0 && l != len(addr.Addr) {
		return 0, tcpip.ErrInvalidEndpointState
	}

	return netProto, nil
}

// Disconnect implements tcpip.Endpoint.Disconnect.
func (e *endpoint) Disconnect() *tcpip.Error {
	e.mu.Lock()
	defer e.mu.Unlock()

	// 未连接，则不需断开
	if e.state != StateConnected {
		return nil
	}

	// id 代表传输层协议端点的标识符，<本地端口, 本地地址，远程端口，远程地址>。
	id := stack.TransportEndpointID{}

	// Exclude ephemerally bound endpoints.

	// 如果指定了绑定的网卡，
	if e.BindNICID != 0 || e.ID.LocalAddress == "" {
		var err *tcpip.Error
		id = stack.TransportEndpointID{
			LocalPort:    e.ID.LocalPort,
			LocalAddress: e.ID.LocalAddress,
		}
		id, err = e.registerWithStack(e.RegisterNICID, e.effectiveNetProtos, id)
		if err != nil {
			return err
		}
		e.state = StateBound
	} else {
		// 关闭连接，则释放端口
		if e.ID.LocalPort != 0 {
			// Release the ephemeral port.
			e.stack.ReleasePort(e.effectiveNetProtos, ProtocolNumber, e.ID.LocalAddress, e.ID.LocalPort, e.bindToDevice)
		}
		// 初始状态
		e.state = StateInitial
	}

	e.stack.UnregisterTransportEndpoint(e.RegisterNICID, e.effectiveNetProtos, ProtocolNumber, e.ID, e, e.bindToDevice)
	e.ID = id
	e.route.Release()
	e.route = stack.Route{}
	e.dstPort = 0

	return nil
}

// Connect connects the endpoint to its peer. Specifying a NIC is optional.
func (e *endpoint) Connect(addr tcpip.FullAddress) *tcpip.Error {


	// 根据 addr 获取网络层协议号(IPv4 or IPv6)
	netProto, err := e.checkV4Mapped(&addr, false)
	if err != nil {
		return err
	}

	// 不支持 connect 到 port 为 0 的目标
	if addr.Port == 0 {
		// We don't support connecting to port zero.
		return tcpip.ErrInvalidEndpointState
	}


	e.mu.Lock()
	defer e.mu.Unlock()

	nicID := addr.NIC
	var localPort uint16

	switch e.state {
	// 当前 endpoint 处于 init 状态，则可以 connect 。
	case StateInitial:
	// 当前 endpoint 已经 connected ，则 ... 。
	case StateBound, StateConnected:
		localPort = e.ID.LocalPort
		if e.BindNICID == 0 {
			break
		}
		if nicID != 0 && nicID != e.BindNICID {
			return tcpip.ErrInvalidEndpointState
		}
		nicID = e.BindNICID
	default:
		return tcpip.ErrInvalidEndpointState
	}

	//
	r, nicID, err := e.connectRoute(nicID, addr, netProto)
	if err != nil {
		return err
	}
	defer r.Release()


	// 传输层端点标识符
	id := stack.TransportEndpointID{
		LocalAddress:  e.ID.LocalAddress,
		LocalPort:     localPort,
		RemotePort:    addr.Port,
		RemoteAddress: r.RemoteAddress,
	}

	if e.state == StateInitial {
		id.LocalAddress = r.LocalAddress
	}

	// Even if we're connected, this endpoint can still be used to send
	// packets on a different network protocol, so we register both even if
	// v6only is set to false and this is an ipv6 endpoint.
	//
	// 即使已经 connected 了，这个端点仍然可以用来在不同的网络层协议上发送数据包，
	// 所以即使 v6only 被设置为 false ，这也是一个 ipv6 端点，我们也要同时注册。
	netProtos := []tcpip.NetworkProtocolNumber{netProto}
	if netProto == header.IPv6ProtocolNumber && !e.v6only {
		netProtos = []tcpip.NetworkProtocolNumber{
			header.IPv4ProtocolNumber,	// IPv4
			header.IPv6ProtocolNumber,	// IPv6
		}
	}



	id, err = e.registerWithStack(nicID, netProtos, id)
	if err != nil {
		return err
	}



	// Remove the old registration.
	if e.ID.LocalPort != 0 {
		e.stack.UnregisterTransportEndpoint(e.RegisterNICID, e.effectiveNetProtos, ProtocolNumber, e.ID, e, e.bindToDevice)
	}

	e.ID = id
	e.route = r.Clone()
	e.dstPort = addr.Port
	e.RegisterNICID = nicID
	e.effectiveNetProtos = netProtos

	e.state = StateConnected

	e.rcvMu.Lock()
	e.rcvReady = true
	e.rcvMu.Unlock()

	return nil
}

// ConnectEndpoint is not supported.
func (*endpoint) ConnectEndpoint(tcpip.Endpoint) *tcpip.Error {
	return tcpip.ErrInvalidEndpointState
}

// Shutdown closes the read and/or write end of the endpoint connection
// to its peer.
func (e *endpoint) Shutdown(flags tcpip.ShutdownFlags) *tcpip.Error {
	e.mu.Lock()
	defer e.mu.Unlock()

	// A socket in the bound state can still receive multicast messages,
	// so we need to notify waiters on shutdown.
	if e.state != StateBound && e.state != StateConnected {
		return tcpip.ErrNotConnected
	}

	e.shutdownFlags |= flags

	if flags&tcpip.ShutdownRead != 0 {
		e.rcvMu.Lock()
		wasClosed := e.rcvClosed
		e.rcvClosed = true
		e.rcvMu.Unlock()

		if !wasClosed {
			e.waiterQueue.Notify(waiter.EventIn)
		}
	}

	return nil
}

// Listen is not supported by UDP, it just fails.
func (*endpoint) Listen(int) *tcpip.Error {
	return tcpip.ErrNotSupported
}

// Accept is not supported by UDP, it just fails.
func (*endpoint) Accept() (tcpip.Endpoint, *waiter.Queue, *tcpip.Error) {
	return nil, nil, tcpip.ErrNotSupported
}

func (e *endpoint) registerWithStack(nicID tcpip.NICID, netProtos []tcpip.NetworkProtocolNumber, id stack.TransportEndpointID) (stack.TransportEndpointID, *tcpip.Error) {

	// 若未指定本地端口，则分配一个临时端口号，保存到 id.LocalPort 。
	if e.ID.LocalPort == 0 {
		port, err := e.stack.ReservePort(
			netProtos,			// 实际使用的网络协议
			ProtocolNumber,		// UDP 协议号
			id.LocalAddress,	// 本地地址
			id.LocalPort,		// 本地端口
			e.reusePort,		// 重用端口
			e.bindToDevice,		// 绑定网卡
		)
		if err != nil {
			return id, err
		}
		id.LocalPort = port
	}

	// 将 endpoint 注册到协议栈传输层，协议号指明为 UDP ，这样后续的 UDP 包会发送到本 endpoint 上来。
	err := e.stack.RegisterTransportEndpoint(
		nicID,				// 网卡 ID
		netProtos,			// 实际使用的网络协议
		ProtocolNumber, 	// UDP 协议号
		id,					// 传输层协议端点的标识符，四元组 <本地端口, 本地地址，远程端口， 远程地址>
		e, 					// 实现了 TransportEndpoint 接口，包括 HandlePacket(), HandleControlPacket() 等函数
		e.reusePort,		// 是否重用端口
		e.bindToDevice,		// 是否将套接字绑定到指定网卡，例如 eth0 等
	)

	if err != nil {
		e.stack.ReleasePort(netProtos, ProtocolNumber, id.LocalAddress, id.LocalPort, e.bindToDevice)
	}
	return id, err
}

func (e *endpoint) bindLocked(addr tcpip.FullAddress) *tcpip.Error {


	// Don't allow binding once endpoint is not in the initial state anymore.
	//
	// 如果端点不处于初始状态，就不允许 Bind() 。
	if e.state != StateInitial {
		return tcpip.ErrInvalidEndpointState
	}

	// 检查地址 addr 的有效性，返回关联的网络层协议号(IPv4 or IPv6)。
	netProto, err := e.checkV4Mapped(&addr, true)
	if err != nil {
		return err
	}

	// Expand netProtos to include v4 and v6 if the caller is binding to a
	// wildcard (empty) address, and this is an IPv6 endpoint with v6only
	// set to false.
	netProtos := []tcpip.NetworkProtocolNumber{netProto}

	// 如果:
	// 	(1) e 是一个 IPv6 端点
	//  (2) addr.Addr 为空，即欲与通配符（空）地址绑定
	//  (3) v6only 设置为 false
	// 则:
	//  将 netProtos 扩展为包括 IPv4 和 IPv6 。
	if netProto == header.IPv6ProtocolNumber && !e.v6only && addr.Addr == "" {
		netProtos = []tcpip.NetworkProtocolNumber{
			header.IPv6ProtocolNumber,
			header.IPv4ProtocolNumber,
		}
	}

	// 网卡
	nicID := addr.NIC

	// 如果:
	// 	(1) addr.Addr 非空
	//  (2) addr.Addr 非广播或者多播地址
	// 则:
	//   addr.Addr 指定了本地的单播地址，需要检查该地址是否有效。
	if len(addr.Addr) != 0 && !isBroadcastOrMulticast(addr.Addr) {
		// A local unicast address was specified, verify that it's valid.
		// 指定了一个本地单播地址，则验证它是否有效。
		nicID = e.stack.CheckLocalAddress(addr.NIC, netProto, addr.Addr)
		if nicID == 0 {
			return tcpip.ErrBadLocalAddress
		}
	}

	// id 是传输层协议端点的标识符: <本地端口, 本地地址，远程端口，远程地址>。
	id := stack.TransportEndpointID{
		LocalPort:    addr.Port,	// 本地端口
		LocalAddress: addr.Addr, 	// 本地地址
	}

	// 将 endpoint<nic, netProtos, id> 注册到协议栈传输层，协议号指明为 UDP ，这样后续的 UDP 包会发送到本 endpoint 上来。
	id, err = e.registerWithStack(nicID, netProtos, id)
	if err != nil {
		return err
	}

	// 更新一些元数据
	e.ID = id
	e.RegisterNICID = nicID
	e.effectiveNetProtos = netProtos

	// Mark endpoint as bound.
	e.state = StateBound

	e.rcvMu.Lock()
	e.rcvReady = true
	e.rcvMu.Unlock()

	return nil
}

// Bind binds the endpoint to a specific local address and port.
// Specifying a NIC is optional.
func (e *endpoint) Bind(addr tcpip.FullAddress) *tcpip.Error {
	e.mu.Lock()
	defer e.mu.Unlock()

	err := e.bindLocked(addr)
	if err != nil {
		return err
	}

	// Save the effective NICID generated by bindLocked.
	//
	// 保存 bindLocked 生成的有效 NICID。
	e.BindNICID = e.RegisterNICID

	return nil
}

// GetLocalAddress returns the address to which the endpoint is bound.
func (e *endpoint) GetLocalAddress() (tcpip.FullAddress, *tcpip.Error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	return tcpip.FullAddress{
		NIC:  e.RegisterNICID,		//
		Addr: e.ID.LocalAddress,
		Port: e.ID.LocalPort,
	}, nil
}

// GetRemoteAddress returns the address to which the endpoint is connected.
func (e *endpoint) GetRemoteAddress() (tcpip.FullAddress, *tcpip.Error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if e.state != StateConnected {
		return tcpip.FullAddress{}, tcpip.ErrNotConnected
	}

	return tcpip.FullAddress{
		NIC:  e.RegisterNICID,
		Addr: e.ID.RemoteAddress,
		Port: e.ID.RemotePort,
	}, nil
}

// Readiness returns the current readiness of the endpoint.
// For example, if waiter.EventIn is set, the endpoint is immediately readable.
//
// Readiness 返回端点的可读状态。
// 如果 endpoint 有数据包可读，会在 result 中设置 waiter.EventIn 标记位。
func (e *endpoint) Readiness(mask waiter.EventMask) waiter.EventMask {

	// The endpoint is always writable.
	// 检查是否可写：endpoint 永远是可写的，如果缓存满，会默认丢弃。
	result := waiter.EventOut & mask

	// Determine if the endpoint is readable if requested.
	// 检查是否可读：
	if (mask & waiter.EventIn) != 0 {
		e.rcvMu.Lock()
		// 当前接收缓冲区非空、且 endpoint 未关闭，则有数据包可读，需要设置 waiter.EventIn 标记位。
		if !e.rcvList.Empty() || e.rcvClosed {
			result |= waiter.EventIn
		}
		e.rcvMu.Unlock()
	}

	return result
}

// HandlePacket is called by the stack when new packets arrive to this transport endpoint.
//
// 当有新的数据包到达这个传输层 endpoint 时，协议栈会调用 endpoint.HandlePacket()，流程：
// 	1. 取出 UDP PKT，解析 Header，检查 Length 是否匹配
// 	2. 检查 endpoint 是否已关闭
// 	3. 检查接收缓存区是否已满
// 	4. 将格式转换为 UDP Packet 并存入接收队列中，更新接收缓冲区大小
// 	5. 如果本次数据接收前缓冲区未空，则需通知等待者
func (e *endpoint) HandlePacket(r *stack.Route, id stack.TransportEndpointID, pkt tcpip.PacketBuffer) {

	// Get the header then trim it from the view.

	// 从 pkt.Data 中取出 UDP Header，检查长度字段 Length 是否等于 len(pkt.Data)，若不等则直接返回
	hdr := header.UDP(pkt.Data.First())
	if int(hdr.Length()) > pkt.Data.Size() { 	// Malformed packet.
		e.stack.Stats().UDP.MalformedPacketsReceived.Increment()
		e.stats.ReceiveErrors.MalformedPacketsReceived.Increment()
		return
	}
	// 从 pkt.Data 中移除 UDP Header，剩下 UDP Payload
	pkt.Data.TrimFront(header.UDPMinimumSize)

	e.rcvMu.Lock()
	e.stack.Stats().UDP.PacketsReceived.Increment()
	e.stats.PacketsReceived.Increment()

	// Drop the packet if our buffer is currently full.

	// 如果当前 endpoint 未准备好接收数据或已关闭，则直接返回。
	if !e.rcvReady || e.rcvClosed {
		e.rcvMu.Unlock()
		e.stack.Stats().UDP.ReceiveBufferErrors.Increment()
		e.stats.ReceiveErrors.ClosedReceiver.Increment()
		return
	}
	// 如果当前接收缓冲区大小超过阈值，则直接返回。
	if e.rcvBufSize >= e.rcvBufSizeMax {
		e.rcvMu.Unlock()
		e.stack.Stats().UDP.ReceiveBufferErrors.Increment()
		e.stats.ReceiveErrors.ReceiveBufferOverflow.Increment()
		return
	}

	// 检查当前缓冲区是否未空，若为空，则本次新到达数据需要触发 notify 通知等待者。
	wasEmpty := e.rcvBufSize == 0

	// Push new packet into receive list and increment the buffer size.

	// 构造 UDP 包
	packet := &udpPacket{
		senderAddress: tcpip.FullAddress{
			NIC:  r.NICID(),		// 网卡 ID
			Addr: id.RemoteAddress,	// 目标地址
			Port: hdr.SourcePort(), // 目标端口
		},
	}
	// 设置 Data
	packet.data = pkt.Data
	// 推入接收包队列
	e.rcvList.PushBack(packet)
	// 增加接收数据计数
	e.rcvBufSize += pkt.Data.Size()
	// 设置时间戳 timestamp
	packet.timestamp = e.stack.NowNanoseconds()

	e.rcvMu.Unlock()

	// Notify any waiters that there's data to be read now.
	// 如果本次数据接收前缓冲区未空，则需通知等待者，有数据可读。
	if wasEmpty {
		e.waiterQueue.Notify(waiter.EventIn)
	}
}

// HandleControlPacket implements stack.TransportEndpoint.HandleControlPacket.
func (e *endpoint) HandleControlPacket(id stack.TransportEndpointID, typ stack.ControlType, extra uint32, pkt tcpip.PacketBuffer) {
}

// State implements tcpip.Endpoint.State.
func (e *endpoint) State() uint32 {
	e.mu.Lock()
	defer e.mu.Unlock()
	return uint32(e.state)
}

// Info returns a copy of the endpoint info.
func (e *endpoint) Info() tcpip.EndpointInfo {
	e.mu.RLock()
	// Make a copy of the endpoint info.
	ret := e.TransportEndpointInfo
	e.mu.RUnlock()
	return &ret
}

// Stats returns a pointer to the endpoint stats.
func (e *endpoint) Stats() tcpip.EndpointStats {
	return &e.stats
}

// Wait implements tcpip.Endpoint.Wait.
func (*endpoint) Wait() {}

func isBroadcastOrMulticast(a tcpip.Address) bool {
	return a == header.IPv4Broadcast || header.IsV4MulticastAddress(a) || header.IsV6MulticastAddress(a)
}
