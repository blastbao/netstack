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

package stack

import (
	"fmt"
	"math/rand"
	"sort"
	"sync"

	"github.com/blastbao/netstack/tcpip"
	"github.com/blastbao/netstack/tcpip/hash/jenkins"
	"github.com/blastbao/netstack/tcpip/header"
)

// protocolID{ NetProto, TransProto }
// 	=> transportEndpoints: 传输层四元组 => endpointsByNic
// 		=> endpointsByNic
// 			=> multiPortEndpoint
// 				=> []TransportEndpoint


type protocolIDs struct {
	network   tcpip.NetworkProtocolNumber
	transport tcpip.TransportProtocolNumber
}

// transportEndpoints manages all endpoints of a given protocol.
// It has its own mutex so as to reduce interference between protocols.
//
// transportEndpoints 管理给定协议的所有端点，它具有 mutex 以减少协议之间的干扰。
type transportEndpoints struct {

	// mu protects all fields of the transportEndpoints.
	mu sync.RWMutex

	// [重要] 传输层四元组 => Endpoints，相同的四元组在传输层协议 protocol 不同的情况下，不会冲突。
	endpoints map[TransportEndpointID]*endpointsByNic

	// rawEndpoints contains endpoints for raw sockets,
	// which receive all traffic of a given protocol regardless of port.
	//
	// rawEndpoints 包含原始套接字的端点，这些端点接收给定协议的所有流量，而与端口无关。
	rawEndpoints []RawTransportEndpoint
}

// unregisterEndpoint unregisters the endpoint with the given id such that it won't receive any more packets.
//
// 从 transportEndpoints 移除四元组 id 关联的所有 eps ，这些 eps 将不再接收传输层数据包。
func (eps *transportEndpoints) unregisterEndpoint(id TransportEndpointID, ep TransportEndpoint, bindToDevice tcpip.NICID) {

	eps.mu.Lock()
	defer eps.mu.Unlock()

	// 根据四元组 id 获取所有传输层 epsByNic
	epsByNic, ok := eps.endpoints[id]
	if !ok {
		return
	}

	// 从 epsByNic[bindToDevice] 中移除 ep
	if !epsByNic.unregisterEndpoint(bindToDevice, ep) {
		return
	}

	// 从 eps 中移除 id 四元组
	delete(eps.endpoints, id)
}

// 获取 transportEndpoints 包含的所有 eps 。
func (eps *transportEndpoints) transportEndpoints() []TransportEndpoint {
	eps.mu.RLock()
	defer eps.mu.RUnlock()

	es := make([]TransportEndpoint, 0, len(eps.endpoints))
	for _, e := range eps.endpoints {
		es = append(es, e.transportEndpoints()...)
	}

	return es
}


// 保存注册到同一个四元组的所有 eps ，这些 eps 可能绑定到不同的网卡上。
type endpointsByNic struct {
	mu        sync.RWMutex

	// 网卡 ID => TransportEndpoints
	endpoints map[tcpip.NICID]*multiPortEndpoint

	// seed is a random secret for a jenkins hash.
	seed uint32
}

func (epsByNic *endpointsByNic) transportEndpoints() []TransportEndpoint {
	epsByNic.mu.RLock()
	defer epsByNic.mu.RUnlock()

	var eps []TransportEndpoint
	for _, ep := range epsByNic.endpoints {
		eps = append(eps, ep.transportEndpoints()...)
	}
	return eps
}

// HandlePacket is called by the stack when new packets arrive to this transport endpoint.
// 当新的数据包到达此传输层端点时，协议栈将调用 HandlePacket 。
func (epsByNic *endpointsByNic) handlePacket(r *Route, id TransportEndpointID, pkt tcpip.PacketBuffer) {

	epsByNic.mu.RLock()

	// 获取绑定到网卡 nic 上的端点
	mpep, ok := epsByNic.endpoints[r.ref.nic.ID()]
	if !ok {
		// 如果不存在，则取 0 号网卡，如果 0 号网卡仍不存在，直接返回。
		if mpep, ok = epsByNic.endpoints[0]; !ok {
			epsByNic.mu.RUnlock() // Don't use defer for performance reasons.
			return
		}
	}

	// If this is a broadcast or multicast datagram, deliver the datagram to all
	// endpoints bound to the right device.
	//
	// 如果这是一个广播或多播数据报，则将数据报传送到绑定到正确设备的所有端点。
	if isMulticastOrBroadcast(id.LocalAddress) {
		mpep.handlePacketAll(r, id, pkt)
		epsByNic.mu.RUnlock() // Don't use defer for performance reasons.
		return
	}

	// multiPortEndpoints are guaranteed to have at least one element.
	// 保证 multiPortEndpoints 具有至少一个元素。

	// 至此，非广播和多播，根据传输层四元组 id 的哈希值选择一个 ep ，然后调用 ep.HandlePacket() 处理来包。
	selectEndpoint(id, mpep, epsByNic.seed).HandlePacket(r, id, pkt)

	epsByNic.mu.RUnlock() // Don't use defer for performance reasons.
}



// HandleControlPacket implements stack.TransportEndpoint.HandleControlPacket.
// HandleControlPacket 实现 stack.TransportEndpoint.HandleControlPacket 接口。
func (epsByNic *endpointsByNic) handleControlPacket(n *NIC, id TransportEndpointID, typ ControlType, extra uint32, pkt tcpip.PacketBuffer) {

	epsByNic.mu.RLock()
	defer epsByNic.mu.RUnlock()

	//
	mpep, ok := epsByNic.endpoints[n.ID()]
	if !ok {
		mpep, ok = epsByNic.endpoints[0]
	}
	if !ok {
		return
	}

	// TODO(eyalsoha): Why don't we look at id to see if this packet needs to
	// broadcast like we are doing with handlePacket above?

	// multiPortEndpoints are guaranteed to have at least one element.
	// 保证 multiPortEndpoints 具有至少一个元素。

	// 根据传输层四元组的哈希值选择一个 ep ，然后调用 ep.HandleControlPacket() 处理来包。
	selectEndpoint(id, mpep, epsByNic.seed).HandleControlPacket(id, typ, extra, pkt)
}

// registerEndpoint returns true if it succeeds.
// It fails and returns false if ep already has an element with the same key.
//
// registerEndpoint 执行成功会返回 true ，如果 ep 中已经有一个相同键的元素，则返回 false 。
func (epsByNic *endpointsByNic) registerEndpoint(t TransportEndpoint, reusePort bool, bindToDevice tcpip.NICID) *tcpip.Error {

	epsByNic.mu.Lock()
	defer epsByNic.mu.Unlock()

	// 根据 bindToDevice 查询绑定到该设备的传输层 multiPortEp 。
	if multiPortEp, ok := epsByNic.endpoints[bindToDevice]; ok {
		// There was already a bind.
		// 若已存在，则向 multiPortEp 注册新端点 t 。
		return multiPortEp.singleRegisterEndpoint(t, reusePort)
	}

	// 至此，意味着尚无端点绑定到 bindToDevice 设备。

	// This is a new binding.
	multiPortEp := &multiPortEndpoint{}
	multiPortEp.endpointsMap = make(map[TransportEndpoint]int)
	multiPortEp.reuse = reusePort
	epsByNic.endpoints[bindToDevice] = multiPortEp

	err := multiPortEp.singleRegisterEndpoint(t, reusePort)
	return err

}

// unregisterEndpoint returns true if endpointsByNic has to be unregistered.
func (epsByNic *endpointsByNic) unregisterEndpoint(bindToDevice tcpip.NICID, t TransportEndpoint) bool {
	epsByNic.mu.Lock()
	defer epsByNic.mu.Unlock()

	// 根据网卡 ID `bindToDevice` 查询传输层 eps `multiPortEp`
	multiPortEp, ok := epsByNic.endpoints[bindToDevice]
	if !ok {
		return false
	}

	// 从 multiPortEp 中移除 t
	if multiPortEp.unregisterEndpoint(t) {
		delete(epsByNic.endpoints, bindToDevice)
	}
	return len(epsByNic.endpoints) == 0
}

// transportDemuxer demultiplexes packets targeted at a transport endpoint
// (i.e., after they've been parsed by the network layer). It does two levels
// of demultiplexing: first based on the network and transport protocols, then
// based on endpoints IDs. It should only be instantiated via newTransportDemuxer.
//
// transportDemuxer 对以传输层 ep 为目标的数据包进行多路复用分解（即在被网络层解析之后）。
//
// 它执行两个级别的多路复用分解：首先基于网络和传输协议，然后基于端点ID。
//
// 它只能通过newTransportDemuxer实例化。
//
//
//
type transportDemuxer struct {
	// protocol is immutable.
	// protocol 保存和协议关联的所有传输层端点。
	protocol map[protocolIDs]*transportEndpoints
}

func newTransportDemuxer(stack *Stack) *transportDemuxer {

	// 构造传输层多路复用器
	demuxer := &transportDemuxer{
		protocol: make(map[protocolIDs]*transportEndpoints),
	}

	// Add each network and transport pair to the demuxer.

	// 遍历协议栈支持的网络层协议
	for netProto := range stack.networkProtocols {
		// 遍历协议栈支持的传输层协议
		for proto := range stack.transportProtocols {
			// 构造协议ID: {网络层协议, 传输层协议}
			id := protocolIDs{netProto, proto}
			// 注册到多路复用分解器 demuxer 中
			demuxer.protocol[id] = &transportEndpoints{endpoints: make(map[TransportEndpointID]*endpointsByNic)}
		}
	}

	return demuxer
}

// registerEndpoint registers the given endpoint with the dispatcher such that
// packets that match the endpoint ID are delivered to it.
//
// registerEndpoint 将给定的端点注册到 demuxer 上，以便将与端点 ID 匹配的数据包传递给它。
func (d *transportDemuxer) registerEndpoint(
	netProtos []tcpip.NetworkProtocolNumber, // 网络层协议号
	protocol tcpip.TransportProtocolNumber, // 传输层协议号
	id TransportEndpointID, // 传输层端点
	ep TransportEndpoint, // 传输层端点
	reusePort bool, // 端口重用
	bindToDevice tcpip.NICID, // 绑定到设备
) *tcpip.Error {

	for i, n := range netProtos {
		// 将 ep 注册到 transportDemuxer 中
		if err := d.singleRegisterEndpoint(n, protocol, id, ep, reusePort, bindToDevice); err != nil {
			// 从 d 中移除四元组 id 关联的所有 eps
			d.unregisterEndpoint(netProtos[:i], protocol, id, ep, bindToDevice)
			return err
		}
	}

	return nil
}


// multiPortEndpoint is a container for TransportEndpoints which are bound to the
// same pair of address and port. endpointsArr always has at least one element.
//
// FIXME(gvisor.dev/issue/873): Restore this properly. Currently, we just save
// this to ensure that the underlying endpoints get saved/restored,
// but not not use the restored copy.
//
// multiPortEndpoint 是 TransportEndpoints 的容器，这些 TransportEndpoints 绑定到同一对地址和端口。
// endpointsArr 至少包含一个元素。
//
// +stateify savable
type multiPortEndpoint struct {
	mu           sync.RWMutex
	endpointsArr []TransportEndpoint
	endpointsMap map[TransportEndpoint]int

	// reuse indicates if more than one endpoint is allowed.
	// reuse 表示是否允许一个以上的 endpoint 。
	reuse bool
}

func (ep *multiPortEndpoint) transportEndpoints() []TransportEndpoint {
	ep.mu.RLock()
	eps := append([]TransportEndpoint(nil), ep.endpointsArr...)
	ep.mu.RUnlock()
	return eps
}

// reciprocalScale scales a value into range [0, n).
//
// This is similar to val % n, but faster.
// See http://lemire.me/blog/2016/06/27/a-fast-alternative-to-the-modulo-reduction/
func reciprocalScale(val, n uint32) uint32 {
	return uint32((uint64(val) * uint64(n)) >> 32)
}

// selectEndpoint calculates a hash of destination and source addresses and
// ports then uses it to select a socket.
//
// In this case, all packets from one address will be sent to same endpoint.
//
// selectEndpoint 计算传输层四元组的哈希值，然后根据它来从 multiPortEndpoint 中选择一个传输层 ep 。
// 在这种情况下，所有来自同一四元组的数据包将被发送到同一个传输层 ep 。
func selectEndpoint(id TransportEndpointID, mpep *multiPortEndpoint, seed uint32) TransportEndpoint {

	// 如果只有一个 ep 则直接返回它。
	if len(mpep.endpointsArr) == 1 {
		return mpep.endpointsArr[0]
	}

	// 计算哈希值 hashValue := hash(LocalPort, RemotePort, LocalAddress, RemoteAddress)
	payload := []byte{
		byte(id.LocalPort),
		byte(id.LocalPort >> 8),
		byte(id.RemotePort),
		byte(id.RemotePort >> 8),
	}

	h := jenkins.Sum32(seed)
	h.Write(payload)
	h.Write([]byte(id.LocalAddress))
	h.Write([]byte(id.RemoteAddress))
	hash := h.Sum32()

	// 取模 idx := hash % n
	idx := reciprocalScale(hash, uint32(len(mpep.endpointsArr)))

	// 根据下标取出 ep
	return mpep.endpointsArr[idx]
}

func (ep *multiPortEndpoint) handlePacketAll(r *Route, id TransportEndpointID, pkt tcpip.PacketBuffer) {
	ep.mu.RLock()
	for i, endpoint := range ep.endpointsArr {
		// HandlePacket takes ownership of pkt, so each endpoint needs its own copy except for the final one.
		// HandlePacket 拥有 pkt 的所有权，所以除了最后一个，每个端点都需要自己的副本。
		if i == len(ep.endpointsArr)-1 {
			endpoint.HandlePacket(r, id, pkt)
			break
		}
		endpoint.HandlePacket(r, id, pkt.Clone())
	}
	ep.mu.RUnlock() // Don't use defer for performance reasons.
}

// Close implements stack.TransportEndpoint.Close.
func (ep *multiPortEndpoint) Close() {
	ep.mu.RLock()
	eps := append([]TransportEndpoint(nil), ep.endpointsArr...)
	ep.mu.RUnlock()
	for _, e := range eps {
		e.Close()
	}
}

// Wait implements stack.TransportEndpoint.Wait.
func (ep *multiPortEndpoint) Wait() {
	ep.mu.RLock()
	eps := append([]TransportEndpoint(nil), ep.endpointsArr...)
	ep.mu.RUnlock()
	for _, e := range eps {
		e.Wait()
	}
}

// singleRegisterEndpoint tries to add an endpoint to the multiPortEndpoint list.
// The list might be empty already.
//
// singleRegisterEndpoint 试图向 multiPortEndpoint 列表添加一个端点。该列表可能已经是空的。
func (ep *multiPortEndpoint) singleRegisterEndpoint(t TransportEndpoint, reusePort bool) *tcpip.Error {

	ep.mu.Lock()
	defer ep.mu.Unlock()

	// 如果列表非空，即代表之前已经绑定，如果 ep 未开启端口重用，或者新端点不支持端口重用，则无法绑定，报错返回。
	if len(ep.endpointsArr) > 0 {
		// If it was previously bound, we need to check if we can bind again.
		if !ep.reuse || !reusePort {
			return tcpip.ErrPortInUse
		}
	}

	// 至此，要么列表为空，要么支持端口重用，可以注册新端点。

	// A new endpoint is added into endpointsArr and its index there is saved in endpointsMap.
	// This will allow us to remove endpoint from the array fast.
	//
	// 一个新的端点被添加到 endpointsArr 中，它的索引被保存在 endpointsMap 中。
	// 这将允许我们从数组中快速删除端点。

	// 将下标添加到 endpointsMap 中。
	ep.endpointsMap[t] = len(ep.endpointsArr)
	// 将端点追加到 endpointsArr 中。
	ep.endpointsArr = append(ep.endpointsArr, t)

	// ep.endpointsArr is sorted by endpoint unique IDs, so that endpoints
	// can be restored in the same order.
	//
	// ep.endpointsArr 是按端点 UniqueID 排序的，因此可以按相同的顺序恢复。

	// 对 endpointsArr 进行排序。
	sort.Slice(ep.endpointsArr, func(i, j int) bool {
		return ep.endpointsArr[i].UniqueID() < ep.endpointsArr[j].UniqueID()
	})

	// 更新索引 map 中存储的下标。
	for i, e := range ep.endpointsArr {
		ep.endpointsMap[e] = i
	}

	return nil
}

// unregisterEndpoint returns true if multiPortEndpoint has to be unregistered.
func (ep *multiPortEndpoint) unregisterEndpoint(t TransportEndpoint) bool {
	ep.mu.Lock()
	defer ep.mu.Unlock()

	// 检查 t 是否存在于 ep 中
	idx, ok := ep.endpointsMap[t]
	if !ok {
		return false
	}

	// 若存在，则
	// (1) 从 ep.endpointsMap[] 中移除 t
	// (2) 从 ep.endpointsArr[] 中移除 t
	delete(ep.endpointsMap, t)
	l := len(ep.endpointsArr)
	if l > 1 {
		// The last endpoint in endpointsArr is moved instead of the deleted one.
		lastEp := ep.endpointsArr[l-1]
		ep.endpointsArr[idx] = lastEp
		ep.endpointsMap[lastEp] = idx
		ep.endpointsArr = ep.endpointsArr[0 : l-1]
		return false
	}
	return true
}

func (d *transportDemuxer) singleRegisterEndpoint(
	netProto tcpip.NetworkProtocolNumber,
	protocol tcpip.TransportProtocolNumber,
	id TransportEndpointID, // 传输层四元组
	ep TransportEndpoint,
	reusePort bool,
	bindToDevice tcpip.NICID,
) *tcpip.Error {

	// 远端端口非空，则无法重用～
	if id.RemotePort != 0 {
		// TODO(eyalsoha): Why?
		reusePort = false
	}

	// 根据 netProto、transProto 定位到传输层 eps
	eps, ok := d.protocol[protocolIDs{netProto, protocol}]
	if !ok {
		return tcpip.ErrUnknownProtocol
	}

	eps.mu.Lock()
	defer eps.mu.Unlock()

	// 根据四元组 id 查询 epsByNic ，若存在，将 ep 则注册到 epsByNic[bindToDevice] 中。
	if epsByNic, ok := eps.endpoints[id]; ok {
		// There was already a binding.
		return epsByNic.registerEndpoint(ep, reusePort, bindToDevice)
	}

	// 若不存在，新建 epsByNic ，再将 ep 则注册到 epsByNic[bindToDevice] 中。

	// This is a new binding.
	epsByNic := &endpointsByNic{
		endpoints: make(map[tcpip.NICID]*multiPortEndpoint),
		seed:      rand.Uint32(),
	}
	eps.endpoints[id] = epsByNic
	return epsByNic.registerEndpoint(ep, reusePort, bindToDevice)
}

// unregisterEndpoint unregisters the endpoint with the given id such that it
// won't receive any more packets.
func (d *transportDemuxer) unregisterEndpoint(netProtos []tcpip.NetworkProtocolNumber, protocol tcpip.TransportProtocolNumber, id TransportEndpointID, ep TransportEndpoint, bindToDevice tcpip.NICID) {
	for _, n := range netProtos {
		if eps, ok := d.protocol[protocolIDs{n, protocol}]; ok {
			eps.unregisterEndpoint(id, ep, bindToDevice)
		}
	}
}

var loopbackSubnet = func() tcpip.Subnet {
	sn, err := tcpip.NewSubnet("\x7f\x00\x00\x00", "\xff\x00\x00\x00")
	if err != nil {
		panic(err)
	}
	return sn
}()


// deliverPacket attempts to find one or more matching transport endpoints,
// and then, if matches are found, delivers the packet to them.
// Returns true if the packet no longer needs to be handled.
//
// deliverPacket() 试图寻找一个或多个匹配的传输层端点，如果找到匹配的端点，则将数据包传送给它们。
// 如果不再需要处理该数据包，则返回 true 。
//
//
//
func (d *transportDemuxer) deliverPacket(r *Route, protocol tcpip.TransportProtocolNumber, pkt tcpip.PacketBuffer, id TransportEndpointID) bool {

	// 根据 netProto 和 transProto 定位到 transport eps
	eps, ok := d.protocol[protocolIDs{r.NetProto, protocol}]
	if !ok {
		return false
	}

	eps.mu.RLock()

	// Determine which transport endpoint or endpoints to deliver this packet to.
	// If the packet is a UDP broadcast or multicast, then find all matching
	// transport endpoints. If the packet is a TCP packet with a non-unicast
	// source or destination address, then do nothing further and instruct
	// the caller to do the same.
	//
	// 确定要将此数据包传送到哪个传输层端点或哪个端点。
	// 如果数据包是 UDP 广播或多(组)播，那么找到所有匹配的传输层端点。
	// 如果数据包是具有非单播 源或目标地址 的 TCP 数据包，则不做进一步操作，并指示调用者也这样做。

	var destEps []*endpointsByNic
	switch protocol {

	// UDP
	case header.UDPProtocolNumber:

		// 如果本地地址是多播或者广播，则按匹配的优先级取出同四元组 id 关联的所有 endpointsByNic 列表。
		if isMulticastOrBroadcast(id.LocalAddress) {
			destEps = d.findAllEndpointsLocked(eps, id)
			break
		}

		// 否则，选择最匹配的一个 endpointsByNic 。
		if ep := d.findEndpointLocked(eps, id); ep != nil {
			destEps = append(destEps, ep)
		}

	// TCP
	case header.TCPProtocolNumber:

		if !(isUnicast(r.LocalAddress) && isUnicast(r.RemoteAddress)) {
			// TCP can only be used to communicate between a single
			// source and a single destination; the addresses must
			// be unicast.
			//
			// TCP 只能用于单个源和单个目的之间的通信，地址必须是单播的。
			eps.mu.RUnlock()
			r.Stats().TCP.InvalidSegmentsReceived.Increment()
			return true
		}

		fallthrough

	// 其它
	default:
		// 选择最匹配的一个 endpointsByNic 。
		if ep := d.findEndpointLocked(eps, id); ep != nil {
			destEps = append(destEps, ep)
		}
	}

	eps.mu.RUnlock()


	// Fail if we didn't find at least one matching transport endpoint.
	// 如果找不到至少一个匹配的传输端点，则失败。
	if len(destEps) == 0 {
		// UDP packet could not be delivered to an unknown destination port.
		// 无法将 UDP 数据包传递到未知的目标端口。
		if protocol == header.UDPProtocolNumber {
			r.Stats().UDP.UnknownPortErrors.Increment()
		}
		return false
	}


	// HandlePacket takes ownership of pkt, so each endpoint needs its own
	// copy except for the final one.
	//
	// HandlePacket 拥有 pkt 的所有权，因此每个端点都需要自己的副本，最后一个副本除外。
	for _, ep := range destEps[:len(destEps)-1] {
		ep.handlePacket(r, id, pkt.Clone())
	}

	destEps[len(destEps)-1].handlePacket(r, id, pkt)

	return true
}

// deliverRawPacket attempts to deliver the given packet and returns whether it was delivered successfully.
// deliverRawPacket 尝试投递给定的数据包，并返回是否成功投递。
func (d *transportDemuxer) deliverRawPacket(r *Route, protocol tcpip.TransportProtocolNumber, pkt tcpip.PacketBuffer) bool {

	// 根据协议 NetProto、TransProto 获取关联的 eps ，其中包含 rawEndpoints 。
	eps, ok := d.protocol[protocolIDs{r.NetProto, protocol}]
	if !ok {
		return false
	}

	// As in net/ipv4/ip_input.c:ip_local_deliver, attempt to deliver via
	// raw endpoint first. If there are multiple raw endpoints, they all
	// receive the packet.
	//
	// 与 net/ipv4/ip_input.c:ip_local_deliver 中一样，
	// 首先尝试通过 raw 端点进行传递。如果有多个 raw 端点，它们都将接收该数据包。

	foundRaw := false
	eps.mu.RLock()

	// 遍历 eps.rawEndpoints 逐个调用 rawEP.HandlePacket(r, pkt) 处理来包 pkt 。
	for _, rawEP := range eps.rawEndpoints {
		// Each endpoint gets its own copy of the packet for the sake of save/restore.
		rawEP.HandlePacket(r, pkt)
		foundRaw = true
	}
	eps.mu.RUnlock()

	// 成功投递。
	return foundRaw
}



// deliverControlPacket attempts to deliver the given control packet.
// Returns true if it found an endpoint, false otherwise.
//
// deliverControlPacket 试图传递给定的控制包。如果找到端点，返回 true ，否则返回 false 。
func (d *transportDemuxer) deliverControlPacket(n *NIC, net tcpip.NetworkProtocolNumber, trans tcpip.TransportProtocolNumber, typ ControlType, extra uint32, pkt tcpip.PacketBuffer, id TransportEndpointID) bool {

	// 根据协议 NetProto、TransProto 获取关联的 eps 。
	eps, ok := d.protocol[protocolIDs{net, trans}]
	if !ok {
		return false
	}

	// Try to find the endpoint.
	eps.mu.RLock()
	// 获取与给定四元组 id 最匹配的端点。
	ep := d.findEndpointLocked(eps, id)
	eps.mu.RUnlock()

	// Fail if we didn't find one.
	// 如果未找到，则返回 false 。
	if ep == nil {
		return false
	}

	// Deliver the packet.
	// 如果找到，则进行包的投递，并返回 true 。
	ep.handleControlPacket(n, id, typ, extra, pkt)

	return true
}

func (d *transportDemuxer) findAllEndpointsLocked(eps *transportEndpoints, id TransportEndpointID) []*endpointsByNic {

	// matchedEPs 按匹配的优先级先后存储了关联的 endpointsByNic 列表。
	var matchedEPs []*endpointsByNic

	// Try to find a match with the id as provided.
	// 根据四元组查找匹配的 endpointsByNic
	if ep, ok := eps.endpoints[id]; ok {
		matchedEPs = append(matchedEPs, ep)
	}

	// Try to find a match with the id minus the local address.
	// 将本地地址置空后查找
	nid := id
	nid.LocalAddress = ""
	if ep, ok := eps.endpoints[nid]; ok {
		matchedEPs = append(matchedEPs, ep)
	}

	// Try to find a match with the id minus the remote part.
	// 将远端地址、端口置空后查找
	nid.LocalAddress = id.LocalAddress
	nid.RemoteAddress = ""
	nid.RemotePort = 0
	if ep, ok := eps.endpoints[nid]; ok {
		matchedEPs = append(matchedEPs, ep)
	}

	// Try to find a match with only the local port.
	// 将本地地址、远端地址、端口置空后查找
	nid.LocalAddress = ""
	if ep, ok := eps.endpoints[nid]; ok {
		matchedEPs = append(matchedEPs, ep)
	}
	return matchedEPs
}

// findTransportEndpoint find a single endpoint that most closely matches the provided id.
func (d *transportDemuxer) findTransportEndpoint(
	netProto tcpip.NetworkProtocolNumber,
	transProto tcpip.TransportProtocolNumber,
	id TransportEndpointID,
	r *Route,
) TransportEndpoint {

	// 先根据协议 netProto、transProto 定位到所有 eps
	eps, ok := d.protocol[protocolIDs{netProto, transProto}]
	if !ok {
		return nil
	}

	// Try to find the endpoint.
	eps.mu.RLock()

	// 根据四元组获取关联的 epsByNic
	epsByNic := d.findEndpointLocked(eps, id)

	// Fail if we didn't find one.
	if epsByNic == nil {
		eps.mu.RUnlock()
		return nil
	}

	epsByNic.mu.RLock()
	eps.mu.RUnlock()

	// 根据网卡 nic 获取关联的传输层 mpep
	mpep, ok := epsByNic.endpoints[r.ref.nic.ID()]
	if !ok {
		if mpep, ok = epsByNic.endpoints[0]; !ok {
			epsByNic.mu.RUnlock() // Don't use defer for performance reasons.
			return nil
		}
	}

	// 根据四元组 id 的哈希值从 mpep 中选择一个 ep
	ep := selectEndpoint(id, mpep, epsByNic.seed)

	epsByNic.mu.RUnlock()

	// 返回 ep
	return ep
}

// findEndpointLocked returns the endpoint that most closely matches the given id.
// findEndpointLocked 返回与给定 id 最匹配的端点。
func (d *transportDemuxer) findEndpointLocked(eps *transportEndpoints, id TransportEndpointID) *endpointsByNic {

	// 按匹配的优先级先后存储了关联的 endpointsByNic 列表。
	if matchedEPs := d.findAllEndpointsLocked(eps, id); len(matchedEPs) > 0 {
		return matchedEPs[0]
	}

	return nil
}

// registerRawEndpoint registers the given endpoint with the dispatcher such
// that packets of the appropriate protocol are delivered to it.
//
// A single packet can be sent to one or more raw endpoints along with a non-raw endpoint.
func (d *transportDemuxer) registerRawEndpoint(netProto tcpip.NetworkProtocolNumber, transProto tcpip.TransportProtocolNumber, ep RawTransportEndpoint) *tcpip.Error {

	// 先根据协议 netProto、transProto 定位到所有 eps
	eps, ok := d.protocol[protocolIDs{netProto, transProto}]
	if !ok {
		return tcpip.ErrNotSupported
	}

	eps.mu.Lock()
	defer eps.mu.Unlock()

	// 将 ep 添加到 eps.rawEps 列表中
	eps.rawEndpoints = append(eps.rawEndpoints, ep)

	return nil
}

// unregisterRawEndpoint unregisters the raw endpoint for the given transport
// protocol such that it won't receive any more packets.
func (d *transportDemuxer) unregisterRawEndpoint(netProto tcpip.NetworkProtocolNumber, transProto tcpip.TransportProtocolNumber, ep RawTransportEndpoint) {
	eps, ok := d.protocol[protocolIDs{netProto, transProto}]
	if !ok {
		panic(fmt.Errorf("tried to unregister endpoint with unsupported network and transport protocol pair: %d, %d", netProto, transProto))
	}

	eps.mu.Lock()
	defer eps.mu.Unlock()
	for i, rawEP := range eps.rawEndpoints {
		if rawEP == ep {
			eps.rawEndpoints = append(eps.rawEndpoints[:i], eps.rawEndpoints[i+1:]...)
			return
		}
	}
}

func isMulticastOrBroadcast(addr tcpip.Address) bool {
	return addr == header.IPv4Broadcast || header.IsV4MulticastAddress(addr) || header.IsV6MulticastAddress(addr)
}

func isUnicast(addr tcpip.Address) bool {
	return addr != header.IPv4Any && addr != header.IPv6Any && !isMulticastOrBroadcast(addr)
}
