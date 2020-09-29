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
	"github.com/blastbao/netstack/sleep"
	"github.com/blastbao/netstack/tcpip"
	"github.com/blastbao/netstack/tcpip/buffer"
	"github.com/blastbao/netstack/tcpip/header"
)

// Route represents a route through the networking stack to a given destination.
// Route 表示通过网络栈到达目的地的路由信息。
type Route struct {

	// RemoteAddress is the final destination of the route.
	// RemoteAddress 是路由最终目的地的网络层（IP）地址。
	RemoteAddress tcpip.Address

	// RemoteLinkAddress is the link-layer (MAC) address of the final destination of the route.
	// RemoteLinkAddress 是路由最终目的地的链路层（MAC）地址。
	RemoteLinkAddress tcpip.LinkAddress

	// LocalAddress is the local address where the route starts.
	// LocalAddress 是指本地网络层（IP）地址。
	LocalAddress tcpip.Address

	// LocalLinkAddress is the link-layer (MAC) address of the where the route starts.
	// LocalLinkAddress 是指本地链路层（MAC）地址。
	LocalLinkAddress tcpip.LinkAddress

	// NextHop is the next node in the path to the destination.
	// NextHop 是通往目的地的路径中的下一个节点。
	NextHop tcpip.Address

	// NetProto is the network-layer protocol.
	// NetProto 是指网络层协议。
	NetProto tcpip.NetworkProtocolNumber

	// ref a reference to the network endpoint through which the route starts.
	// ref 引用本地端点。
	ref *referencedNetworkEndpoint

	// Loop controls where WritePacket should send packets.
	// Loop 控制 WritePacket 应该在哪里发送数据包。
	Loop PacketLooping

}

// makeRoute initializes a new route. It takes ownership of the provided
// reference to a network endpoint.
func makeRoute(
	netProto tcpip.NetworkProtocolNumber,
	localAddr, remoteAddr tcpip.Address,
	localLinkAddr tcpip.LinkAddress,
	ref *referencedNetworkEndpoint,
	handleLocal, multicastLoop bool,
) Route {

	loop := PacketOut

	// 回环处理
	if handleLocal && localAddr != "" && remoteAddr == localAddr {
		loop = PacketLoop
	} else if multicastLoop && (header.IsV4MulticastAddress(remoteAddr) || header.IsV6MulticastAddress(remoteAddr)) {
		loop |= PacketLoop
	} else if remoteAddr == header.IPv4Broadcast {
		loop |= PacketLoop
	}

	return Route{
		NetProto:         netProto,			// 网络协议
		LocalAddress:     localAddr,		// 本地 ip 地址
		LocalLinkAddress: localLinkAddr,	// 本地 mac 地址
		RemoteAddress:    remoteAddr,		// 远端 ip 地址
		ref:              ref,				//
		Loop:             loop,				//
	}
}

// NICID returns the id of the NIC from which this route originates.
func (r *Route) NICID() tcpip.NICID {
	return r.ref.ep.NICID()
}

// MaxHeaderLength forwards the call to the network endpoint's implementation.
func (r *Route) MaxHeaderLength() uint16 {
	return r.ref.ep.MaxHeaderLength()
}

// Stats returns a mutable copy of current stats.
func (r *Route) Stats() tcpip.Stats {
	return r.ref.nic.stack.Stats()
}

// PseudoHeaderChecksum forwards the call to the network endpoint's
// implementation.
func (r *Route) PseudoHeaderChecksum(protocol tcpip.TransportProtocolNumber, totalLen uint16) uint16 {
	return header.PseudoHeaderChecksum(protocol, r.LocalAddress, r.RemoteAddress, totalLen)
}

// Capabilities returns the link-layer capabilities of the route.
func (r *Route) Capabilities() LinkEndpointCapabilities {
	return r.ref.ep.Capabilities()
}

// GSOMaxSize returns the maximum GSO packet size.
func (r *Route) GSOMaxSize() uint32 {
	if gso, ok := r.ref.ep.(GSOEndpoint); ok {
		return gso.GSOMaxSize()
	}
	return 0
}

// Resolve attempts to resolve the link address if necessary. Returns ErrWouldBlock in
// case address resolution requires blocking, e.g. wait for ARP reply. Waker is
// notified when address resolution is complete (success or not).
//
// If address resolution is required, ErrNoLinkAddress and a notification channel is
// returned for the top level caller to block. Channel is closed once address resolution
// is complete (success or not).
func (r *Route) Resolve(waker *sleep.Waker) (<-chan struct{}, *tcpip.Error) {
	if !r.IsResolutionRequired() {
		// Nothing to do if there is no cache (which does the resolution on cache miss) or
		// link address is already known.
		return nil, nil
	}

	nextAddr := r.NextHop
	if nextAddr == "" {
		// Local link address is already known.
		if r.RemoteAddress == r.LocalAddress {
			r.RemoteLinkAddress = r.LocalLinkAddress
			return nil, nil
		}
		nextAddr = r.RemoteAddress
	}
	linkAddr, ch, err := r.ref.linkCache.GetLinkAddress(r.ref.nic.ID(), nextAddr, r.LocalAddress, r.NetProto, waker)
	if err != nil {
		return ch, err
	}
	r.RemoteLinkAddress = linkAddr
	return nil, nil
}

// RemoveWaker removes a waker that has been added in Resolve().
func (r *Route) RemoveWaker(waker *sleep.Waker) {
	nextAddr := r.NextHop
	if nextAddr == "" {
		nextAddr = r.RemoteAddress
	}
	r.ref.linkCache.RemoveWaker(r.ref.nic.ID(), nextAddr, waker)
}

// IsResolutionRequired returns true if Resolve() must be called to resolve
// the link address before the this route can be written to.
//
// 如果必须调用 Resolve() 来解析链路层地址，IsResolutionRequired 返回 true 。
func (r *Route) IsResolutionRequired() bool {
	return r.ref.isValidForOutgoing() && r.ref.linkCache != nil && r.RemoteLinkAddress == ""
}

// WritePacket writes the packet through the given route.
func (r *Route) WritePacket(gso *GSO, params NetworkHeaderParams, pkt tcpip.PacketBuffer) *tcpip.Error {
	if !r.ref.isValidForOutgoing() {
		return tcpip.ErrInvalidEndpointState
	}

	err := r.ref.ep.WritePacket(r, gso, params, r.Loop, pkt)
	if err != nil {
		r.Stats().IP.OutgoingPacketErrors.Increment()
	} else {
		r.ref.nic.stats.Tx.Packets.Increment()
		r.ref.nic.stats.Tx.Bytes.IncrementBy(uint64(pkt.Header.UsedLength() + pkt.Data.Size()))
	}
	return err
}

// PacketDescriptor is a packet descriptor which contains a packet header and
// offset and size of packet data in a payload view.
type PacketDescriptor struct {
	Hdr  buffer.Prependable
	Off  int
	Size int
}

// NewPacketDescriptors allocates a set of packet descriptors.
func NewPacketDescriptors(n int, hdrSize int) []PacketDescriptor {
	buf := make([]byte, n*hdrSize)
	hdrs := make([]PacketDescriptor, n)
	for i := range hdrs {
		hdrs[i].Hdr = buffer.NewEmptyPrependableFromView(buf[i*hdrSize:][:hdrSize])
	}
	return hdrs
}

// WritePackets writes the set of packets through the given route.
func (r *Route) WritePackets(gso *GSO, hdrs []PacketDescriptor, payload buffer.VectorisedView, params NetworkHeaderParams) (int, *tcpip.Error) {
	if !r.ref.isValidForOutgoing() {
		return 0, tcpip.ErrInvalidEndpointState
	}

	n, err := r.ref.ep.WritePackets(r, gso, hdrs, payload, params, r.Loop)
	if err != nil {
		r.Stats().IP.OutgoingPacketErrors.IncrementBy(uint64(len(hdrs) - n))
	}
	r.ref.nic.stats.Tx.Packets.IncrementBy(uint64(n))
	payloadSize := 0
	for i := 0; i < n; i++ {
		r.ref.nic.stats.Tx.Bytes.IncrementBy(uint64(hdrs[i].Hdr.UsedLength()))
		payloadSize += hdrs[i].Size
	}
	r.ref.nic.stats.Tx.Bytes.IncrementBy(uint64(payloadSize))
	return n, err
}

// WriteHeaderIncludedPacket writes a packet already containing a network
// header through the given route.
func (r *Route) WriteHeaderIncludedPacket(pkt tcpip.PacketBuffer) *tcpip.Error {
	if !r.ref.isValidForOutgoing() {
		return tcpip.ErrInvalidEndpointState
	}

	if err := r.ref.ep.WriteHeaderIncludedPacket(r, r.Loop, pkt); err != nil {
		r.Stats().IP.OutgoingPacketErrors.Increment()
		return err
	}
	r.ref.nic.stats.Tx.Packets.Increment()
	r.ref.nic.stats.Tx.Bytes.IncrementBy(uint64(pkt.Data.Size()))
	return nil
}

// DefaultTTL returns the default TTL of the underlying network endpoint.
func (r *Route) DefaultTTL() uint8 {
	return r.ref.ep.DefaultTTL()
}

// MTU returns the MTU of the underlying network endpoint.
func (r *Route) MTU() uint32 {
	return r.ref.ep.MTU()
}

// Release frees all resources associated with the route.
// 释放
func (r *Route) Release() {
	if r.ref != nil {
		r.ref.decRef()
		r.ref = nil
	}
}

// Clone Clone a route such that the original one can be released and the new
// one will remain valid.
// 拷贝
func (r *Route) Clone() Route {
	r.ref.incRef()
	return *r
}

// MakeLoopedRoute duplicates the given route with special handling for routes
// used for sending multicast or broadcast packets. In those cases the
// multicast/broadcast address is the remote address when sending out, but for
// incoming (looped) packets it becomes the local address. Similarly, the local
// interface address that was the local address going out becomes the remote
// address coming in. This is different to unicast routes where local and
// remote addresses remain the same as they identify location (local vs remote)
// not direction (source vs destination).
func (r *Route) MakeLoopedRoute() Route {
	l := r.Clone()
	if r.RemoteAddress == header.IPv4Broadcast || header.IsV4MulticastAddress(r.RemoteAddress) || header.IsV6MulticastAddress(r.RemoteAddress) {
		l.RemoteAddress, l.LocalAddress = l.LocalAddress, l.RemoteAddress
		l.RemoteLinkAddress = l.LocalLinkAddress
	}
	return l
}

// Stack returns the instance of the Stack that owns this route.
func (r *Route) Stack() *Stack {
	return r.ref.stack()
}
