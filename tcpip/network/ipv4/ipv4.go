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

// Package ipv4 contains the implementation of the ipv4 network protocol. To use
// it in the networking stack, this package must be added to the project, and
// activated on the stack by passing ipv4.NewProtocol() as one of the network
// protocols when calling stack.New(). Then endpoints can be created by passing
// ipv4.ProtocolNumber as the network protocol number when calling
// Stack.NewEndpoint().
package ipv4

import (
	"sync/atomic"

	"github.com/blastbao/netstack/tcpip"
	"github.com/blastbao/netstack/tcpip/buffer"
	"github.com/blastbao/netstack/tcpip/header"
	"github.com/blastbao/netstack/tcpip/network/fragmentation"
	"github.com/blastbao/netstack/tcpip/network/hash"
	"github.com/blastbao/netstack/tcpip/stack"
)

const (

	// ProtocolNumber is the ipv4 protocol number.
	ProtocolNumber = header.IPv4ProtocolNumber

	// MaxTotalSize is maximum size that can be encoded in the 16-bit
	// TotalLength field of the ipv4 header.
	MaxTotalSize = 0xffff

	// DefaultTTL is the default time-to-live value for this endpoint.
	DefaultTTL = 64

	// buckets is the number of identifier buckets.
	buckets = 2048
)

type endpoint struct {
	nicID         tcpip.NICID
	id            stack.NetworkEndpointID
	prefixLen     int
	linkEP        stack.LinkEndpoint
	dispatcher    stack.TransportDispatcher
	fragmentation *fragmentation.Fragmentation
	protocol      *protocol
}

// NewEndpoint creates a new ipv4 endpoint.
// NewEndpoint 创建一个新的 ipv4 端点。
func (p *protocol) NewEndpoint(nicID tcpip.NICID, addrWithPrefix tcpip.AddressWithPrefix, linkAddrCache stack.LinkAddressCache, dispatcher stack.TransportDispatcher, linkEP stack.LinkEndpoint) (stack.NetworkEndpoint, *tcpip.Error) {

	e := &endpoint{
		nicID:         nicID,
		id:            stack.NetworkEndpointID{LocalAddress: addrWithPrefix.Address},
		prefixLen:     addrWithPrefix.PrefixLen,
		linkEP:        linkEP,
		dispatcher:    dispatcher,
		fragmentation: fragmentation.NewFragmentation(fragmentation.HighFragThreshold, fragmentation.LowFragThreshold, fragmentation.DefaultReassembleTimeout),
		protocol:      p,
	}

	return e, nil
}

// DefaultTTL is the default time-to-live value for this endpoint.
func (e *endpoint) DefaultTTL() uint8 {
	return e.protocol.DefaultTTL()
}

// MTU implements stack.NetworkEndpoint.MTU. It returns the link-layer MTU minus
// the network layer max header length.
func (e *endpoint) MTU() uint32 {
	return calculateMTU(e.linkEP.MTU())
}

// Capabilities implements stack.NetworkEndpoint.Capabilities.
func (e *endpoint) Capabilities() stack.LinkEndpointCapabilities {
	return e.linkEP.Capabilities()
}

// NICID returns the ID of the NIC this endpoint belongs to.
func (e *endpoint) NICID() tcpip.NICID {
	return e.nicID
}

// ID returns the ipv4 endpoint ID.
func (e *endpoint) ID() *stack.NetworkEndpointID {
	return &e.id
}

// PrefixLen returns the ipv4 endpoint subnet prefix length in bits.
func (e *endpoint) PrefixLen() int {
	return e.prefixLen
}

// MaxHeaderLength returns the maximum length needed by ipv4 headers (and
// underlying protocols).
func (e *endpoint) MaxHeaderLength() uint16 {
	return e.linkEP.MaxHeaderLength() + header.IPv4MinimumSize
}

// GSOMaxSize returns the maximum GSO packet size.
func (e *endpoint) GSOMaxSize() uint32 {
	if gso, ok := e.linkEP.(stack.GSOEndpoint); ok {
		return gso.GSOMaxSize()
	}
	return 0
}

// writePacketFragments calls e.linkEP.WritePacket with each packet fragment to write.
// It assumes that the IP header is entirely in pkt.Header but does not assume that only the IP header is in pkt.Header.
// It assumes that the input packet's stated length matches the length of the header+payload.
// mtu includes the IP header and options.
// This does not support the DontFragment IP flag.
//
// writePacketFragments 调用 e.linkEP.WritePacket 处理每个要写入的数据包片段。
// 它假设 IP 头完全在 pkt.Header 中，但不假设仅有 IP 头在 pkt.Header 中。
// 它假设输入数据包的声明长度与 header+payload 的长度一致。
// mtu 包括 IP 头和选项。
// 这不支持 DontFragment IP 标志。
func (e *endpoint) writePacketFragments(r *stack.Route, gso *stack.GSO, mtu int, pkt tcpip.PacketBuffer) *tcpip.Error {

	// This packet is too big, it needs to be fragmented.
	// 该数据包太大，需要进行分段。

	ip := header.IPv4(pkt.Header.View())
	flags := ip.Flags()

	// innerMTU 即每一个分片能携带数据的最大值
	// outerMTU 即每一个分片能携带数据和协议头的最大值

	// 1. 计算分片数量

	// Update mtu to take into account the header, which will exist in all fragments anyway.
	innerMTU := mtu - int(ip.HeaderLength())
	// Round the MTU down to align to 8 bytes. Then calculate the number of
	// fragments. Calculate fragment sizes as in RFC791.
	innerMTU &^= 7
	n := (int(ip.PayloadLength()) + innerMTU - 1) / innerMTU

	outerMTU := innerMTU + int(ip.HeaderLength())
	offset := ip.FragmentOffset()
	originalAvailableLength := pkt.Header.AvailableLength()
	for i := 0; i < n; i++ {

		// Where possible, the first fragment that is sent has the same pkt.Header.UsedLength() as the input packet.
		// The link-layer endpoint may depend on this for looking at, eg, L4 headers.
		//
		// 在可能的情况下，发送的第一个片段与输入数据包具有相同的 pkt.Header.UsedLength() 。
		// 链路层端点可能会依赖这个来查看，例如，L4 报头。

		h := ip
		if i > 0 {
			pkt.Header = buffer.NewPrependable(int(ip.HeaderLength()) + originalAvailableLength)
			h = header.IPv4(pkt.Header.Prepend(int(ip.HeaderLength())))
			copy(h, ip[:ip.HeaderLength()])
		}

		// 最后一个分片的 TotalLength 和其他分片不同，其它分片都是 outerMTU，最后分片长度为实际长度。
		if i != n-1 {
			// 设置分片长度为 outerMTU
			h.SetTotalLength(uint16(outerMTU))
			// 设置分片标志，代表后续还有更多分片
			h.SetFlagsFragmentOffset(flags|header.IPv4FlagMoreFragments, offset)
		} else {
			// 设置分片长度为实际长度
			h.SetTotalLength(uint16(h.HeaderLength()) + uint16(pkt.Data.Size()))
			h.SetFlagsFragmentOffset(flags, offset)
		}

		h.SetChecksum(0)
		h.SetChecksum(^h.CalculateChecksum())
		offset += uint16(innerMTU)

		// 将分片交给数据链路层处理
		if i > 0 {
			newPayload := pkt.Data.Clone(nil)
			newPayload.CapLength(innerMTU)

			//
			if err := e.linkEP.WritePacket(r, gso, ProtocolNumber, tcpip.PacketBuffer{
				Header:        pkt.Header,
				Data:          newPayload,
				NetworkHeader: buffer.View(h),
			}); err != nil {
				return err
			}

			r.Stats().IP.PacketsSent.Increment()
			pkt.Data.TrimFront(newPayload.Size())
			continue
		}

		// Special handling for the first fragment because it comes from the header.
		// 对第一个片段的特殊处理，因为它来自标头。
		if outerMTU >= pkt.Header.UsedLength() {

			// This fragment can fit all of pkt.Header and possibly some of pkt.Data, too.
			// 这个片段可以容纳所有的 pkt.Header ，也可能容纳部分的 pkt.Data 。
			newPayload := pkt.Data.Clone(nil)
			newPayloadLength := outerMTU - pkt.Header.UsedLength()
			newPayload.CapLength(newPayloadLength)

			if err := e.linkEP.WritePacket(r, gso, ProtocolNumber, tcpip.PacketBuffer{
				Header:        pkt.Header,
				Data:          newPayload,
				NetworkHeader: buffer.View(h),
			}); err != nil {
				return err
			}

			r.Stats().IP.PacketsSent.Increment()
			pkt.Data.TrimFront(newPayloadLength)
		} else {

			// The fragment is too small to fit all of pkt.Header.
			// 该片段太小，无法容纳所有的 pkt.Header 。
			startOfHdr := pkt.Header
			startOfHdr.TrimBack(pkt.Header.UsedLength() - outerMTU)
			emptyVV := buffer.NewVectorisedView(0, []buffer.View{})

			//
			if err := e.linkEP.WritePacket(r, gso, ProtocolNumber, tcpip.PacketBuffer{
				Header:        startOfHdr,
				Data:          emptyVV,
				NetworkHeader: buffer.View(h),
			}); err != nil {
				return err
			}

			r.Stats().IP.PacketsSent.Increment()

			// Add the unused bytes of pkt.Header into the pkt.Data that remains to be sent.
			// 将 pkt.Header 未使用的字节添加到待发送的 pkt.Data 中。
			restOfHdr := pkt.Header.View()[outerMTU:]
			tmp := buffer.NewVectorisedView(len(restOfHdr), []buffer.View{buffer.NewViewFromBytes(restOfHdr)})
			tmp.Append(pkt.Data)
			pkt.Data = tmp
		}
	}

	return nil
}

func (e *endpoint) addIPHeader(r *stack.Route, hdr *buffer.Prependable, payloadSize int, params stack.NetworkHeaderParams) header.IPv4 {

	// 构造 IPv4 头部
	ip := header.IPv4(hdr.Prepend(header.IPv4MinimumSize))
	// 计算总长度
	length := uint16(hdr.UsedLength() + payloadSize)
	// 包序号，用于标识 IPv4 分片
	id := uint32(0)
	if length > header.IPv4MaximumHeaderSize+8 {
		// Packets of 68 bytes or less are required by RFC 791 to not be fragmented,
		// so we only assign ids to larger packets.
		//
		// RFC 791 要求 68 个字节或更少的数据包不被分段，因此我们仅将 ID 分配给较大的数据包。
		id = atomic.AddUint32(&e.protocol.ids[hashRoute(r, params.Protocol, e.protocol.hashIV)%buckets], 1)
	}

	// IPv4 头部格式
	ip.Encode(&header.IPv4Fields{
		IHL:         header.IPv4MinimumSize, // 互联网报头长度最少为 20B
		TotalLength: length,
		ID:          uint16(id),
		TTL:         params.TTL,
		TOS:         params.TOS,
		Protocol:    uint8(params.Protocol),
		SrcAddr:     r.LocalAddress,  // 本地地址
		DstAddr:     r.RemoteAddress, // 远端地址
	})

	// 校验和
	ip.SetChecksum(^ip.CalculateChecksum())
	return ip
}

// WritePacket writes a packet to the given destination address and protocol.
//
// WritePacket 根据目标地址和协议发送数据（到链路层）。
//
// 执行步骤:
//	构造 IPv4 头部
//  若需回环处理，直接在网络层转发回协议栈
//  若需分段发送，则调用 `writePacketFragments()` 先分段、再发往链路层
//  若无需分段发送，直接发往链路层
//
func (e *endpoint) WritePacket(
	r *stack.Route, // 路由对象，包含了两个通信端点的地址信息等
	gso *stack.GSO, // 通用分段处理
	params stack.NetworkHeaderParams, // 网络层协议头参数，主要包括: 传输层协议号、TTL、TOS。
	loop stack.PacketLooping, // 回环处理标识
	pkt tcpip.PacketBuffer, // 网络层数据包
) *tcpip.Error {

	// 构造 IPv4 头部
	ip := e.addIPHeader(r, &pkt.Header, pkt.Data.Size(), params)

	// stack.PacketLoop 表示回环数据包，无需发往链路层，直接在网络层转发回协议栈。
	if loop&stack.PacketLoop != 0 {

		// 构造网络层数据包：payload = Pkt.Header + Pkt.Data
		views := make([]buffer.View, 1, 1+len(pkt.Data.Views()))
		views[0] = pkt.Header.View()
		views = append(views, pkt.Data.Views()...)

		// 回环路由
		loopedR := r.MakeLoopedRoute()

		// 直接转发给本网络层端点
		e.HandlePacket(
			&loopedR,
			tcpip.PacketBuffer{
				Data:          buffer.NewVectorisedView(len(views[0])+pkt.Data.Size(), views), // Data 存储着网络包的有效载荷。
				NetworkHeader: buffer.View(ip),                                                // NetworkHeader 存储着网络包头。
			},
		)

		// 释放路由
		loopedR.Release()
	}

	// stack.PacketOut 表示应该将数据包传递给链路层端点，如果未设置此位，则无需发往链路层。
	if loop&stack.PacketOut == 0 {
		return nil
	}

	// 如果 len(header+data) 超过 mtu 且链路层不支持 gso ，需要在网络层执行数据分段，调用 `writePacketFragments()` 发送数据包。
	if pkt.Header.UsedLength()+pkt.Data.Size() > int(e.linkEP.MTU()) && (gso == nil || gso.Type == stack.GSONone) {
		return e.writePacketFragments(r, gso, int(e.linkEP.MTU()), pkt)
	}

	// 如果无需分段，直接调用链路层端点进行发包
	if err := e.linkEP.WritePacket(r, gso, ProtocolNumber, pkt); err != nil {
		return err
	}

	// 统计发包数量
	r.Stats().IP.PacketsSent.Increment()
	return nil
}

// WritePackets implements stack.NetworkEndpoint.WritePackets.
func (e *endpoint) WritePackets(r *stack.Route, gso *stack.GSO, hdrs []stack.PacketDescriptor, payload buffer.VectorisedView, params stack.NetworkHeaderParams, loop stack.PacketLooping) (int, *tcpip.Error) {
	if loop&stack.PacketLoop != 0 {
		panic("multiple packets in local loop")
	}
	if loop&stack.PacketOut == 0 {
		return len(hdrs), nil
	}

	for i := range hdrs {
		e.addIPHeader(r, &hdrs[i].Hdr, hdrs[i].Size, params)
	}
	n, err := e.linkEP.WritePackets(r, gso, hdrs, payload, ProtocolNumber)
	r.Stats().IP.PacketsSent.IncrementBy(uint64(n))
	return n, err
}

// WriteHeaderIncludedPacket writes a packet already containing a network
// header through the given route.
func (e *endpoint) WriteHeaderIncludedPacket(r *stack.Route, loop stack.PacketLooping, pkt tcpip.PacketBuffer) *tcpip.Error {
	// The packet already has an IP header, but there are a few required
	// checks.
	ip := header.IPv4(pkt.Data.First())
	if !ip.IsValid(pkt.Data.Size()) {
		return tcpip.ErrInvalidOptionValue
	}

	// Always set the total length.
	ip.SetTotalLength(uint16(pkt.Data.Size()))

	// Set the source address when zero.
	if ip.SourceAddress() == tcpip.Address(([]byte{0, 0, 0, 0})) {
		ip.SetSourceAddress(r.LocalAddress)
	}

	// Set the destination. If the packet already included a destination,
	// it will be part of the route.
	ip.SetDestinationAddress(r.RemoteAddress)

	// Set the packet ID when zero.
	if ip.ID() == 0 {
		id := uint32(0)
		if pkt.Data.Size() > header.IPv4MaximumHeaderSize+8 {
			// Packets of 68 bytes or less are required by RFC 791 to not be
			// fragmented, so we only assign ids to larger packets.
			id = atomic.AddUint32(&e.protocol.ids[hashRoute(r, 0 /* protocol */, e.protocol.hashIV)%buckets], 1)
		}
		ip.SetID(uint16(id))
	}

	// Always set the checksum.
	ip.SetChecksum(0)
	ip.SetChecksum(^ip.CalculateChecksum())

	if loop&stack.PacketLoop != 0 {
		e.HandlePacket(r, pkt.Clone())
	}
	if loop&stack.PacketOut == 0 {
		return nil
	}

	r.Stats().IP.PacketsSent.Increment()

	ip = ip[:ip.HeaderLength()]
	pkt.Header = buffer.NewPrependableFromView(buffer.View(ip))
	pkt.Data.TrimFront(int(ip.HeaderLength()))
	return e.linkEP.WritePacket(r, nil /* gso */, ProtocolNumber, pkt)
}

// HandlePacket is called by the link layer when new ipv4 packets arrive for this endpoint.
//
// 当新的 ipv4 网络层数据包到达此端点时，链路层将调用 HandlePacket() 来处理。
//
// 执行步骤:
// 	解析 IPv4 头部和数据
// 	检查和组装 IP 分段
// 	从头部获取传输层协议号
// 	将 pkt 发给传输层处理
//
func (e *endpoint) HandlePacket(r *stack.Route, pkt tcpip.PacketBuffer) {

	// 取出 IPv4 Header
	headerView := pkt.Data.First()
	// 解析 IPv4 Header
	h := header.IPv4(headerView)
	// 合法性检查
	if !h.IsValid(pkt.Data.Size()) {
		r.Stats().IP.MalformedPacketsReceived.Increment()
		return
	}

	// 设置 pkt 的网络层头部
	pkt.NetworkHeader = headerView[:h.HeaderLength()]

	hlen := int(h.HeaderLength()) // 头部长度
	tlen := int(h.TotalLength())  // 总长度
	pkt.Data.TrimFront(hlen)      // 从 data 中移除头部
	pkt.Data.CapLength(tlen - hlen)

	// 是否有更多 IP 分段
	more := (h.Flags() & header.IPv4FlagMoreFragments) != 0

	// 检查和组装 IP 分段
	if more || h.FragmentOffset() != 0 {

		if pkt.Data.Size() == 0 {
			// Drop the packet as it's marked as a fragment but has no payload.
			// 丢弃数据包，因为它被标记为 IP 片段但没有有效负载。
			r.Stats().IP.MalformedPacketsReceived.Increment()
			r.Stats().IP.MalformedFragmentsReceived.Increment()
			return
		}

		// The packet is a fragment, let's try to reassemble it.
		// 该数据包是一个片段，让我们尝试重新组装它。

		// Drop the packet if the fragmentOffset is incorrect.
		// i.e the combination of fragmentOffset and pkt.Data.size() causes
		// a wrap around resulting in last being less than the offset.
		//
		// 如果 fragmentOffset 不正确，则丢弃该数据包。
		// 比如 fragmentOffset 和 pkt.Data.size() 的组合会导致最后一个数据包小于偏移量。
		last := h.FragmentOffset() + uint16(pkt.Data.Size()) - 1
		if last < h.FragmentOffset() {
			r.Stats().IP.MalformedPacketsReceived.Increment()
			r.Stats().IP.MalformedFragmentsReceived.Increment()
			return
		}

		// xxx
		var ready bool
		var err error
		pkt.Data, ready, err = e.fragmentation.Process(hash.IPv4FragmentHash(h), h.FragmentOffset(), last, more, pkt.Data)
		if err != nil {
			r.Stats().IP.MalformedPacketsReceived.Increment()
			r.Stats().IP.MalformedFragmentsReceived.Increment()
			return
		}

		// 尚未收到完整 IPv4 报文，则 return 。
		if !ready {
			return
		}
	}

	// 至此，收到完整的 IPv4 报文 pkt 。

	// 获取传输层协议号
	p := h.TransportProtocol()

	// 处理 ICMP 协议
	if p == header.ICMPv4ProtocolNumber {
		headerView.CapLength(hlen)
		e.handleICMP(r, pkt)
		return
	}

	r.Stats().IP.PacketsDelivered.Increment()
	// 将数据包 pkt 投递给传输层 ep 来处理。
	e.dispatcher.DeliverTransportPacket(r, p, pkt)
}

// Close cleans up resources associated with the endpoint.
func (e *endpoint) Close() {}

type protocol struct {
	ids    []uint32
	hashIV uint32

	// defaultTTL is the current default TTL for the protocol.
	// Only the uint8 portion of it is meaningful and it must be accessed atomically.
	//
	// defaultTTL 是协议的当前默认 TTL ，只有后 8bit 是有意义的，须以原子方式访问。
	defaultTTL uint32
}

// Number returns the ipv4 protocol number.
func (p *protocol) Number() tcpip.NetworkProtocolNumber {
	return ProtocolNumber
}

// MinimumPacketSize returns the minimum valid ipv4 packet size.
func (p *protocol) MinimumPacketSize() int {
	return header.IPv4MinimumSize
}

// DefaultPrefixLen returns the IPv4 default prefix length.
func (p *protocol) DefaultPrefixLen() int {
	return header.IPv4AddressSize * 8
}

// ParseAddresses implements NetworkProtocol.ParseAddresses.
func (*protocol) ParseAddresses(v buffer.View) (src, dst tcpip.Address) {
	h := header.IPv4(v)
	return h.SourceAddress(), h.DestinationAddress()
}

// SetOption implements NetworkProtocol.SetOption.
func (p *protocol) SetOption(option interface{}) *tcpip.Error {
	switch v := option.(type) {
	case tcpip.DefaultTTLOption:
		p.SetDefaultTTL(uint8(v))
		return nil
	default:
		return tcpip.ErrUnknownProtocolOption
	}
}

// Option implements NetworkProtocol.Option.
func (p *protocol) Option(option interface{}) *tcpip.Error {
	switch v := option.(type) {
	case *tcpip.DefaultTTLOption:
		*v = tcpip.DefaultTTLOption(p.DefaultTTL())
		return nil
	default:
		return tcpip.ErrUnknownProtocolOption
	}
}

// SetDefaultTTL sets the default TTL for endpoints created with this protocol.
func (p *protocol) SetDefaultTTL(ttl uint8) {
	atomic.StoreUint32(&p.defaultTTL, uint32(ttl))
}

// DefaultTTL returns the default TTL for endpoints created with this protocol.
func (p *protocol) DefaultTTL() uint8 {
	return uint8(atomic.LoadUint32(&p.defaultTTL))
}

// calculateMTU calculates the network-layer payload MTU based on the link-layer
// payload mtu.
func calculateMTU(mtu uint32) uint32 {
	if mtu > MaxTotalSize {
		mtu = MaxTotalSize
	}
	return mtu - header.IPv4MinimumSize
}

// hashRoute calculates a hash value for the given route. It uses the source &
// destination address, the transport protocol number, and a random initial
// value (generated once on initialization) to generate the hash.
func hashRoute(r *stack.Route, protocol tcpip.TransportProtocolNumber, hashIV uint32) uint32 {
	t := r.LocalAddress
	a := uint32(t[0]) | uint32(t[1])<<8 | uint32(t[2])<<16 | uint32(t[3])<<24
	t = r.RemoteAddress
	b := uint32(t[0]) | uint32(t[1])<<8 | uint32(t[2])<<16 | uint32(t[3])<<24
	return hash.Hash3Words(a, b, uint32(protocol), hashIV)
}

// NewProtocol returns an IPv4 network protocol.
// NewProtocol 返回一个 IPv4 网络协议。
func NewProtocol() stack.NetworkProtocol {

	ids := make([]uint32, buckets)

	// Randomly initialize hashIV and the ids.
	// 随机初始化 hashIV 和 ids 。
	r := hash.RandN32(1 + buckets)
	for i := range ids {
		ids[i] = r[i]
	}
	hashIV := r[buckets]

	return &protocol{ids: ids, hashIV: hashIV, defaultTTL: DefaultTTL}
}
