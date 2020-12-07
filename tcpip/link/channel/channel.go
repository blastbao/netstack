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

// Package channel provides the implemention of channel-based data-link layer
// endpoints. Such endpoints allow injection of inbound packets and store
// outbound packets in a channel.
package channel

import (
	"github.com/blastbao/netstack/tcpip"
	"github.com/blastbao/netstack/tcpip/buffer"
	"github.com/blastbao/netstack/tcpip/stack"
)


// PacketInfo holds all the information about an outbound packet.
// PacketInfo 保存了出栈数据包的所有信息。
type PacketInfo struct {
	Pkt   tcpip.PacketBuffer
	Proto tcpip.NetworkProtocolNumber
	GSO   *stack.GSO
}


// Endpoint is link layer endpoint that stores outbound packets in a channel
// and allows injection of inbound packets.
type Endpoint struct {
	dispatcher stack.NetworkDispatcher
	mtu        uint32
	linkAddr   tcpip.LinkAddress
	GSO        bool

	// C is where outbound packets are queued.
	C chan PacketInfo
}

// New creates a new channel endpoint.
func New(size int, mtu uint32, linkAddr tcpip.LinkAddress) *Endpoint {
	return &Endpoint{
		C:        make(chan PacketInfo, size),
		mtu:      mtu,
		linkAddr: linkAddr,
	}
}


// Drain removes all outbound packets from the channel and counts them.
// Drain 将所有出栈数据包从管道 e.C 中移除。
func (e *Endpoint) Drain() int {
	c := 0
	for {
		select {
		case <-e.C:
			c++
		default:
			return c
		}
	}
}

// InjectInbound injects an inbound packet.
// InjectInbound 注入一个入栈数据包。
func (e *Endpoint) InjectInbound(protocol tcpip.NetworkProtocolNumber, pkt tcpip.PacketBuffer) {
	e.InjectLinkAddr(protocol, "", pkt)
}

// InjectLinkAddr injects an inbound packet with a remote link address.
// InjectLinkAddr 注入一个带有远端 MAC 地址的入栈数据包。
func (e *Endpoint) InjectLinkAddr(protocol tcpip.NetworkProtocolNumber, remote tcpip.LinkAddress, pkt tcpip.PacketBuffer) {
	e.dispatcher.DeliverNetworkPacket(e, remote, "" /* local */, protocol, pkt)
}

// Attach saves the stack network-layer dispatcher for use later when packets are injected.
// Attach 将协议栈的网络层调度器保存下来，以便以后注入数据包时使用。
func (e *Endpoint) Attach(dispatcher stack.NetworkDispatcher) {
	e.dispatcher = dispatcher
}

// IsAttached implements stack.LinkEndpoint.IsAttached.
func (e *Endpoint) IsAttached() bool {
	return e.dispatcher != nil
}

// MTU implements stack.LinkEndpoint.MTU. It returns the value initialized
// during construction.
func (e *Endpoint) MTU() uint32 {
	return e.mtu
}

// Capabilities implements stack.LinkEndpoint.Capabilities.
func (e *Endpoint) Capabilities() stack.LinkEndpointCapabilities {
	caps := stack.LinkEndpointCapabilities(0)
	if e.GSO {
		caps |= stack.CapabilityHardwareGSO
	}
	return caps
}

// GSOMaxSize returns the maximum GSO packet size.
func (*Endpoint) GSOMaxSize() uint32 {
	return 1 << 15
}

// MaxHeaderLength returns the maximum size of the link layer header. Given it
// doesn't have a header, it just returns 0.
func (*Endpoint) MaxHeaderLength() uint16 {
	return 0
}

// LinkAddress returns the link address of this endpoint.
func (e *Endpoint) LinkAddress() tcpip.LinkAddress {
	return e.linkAddr
}

// WritePacket stores outbound packets into the channel.
func (e *Endpoint) WritePacket(_ *stack.Route, gso *stack.GSO, protocol tcpip.NetworkProtocolNumber, pkt tcpip.PacketBuffer) *tcpip.Error {

	// 构造链路层 Pkt
	p := PacketInfo{
		// 网络层 Pkt
		Pkt:   pkt,
		// 网络层协议号
		Proto: protocol,
		// 通用分段
		GSO:   gso,
	}

	// 将 Pkt 发送到管道 e.C 中
	select {
	case e.C <- p:
	default:
	}

	return nil
}

// WritePackets stores outbound packets into the channel.
// WritePackets 将出站数据包存储到管道 e.C 中。
func (e *Endpoint) WritePackets(
	_ *stack.Route,
	gso *stack.GSO,
	hdrs []stack.PacketDescriptor,
	payload buffer.VectorisedView,
	protocol tcpip.NetworkProtocolNumber,
) (
	int,
	*tcpip.Error,
) {

	payloadView := payload.ToView()
	n := 0

	packetLoop:
	for _, hdr := range hdrs {

		off := hdr.Off
		size := hdr.Size

		// 构造链路层 Pkt
		p := PacketInfo{
			// 网络层 Pkt
			Pkt: tcpip.PacketBuffer{
				Header: hdr.Hdr,
				Data:   buffer.NewViewFromBytes(payloadView[off : off+size]).ToVectorisedView(),
			},
			// 网络层协议号
			Proto: protocol,
			// 通用分段
			GSO:   gso,
		}

		// 将 Pkt 发送到管道，若阻塞则停止发送(break)。
		select {
		case e.C <- p:
			n++
		default:
			break packetLoop
		}
	}

	// 返回发送的 pkt 总数
	return n, nil
}

// WriteRawPacket implements stack.LinkEndpoint.WriteRawPacket.
func (e *Endpoint) WriteRawPacket(vv buffer.VectorisedView) *tcpip.Error {

	// 构造链路层 Pkt
	p := PacketInfo{
		// 网络层 Pkt
		Pkt:   tcpip.PacketBuffer{Data: vv},
		// 网络层协议号
		Proto: 0,
		// 通用分段
		GSO:   nil,
	}

	// 将 Pkt 发送到管道 e.C 中
	select {
	case e.C <- p:
	default:
	}

	return nil
}

// Wait implements stack.LinkEndpoint.Wait.
func (*Endpoint) Wait() {}
