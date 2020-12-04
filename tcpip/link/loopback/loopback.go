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

// Package loopback provides the implemention of loopback data-link layer
// endpoints. Such endpoints just turn outbound packets into inbound ones.
//
// Loopback endpoints can be used in the networking stack by calling New() to
// create a new endpoint, and then passing it as an argument to
// Stack.CreateNIC().
package loopback

import (
	"github.com/blastbao/netstack/tcpip"
	"github.com/blastbao/netstack/tcpip/buffer"
	"github.com/blastbao/netstack/tcpip/header"
	"github.com/blastbao/netstack/tcpip/stack"
)

type endpoint struct {
	dispatcher stack.NetworkDispatcher
}

// New creates a new loopback endpoint.
// This link-layer endpoint just turns outbound packets into inbound packets.
//
// New 创建一个新的回环端点，该端点把出站数据包变成入站数据包。
func New() stack.LinkEndpoint {
	return &endpoint{}
}

// Attach implements stack.LinkEndpoint.Attach.
// It just saves the stack network-layer dispatcher for later use when packets need to be dispatched.
//
// Attach 实现 stack.LinkEndpoint.Attach 。
// 它只是将协议栈网络层调度器保存下来，以便以后需要分发数据包时使用。
func (e *endpoint) Attach(dispatcher stack.NetworkDispatcher) {
	e.dispatcher = dispatcher
}

// IsAttached implements stack.LinkEndpoint.IsAttached.
//
// IsAttached 实现 stack.LinkEndpoint.IsAttached 。
func (e *endpoint) IsAttached() bool {
	return e.dispatcher != nil
}

// MTU implements stack.LinkEndpoint.MTU.
// It returns a constant that matches the linux loopback interface.
//
// 它返回一个与 linux loopback 接口匹配的常量。
func (*endpoint) MTU() uint32 {
	return 65536
}

// Capabilities implements stack.LinkEndpoint.Capabilities.
// Loopback advertises itself as supporting checksum offload, but in reality it's just omitted.
//
func (*endpoint) Capabilities() stack.LinkEndpointCapabilities {
	return stack.CapabilityRXChecksumOffload |
		   stack.CapabilityTXChecksumOffload |
		   stack.CapabilitySaveRestore |
		   stack.CapabilityLoopback
}

// MaxHeaderLength implements stack.LinkEndpoint.MaxHeaderLength.
// Given that the loopback interface doesn't have a header, it just returns 0.
//
// 鉴于 loopback 接口没有报头，返回 0 。
func (*endpoint) MaxHeaderLength() uint16 {
	return 0
}

// LinkAddress returns the link address of this endpoint.
//
// 返回本端点的 MAC 地址。
func (*endpoint) LinkAddress() tcpip.LinkAddress {
	return ""
}

// Wait implements stack.LinkEndpoint.Wait.
func (*endpoint) Wait() {}

// WritePacket implements stack.LinkEndpoint.WritePacket.
// It delivers outbound packets to the network-layer dispatcher.
//
// 将出站数据包传递到网络层调度程序。
func (e *endpoint) WritePacket(
	_ *stack.Route,
	_ *stack.GSO,
	protocol tcpip.NetworkProtocolNumber,
	pkt tcpip.PacketBuffer,
) *tcpip.Error {

	// 构造 Pkg 数据包
	views := make([]buffer.View, 1, 1+len(pkt.Data.Views()))
	views[0] = pkt.Header.View()	// 设置 Header
	views = append(views, pkt.Data.Views()...) // 设置 Payload


	// Because we're immediately turning around and writing the packet back to the rx path,
	// we intentionally don't preserve the remote and local link addresses from the stack.Route we're passed.
	//
	//
	// 因为我们会立即转过来并将数据包写回到rx路径，所以我们故意不保留堆栈中的远程和本地 Mac 地址。

	e.dispatcher.DeliverNetworkPacket(
		e,
		"" /* remote */,
		"" /* local */,
		protocol,
		tcpip.PacketBuffer{
			Data: buffer.NewVectorisedView(len(views[0])+pkt.Data.Size(), views),
		},
	)

	return nil
}

// WritePackets implements stack.LinkEndpoint.WritePackets.
func (e *endpoint) WritePackets(_ *stack.Route, _ *stack.GSO, hdrs []stack.PacketDescriptor, payload buffer.VectorisedView, protocol tcpip.NetworkProtocolNumber) (int, *tcpip.Error) {
	panic("not implemented")
}

// WriteRawPacket implements stack.LinkEndpoint.WriteRawPacket.
func (e *endpoint) WriteRawPacket(vv buffer.VectorisedView) *tcpip.Error {

	// Reject the packet if it's shorter than an ethernet header.
	// 如果数据包比以太网帧头短，则拒绝它。
	if vv.Size() < header.EthernetMinimumSize {
		return tcpip.ErrBadAddress
	}

	// There should be an ethernet header at the beginning of vv.
	// vv 包含以太网帧头，去除该头。
	linkHeader := header.Ethernet(vv.First()[:header.EthernetMinimumSize])
	vv.TrimFront(len(linkHeader))

	// 分发数据包
	e.dispatcher.DeliverNetworkPacket(e, "" /* remote */, "" /* local */, linkHeader.Type(), tcpip.PacketBuffer{
		Data:       vv,
		LinkHeader: buffer.View(linkHeader),
	})

	return nil
}
