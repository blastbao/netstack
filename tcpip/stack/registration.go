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
	"github.com/blastbao/netstack/waiter"
)

// NetworkEndpointID is the identifier of a network layer protocol endpoint.
// Currently the local address is sufficient because all supported protocols
// (i.e., IPv4 and IPv6) have different sizes for their addresses.
//
// NetworkEndpointID 是网络层协议端点的标识符。
type NetworkEndpointID struct {
	// 本地 IP 地址
	LocalAddress tcpip.Address
}

// TransportEndpointID is the identifier of a transport layer protocol endpoint.
//
// TransportEndpointID 是传输层协议端点的标识符，<本地端口, 本地地址，远程端口，远程地址>。
//
// +stateify savable
type TransportEndpointID struct {

	// LocalPort is the local port associated with the endpoint.
	// LocalPort 是与端点相关联的本地端口。
	LocalPort uint16

	// LocalAddress is the local [network layer] address associated with the endpoint.
	// LocalAddress 是与端点相关联的本地[网络层]地址。
	LocalAddress tcpip.Address

	// RemotePort is the remote port associated with the endpoint.
	// RemotePort 是与端点相关联的远程端口。
	RemotePort uint16

	// RemoteAddress is the remote [network layer] address associated with the endpoint.
	// RemoteAddress 是与端点相关联的远程[网络层]地址。
	RemoteAddress tcpip.Address
}

// ControlType is the type of network control message.
type ControlType int

// The following are the allowed values for ControlType values.
const (
	ControlPacketTooBig ControlType = iota		// 包太大
	ControlPortUnreachable						// 端口不可达
	ControlUnknown								// 未知
)

// TransportEndpoint is the interface that needs to be implemented by transport
// protocol (e.g., tcp, udp) endpoints that can handle packets.
type TransportEndpoint interface {

	// UniqueID returns an unique ID for this transport endpoint.
	UniqueID() uint64

	// HandlePacket is called by the stack when new packets arrive to
	// this transport endpoint. It sets pkt.TransportHeader.
	// HandlePacket takes ownership of pkt.
	//
	// 当新数据包到达这个传输端点时，协议栈会调用 HandlePacket() 。
	HandlePacket(r *Route, id TransportEndpointID, pkt tcpip.PacketBuffer)

	// HandleControlPacket is called by the stack when new control (e.g. ICMP)
	// packets arrive to this transport endpoint.
	// HandleControlPacket takes ownership of pkt.
	//
	// 当新的控制报文（如 ICMP ）到达这个传输端点时，协议栈会调用 HandleControlPacket() 。
	HandleControlPacket(id TransportEndpointID, typ ControlType, extra uint32, pkt tcpip.PacketBuffer)

	// Close puts the endpoint in a closed state and frees all resources
	// associated with it. This cleanup may happen asynchronously. Wait can
	// be used to block on this asynchronous cleanup.
	Close()

	// Wait waits for any worker goroutines owned by the endpoint to stop.
	//
	// An endpoint can be requested to stop its worker goroutines by calling
	// its Close method.
	//
	// Wait will not block if the endpoint hasn't started any goroutines
	// yet, even if it might later.
	Wait()
}

// RawTransportEndpoint is the interface that needs to be implemented by raw
// transport protocol endpoints. RawTransportEndpoints receive the entire
// packet - including the network and transport headers - as delivered to
// netstack.
type RawTransportEndpoint interface {

	// HandlePacket is called by the stack when new packets arrive to
	// this transport endpoint. The packet contains all data from the link
	// layer up.
	//
	// HandlePacket takes ownership of pkt.
	HandlePacket(r *Route, pkt tcpip.PacketBuffer)
}

// PacketEndpoint is the interface that needs to be implemented by packet
// transport protocol endpoints. These endpoints receive link layer headers in
// addition to whatever they contain (usually network and transport layer
// headers and a payload).
//
// PacketEndpoint 是需要由数据包传输协议端点实现的接口。
// 这些端点除了接收它们所包含的内容（通常是网络和传输层头以及有效负载）之外，还接收链路层头。
type PacketEndpoint interface {

	// HandlePacket is called by the stack when new packets arrive that
	// match the endpoint.
	//
	// Implementers should treat packet as immutable and should copy it
	// before before modification.
	//
	// linkHeader may have a length of 0, in which case the PacketEndpoint
	// should construct its own ethernet header for applications.
	//
	// HandlePacket takes ownership of pkt.
	//
	// 当有与端点匹配的新数据包到达时，堆栈会调用 HandlePacket 。
	// 实现者应将数据包视为不可更改的，在修改前应先将其复制。
	// linkHeader 的长度可能为 0 ，在这种情况下，PacketEndpoint 应该为应用构建自己的以太网头。
	// HandlePacket 拥有 pkt 的所有权。
	HandlePacket(nicID tcpip.NICID, addr tcpip.LinkAddress, netProto tcpip.NetworkProtocolNumber, pkt tcpip.PacketBuffer)
}

// TransportProtocol is the interface that needs to be implemented by transport
// protocols (e.g., tcp, udp) that want to be part of the networking stack.
type TransportProtocol interface {
	// Number returns the transport protocol number.
	Number() tcpip.TransportProtocolNumber

	// NewEndpoint creates a new endpoint of the transport protocol.
	NewEndpoint(stack *Stack, netProto tcpip.NetworkProtocolNumber, waitQueue *waiter.Queue) (tcpip.Endpoint, *tcpip.Error)

	// NewRawEndpoint creates a new raw endpoint of the transport protocol.
	NewRawEndpoint(stack *Stack, netProto tcpip.NetworkProtocolNumber, waitQueue *waiter.Queue) (tcpip.Endpoint, *tcpip.Error)

	// MinimumPacketSize returns the minimum valid packet size of this
	// transport protocol. The stack automatically drops any packets smaller
	// than this targeted at this protocol.
	MinimumPacketSize() int

	// ParsePorts returns the source and destination ports stored in a
	// packet of this protocol.
	ParsePorts(v buffer.View) (src, dst uint16, err *tcpip.Error)

	// HandleUnknownDestinationPacket handles packets targeted at this
	// protocol but that don't match any existing endpoint. For example,
	// it is targeted at a port that have no listeners.
	//
	// The return value indicates whether the packet was well-formed (for
	// stats purposes only).
	//
	// HandleUnknownDestinationPacket takes ownership of pkt.
	HandleUnknownDestinationPacket(r *Route, id TransportEndpointID, pkt tcpip.PacketBuffer) bool

	// SetOption allows enabling/disabling protocol specific features.
	// SetOption returns an error if the option is not supported or the
	// provided option value is invalid.
	SetOption(option interface{}) *tcpip.Error

	// Option allows retrieving protocol specific option values.
	// Option returns an error if the option is not supported or the
	// provided option value is invalid.
	Option(option interface{}) *tcpip.Error
}

// TransportDispatcher contains the methods used by the network stack to deliver
// packets to the appropriate transport endpoint after it has been handled by
// the network layer.
type TransportDispatcher interface {

	// DeliverTransportPacket delivers packets to the appropriate
	// transport protocol endpoint.
	//
	// pkt.NetworkHeader must be set before calling DeliverTransportPacket.
	//
	// DeliverTransportPacket takes ownership of pkt.
	DeliverTransportPacket(r *Route, protocol tcpip.TransportProtocolNumber, pkt tcpip.PacketBuffer)

	// DeliverTransportControlPacket delivers control packets to the
	// appropriate transport protocol endpoint.
	//
	// pkt.NetworkHeader must be set before calling
	// DeliverTransportControlPacket.
	//
	// DeliverTransportControlPacket takes ownership of pkt.
	DeliverTransportControlPacket(local, remote tcpip.Address, net tcpip.NetworkProtocolNumber, trans tcpip.TransportProtocolNumber, typ ControlType, extra uint32, pkt tcpip.PacketBuffer)
}

// PacketLooping specifies where an outbound packet should be sent.
// PacketLooping 指定出站数据包应该发送到哪里。
type PacketLooping byte

const (
	// PacketOut indicates that the packet should be passed to the link endpoint.
	// PacketOut 表示应该将数据包传递给链路层端点。
	PacketOut PacketLooping = 1 << iota

	// PacketLoop indicates that the packet should be handled locally.
	// PacketLoop 表示应该在本地处理数据包。
	PacketLoop
)

// NetworkHeaderParams are the header parameters given as input by the
// transport endpoint to the network.
type NetworkHeaderParams struct {

	// Protocol refers to the transport protocol number.
	// 传输层协议号。
	Protocol tcpip.TransportProtocolNumber

	// TTL refers to Time To Live field of the IP-header.
	// 报文最大生存时间。
	TTL uint8

	// TOS refers to TypeOfService or TrafficClass field of the IP-header.
	// 服务类型，该字段描述了 IP 包的优先级和 QoS 选项。
	TOS uint8
}

// NetworkEndpoint is the interface that needs to be implemented by endpoints
// of network layer protocols (e.g., ipv4, ipv6).
//
// NetworkEndpoint 是网络层协议（如ipv4、ipv6）端点需要实现的接口。
//
// 入栈数据包 => HandlePacket()
// 出栈数据包 => WritePacket() / WritePackets()
type NetworkEndpoint interface {

	// DefaultTTL is the default time-to-live value (or hop limit, in ipv6) for this endpoint.
	DefaultTTL() uint8

	// MTU is the maximum transmission unit for this endpoint.
	// This is generally calculated as the MTU of the underlying data link
	// endpoint minus the network endpoint max header length.
	MTU() uint32

	// Capabilities returns the set of capabilities supported by the underlying link-layer endpoint.
	// Capabilities 返回底层链路层端点支持的能力集。
	Capabilities() LinkEndpointCapabilities

	// MaxHeaderLength returns the maximum size the network (and lower level layers combined) headers can have.
	// Higher levels use this information to reserve space in the front of the packets they're building.
	MaxHeaderLength() uint16

	// WritePacket writes a packet to the given destination address and protocol.
	// It sets pkt.NetworkHeader. pkt.TransportHeader must have already been set.
	//
	// WritePacket 将一个数据包写入给定的目标地址和协议。
	// 它设置了 pkt.NetworkHeader，而 pkt.TransportHeader 必须已被设置。
	WritePacket(r *Route, gso *GSO, params NetworkHeaderParams, loop PacketLooping, pkt tcpip.PacketBuffer) *tcpip.Error

	// WritePackets writes packets to the given destination address and protocol.
	WritePackets(r *Route, gso *GSO, hdrs []PacketDescriptor, payload buffer.VectorisedView, params NetworkHeaderParams, loop PacketLooping) (int, *tcpip.Error)

	// WriteHeaderIncludedPacket writes a packet that includes a network
	// header to the given destination address.
	//
	// WriteHeaderIncludedPacket 将包含网络头的数据包写入给定的目标地址。
	WriteHeaderIncludedPacket(r *Route, loop PacketLooping, pkt tcpip.PacketBuffer) *tcpip.Error

	// ID returns the network protocol endpoint ID.
	ID() *NetworkEndpointID

	// PrefixLen returns the network endpoint's subnet prefix length in bits.
	// PrefixLen 返回网络端点的子网前缀长度，单位为比特。
	PrefixLen() int

	// NICID returns the id of the NIC this endpoint belongs to.
	// NICID 返回此端点所属的 NIC id。
	NICID() tcpip.NICID

	// HandlePacket is called by the link layer when new packets arrive to
	// this network endpoint. It sets pkt.NetworkHeader.
	//
	// HandlePacket takes ownership of pkt.
	//
	// 当有新的数据包到达时，链路层会调用 HandlePacket 。
	HandlePacket(r *Route, pkt tcpip.PacketBuffer)

	// Close is called when the endpoint is reomved from a stack.
	Close()
}

// NetworkProtocol is the interface that needs to be implemented by network
// protocols (e.g., ipv4, ipv6) that want to be part of the networking stack.
type NetworkProtocol interface {

	// Number returns the network protocol number.
	Number() tcpip.NetworkProtocolNumber

	// MinimumPacketSize returns the minimum valid packet size of this
	// network protocol. The stack automatically drops any packets smaller
	// than this targeted at this protocol.
	MinimumPacketSize() int

	// DefaultPrefixLen returns the protocol's default prefix length.
	DefaultPrefixLen() int

	// ParseAddresses returns the source and destination addresses stored in a
	// packet of this protocol.
	//
	// ParseAddresses 返回存储在该协议数据包中的源地址和目的地址。
	ParseAddresses(v buffer.View) (src, dst tcpip.Address)

	// NewEndpoint creates a new endpoint of this protocol.
	// NewEndpoint 创建该协议的新端点。
	NewEndpoint(
		nicID tcpip.NICID,
		addrWithPrefix tcpip.AddressWithPrefix,
		linkAddrCache LinkAddressCache,
		dispatcher TransportDispatcher,
		sender LinkEndpoint,
	) (
		NetworkEndpoint,
		*tcpip.Error,
	)

	// SetOption allows enabling/disabling protocol specific features.
	// SetOption returns an error if the option is not supported or the
	// provided option value is invalid.
	SetOption(option interface{}) *tcpip.Error

	// Option allows retrieving protocol specific option values.
	// Option returns an error if the option is not supported or the
	// provided option value is invalid.
	Option(option interface{}) *tcpip.Error
}

// NetworkDispatcher contains the methods used by the network stack to deliver
// packets to the appropriate network endpoint after it has been handled by
// the data link layer.
//
// NetworkDispatcher 包含网络协议栈在数据链路层处理完数据包后将数据包传递到适当的网络层端点的方法。
//
type NetworkDispatcher interface {

	// DeliverNetworkPacket finds the appropriate network protocol endpoint
	// and hands the packet over for further processing.
	//
	// pkt.LinkHeader may or may not be set before calling
	// DeliverNetworkPacket. Some packets do not have link headers (e.g.
	// packets sent via loopback), and won't have the field set.
	//
	// DeliverNetworkPacket takes ownership of pkt.
	//
	// DeliverNetworkPacket 找到适当的网络层协议端点，并将数据包移交给它进一步处理。
	// 在调用 DeliverNetworkPacket 之前，可能会也可能不会设置 pkt.LinkHeader 字段。
	// 某些数据包没有数据链路层头（例如，通过环回发送的数据包），将不会设置该字段。
	// DeliverNetworkPacket 拥有 pkt 的所有权。
	DeliverNetworkPacket(linkEP LinkEndpoint, remote, local tcpip.LinkAddress, protocol tcpip.NetworkProtocolNumber, pkt tcpip.PacketBuffer)
}

// LinkEndpointCapabilities is the type associated with the capabilities
// supported by a link-layer endpoint. It is a set of bitfields.
//
// LinkEndpointCapabilities 描述链路层端点支持的功能。
type LinkEndpointCapabilities uint

// The following are the supported link endpoint capabilities.
// 以下是支持的链接层端点功能。
const (

	CapabilityNone LinkEndpointCapabilities = 0

	// CapabilityTXChecksumOffload indicates that the link endpoint supports
	// checksum computation for outgoing packets and the stack can skip
	// computing checksums when sending packets.
	//
	// CapabilityTXChecksumOffload 表示链路层端点支持对出栈数据包进行校验和计算，
	// 此时，网络层在发送数据包时可以跳过计算校验和。
	//
	// CheckSum Offload 实际上就是是将 TCP/UDP/IP 校验和工作交给了网卡硬件完成，以节约系统的 CPU 资源。
	// 譬如：以太网发送网卡计算以太网 CRC32 校验和，接收网卡验证这个校验和。如果接收到的校验和错误，网卡会在内部丢弃数据包。
	CapabilityTXChecksumOffload LinkEndpointCapabilities = 1 << iota


	// CapabilityRXChecksumOffload indicates that the link endpoint supports
	// checksum verification on received packets and that it's safe for the
	// stack to skip checksum verification.
	//
	// CapabilityRXChecksumOffload 表示链路层端点支持对接收到的数据包进行校验和验证，对于协议栈而言，跳过校验和验证是安全的。
	CapabilityRXChecksumOffload

	CapabilityResolutionRequired
	CapabilitySaveRestore
	CapabilityDisconnectOk
	CapabilityLoopback
	CapabilityHardwareGSO

	// CapabilitySoftwareGSO indicates the link endpoint supports of sending
	// multiple packets using a single call (LinkEndpoint.WritePackets).
	//
	// CapabilitySoftwareGSO 表示链接端点支持使用单个调用发送多个数据包（ LinkEndpoint.WritePackets ）。
	CapabilitySoftwareGSO
)


// LinkEndpoint is the interface implemented by data link layer protocols (e.g.,
// ethernet, loopback, raw) and used by network layer protocols to send packets
// out through the implementer's data link endpoint.
//
// When a link header exists, it sets each tcpip.PacketBuffer's LinkHeader field
// before passing it up the stack.
//
//
// LinkEndpoint 是由数据链路层协议（例如，以太网，环回，原始）实现的接口，被网络层协议用来发送数据包到关联的数据链路层。
//
// 当数据链接层报头存在时，在将数据传递到协议栈之前要设置每个 tcpip.PacketBuffer 的 LinkHeader 字段。
//
type LinkEndpoint interface {

	// MTU is the maximum transmission unit for this endpoint. This is
	// usually dictated by the backing physical network; when such a
	// physical network doesn't exist, the limit is generally 64k, which
	// includes the maximum size of an IP packet.
	//
	// MTU 是此端点的最大传输单元。
	// MTU 通常由支持的物理网络决定；当物理网络不存在时，限制通常为 64k ，其中包括 IP 数据包的最大大小。
	MTU() uint32

	// Capabilities returns the set of capabilities supported by the endpoint.
	//
	// Capabilities 返回端点支持的功能集。
	Capabilities() LinkEndpointCapabilities

	// MaxHeaderLength returns the maximum size the data link (and
	// lower level layers combined) headers can have. Higher levels use this
	// information to reserve space in the front of the packets they're
	// building.
	//
	// MaxHeaderLength 返回数据链接层报头的最大大小。
	// 高层协议使用此信息在正在构建的数据包的前面保留空间。
	MaxHeaderLength() uint16


	// LinkAddress returns the link address (typically a MAC) of the link endpoint.
	//
	// LinkAddress 返回链路层端点的链路层地址（通常为MAC）。
	LinkAddress() tcpip.LinkAddress


	// WritePacket writes a packet with the given protocol through the
	// given route. It sets pkt.LinkHeader if a link layer header exists.
	// pkt.NetworkHeader and pkt.TransportHeader must have already been
	// set.
	//
	// To participate in transparent bridging, a LinkEndpoint implementation
	// should call eth.Encode with header.EthernetFields.SrcAddr set to
	// r.LocalLinkAddress if it is provided.
	//
	//
	// WritePacket 通过给定的路由写入指定协议的数据包。
	// 如果存在数据链接层头，则需设置 pkt.LinkHeader ，而 pkt.NetworkHeader 和 pkt.TransportHeader 必须被设置。
	//
	// 要参与透明桥接，实现 LinkEndpoint 接口的对象应调用 eth.Encode 并将 header.EthernetFields.SrcAddr 设置
	// 为 r.LocalLinkAddress（如果已提供）。
	WritePacket(r *Route, gso *GSO, protocol tcpip.NetworkProtocolNumber, pkt tcpip.PacketBuffer) *tcpip.Error



	// WritePackets writes packets with the given protocol through the
	// given route.
	//
	// Right now, WritePackets is used only when the software segmentation
	// offload is enabled. If it will be used for something else, it may
	// require to change syscall filters.
	//
	// WritePackets 通过给定的路由写入指定协议的数据包。
	// 现在，仅在启用软件分段卸载时才使用 WritePackets 。
	// 如果将其用于其他用途，则可能需要更改 syscall filters 。
	WritePackets(r *Route, gso *GSO, hdrs []PacketDescriptor, payload buffer.VectorisedView, protocol tcpip.NetworkProtocolNumber) (int, *tcpip.Error)



	// WriteRawPacket writes a packet directly to the link.
	// The packet should already have an ethernet header.
	//
	// WriteRawPacket 直接向数据链路层写入一个数据包。该数据包已经添加以太网头。
	WriteRawPacket(vv buffer.VectorisedView) *tcpip.Error


	// Attach attaches the data link layer endpoint to the network-layer
	// dispatcher of the stack.
	//
	// Attach 将数据链路层端点连接到协议栈的网络层调度器。
	Attach(dispatcher NetworkDispatcher)


	// IsAttached returns whether a NetworkDispatcher is attached to the
	// endpoint.
	//
	// IsAttached 返回 NetworkDispatcher 是否连接到端点。
	IsAttached() bool


	// Wait waits for any worker goroutines owned by the endpoint to stop.
	//
	// For now, requesting that an endpoint's worker goroutine(s) stop is
	// implementation specific.
	//
	// Wait will not block if the endpoint hasn't started any goroutines
	// yet, even if it might later.
	//
	//
	// Wait 等待端点拥有的任何 worker goroutines 停止。
	//
	// 目前，要求端点的 worker goroutine 停止是特定的实现。
	//
	// 如果端点还没有启动任何 goroutine ，即使以后可能会启动，Wait 也不会阻塞。
	Wait()
}



// InjectableLinkEndpoint is a LinkEndpoint where inbound packets are
// delivered via the Inject method.
type InjectableLinkEndpoint interface {

	LinkEndpoint


	// InjectInbound injects an inbound packet.
	InjectInbound(protocol tcpip.NetworkProtocolNumber, pkt tcpip.PacketBuffer)


	// InjectOutbound writes a fully formed outbound packet directly to the link.
	//
	// dest is used by endpoints with multiple raw destinations.
	InjectOutbound(dest tcpip.Address, packet []byte) *tcpip.Error


}

// A LinkAddressResolver is an extension to a NetworkProtocol that
// can resolve link addresses.
//
// LinkAddressResolver 是 NetworkProtocol 的扩展，可以解析链接地址。
type LinkAddressResolver interface {

	// LinkAddressRequest sends a request for the LinkAddress of addr.
	// The request is sent on linkEP with localAddr as the source.
	//
	// A valid response will cause the discovery protocol's network
	// endpoint to call AddLinkAddress.
	//
	// LinkAddressRequest 发送对 addr 的 LinkAddress 的请求。
	// 该请求在 linkEP 上发送，以 localAddr 作为源。
	LinkAddressRequest(addr, localAddr tcpip.Address, linkEP LinkEndpoint) *tcpip.Error

	// ResolveStaticAddress attempts to resolve address without sending
	// requests. It either resolves the name immediately or returns the
	// empty LinkAddress.
	//
	// It can be used to resolve broadcast addresses for example.
	//
	// ResolveStaticAddress 尝试在不发送请求的情况下解析地址。它要么立即解析名称，要么返回空的 LinkAddress 。
	// 例如，它可以用于解析广播地址。
	ResolveStaticAddress(addr tcpip.Address) (tcpip.LinkAddress, bool)

	// LinkAddressProtocol returns the network protocol of the
	// addresses this this resolver can resolve.
	//
	// LinkAddressProtocol 返回此解析器可以解析的网络协议。
	LinkAddressProtocol() tcpip.NetworkProtocolNumber
}

// A LinkAddressCache caches link addresses.
// LinkAddressCache 会缓存链路层地址。
type LinkAddressCache interface {


	// CheckLocalAddress determines if the given local address exists, and if it does not exist.
	// 确定给定的本地地址是否存在。
	CheckLocalAddress(nicID tcpip.NICID, protocol tcpip.NetworkProtocolNumber, addr tcpip.Address) tcpip.NICID


	// AddLinkAddress adds a link address to the cache.
	// 在缓存中添加一个链接地址。
	AddLinkAddress(nicID tcpip.NICID, addr tcpip.Address, linkAddr tcpip.LinkAddress)


	// GetLinkAddress looks up the cache to translate address to link address (e.g. IP -> MAC).
	// If the LinkEndpoint requests address resolution and there is a LinkAddressResolver
	// registered with the network protocol, the cache attempts to resolve the address
	// and returns ErrWouldBlock. Waker is notified when address resolution is
	// complete (success or not).
	//
	// If address resolution is required, ErrNoLinkAddress and a notification channel is
	// returned for the top level caller to block. Channel is closed once address resolution
	// is complete (success or not).
	//
	//
	// GetLinkAddress 查找缓存，以将地址翻译成链路地址（如 IP->MAC ）。
	//
	// 如果链路层端点 LinkEndpoint 请求地址解析，并且有一个 LinkAddressResolver 在网络协议中注册，
	// 缓存会尝试解析地址并返回 ErrWouldBlock 。当地址解析完成时（成功或失败），Waker 会得到通知。
	//
	// 如果需要地址解析，则返回 ErrNoLinkAddress 和一个通知通道，供调用者阻塞式等待，在地址解析完成后（无论成功与否），通道即被关闭。
	GetLinkAddress(
		nicID tcpip.NICID,
		addr, localAddr tcpip.Address,
		protocol tcpip.NetworkProtocolNumber,
		w *sleep.Waker,
	) (tcpip.LinkAddress, <-chan struct{}, *tcpip.Error)


	// RemoveWaker removes a waker that has been added in GetLinkAddress().
	//
	// 删除一个在 GetLinkAddress() 中添加的 waker 。
	RemoveWaker(nicID tcpip.NICID, addr tcpip.Address, waker *sleep.Waker)
}

// RawFactory produces endpoints for writing various types of raw packets.
type RawFactory interface {
	// NewUnassociatedEndpoint produces endpoints for writing packets not
	// associated with a particular transport protocol. Such endpoints can
	// be used to write arbitrary packets that include the network header.
	NewUnassociatedEndpoint(stack *Stack, netProto tcpip.NetworkProtocolNumber, transProto tcpip.TransportProtocolNumber, waiterQueue *waiter.Queue) (tcpip.Endpoint, *tcpip.Error)

	// NewPacketEndpoint produces endpoints for reading and writing packets
	// that include network and (when cooked is false) link layer headers.
	NewPacketEndpoint(stack *Stack, cooked bool, netProto tcpip.NetworkProtocolNumber, waiterQueue *waiter.Queue) (tcpip.Endpoint, *tcpip.Error)
}

// GSOType is the type of GSO segments.
//
// +stateify savable
type GSOType int

// Types of gso segments.
const (
	GSONone GSOType = iota

	// Hardware GSO types:
	GSOTCPv4
	GSOTCPv6

	// GSOSW is used for software GSO segments which have to be sent by
	// endpoint.WritePackets.
	GSOSW
)

// GSO contains generic segmentation offload properties.
//
// +stateify savable
type GSO struct {
	// Type is one of GSONone, GSOTCPv4, etc.
	Type GSOType
	// NeedsCsum is set if the checksum offload is enabled.
	NeedsCsum bool
	// CsumOffset is offset after that to place checksum.
	CsumOffset uint16

	// Mss is maximum segment size.
	MSS uint16
	// L3Len is L3 (IP) header length.
	L3HdrLen uint16

	// MaxSize is maximum GSO packet size.
	MaxSize uint32
}

// GSOEndpoint provides access to GSO properties.
type GSOEndpoint interface {
	// GSOMaxSize returns the maximum GSO packet size.
	GSOMaxSize() uint32
}

// SoftwareGSOMaxSize is a maximum allowed size of a software GSO segment.
// This isn't a hard limit, because it is never set into packet headers.
const SoftwareGSOMaxSize = (1 << 16)
