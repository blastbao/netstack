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
	"strings"
	"sync"
	"sync/atomic"

	"github.com/blastbao/netstack/tcpip"
	"github.com/blastbao/netstack/tcpip/buffer"
	"github.com/blastbao/netstack/tcpip/header"
)

// NIC represents a "network interface card" to which the networking stack is attached.
//
// NIC 代表网络协议栈所连接的网卡。
type NIC struct {
	// 协议栈
	stack *Stack
	// 网卡ID
	id tcpip.NICID
	// 网卡名称
	name string
	//
	linkEP   LinkEndpoint
	loopback bool

	mu sync.RWMutex

	// ARP 欺骗
	spoofing bool
	// 混杂模式: 指网卡能够接收所有经过它的数据流，而不论其目的地址是否是它。
	promiscuous bool

	//
	primary map[tcpip.NetworkProtocolNumber][]*referencedNetworkEndpoint

	// endpoints 中保存了与此 NIC 关联的所有地址 (primary and non-primary) 。
	endpoints map[NetworkEndpointID]*referencedNetworkEndpoint

	//
	addressRanges []tcpip.Subnet


	mcastJoins map[NetworkEndpointID]int32


	// packetEPs is protected by mu, but the contained PacketEndpoint values are not.
	// packetEPs 受 mu 保护，但包含的 PacketEndpoint 不受保护。
	//
	// packetEPs 中保存了监听本网卡上指定网络协议号的网络层端点，
	// 当本网卡收到该网络协议号上的数据包时，会回调各个监听端点提供的 HandlePacket() 来处理。
	packetEPs map[tcpip.NetworkProtocolNumber][]PacketEndpoint


	stats NICStats


	// ndp is the NDP related state for NIC.
	// Note, read and write operations on ndp require that the NIC is appropriately locked.
	ndp ndpState
}

// NICStats includes transmitted and received stats.
type NICStats struct {
	// 传出
	Tx DirectionStats
	// 接收
	Rx DirectionStats
}

// DirectionStats includes packet and byte counts.
type DirectionStats struct {
	// 包数
	Packets *tcpip.StatCounter
	// 字节数
	Bytes *tcpip.StatCounter
}

// PrimaryEndpointBehavior is an enumeration of an endpoint's primacy behavior.
// PrimaryEndpointBehavior 是端点首要行为的枚举。
type PrimaryEndpointBehavior int

const (

	// CanBePrimaryEndpoint indicates the endpoint can be used as a primary
	// endpoint for new connections with no local address. This is the
	// default when calling NIC.AddAddress.
	//
	// CanBePrimaryEndpoint 表示端点可以作为主端点。
	// 当调用 NIC.AddAddress 时，这是默认值。
	CanBePrimaryEndpoint PrimaryEndpointBehavior = iota

	// FirstPrimaryEndpoint indicates the endpoint should be the first
	// primary endpoint considered. If there are multiple endpoints with
	// this behavior, the most recently-added one will be first.
	///
	//
	// FirstPrimaryEndpoint 表示该端点应该是考虑的第一个主要端点。
	// 如果有多个端点具有这种行为，则最近添加的端点将是第一个。
	FirstPrimaryEndpoint

	// NeverPrimaryEndpoint indicates the endpoint should never be a primary endpoint.
	//
	// NeverPrimaryEndpoint 表示该端点永远不应成为主要端点。
	NeverPrimaryEndpoint
)

// newNIC returns a new NIC using the default NDP configurations from stack.
// newNIC 使用协议栈中的默认 ND P配置创建新的 NIC 。
func newNIC(stack *Stack, id tcpip.NICID, name string, ep LinkEndpoint, loopback bool) *NIC {

	// TODO(b/141011931): Validate a LinkEndpoint (ep) is valid. For
	// example, make sure that the link address it provides is a valid
	// unicast ethernet address.
	//
	// 例如，确保它提供的链路地址是一个有效的单播以太网地址。

	// TODO(b/143357959): RFC 8200 section 5 requires that IPv6 endpoints
	// observe an MTU of at least 1280 bytes. Ensure that this requirement
	// of IPv6 is supported on this endpoint's LinkEndpoint.
	//
	// 遵守至少 1280 字节的 MTU 。
	// 确保该端点的 LinkEndpoint 上支持 IPv6 的这一要求。

	nic := &NIC{
		stack:      stack,
		id:         id,
		name:       name,
		linkEP:     ep,
		loopback:   loopback,
		primary:    make(map[tcpip.NetworkProtocolNumber][]*referencedNetworkEndpoint),
		endpoints:  make(map[NetworkEndpointID]*referencedNetworkEndpoint),
		mcastJoins: make(map[NetworkEndpointID]int32),
		packetEPs:  make(map[tcpip.NetworkProtocolNumber][]PacketEndpoint),
		stats: NICStats{
			Tx: DirectionStats{
				Packets: &tcpip.StatCounter{},
				Bytes:   &tcpip.StatCounter{},
			},
			Rx: DirectionStats{
				Packets: &tcpip.StatCounter{},
				Bytes:   &tcpip.StatCounter{},
			},
		},
		ndp: ndpState{
			configs:        stack.ndpConfigs,
			dad:            make(map[tcpip.Address]dadState),
			defaultRouters: make(map[tcpip.Address]defaultRouterState),
			onLinkPrefixes: make(map[tcpip.Subnet]onLinkPrefixState),
		},
	}

	nic.ndp.nic = nic

	// Register supported packet endpoint protocols.
	for _, netProto := range header.Ethertypes {
		nic.packetEPs[netProto] = []PacketEndpoint{}
	}

	// 遍历协议栈支持的所有网络层协议
	for _, netProto := range stack.networkProtocols {
		nic.packetEPs[netProto.Number()] = []PacketEndpoint{}
	}

	return nic
}

// enable enables the NIC.
// enable will attach the link to its LinkEndpoint and join the IPv6 All-Nodes Multicast address (ff02::1).
//
// enable 将把链接附加到其 LinkEndpoint 并加入 IPv6 All-Nodes 多播地址(ff02::1)。
func (n *NIC) enable() *tcpip.Error {

	n.attachLinkEndpoint()

	// Create an endpoint to receive broadcast packets on this interface.
	//
	// 创建一个端点，以便在此接口上接收 IPv4 广播数据包。
	if _, ok := n.stack.networkProtocols[header.IPv4ProtocolNumber]; ok {

		// 将新地址添加到网卡 n 中，这样便能接收发往该地址的数据包。
		if err := n.AddAddress(
			tcpip.ProtocolAddress{ // 协议地址
				Protocol: header.IPv4ProtocolNumber, // IPv4 协议号，0x0800
				AddressWithPrefix: tcpip.AddressWithPrefix{
								header.IPv4Broadcast,       // IPv4 广播地址，0xFF 0xFF 0xFF 0xFF
								8 * header.IPv4AddressSize, // IPv4 地址长度，以 bit 为单位
								   },
			},
			NeverPrimaryEndpoint,
		); err != nil {
			return err
		}
	}

	// Join the IPv6 All-Nodes Multicast group if the stack is configured to
	// use IPv6. This is required to ensure that this node properly receives
	// and responds to the various NDP messages that are destined to the
	// all-nodes multicast address. An example is the Neighbor Advertisement
	// when we perform Duplicate Address Detection, or Router Advertisement
	// when we do Router Discovery. See RFC 4862, section 5.4.2 and RFC 4861
	// section 4.2 for more information.
	//
	// Also auto-generate an IPv6 link-local address based on the NIC's
	// link address if it is configured to do so. Note, each interface is
	// required to have IPv6 link-local unicast address, as per RFC 4291
	// section 2.1.

	_, ok := n.stack.networkProtocols[header.IPv6ProtocolNumber]
	if !ok {
		return nil
	}

	n.mu.Lock()
	defer n.mu.Unlock()

	if err := n.joinGroupLocked(header.IPv6ProtocolNumber, header.IPv6AllNodesMulticastAddress); err != nil {
		return err
	}

	if !n.stack.autoGenIPv6LinkLocal {
		return nil
	}

	l2addr := n.linkEP.LinkAddress()

	// Only attempt to generate the link-local address if we have a valid MAC address.
	//
	// TODO(b/141011931): Validate a LinkEndpoint's link address (provided by LinkEndpoint.LinkAddress) before reaching this point.
	//
	// 只有当我们有一个有效的 MAC 地址时，才会尝试生成 link-local 地址。
	// TODO(b/141011931): 在到达此处前，请验证 LinkEndpoint 的链接地址（由LinkEndpoint.LinkAddress提供）。
	if !header.IsValidUnicastEthernetAddress(l2addr) {
		return nil
	}

	//
	addr := header.LinkLocalAddr(l2addr)

	//
	_, err := n.addPermanentAddressLocked(
		tcpip.ProtocolAddress{
			Protocol: header.IPv6ProtocolNumber,
			AddressWithPrefix: tcpip.AddressWithPrefix{
				Address:   addr,
				PrefixLen: header.IPv6LinkLocalPrefix.PrefixLen,
			},
		},
		CanBePrimaryEndpoint,
	)

	return err
}

// attachLinkEndpoint attaches the NIC to the endpoint, which will enable it to start delivering packets.
// attachLinkEndpoint 将 NIC 附加到链路层端点，使其能够开始传递数据包。
func (n *NIC) attachLinkEndpoint() {
	n.linkEP.Attach(n)
}

// setPromiscuousMode enables or disables promiscuous mode.
func (n *NIC) setPromiscuousMode(enable bool) {
	n.mu.Lock()
	n.promiscuous = enable
	n.mu.Unlock()
}

func (n *NIC) isPromiscuousMode() bool {
	n.mu.RLock()
	rv := n.promiscuous
	n.mu.RUnlock()
	return rv
}

// setSpoofing enables or disables address spoofing.
func (n *NIC) setSpoofing(enable bool) {
	n.mu.Lock()
	n.spoofing = enable
	n.mu.Unlock()
}

// primaryEndpoint returns the primary endpoint of n for the given network protocol.
//
// primaryEndpoint 返回本网卡上指定网络协议号 protocol 的主端点。
func (n *NIC) primaryEndpoint(protocol tcpip.NetworkProtocolNumber) *referencedNetworkEndpoint {

	n.mu.RLock()
	defer n.mu.RUnlock()

	// 根据网络协议号，获取关联的所有主端点，遍历这些主端点。
	for _, r := range n.primary[protocol] {
		// 如果当前端点可以用于对外发包，则返回它。
		if r.isValidForOutgoing() && r.tryIncRef() {
			return r
		}
	}

	return nil
}



// 根据网络层协议号和目标地址，获取网络端点的引用
func (n *NIC) getRef(protocol tcpip.NetworkProtocolNumber, dst tcpip.Address) *referencedNetworkEndpoint {
	return n.getRefOrCreateTemp(protocol, dst, CanBePrimaryEndpoint, n.promiscuous)
}




// findEndpoint finds the endpoint, if any, with the given address.
//
// findEndpoint 查找具有给定地址 address 的端点（如果有）。
func (n *NIC) findEndpoint(protocol tcpip.NetworkProtocolNumber, address tcpip.Address, peb PrimaryEndpointBehavior) *referencedNetworkEndpoint {
	return n.getRefOrCreateTemp(protocol, address, peb, n.spoofing)
}




// getRefEpOrCreateTemp returns the referenced network endpoint for the given
// protocol and address. If none exists a temporary one may be created if
// we are in promiscuous mode or spoofing.
//
// getRefEpOrCreateTemp 返回给定协议和地址的引用网络端点。
// 如果不存在，在我们处于混杂模式或欺骗的情况下，可能会创建一个临时的。
func (n *NIC) getRefOrCreateTemp(
	protocol tcpip.NetworkProtocolNumber, // 网络层协议号
	address tcpip.Address, // 地址
	peb PrimaryEndpointBehavior, //
	spoofingOrPromiscuous bool, // 地址欺诈 or 地址混杂
) *referencedNetworkEndpoint {

	// 网络层协议端点的标识符
	id := NetworkEndpointID{address}

	n.mu.RLock()

	// 根据 id 获取网络层端点。
	if ref, ok := n.endpoints[id]; ok {

		// An endpoint with this id exists, check if it can be used and return it.
		// 存在一个具有这个 id 的端点，检查是否可以使用并返回。

		switch ref.getKind() {
		case permanentExpired:
			if !spoofingOrPromiscuous {
				n.mu.RUnlock()
				return nil
			}
			fallthrough
		case temporary, permanent:
			// 增加引用计数，若成功，返回 ref 。
			if ref.tryIncRef() {
				n.mu.RUnlock()
				return ref
			}
		}

	}

	// A usable reference was not found, create a temporary one if requested by
	// the caller or if the address is found in the NIC's subnets.
	//
	// 找不到可用的引用，如果呼叫者请求或在 NIC 的子网中找到地址，请创建一个临时引用。

	createTempEP := spoofingOrPromiscuous

	if !createTempEP {

		// 遍历子网
		for _, sn := range n.addressRanges {

			// Skip the subnet address.
			// 略过子网地址。
			if address == sn.ID() {
				continue
			}

			// For now just skip the broadcast address, until we support it.
			// FIXME(b/137608825): Add support for sending/receiving directed (subnet) broadcast.
			//
			// 现在需略过广播地址，因为尚不支持。
			if address == sn.Broadcast() {
				continue
			}

			// 如果 address 同子网 sn 匹配，则 break 。
			if sn.Contains(address) {
				createTempEP = true
				break
			}

		}
	}

	n.mu.RUnlock()

	if !createTempEP {
		return nil
	}

	// Try again with the lock in exclusive mode. If we still can't get the
	// endpoint, create a new "temporary" endpoint. It will only exist while
	// there's a route through it.
	//
	//
	// 尝试用排他锁，如果仍然无法获得 endpoint ，则创建一个新的 "临时" 端点，它只会在有路由通过时才会存在。

	n.mu.Lock()
	if ref, ok := n.endpoints[id]; ok {

		// No need to check the type as we are ok with expired endpoints at this point.
		// 不需要检查类型，因为现在可以接受过期的端点。
		if ref.tryIncRef() {
			n.mu.Unlock()
			return ref
		}

		// tryIncRef failing means the endpoint is scheduled to be removed once the
		// lock is released. Remove it here so we can create a new (temporary) one.
		// The removal logic waiting for the lock handles this case.
		//
		// tryIncRef 失败意味着一旦锁被释放，端点就会被清理。
		// 在这里移除它，这样我们就可以创建一个新的（临时）锁。
		// 等待锁的移除逻辑会处理这种情况。
		n.removeEndpointLocked(ref)

	}

	// Add a new temporary endpoint.
	// 增加一个新的临时端点。

	netProto, ok := n.stack.networkProtocols[protocol]
	if !ok {
		n.mu.Unlock()
		return nil
	}

	//
	ref, _ := n.addAddressLocked(
		// 网络层地址
		tcpip.ProtocolAddress{
			Protocol: protocol, // 网络层协议号
			AddressWithPrefix: tcpip.AddressWithPrefix{ // 网络层前缀地址
				Address:   address,                     // 地址
				PrefixLen: netProto.DefaultPrefixLen(), // 前缀长度
			},
		},
		//
		peb,
		//
		temporary,
	)

	n.mu.Unlock()
	return ref
}


//
//
//
//
//
//
func (n *NIC) addPermanentAddressLocked(protocolAddress tcpip.ProtocolAddress, peb PrimaryEndpointBehavior) (*referencedNetworkEndpoint, *tcpip.Error) {

	// 本地 IP 地址
	id := NetworkEndpointID{protocolAddress.AddressWithPrefix.Address}

	// 检查网卡 n 上是否存在与指定 IP 地址关联的网络层端点引用 ref 。


	// (1) 若已经存在关联的 ref ，则
	if ref, ok := n.endpoints[id]; ok {

		// 检查端点类型
		switch ref.getKind() {

		// 如果是持久端点，则报错
		case permanentTentative, permanent:

			// The NIC already have a permanent endpoint with that address.
			// 网卡已经有了一个 `permanent` 的端点地址。

			return nil, tcpip.ErrDuplicateAddress

		// 如果是过期端点，
		case permanentExpired, temporary:

			// Promote the endpoint to become permanent and respect the new peb.
			if ref.tryIncRef() {

				// 设置状态为永久
				ref.setKind(permanent)

				//
				refs := n.primary[ref.protocol]
				for i, r := range refs {
					if r == ref {
						switch peb {
						case CanBePrimaryEndpoint:
							return ref, nil
						case FirstPrimaryEndpoint:
							if i == 0 {
								return ref, nil
							}
							n.primary[r.protocol] = append(refs[:i], refs[i+1:]...)
						case NeverPrimaryEndpoint:
							n.primary[r.protocol] = append(refs[:i], refs[i+1:]...)
							return ref, nil
						}
					}
				}

				n.insertPrimaryEndpointLocked(ref, peb)

				return ref, nil
			}


			// tryIncRef failing means the endpoint is scheduled to be removed once the lock is released.
			//
			// Remove it here so we can create a new (permanent) one.
			//
			// The removal logic waiting for the lock handles this case.
			//
			//
			// tryIncRef 失败意味着释放锁定后计划删除端点


			n.removeEndpointLocked(ref)
		}
	}

	// (2) 若不存在关联的 ref ，则需要创建端点，并关联到指定地址，这样后续来包会发往该 ep 。
	return n.addAddressLocked(protocolAddress, peb, permanent)
}



//
func (n *NIC) addAddressLocked(
	protocolAddress tcpip.ProtocolAddress, // 网络层协议 + 地址
	peb PrimaryEndpointBehavior, //
	kind networkEndpointKind, //
) (*referencedNetworkEndpoint, *tcpip.Error) {

	// TODO(b/141022673): Validate IP address before adding them.
	// TODO(b/141022673): 添加前先验证 IP 地址。

	// Sanity check.
	id := NetworkEndpointID{
		protocolAddress.AddressWithPrefix.Address,
	}

	// 检查 Endpoint 是否已存在，若已存在，则报错。
	if _, ok := n.endpoints[id]; ok {
		// Endpoint already exists.
		return nil, tcpip.ErrDuplicateAddress
	}

	// 检查网络层协议号是否被协议栈支持，如果支持，则取出协议对象
	netProto, ok := n.stack.networkProtocols[protocolAddress.Protocol]
	if !ok {
		return nil, tcpip.ErrUnknownProtocol
	}

	// Create the new network endpoint.
	// 用 netProto 创建新的网络层端点 ep 。
	ep, err := netProto.NewEndpoint(n.id, protocolAddress.AddressWithPrefix, n.stack, n, n.linkEP)
	if err != nil {
		return nil, err
	}

	// 是否为 IPv6 单播
	isIPv6Unicast :=
		protocolAddress.Protocol == header.IPv6ProtocolNumber &&
			header.IsV6UnicastAddress(protocolAddress.AddressWithPrefix.Address)

	// If the address is an IPv6 address and it is a permanent address, mark it as tentative so it goes through the DAD process.
	//
	// 如果是 IPv6 单播地址，而且是 `permanent` 地址，则将其标记为 `tentative` 地址，以便通过 DAD 程序。
	if isIPv6Unicast && kind == permanent {
		kind = permanentTentative
	}

	// 构造端点 ep 的引用对象
	ref := &referencedNetworkEndpoint{
		refs:     1,                        // refs 为本端点的引用计数，当 refs 为 0 时，会触发将本端点从关联 NIC 中移除。初始值为 1 。
		ep:       ep,                       // 新创建的网络层端点。
		nic:      n,                        // 关联网卡。
		protocol: protocolAddress.Protocol, // 关联的网络层协议。
		kind:     kind,                     //
	}

	// Set up cache if link address resolution exists for this protocol.
	// 如果该协议存在链路层地址解析，则设置 ARP 缓存。
	if n.linkEP.Capabilities()&CapabilityResolutionRequired != 0 {
		if _, ok := n.stack.linkAddrResolvers[protocolAddress.Protocol]; ok {
			ref.linkCache = n.stack
		}
	}

	// If we are adding an IPv6 unicast address, join the solicited-node multicast address.
	// 如果我们增加的是 IPv6 单播地址，加入 solicited-node 组播地址。
	if isIPv6Unicast {
		snmc := header.SolicitedNodeAddr(protocolAddress.AddressWithPrefix.Address)
		if err := n.joinGroupLocked(protocolAddress.Protocol, snmc); err != nil {
			return nil, err
		}
	}

	//
	n.endpoints[id] = ref

	n.insertPrimaryEndpointLocked(ref, peb)

	// If we are adding a tentative IPv6 address, start DAD.
	if isIPv6Unicast && kind == permanentTentative {
		if err := n.ndp.startDuplicateAddressDetection(protocolAddress.AddressWithPrefix.Address, ref); err != nil {
			return nil, err
		}
	}

	return ref, nil
}

// AddAddress adds a new address to n, so that it starts accepting packets
// targeted at the given address (and network protocol).
//
// AddAddress 将一个新的地址添加到 n *NIC 中，这样就可以接受发往给定网络协议和地址的数据包。
//
func (n *NIC) AddAddress(protocolAddress tcpip.ProtocolAddress, peb PrimaryEndpointBehavior) *tcpip.Error {
	// Add the endpoint.
	n.mu.Lock()
	_, err := n.addPermanentAddressLocked(protocolAddress, peb)
	n.mu.Unlock()

	return err
}

// AllAddresses returns all addresses (primary and non-primary) associated with this NIC.
//
// AllAddresses 返回与此 NIC 关联的所有地址 (primary and non-primary) 。
func (n *NIC) AllAddresses() []tcpip.ProtocolAddress {

	n.mu.RLock()
	defer n.mu.RUnlock()

	// 返回地址集合
	addrs := make([]tcpip.ProtocolAddress, 0, len(n.endpoints))

	//
	for nid, ref := range n.endpoints {

		// Don't include tentative, expired or temporary endpoints to
		// avoid confusion and prevent the caller from using those.
		//
		// 为避免造成混乱，不返回 Tentative 、Expired 和 Temporary 状态的地址，防止调用者使用这些端点。
		switch ref.getKind() {
		case permanentTentative, permanentExpired, temporary:
			// TODO(b/140898488): Should tentative addresses be returned?
			continue
		}

		// 添加到返回结果集合中
		addrs = append(addrs,
			// addr = [协议号 + 地址 + 掩码]
			tcpip.ProtocolAddress{
				Protocol: ref.protocol, // 网络层协议号
				AddressWithPrefix: tcpip.AddressWithPrefix{ // 带前缀的地址
					Address:   nid.LocalAddress,   // 本地地址
					PrefixLen: ref.ep.PrefixLen(), // 前缀长度(子网掩码)
				},
			},
		)
	}
	return addrs
}

// PrimaryAddresses returns the primary addresses associated with this NIC.
//
// PrimaryAddresses 返回与此 NIC 关联的 primary 地址。
func (n *NIC) PrimaryAddresses() []tcpip.ProtocolAddress {
	n.mu.RLock()
	defer n.mu.RUnlock()

	// 返回地址集合
	var addrs []tcpip.ProtocolAddress

	//
	for proto, list := range n.primary {

		//
		for _, ref := range list {

			// Don't include tentative, expired or tempory endpoints to
			// avoid confusion and prevent the caller from using those.
			//
			// 为避免造成混乱，不返回 Tentative 、Expired 和 Temporary 状态的地址，防止调用者使用这些端点。
			switch ref.getKind() {
			case permanentTentative, permanentExpired, temporary:
				continue
			}

			// 添加到返回结果集合中
			addrs = append(addrs,
				// addr = [协议号 + 地址 + 掩码]
				tcpip.ProtocolAddress{
					Protocol: proto,
					AddressWithPrefix: tcpip.AddressWithPrefix{
						Address:   ref.ep.ID().LocalAddress,
						PrefixLen: ref.ep.PrefixLen(),
					},
				},
			)
		}
	}
	return addrs
}

// AddAddressRange adds a range of addresses to n, so that it starts accepting
// packets targeted at the given addresses and network protocol. The range is
// given by a subnet address, and all addresses contained in the subnet are
// used except for the subnet address itself and the subnet's broadcast address.
func (n *NIC) AddAddressRange(protocol tcpip.NetworkProtocolNumber, subnet tcpip.Subnet) {
	n.mu.Lock()
	n.addressRanges = append(n.addressRanges, subnet)
	n.mu.Unlock()
}

// RemoveAddressRange removes the given address range from n.
func (n *NIC) RemoveAddressRange(subnet tcpip.Subnet) {
	n.mu.Lock()

	// Use the same underlying array.
	tmp := n.addressRanges[:0]
	for _, sub := range n.addressRanges {
		if sub != subnet {
			tmp = append(tmp, sub)
		}
	}
	n.addressRanges = tmp

	n.mu.Unlock()
}

// Subnets returns the Subnets associated with this NIC.
// Subnets 返回与该 NIC 相关联的 Subnets。
func (n *NIC) AddressRanges() []tcpip.Subnet {
	n.mu.RLock()
	defer n.mu.RUnlock()

	sns := make([]tcpip.Subnet, 0, len(n.addressRanges)+len(n.endpoints))

	//
	for nid := range n.endpoints {

		sn, err := tcpip.NewSubnet(nid.LocalAddress, tcpip.AddressMask(strings.Repeat("\xff", len(nid.LocalAddress))))
		if err != nil {
			// This should never happen as the mask has been carefully crafted to match the address.
			// 这种情况不应该发生，因为掩码是经过精心制作的，与地址相匹配。
			panic("Invalid endpoint subnet: " + err.Error())
		}

		sns = append(sns, sn)

	}

	return append(sns, n.addressRanges...)
}

// insertPrimaryEndpointLocked adds r to n's primary endpoint list as required by peb.
//
// n MUST be locked.
func (n *NIC) insertPrimaryEndpointLocked(r *referencedNetworkEndpoint, peb PrimaryEndpointBehavior) {
	switch peb {
	case CanBePrimaryEndpoint:
		n.primary[r.protocol] = append(n.primary[r.protocol], r)
	case FirstPrimaryEndpoint:
		n.primary[r.protocol] = append([]*referencedNetworkEndpoint{r}, n.primary[r.protocol]...)
	}
}

func (n *NIC) removeEndpointLocked(r *referencedNetworkEndpoint) {

	id := *r.ep.ID()

	// Nothing to do if the reference has already been replaced with a different
	// one. This happens in the case where 1) this endpoint's ref count hit zero
	// and was waiting (on the lock) to be removed and 2) the same address was
	// re-added in the meantime by removing this endpoint from the list and
	// adding a new one.
	if n.endpoints[id] != r {
		return
	}

	if r.getKind() == permanent {
		panic("Reference count dropped to zero before being removed")
	}

	delete(n.endpoints, id)
	refs := n.primary[r.protocol]
	for i, ref := range refs {
		if ref == r {
			n.primary[r.protocol] = append(refs[:i], refs[i+1:]...)
			break
		}
	}

	r.ep.Close()
}

func (n *NIC) removeEndpoint(r *referencedNetworkEndpoint) {
	n.mu.Lock()
	n.removeEndpointLocked(r)
	n.mu.Unlock()
}

func (n *NIC) removePermanentAddressLocked(addr tcpip.Address) *tcpip.Error {
	r, ok := n.endpoints[NetworkEndpointID{addr}]
	if !ok {
		return tcpip.ErrBadLocalAddress
	}

	kind := r.getKind()
	if kind != permanent && kind != permanentTentative {
		return tcpip.ErrBadLocalAddress
	}

	isIPv6Unicast := r.protocol == header.IPv6ProtocolNumber && header.IsV6UnicastAddress(addr)

	// If we are removing a tentative IPv6 unicast address, stop DAD.
	if isIPv6Unicast && kind == permanentTentative {
		n.ndp.stopDuplicateAddressDetection(addr)
	}

	r.setKind(permanentExpired)
	if !r.decRefLocked() {
		// The endpoint still has references to it.
		return nil
	}

	// At this point the endpoint is deleted.

	// If we are removing an IPv6 unicast address, leave the solicited-node multicast address.
	if isIPv6Unicast {
		snmc := header.SolicitedNodeAddr(addr)
		if err := n.leaveGroupLocked(snmc); err != nil {
			return err
		}
	}

	return nil
}

// RemoveAddress removes an address from n.
func (n *NIC) RemoveAddress(addr tcpip.Address) *tcpip.Error {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.removePermanentAddressLocked(addr)
}

// joinGroup adds a new endpoint for the given multicast address,
// if none exists yet. Otherwise it just increments its count.
func (n *NIC) joinGroup(protocol tcpip.NetworkProtocolNumber, addr tcpip.Address) *tcpip.Error {
	n.mu.Lock()
	defer n.mu.Unlock()

	return n.joinGroupLocked(protocol, addr)
}

// joinGroupLocked adds a new endpoint for the given multicast address, if none
// exists yet. Otherwise it just increments its count. n MUST be locked before
// joinGroupLocked is called.
//
// joinGroupLocked 为指定的多播地址 addr 添加一个新端点，若已存在，则增加计数。
// 注意，在调用 joinGroupLocked 之前，需将 n *NIC 锁定。
//
func (n *NIC) joinGroupLocked(protocol tcpip.NetworkProtocolNumber, addr tcpip.Address) *tcpip.Error {

	// TODO(b/143102137): When implementing MLD, make sure MLD packets are
	// not sent unless a valid link-local address is available for use on n
	// as an MLD packet's source address must be a link-local address as
	// outlined in RFC 3810 section 5.
	//
	//
	// TODO(b/143102137):
	// 在实现 MLD 时，请确保除非有效的链路本地地址可用于 n ，否则不要发送 MLD 数据包，
	// 因为 MLD 数据包的源地址必须是 RFC 3810 section 5 描述的本地链路地址。

	id := NetworkEndpointID{addr}
	joins := n.mcastJoins[id]
	if joins == 0 {

		//
		netProto, ok := n.stack.networkProtocols[protocol]
		if !ok {
			return tcpip.ErrUnknownProtocol
		}

		if _, err := n.addPermanentAddressLocked(
			tcpip.ProtocolAddress{
				Protocol: protocol,
				AddressWithPrefix: tcpip.AddressWithPrefix{
					Address:   addr,
					PrefixLen: netProto.DefaultPrefixLen(),
				},
			},
			NeverPrimaryEndpoint,
		); err != nil {
			return err
		}

	}

	n.mcastJoins[id] = joins + 1
	return nil
}

// leaveGroup decrements the count for the given multicast address,
// and when it reaches zero removes the endpoint for this address.
func (n *NIC) leaveGroup(addr tcpip.Address) *tcpip.Error {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.leaveGroupLocked(addr)
}

// leaveGroupLocked decrements the count for the given multicast address,
// and when it reaches zero removes the endpoint for this address.
// n MUST be locked before leaveGroupLocked is called.
func (n *NIC) leaveGroupLocked(addr tcpip.Address) *tcpip.Error {
	id := NetworkEndpointID{addr}
	joins := n.mcastJoins[id]
	switch joins {
	case 0:
		// There are no joins with this address on this NIC.
		return tcpip.ErrBadLocalAddress
	case 1:
		// This is the last one, clean up.
		if err := n.removePermanentAddressLocked(addr); err != nil {
			return err
		}
	}
	n.mcastJoins[id] = joins - 1
	return nil
}

func handlePacket(
	protocol tcpip.NetworkProtocolNumber,				// 网络层协议号
	dst, src tcpip.Address,								// 源地址，目的地址
	localLinkAddr, remotelinkAddr tcpip.LinkAddress,	// 源 mac 地址，目的 mac 地址
	ref *referencedNetworkEndpoint,						// 网络层端点的引用
	pkt tcpip.PacketBuffer,								// 数据包
) {

	// 构造路由
	r := makeRoute(protocol, dst, src, localLinkAddr, ref, false /* handleLocal */, false /* multicastLoop */)
	// 设置目的 Mac 地址
	r.RemoteLinkAddress = remotelinkAddr
	// 根据路由将数据包交给上层业务处理，HandlePacket 在上层协议中定义，如 tcp、udp、icmp 都有自己的定义。
	ref.ep.HandlePacket(&r, pkt)
	// 解除路由引用
	ref.decRef()

}

// DeliverNetworkPacket finds the appropriate network protocol endpoint and
// hands the packet over for further processing. This function is called when
// the NIC receives a packet from the physical interface.
//
// Note that the ownership of the slice backing vv is retained by the caller.
// This rule applies only to the slice itself, not to the items of the slice;
// the ownership of the items is not retained by the caller.
//
//
// 当网卡收到来自物理接口的数据包时，会调用此函数，让与 NIC 关联的网络层 ep 能接收并处理包。
//
func (n *NIC) DeliverNetworkPacket(
	linkEP LinkEndpoint, 					// 数据链路层端点
	remote, local tcpip.LinkAddress, 		// mac 地址
	protocol tcpip.NetworkProtocolNumber, 	// 网络层协议号
	pkt tcpip.PacketBuffer,				 	// 数据包
) {

	// 接收 包/字节 数目统计
	n.stats.Rx.Packets.Increment()
	n.stats.Rx.Bytes.IncrementBy(uint64(pkt.Data.Size()))

	// 根据网络层协议号取出关联的协议对象
	netProto, ok := n.stack.networkProtocols[protocol]
	if !ok {
		n.stack.stats.UnknownProtocolRcvdPackets.Increment()
		return
	}

	// If no local link layer address is provided, assume it was sent directly to this NIC.
	// 如果没有提供本地 MAC 地址，则假设它是直接发送到本 NIC 的。
	if local == "" {
		local = n.linkEP.LinkAddress()
	}

	// Are any packet sockets listening for this network protocol?
	// 是否有套接字监听这个网络协议？
	n.mu.RLock()

	// 取出监听本网卡上网络协议号 protocol 的所有端点，后面会逐个回调各端点的 HandlePacket() 来处理数据包。
	packetEPs := n.packetEPs[protocol]

	// Check whether there are packet sockets listening for every protocol.
	// If we received a packet with protocol EthernetProtocolAll, then the
	// previous for loop will have handled it.
	//
	// 如果有某些端点，正在监听所有网络层协议，它会注册在 n.packetEPs[header.EthernetProtocolAll] 中，也需要回调这些节点。
	if protocol != header.EthernetProtocolAll {
		packetEPs = append(packetEPs, n.packetEPs[header.EthernetProtocolAll]...)
	}

	n.mu.RUnlock()

	// [重要] 遍历正在监听的端点 ，逐个调用 HandlePacket() 处理数据包。
	for _, ep := range packetEPs {
		ep.HandlePacket(n.id, local, protocol, pkt.Clone())
	}

	// 如果网络层协议是 IP(IPv4/IPv6)，更新统计信息。
	if netProto.Number() == header.IPv4ProtocolNumber || netProto.Number() == header.IPv6ProtocolNumber {
		n.stack.stats.IP.PacketsReceived.Increment()
	}

	// 如果收到的网络成数据包小于最小长度，则报错，并更新统计信息。
	if len(pkt.Data.First()) < netProto.MinimumPacketSize() {
		n.stack.stats.MalformedRcvdPackets.Increment()
		return
	}

	// 获取源地址和目的地址。
	src, dst := netProto.ParseAddresses(pkt.Data.First())

	// [重要] 根据 dst ip 获取关联的 referencedNetworkEndpoint ，并调用其 HandlePacket 来处理包。
	if ref := n.getRef(protocol, dst); ref != nil {
		handlePacket(protocol, dst, src, linkEP.LinkAddress(), remote, ref, pkt)
		return
	}


	// This NIC doesn't care about the packet. Find a NIC that cares about the packet and forward it to the NIC.
	// 此网卡不关心当前数据包，找到一个关心当前数据包的网卡，并将其转发给该网卡。

	// TODO: Should we be forwarding the packet even if promiscuous?
	// TODO：即使是混杂模式也要转发吗？

	// 启用了 NIC 之间的数据包转发，才执行转发。
	if n.stack.Forwarding() {

		// 参数列表：网卡 ID 填 0，本地地址为空，目标地址为 dst，目标协议号 protocol ，非多播。
		r, err := n.stack.FindRoute(0, "", dst, protocol, false /* multicastLoop */)
		if err != nil {
			n.stack.stats.IP.InvalidAddressesReceived.Increment()
			return
		}
		defer r.Release()

		r.LocalLinkAddress = n.linkEP.LinkAddress() // 本地 MAC 地址
		r.RemoteLinkAddress = remote                // 目的 MAC 地址

		// Found a NIC.
		n := r.ref.nic
		n.mu.RLock()
		ref, ok := n.endpoints[NetworkEndpointID{dst}]
		ok = ok && ref.isValidForOutgoing() && ref.tryIncRef()
		n.mu.RUnlock()

		if ok {
			// 设置目的 IP 地址
			r.RemoteAddress = src
			// TODO(b/123449044): Update the source NIC as well.
			// TODO(b/123449044): 同时更新源 NIC 。
			// 调用 HandlePacket
			ref.ep.HandlePacket(&r, pkt)
			// 减引用
			ref.decRef()
		} else {

			// n doesn't have a destination endpoint.
			// n 没有目的端点。


			// Send the packet out of n.


			pkt.Header = buffer.NewPrependableFromView(pkt.Data.First())
			pkt.Data.RemoveFirst()

			// TODO(b/128629022): use route.WritePacket.

			// 通过给定的路由 r 写入指定协议 protocol 的数据包 pkt 。
			if err := n.linkEP.WritePacket(&r, nil /* gso */, protocol, pkt); err != nil {
				// 发包错误数统计
				r.Stats().IP.OutgoingPacketErrors.Increment()
			} else {
				// 发包数统计
				n.stats.Tx.Packets.Increment()
				// 发包字节数统计
				n.stats.Tx.Bytes.IncrementBy(uint64(pkt.Header.UsedLength() + pkt.Data.Size()))
			}


		}

		// 直接退出函数
		return
	}



	// If a packet socket handled the packet, don't treat it as invalid.
	//
	// 如果一个数据包套接字处理了这个数据包，不要将其视为无效。
	if len(packetEPs) == 0 {
		n.stack.stats.IP.InvalidAddressesReceived.Increment()
	}



}

// DeliverTransportPacket delivers the packets to the appropriate transport protocol endpoint.
//
// DeliverTransportPacket 将数据包传送到相应的传输层端点。
func (n *NIC) DeliverTransportPacket(r *Route, protocol tcpip.TransportProtocolNumber, pkt tcpip.PacketBuffer) {

	// 根据传输层协议号获取关联的协议
	state, ok := n.stack.transportProtocols[protocol]
	if !ok {
		n.stack.stats.UnknownProtocolRcvdPackets.Increment()
		return
	}

	// 获取传输层协议对象
	transProto := state.proto

	// Raw socket packets are delivered based solely on the transport protocol number.
	// We do not inspect the payload to ensure it's validly formed.
	//
	// 原始套接字数据包仅根据传输协议号进行传输，不会检查其载荷。

	n.stack.demux.deliverRawPacket(r, protocol, pkt)

	// 检查包大小
	if len(pkt.Data.First()) < transProto.MinimumPacketSize() {
		n.stack.stats.MalformedRcvdPackets.Increment()
		return
	}

	// 获取源端口、目的端口
	srcPort, dstPort, err := transProto.ParsePorts(pkt.Data.First())
	if err != nil {
		n.stack.stats.MalformedRcvdPackets.Increment()
		return
	}

	// 构造传输层四元组
	id := TransportEndpointID{dstPort, r.LocalAddress, srcPort, r.RemoteAddress}
	if n.stack.demux.deliverPacket(r, protocol, pkt, id) {
		return
	}

	// Try to deliver to per-stack default handler.
	// 尝试向协议栈的默认处理程序递送数据包。
	if state.defaultHandler != nil {
		if state.defaultHandler(r, id, pkt) {
			return
		}
	}

	// We could not find an appropriate destination for this packet, so deliver it to the global handler.
	// 我们无法为这个数据包找到合适的目的地，所以将其交付给全局处理程序。
	if !transProto.HandleUnknownDestinationPacket(r, id, pkt) {
		n.stack.stats.MalformedRcvdPackets.Increment()
	}

}

// DeliverTransportControlPacket delivers control packets to the appropriate transport protocol endpoint.
//
// DeliverTransportControlPacket 将控制数据包传送到相应的传输层端点。
func (n *NIC) DeliverTransportControlPacket(local, remote tcpip.Address, net tcpip.NetworkProtocolNumber, trans tcpip.TransportProtocolNumber, typ ControlType, extra uint32, pkt tcpip.PacketBuffer) {

	// 根据传输层协议号获取关联的协议
	state, ok := n.stack.transportProtocols[trans]
	if !ok {
		return
	}

	// 获取传输层协议对象
	transProto := state.proto

	// ICMPv4 only guarantees that 8 bytes of the transport protocol will
	// be present in the payload. We know that the ports are within the
	// first 8 bytes for all known transport protocols.
	//
	// ICMPv4 仅保证将传输层协议的前 8 个字节存储在其载荷中，而所有传输层协议的端口信息都保存在前 8 字节。
	if len(pkt.Data.First()) < 8 {
		return
	}

	// 获取源端口、目的端口
	srcPort, dstPort, err := transProto.ParsePorts(pkt.Data.First())
	if err != nil {
		return
	}

	// 构造传输层四元组
	id := TransportEndpointID{srcPort, local, dstPort, remote}

	// 递送控制包
	if n.stack.demux.deliverControlPacket(n, net, trans, typ, extra, pkt, id) {
		return
	}
}

// ID returns the identifier of n.
func (n *NIC) ID() tcpip.NICID {
	return n.id
}

// Stack returns the instance of the Stack that owns this NIC.
func (n *NIC) Stack() *Stack {
	return n.stack
}

// isAddrTentative returns true if addr is tentative on n.
//
// Note that if addr is not associated with n, then this function will return
// false. It will only return true if the address is associated with the NIC
// AND it is tentative.
//
// 如果 addr 在 n 上是临时的，则 isAddrTentative 返回 true 。
// 注意，如果 addr 不与 n 关联，则此函数将返回 false 。
// 仅当地址与 NIC 关联并且是 Tentative 地址时，才会返回 true 。
func (n *NIC) isAddrTentative(addr tcpip.Address) bool {
	ref, ok := n.endpoints[NetworkEndpointID{addr}]
	if !ok {
		return false
	}
	return ref.getKind() == permanentTentative
}

// dupTentativeAddrDetected attempts to inform n that a tentative addr
// is a duplicate on a link.
//
// dupTentativeAddrDetected will delete the tentative address if it exists.
func (n *NIC) dupTentativeAddrDetected(addr tcpip.Address) *tcpip.Error {
	n.mu.Lock()
	defer n.mu.Unlock()

	ref, ok := n.endpoints[NetworkEndpointID{addr}]
	if !ok {
		return tcpip.ErrBadAddress
	}

	if ref.getKind() != permanentTentative {
		return tcpip.ErrInvalidEndpointState
	}

	return n.removePermanentAddressLocked(addr)
}

// setNDPConfigs sets the NDP configurations for n.
//
// Note, if c contains invalid NDP configuration values, it will be fixed to
// use default values for the erroneous values.
func (n *NIC) setNDPConfigs(c NDPConfigurations) {
	c.validate()
	n.mu.Lock()
	n.ndp.configs = c
	n.mu.Unlock()
}

// handleNDPRA handles an NDP Router Advertisement message that arrived on n.
// handleNDPRA 处理到达 n 的 NDP Router Advertisement 消息。
func (n *NIC) handleNDPRA(ip tcpip.Address, ra header.NDPRouterAdvert) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.ndp.handleRA(ip, ra)
}

//
type networkEndpointKind int32

const (

	// A permanentTentative endpoint is a permanent address that is not yet
	// considered to be fully bound to an interface in the traditional sense.
	//
	// That is, the address is associated with a NIC, but packets
	// destined to the address MUST NOT be accepted and MUST be silently
	// dropped, and the address MUST NOT be used as a source address for
	// outgoing packets. For IPv6, addresses will be of this kind until
	// NDP's Duplicate Address Detection has resolved, or be deleted if
	// the process results in detecting a duplicate address.

	//
	// permanentTentative endpoint 是一个永久的地址，它还没有被认为是完全绑定在传统意义上的接口上。
	//
	// 也就是说，该地址是与网卡相关联的，但指向该地址的数据包必须不被接受，必须静静地丢弃，
	// 而且该地址必须不作为出站数据包的源地址。
	//
	// 对于IPv6，在 NDP 的 Duplicate Address Detection 解决之前，地址将是这种类型的，
	// 如果过程中检测到重复的地址，则会被删除。
	permanentTentative networkEndpointKind = iota

	// A permanent endpoint is created by adding a permanent address (vs. a
	// temporary one) to the NIC. Its reference count is biased by 1 to avoid
	// removal when no route holds a reference to it. It is removed by explicitly
	// removing the permanent address from the NIC.
	//
	//
	// 通过向 NIC 添加永久地址(相对于临时地址)创建永久端点。
	// 它的引用数会偏向于1，以避免在没有路由指向它时被删除。
	// 通过明确地从 NIC 中删除永久地址来删除它。
	permanent

	// An expired permanent endoint is a permanent endoint that had its address
	// removed from the NIC, and it is waiting to be removed once no more routes
	// hold a reference to it. This is achieved by decreasing its reference count
	// by 1. If its address is re-added before the endpoint is removed, its type
	// changes back to permanent and its reference count increases by 1 again.
	//
	//
	// 过期的永久端点是指其地址已从 NIC 中删除的永久端点，一旦没有更多的路由持有对它的引用，它就会等待被删除。
	// 如果在端点被删除之前，它的地址被重新添加，它的类型就会变回永久，并且其引用计数将再次增加1。
	permanentExpired


	// A temporary endpoint is created for spoofing outgoing packets, or when in
	// promiscuous mode and accepting incoming packets that don't match any
	// permanent endpoint. Its reference count is not biased by 1 and the
	// endpoint is removed immediately when no more route holds a reference to
	// it. A temporary endpoint can be promoted to permanent if its address
	// is added permanently.
	//
	//
	// 临时端点用来发送欺诈数据包，或者在混杂模式下接收入栈数据包，当没有更多的路由持有对它的引用时，端点会立即被删除。
	// 如果临时端点的地址被永久添加，则可以将其晋升为永久端点。
	temporary
)


// 把 ep 注册到 n.packetEPs[netProto] 中。
func (n *NIC) registerPacketEndpoint(netProto tcpip.NetworkProtocolNumber, ep PacketEndpoint) *tcpip.Error {
	n.mu.Lock()
	defer n.mu.Unlock()
	eps, ok := n.packetEPs[netProto]
	if !ok {
		return tcpip.ErrNotSupported
	}
	n.packetEPs[netProto] = append(eps, ep)
	return nil
}

// 把 ep 从 n.packetEPs[netProto] 中移除。
func (n *NIC) unregisterPacketEndpoint(netProto tcpip.NetworkProtocolNumber, ep PacketEndpoint) {
	n.mu.Lock()
	defer n.mu.Unlock()

	eps, ok := n.packetEPs[netProto]
	if !ok {
		return
	}

	for i, epOther := range eps {
		if epOther == ep {
			n.packetEPs[netProto] = append(eps[:i], eps[i+1:]...)
			return
		}
	}
}

// 网络层端点的引用，附加了 ARP 缓存、引用计数、类型 等功能。
type referencedNetworkEndpoint struct {
	ep       NetworkEndpoint             // 网络层端点
	nic      *NIC                        // 关联的网卡
	protocol tcpip.NetworkProtocolNumber // 网络层协议号

	// linkCache is set if link address resolution is enabled for this protocol.
	// Set to nil otherwise.
	//
	// 如果该协议启用了 MAC 地址解析，则设置 linkCache ，否则设置为 nil 。
	linkCache LinkAddressCache

	// refs is counting references held for this endpoint.
	// When refs hits zero it triggers the automatic removal of the endpoint from the NIC.
	//
	// refs 为本端的引用计数，当 refs 为 0 时，会触发将本端点从关联 NIC 中移除。
	refs int32

	// networkEndpointKind must only be accessed using {get,set}Kind().
	//
	// 只能使用 getKind()/setKind() 来访问 kind ，以保证原子性。
	kind networkEndpointKind
}

func (r *referencedNetworkEndpoint) getKind() networkEndpointKind {
	return networkEndpointKind(atomic.LoadInt32((*int32)(&r.kind)))
}

func (r *referencedNetworkEndpoint) setKind(kind networkEndpointKind) {
	atomic.StoreInt32((*int32)(&r.kind), int32(kind))
}

// isValidForOutgoing returns true if the endpoint can be used to send out a
// packet. It requires the endpoint to not be marked expired (i.e., its address
// has been removed), or the NIC to be in spoofing mode.
//
// 如果端点可以用来发送数据包，则 isValidForOutgoing() 返回 true 。
// 这要求端点未被标记为 `Expired` ，或者 NIC 处于欺骗模式。
func (r *referencedNetworkEndpoint) isValidForOutgoing() bool {
	return r.getKind() != permanentExpired || r.nic.spoofing
}

// isValidForIncoming returns true if the endpoint can accept an incoming packet.
// It requires the endpoint to not be marked expired (i.e., its address has been removed),
// or the NIC to be in promiscuous mode.
//
// 如果端点可以接受传入的数据包，则 isValidForIncoming() 返回 true 。
// 这要求端点没有被标记为 `Expired` ，或者 NIC 处于混杂模式。
func (r *referencedNetworkEndpoint) isValidForIncoming() bool {
	return r.getKind() != permanentExpired || r.nic.promiscuous
}

// decRef decrements the ref count and cleans up the endpoint once it reaches zero.
//
// decRef 会递减 r.refs 计数，一旦达到零，就会对端点进行清理。
func (r *referencedNetworkEndpoint) decRef() {
	if atomic.AddInt32(&r.refs, -1) == 0 {
		r.nic.removeEndpoint(r)
	}
}

// decRefLocked is the same as decRef but assumes that the NIC.mu mutex is locked.
// Returns true if the endpoint was removed.
//
// decRefLocked 与 decRef 相同，但它假设 NIC.mu mutex 被锁定。
// 如果端点被清理，返回 true 。
func (r *referencedNetworkEndpoint) decRefLocked() bool {
	if atomic.AddInt32(&r.refs, -1) == 0 {
		r.nic.removeEndpointLocked(r)
		return true
	}
	return false
}

// incRef increments the ref count. It must only be called when the caller is
// known to be holding a reference to the endpoint, otherwise tryIncRef should be used.
//
// incRef 递增 ref 计数。
// 仅当调用者明确持有对端点的引用时，才调用本函数，否则应使用 tryIncRef 。
func (r *referencedNetworkEndpoint) incRef() {
	atomic.AddInt32(&r.refs, 1)
}

// tryIncRef attempts to increment the ref count from n to n+1, but only if n is not zero.
// That is, it will increment the count if the endpoint is still alive,
// and do nothing if it has already been clean up.
//
// tryIncRef 试图在 r.refs 不为零的情况下，将 r.refs 从 n 递增到 n+1 。
// 也就是说：如果端点还活着，它将递增计数，如果它已经被清理，则不做任何事情。
func (r *referencedNetworkEndpoint) tryIncRef() bool {
	for {
		// 取引用计数，若为 0 则代表已被释放，返回 false 。
		v := atomic.LoadInt32(&r.refs)
		if v == 0 {
			return false
		}
		// 尝试增加引用计数，若增加成功，返回 true 。
		if atomic.CompareAndSwapInt32(&r.refs, v, v+1) {
			return true
		}
	}
}

// stack returns the Stack instance that owns the underlying endpoint.
//
// stack 返回网卡关联的协议栈对象。
func (r *referencedNetworkEndpoint) stack() *Stack {
	return r.nic.stack
}
