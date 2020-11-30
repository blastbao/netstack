// Copyright 2019 The gVisor Authors.
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
	"log"
	"time"

	"github.com/blastbao/netstack/tcpip"
	"github.com/blastbao/netstack/tcpip/buffer"
	"github.com/blastbao/netstack/tcpip/header"
)



// 路由器请求 RS (Router Solicitations)
// 当主机网络接口启用时，主机可以发送 RS 消息要求路由器立即发布 RA 消息，不用等待路由器下次自动发布。
//
//
//  +-----------+-----------+-----------------------+
//  | Type(1B)  | Code(1B)  | CheckSum(2B)          |
//  +-----------+-----------+-----------------------+
//  |                Reserved(4B)                   |
//  +-----------+-----------+-----------------------+
//  |                 Options                       |
//  +-----------+-----------+-----------------------+
//
//
//	类型 : 消息类型， RS 固定为 133
//	代码 : 发送者固定为 0，接收者忽略
//	校验和 : 用于校验 ICMPv6 和部分 IPv6 首部完整性
//	选项 : 源链路层地址选项，发送者的链路层地址，如果知道的话
//
// 路由器公告 RA (Router Advertisement)
// 路由器周期性地发布 RA 消息，包含 on-link/off-link 的 prefix、hop-limit 和 link-MTU 等
//
//
//  +-------------+-----------+-----------------------+
//  | 类型(1B)    | 代码(1B)   | 校验和(2B)            |
//  +-------------+-----------+-----------------------+
//  | 跳数限制(1B) |M|O|保留   | 默认路由器有消息(2B)    |
//  +-------------+-----------+-----------------------+
//  |             节点可达有效期(4B)                   |
//  +-----------+-----------+-------------------------+
//  |            重传间隔(4B)                          |
//  +-----------+-----------+-------------------------+
//  |                 Options                         |
//  +-----------+-----------+-------------------------+
//
//	类型 : 消息类型， RA 固定为 134
//	代码 : 发送者固定为 0，接收者忽略
//	校验和 : 用于校验 ICMPv6 和部分 IPv6 首部完整性
//	跳数限制 : 主机跳数限制，0 表示路由器没有指定，需主机设置
//	M (Managed Address Configuration) :
//		M=1 : 表示目标机使用 DHCPv6 获取 IPv6 地址
//		M=0 : 表示目标机使用 RA 消息获得的 IPv6 前缀构造 IPv6 地址
//	O (Other Configuration) :
//		O=1 : 目标机使用 DHCPv6 获取其他配置信息(不包括 IPv6 地址)，比如 DNS 等
//		O=0 : 目标机不使用 DHCPv6 获取其他配置信息(不包括 IPv6 地址)，比如手工配置 DNS 等
//	默认路由器有效期: 表示该路由器能当默认路由器的时间，0 表示不是默认路由，单位为秒
//	节点可达有效期 : 表示某个节点被确认可达之后的有效时间，0 表示路由器没有指定，需主机设置，单位毫秒
//	重传间隔时间 : 重新发送 NS 消息间隔时间，单位毫秒
//	选项 :
//		源链路层地址 : 发送者的链路层地址，如果知道的话
//		MTU : 如果 MTU 可变, router 会发送该选项
//		前缀信息 : 自动配置地址时，指明前缀是否为 on-link 和是否可用来自动配置 IPv6 地址
//		路由信息 : 通知主机添加指定的路由到路由表
//		通告间隔 : Mobile IPv6 extension，通知主机每隔多久 home agent 会定期发送 NA 消息
//		Home Agent Info : Mobile IPv6 extension，每个 Home agent 用来公告自己的优先顺序及有效期
//
// 邻居请求 NS (Neighbor Solicitations)
// 用于邻居节点 link 层地址解析、是否可达和重复地址检测
//
//  +-----------+-----------+-----------------------+
//  | Type(1B)  | Code(1B)  | CheckSum(2B)          |
//  +-----------+-----------+-----------------------+
//  |                Reserved(4B)                   |
//  +-----------+-----------+-----------------------+
//  |                目的地址(16B)                   |
//  +-----------+-----------+-----------------------+
//  |                 Options                       |
//  +-----------+-----------+-----------------------+
//
//	类型 : 消息类型， NS 固定为 135
//	代码 : 发送者固定为 0，接收者忽略
//	校验和 : 用于校验 ICMPv6 和部分 IPv6 首部完整性
//	目标地址 : 请求解析的目标 IP 地址，不能是多播地址
//	选项 : 源链路层地址选项，即发送者的链路层地址，如果知道的话
//
//
//
//
// 邻居公告 NA (Neighbor Advertisements)
// 用于邻居节点 link 层地址解析、是否可达和重复地址检测
//

const (



	// defaultDupAddrDetectTransmits is the default number of NDP Neighbor
	// Solicitation messages to send when doing Duplicate Address Detection
	// for a tentative address.
	//
	// Default = 1 (from RFC 4862 section 5.1)
	//
	// defaultDupAddrDetectTransmits 是对 tentative 地址进行重复地址检测时要发送的 NDP 邻居请求消息的默认数量。
	defaultDupAddrDetectTransmits = 1

	// defaultRetransmitTimer is the default amount of time to wait between
	// sending NDP Neighbor solicitation messages.
	//
	// Default = 1s (from RFC 4861 section 10).
	//
	// defaultRetransmitTimer 是发送 NDP 邻居请求消息之间等待的默认时间。
	defaultRetransmitTimer = time.Second

	// defaultHandleRAs is the default configuration for whether or not to
	// handle incoming Router Advertisements as a host.
	//
	// Default = true.
	//
	// defaultHandleRAs 控制是否以主机的身份处理传入的 Router Advertisements 。
	defaultHandleRAs = true

	// defaultDiscoverDefaultRouters is the default configuration for
	// whether or not to discover default routers from incoming Router
	// Advertisements, as a host.
	//
	// Default = true.
	//
	// defaultDiscoverDefaultRouters 控制是否从传入的 Router Advertisements 中发现默认路由器的。
	defaultDiscoverDefaultRouters = true

	// defaultDiscoverOnLinkPrefixes is the default configuration for
	// whether or not to discover on-link prefixes from incoming Router
	// Advertisements' Prefix Information option, as a host.
	//
	// Default = true.
	//
	// defaultDiscoverOnLinkPrefixes 控制是否从传入的 Router Advertisements 的 Prefix Information 选项中发现 on-link prefixes 。
	defaultDiscoverOnLinkPrefixes = true

	// minimumRetransmitTimer is the minimum amount of time to wait between
	// sending NDP Neighbor solicitation messages. Note, RFC 4861 does
	// not impose a minimum Retransmit Timer, but we do here to make sure
	// the messages are not sent all at once. We also come to this value
	// because in the RetransmitTimer field of a Router Advertisement, a
	// value of 0 means unspecified, so the smallest valid value is 1.
	// Note, the unit of the RetransmitTimer field in the Router
	// Advertisement is milliseconds.
	//
	// Min = 1ms.
	//
	// minimumRetransmitTimer 是发送 NDP 邻居请求消息之间的最短等待时间。
	// 注意，RFC 4861 并未规定最小 “重传计时器” 时间间隔 ，但是我们在此处确保不会一次发送完毕。
	//
	// 之所以得出这个值，是因为在 Router Advertisement 的 RetransmitTimer 字段中，值为 0 表示未指定，因此最小有效值为 1 。
	// 注意，Router Advertisement 中 RetransmitTimer 字段的单位为毫秒。
	minimumRetransmitTimer = time.Millisecond

	// MaxDiscoveredDefaultRouters is the maximum number of discovered
	// default routers. The stack should stop discovering new routers after
	// discovering MaxDiscoveredDefaultRouters routers.
	//
	// This value MUST be at minimum 2 as per RFC 4861 section 6.3.4, and
	// SHOULD be more.
	//
	// Max = 10.
	//
	// MaxDiscoveredDefaultRouters 是已发现的默认路由器的最大数量。
	// 在发现 MaxDiscoveredDefaultRouters 个路由器后，协议栈应停止发现新路由器。
	// 根据 RFC 4861 第 6.3.4 节的规定，这个值必须至少是 2 ，而且应该更大。
	MaxDiscoveredDefaultRouters = 10

	// MaxDiscoveredOnLinkPrefixes is the maximum number of discovered
	// on-link prefixes. The stack should stop discovering new on-link
	// prefixes after discovering MaxDiscoveredOnLinkPrefixes on-link
	// prefixes.
	//
	// Max = 10.
	//
	// MaxDiscoveredOnLinkPrefixes 是被发现的 on-link 前缀的最大数量。
	// 在发现 MaxDiscoveredOnLinkPrefixes 个 on-link prefixes 后，协议栈应停止发现新的 on-link prefixes 。
	MaxDiscoveredOnLinkPrefixes = 10
)

// NDPDispatcher is the interface integrators of netstack must implement to
// receive and handle NDP related events.
//
// NDPDispatcher 是 netstack 的集成者必须实现的接口，用于接收和处理 NDP 相关事件。
//
type NDPDispatcher interface {


	// OnDuplicateAddressDetectionStatus will be called when the DAD process
	// for an address (addr) on a NIC (with ID nicID) completes. resolved
	// will be set to true if DAD completed successfully (no duplicate addr
	// detected); false otherwise (addr was detected to be a duplicate on
	// the link the NIC is a part of, or it was stopped for some other
	// reason, such as the address being removed). If an error occured
	// during DAD, err will be set and resolved must be ignored.
	//
	// This function is permitted to block indefinitely without interfering
	// with the stack's operation.
	//
	//
	// 当 NIC（nicID）上的地址（addr）的 DAD 处理完成时，将调用 OnDuplicateAddressDetectionStatus 。
	//
	// 如果 DAD 成功完成（未检测到重复的地址），则将 resolve 设置为 true ；否则为false
	// ( 检测到 addr 在 NIC 所属的链路上是重复的，或者因为其他原因被停止，比如地址被删除)。
	//
	// 如果在 DAD 期间发生错误，将设置 err ，并且必须忽略 resolved 。
	//
	//
	OnDuplicateAddressDetectionStatus(nicID tcpip.NICID, addr tcpip.Address, resolved bool, err *tcpip.Error)

	// OnDefaultRouterDiscovered will be called when a new default router is
	// discovered. Implementations must return true along with a new valid
	// route table if the newly discovered router should be remembered. If
	// an implementation returns false, the second return value will be
	// ignored.
	//
	// This function is not permitted to block indefinitely. This function
	// is also not permitted to call into the stack.
	//
	//
	// 当发现一个新的默认路由器时，OnDefaultRouterDiscovered 将被调用。
	// 如果新发现的路由器应该被记住，那么实现必须返回 true 以及一个新的有效路由表。
	// 如果一个实现返回 false ，第二个返回值将被忽略。
	//
	// 该函数不允许无限期阻塞。此函数也不允许调用到堆栈中。
	OnDefaultRouterDiscovered(nicID tcpip.NICID, addr tcpip.Address) (bool, []tcpip.Route)


	// OnDefaultRouterInvalidated will be called when a discovered default
	// router is invalidated. Implementers must return a new valid route
	// table.
	//
	// This function is not permitted to block indefinitely. This function
	// is also not permitted to call into the stack.
	//
	//
	// 当发现的默认路由器无效时，将调用 OnDefaultRouterInvalidated 。
	// 实现者必须返回一个新的有效路由表。
	//
	// 本功能不允许无限阻塞，也不允许在协议栈中调用。
	OnDefaultRouterInvalidated(nicID tcpip.NICID, addr tcpip.Address) []tcpip.Route



	// OnOnLinkPrefixDiscovered will be called when a new on-link prefix is
	// discovered. Implementations must return true along with a new valid
	// route table if the newly discovered on-link prefix should be
	// remembered. If an implementation returns false, the second return
	// value will be ignored.
	//
	// This function is not permitted to block indefinitely. This function
	// is also not permitted to call into the stack.
	//
	//
	// 当发现一个新的 on-link 前缀时，OnOnLinkPrefixDiscovered 将被调用。
	// 如果新发现的 on-link prefix 应该被记住，实现必须返回 true ，同时返回一个新的有效路由表。
	// 如果一个实现返回false，第二个返回值将被忽略。
	//
	// 本功能不允许无限阻塞，也不允许在协议栈中调用。
	OnOnLinkPrefixDiscovered(nicID tcpip.NICID, prefix tcpip.Subnet) (bool, []tcpip.Route)

	// OnOnLinkPrefixInvalidated will be called when a discovered on-link
	// prefix is invalidated. Implementers must return a new valid route
	// table.
	//
	// This function is not permitted to block indefinitely. This function
	// is also not permitted to call into the stack.
	//
	//
	// OnOnLinkPrefixInvalidated 将在发现的 on-link 前缀无效时被调用。
	// 实现者必须返回一个新的有效路由表。
	//
	OnOnLinkPrefixInvalidated(nicID tcpip.NICID, prefix tcpip.Subnet) []tcpip.Route
}

// NDPConfigurations is the NDP configurations for the netstack.
type NDPConfigurations struct {

	// The number of Neighbor Solicitation messages to send when doing
	// Duplicate Address Detection for a tentative address.
	//
	// Note, a value of zero effectively disables DAD.
	//
	// 在对 tentative 地址进行重复地址检测(DAD)时，要发送的邻居问询请求 NS 消息的数量。
	// 请注意，值为零时将禁用 DAD 。
	DupAddrDetectTransmits uint8

	// The amount of time to wait between sending Neighbor Solicitation
	// messages.
	//
	// Must be greater than 0.5s.
	//
	// 发送邻居问询请求 NS 消息之间的等待时间。
	RetransmitTimer time.Duration


	// HandleRAs determines whether or not Router Advertisements will be
	// processed.
	//
	// HandleRAs 决定是否处理路由器广告 。
	HandleRAs bool

	// DiscoverDefaultRouters determines whether or not default routers will
	// be discovered from Router Advertisements. This configuration is
	// ignored if HandleRAs is false.
	//
	// DiscoverDefaultRouters 决定是否会从路由器广告中发现默认路由器。
	// 如果 HandleRAs 为 false ，则会忽略此配置。
	DiscoverDefaultRouters bool


	// DiscoverOnLinkPrefixes determines whether or not on-link prefixes
	// will be discovered from Router Advertisements' Prefix Information
	// option. This configuration is ignored if HandleRAs is false.
	//
	// DiscoverOnLinkPrefixes 决定是否会从 Router Advertisements 的 Prefix Information 选项中发现链路前缀。
	// 如果 HandleRAs 为 false ，则会忽略此配置。
	DiscoverOnLinkPrefixes bool
}

// DefaultNDPConfigurations returns an NDPConfigurations populated with default values.
// DefaultNDPConfigurations 返回一个用默认值填充的 NDPConfigurations 。
func DefaultNDPConfigurations() NDPConfigurations {
	return NDPConfigurations{
		DupAddrDetectTransmits: defaultDupAddrDetectTransmits,
		RetransmitTimer:        defaultRetransmitTimer,
		HandleRAs:              defaultHandleRAs,
		DiscoverDefaultRouters: defaultDiscoverDefaultRouters,
		DiscoverOnLinkPrefixes: defaultDiscoverOnLinkPrefixes,
	}
}

// validate modifies an NDPConfigurations with valid values. If invalid values
// are present in c, the corresponding default values will be used instead.
//
// If RetransmitTimer is less than minimumRetransmitTimer, then a value of
// defaultRetransmitTimer will be used.
//
// validate 用有效值修改 NDPConfigurations ，如果 c 中存在无效值，将设置为相应的默认值。
// 如果 RetransmitTimer 小于最小 RetransmitTimer ，那么将使用 defaultRetransmitTimer 的值。
func (c *NDPConfigurations) validate() {
	if c.RetransmitTimer < minimumRetransmitTimer {
		c.RetransmitTimer = defaultRetransmitTimer
	}
}

// ndpState is the per-interface NDP state.
type ndpState struct {

	// The NIC this ndpState is for.
	nic *NIC

	// configs is the per-interface NDP configurations.
	// configs 是每个接口的 NDP 配置。
	configs NDPConfigurations

	// The DAD state to send the next NS message, or resolve the address.
	// DAD 状态下发送下一条 NS 消息，或者解析地址。
	dad map[tcpip.Address]dadState

	// The default routers discovered through Router Advertisements.
	// 通过路由器广告发现的默认路由器。
	defaultRouters map[tcpip.Address]defaultRouterState

	// The on-link prefixes discovered through Router Advertisements' Prefix Information option.
	// 通过路由器广告的 "前缀信息" 选项发现的链路前缀。
	onLinkPrefixes map[tcpip.Subnet]onLinkPrefixState
}



// dadState holds the Duplicate Address Detection timer and channel to signal
// to the DAD goroutine that DAD should stop.
//
// dadState 持有 Duplicate Address Detection 定时器和通道，用于向 DAD goroutine 发出 DAD 应该停止的信号。
type dadState struct {

	// The DAD timer to send the next NS message, or resolve the address.
	// 发送下一条 NS 消息或解析地址的 DAD 定时器。
	timer *time.Timer

	// Used to let the DAD timer know that it has been stopped.
	//
	// Must only be read from or written to while protected by the lock of
	// the NIC this dadState is associated with.
	//
	// 用于让 DAD 定时器知道它已经停止。
	// 只能在 dadState 关联的 NIC 的锁保护的情况下读取或写入。
	done *bool
}




// defaultRouterState holds data associated with a default router discovered by
// a Router Advertisement (RA).
//
// defaultRouterState 保存了与由路由器广告（RA）发现的默认路由器相关的数据。
type defaultRouterState struct {

	invalidationTimer *time.Timer

	// Used to inform the timer not to invalidate the default router (R) in
	// a race condition (T1 is a goroutine that handles an RA from R and T2
	// is the goroutine that handles R's invalidation timer firing):
	//   T1: Receive a new RA from R
	//   T1: Obtain the NIC's lock before processing the RA
	//   T2: R's invalidation timer fires, and gets blocked on obtaining the
	//       NIC's lock
	//   T1: Refreshes/extends R's lifetime & releases NIC's lock
	//   T2: Obtains NIC's lock & invalidates R immediately
	//
	// To resolve this, T1 will check to see if the timer already fired, and
	// inform the timer using doNotInvalidate to not invalidate R, so that
	// once T2 obtains the lock, it will see that it is set to true and do
	// nothing further.
	doNotInvalidate *bool
}

// onLinkPrefixState holds data associated with an on-link prefix discovered by
// a Router Advertisement's Prefix Information option (PI) when the NDP
// configurations was configured to do so.
type onLinkPrefixState struct {
	invalidationTimer *time.Timer

	// Used to signal the timer not to invalidate the on-link prefix (P) in
	// a race condition (T1 is a goroutine that handles a PI for P and T2
	// is the goroutine that handles P's invalidation timer firing):
	//   T1: Receive a new PI for P
	//   T1: Obtain the NIC's lock before processing the PI
	//   T2: P's invalidation timer fires, and gets blocked on obtaining the
	//       NIC's lock
	//   T1: Refreshes/extends P's lifetime & releases NIC's lock
	//   T2: Obtains NIC's lock & invalidates P immediately
	//
	// To resolve this, T1 will check to see if the timer already fired, and
	// inform the timer using doNotInvalidate to not invalidate P, so that
	// once T2 obtains the lock, it will see that it is set to true and do
	// nothing further.
	doNotInvalidate *bool
}

// startDuplicateAddressDetection performs Duplicate Address Detection.
//
// This function must only be called by IPv6 addresses that are currently
// tentative.
//
// The NIC that ndp belongs to MUST be locked.
func (ndp *ndpState) startDuplicateAddressDetection(addr tcpip.Address, ref *referencedNetworkEndpoint) *tcpip.Error {


 	// addr must be a valid unicast IPv6 address.
	if !header.IsV6UnicastAddress(addr) {
		return tcpip.ErrAddressFamilyNotSupported
	}

	// Should not attempt to perform DAD on an address that is currently in
	// the DAD process.
	if _, ok := ndp.dad[addr]; ok {
		// Should never happen because we should only ever call this
		// function for newly created addresses. If we attemped to
		// "add" an address that already existed, we would returned an
		// error since we attempted to add a duplicate address, or its
		// reference count would have been increased without doing the
		// work that would have been done for an address that was brand
		// new. See NIC.addPermanentAddressLocked.
		panic(fmt.Sprintf("ndpdad: already performing DAD for addr %s on NIC(%d)", addr, ndp.nic.ID()))
	}

	remaining := ndp.configs.DupAddrDetectTransmits

	{
		done, err := ndp.doDuplicateAddressDetection(addr, remaining, ref)
		if err != nil {
			return err
		}
		if done {
			return nil
		}
	}

	remaining--

	var done bool
	var timer *time.Timer
	timer = time.AfterFunc(ndp.configs.RetransmitTimer, func() {

		var d bool
		var err *tcpip.Error

		// doDadIteration does a single iteration of the DAD loop.
		//
		// Returns true if the integrator needs to be informed of DAD
		// completing.
		doDadIteration := func() bool {
			ndp.nic.mu.Lock()
			defer ndp.nic.mu.Unlock()

			if done {
				// If we reach this point, it means that the DAD
				// timer fired after another goroutine already
				// obtained the NIC lock and stopped DAD before
				// this function obtained the NIC lock. Simply
				// return here and do nothing further.
				return false
			}

			ref, ok := ndp.nic.endpoints[NetworkEndpointID{addr}]
			if !ok {
				// This should never happen.
				// We should have an endpoint for addr since we
				// are still performing DAD on it. If the
				// endpoint does not exist, but we are doing DAD
				// on it, then we started DAD at some point, but
				// forgot to stop it when the endpoint was
				// deleted.
				panic(fmt.Sprintf("ndpdad: unrecognized addr %s for NIC(%d)", addr, ndp.nic.ID()))
			}

			d, err = ndp.doDuplicateAddressDetection(addr, remaining, ref)
			if err != nil || d {
				delete(ndp.dad, addr)

				if err != nil {
					log.Printf("ndpdad: Error occured during DAD iteration for addr (%s) on NIC(%d); err = %s", addr, ndp.nic.ID(), err)
				}

				// Let the integrator know DAD has completed.
				return true
			}

			remaining--
			timer.Reset(ndp.nic.stack.ndpConfigs.RetransmitTimer)
			return false
		}


		//
		if doDadIteration() && ndp.nic.stack.ndpDisp != nil {
			ndp.nic.stack.ndpDisp.OnDuplicateAddressDetectionStatus(ndp.nic.ID(), addr, d, err)
		}


	})

	ndp.dad[addr] = dadState{
		timer: timer,
		done:  &done,
	}

	return nil
}

// doDuplicateAddressDetection is called on every iteration of the timer, and
// when DAD starts.
//
// It handles resolving the address (if there are no more NS to send), or
// sending the next NS if there are more NS to send.
//
// This function must only be called by IPv6 addresses that are currently
// tentative.
//
// The NIC that ndp belongs to (n) MUST be locked.
//
// Returns true if DAD has resolved; false if DAD is still ongoing.
func (ndp *ndpState) doDuplicateAddressDetection(addr tcpip.Address, remaining uint8, ref *referencedNetworkEndpoint) (bool, *tcpip.Error) {

	if ref.getKind() != permanentTentative {
		// The endpoint should still be marked as tentative since we are still performing DAD on it.
		panic(fmt.Sprintf("ndpdad: addr %s is not tentative on NIC(%d)", addr, ndp.nic.ID()))
	}

	if remaining == 0 {
		// DAD has resolved.
		ref.setKind(permanent)
		return true, nil
	}

	// Send a new NS.
	snmc := header.SolicitedNodeAddr(addr)
	snmcRef, ok := ndp.nic.endpoints[NetworkEndpointID{snmc}]
	if !ok {
		// This should never happen as if we have the address,
		// we should have the solicited-node address.
		panic(fmt.Sprintf("ndpdad: NIC(%d) is not in the solicited-node multicast group (%s) but it has addr %s", ndp.nic.ID(), snmc, addr))
	}


	// Use the unspecified address as the source address when performing DAD.
	r := makeRoute(header.IPv6ProtocolNumber, header.IPv6Any, snmc, ndp.nic.linkEP.LinkAddress(), snmcRef, false, false)


	hdr := buffer.NewPrependable(int(r.MaxHeaderLength()) + header.ICMPv6NeighborSolicitMinimumSize)
	pkt := header.ICMPv6(hdr.Prepend(header.ICMPv6NeighborSolicitMinimumSize))
	pkt.SetType(header.ICMPv6NeighborSolicit)
	ns := header.NDPNeighborSolicit(pkt.NDPPayload())
	ns.SetTargetAddress(addr)
	pkt.SetChecksum(header.ICMPv6Checksum(pkt, r.LocalAddress, r.RemoteAddress, buffer.VectorisedView{}))

	sent := r.Stats().ICMP.V6PacketsSent
	if err := r.WritePacket(nil, NetworkHeaderParams{Protocol: header.ICMPv6ProtocolNumber, TTL: header.NDPHopLimit, TOS: DefaultTOS}, tcpip.PacketBuffer{
		Header: hdr,
	}); err != nil {
		sent.Dropped.Increment()
		return false, err
	}
	sent.NeighborSolicit.Increment()

	return false, nil
}

// stopDuplicateAddressDetection ends a running Duplicate Address Detection
// process. Note, this may leave the DAD process for a tentative address in
// such a state forever, unless some other external event resolves the DAD
// process (receiving an NA from the true owner of addr, or an NS for addr
// (implying another node is attempting to use addr)). It is up to the caller
// of this function to handle such a scenario. Normally, addr will be removed
// from n right after this function returns or the address successfully resolved.
//
// The NIC that ndp belongs to MUST be locked.
func (ndp *ndpState) stopDuplicateAddressDetection(addr tcpip.Address) {

	dad, ok := ndp.dad[addr]
	if !ok {
		// Not currently performing DAD on addr, just return.
		return
	}

	if dad.timer != nil {
		dad.timer.Stop()
		dad.timer = nil

		*dad.done = true
		dad.done = nil
	}

	delete(ndp.dad, addr)

	// Let the integrator know DAD did not resolve.
	if ndp.nic.stack.ndpDisp != nil {
		go ndp.nic.stack.ndpDisp.OnDuplicateAddressDetectionStatus(ndp.nic.ID(), addr, false, nil)
	}
}

// handleRA handles a Router Advertisement message that arrived on the NIC
// this ndp is for. Does nothing if the NIC is configured to not handle RAs.
//
// The NIC that ndp belongs to and its associated stack MUST be locked.
//
//
//
//
func (ndp *ndpState) handleRA(ip tcpip.Address, ra header.NDPRouterAdvert) {

	// Is the NIC configured to handle RAs at all?
	//
	// Currently, the stack does not determine router interface status on a
	// per-interface basis; it is a stack-wide configuration, so we check
	// stack's forwarding flag to determine if the NIC is a routing interface.
	if !ndp.configs.HandleRAs || ndp.nic.stack.forwarding {
		return
	}

	// Is the NIC configured to discover default routers?
	if ndp.configs.DiscoverDefaultRouters {
		rtr, ok := ndp.defaultRouters[ip]
		rl := ra.RouterLifetime()
		switch {
		case !ok && rl != 0:

			// This is a new default router we are discovering.
			//
			// Only remember it if we currently know about less than
			// MaxDiscoveredDefaultRouters routers.
			if len(ndp.defaultRouters) < MaxDiscoveredDefaultRouters {
				ndp.rememberDefaultRouter(ip, rl)
			}

		case ok && rl != 0:
			// This is an already discovered default router. Update
			// the invalidation timer.
			timer := rtr.invalidationTimer

			// We should ALWAYS have an invalidation timer for a
			// discovered router.
			if timer == nil {
				panic("ndphandlera: RA invalidation timer should not be nil")
			}

			if !timer.Stop() {
				// If we reach this point, then we know the
				// timer fired after we already took the NIC
				// lock. Inform the timer not to invalidate the
				// router when it obtains the lock as we just
				// got a new RA that refreshes its lifetime to a
				// non-zero value. See
				// defaultRouterState.doNotInvalidate for more
				// details.
				*rtr.doNotInvalidate = true
			}

			timer.Reset(rl)

		case ok && rl == 0:
			// We know about the router but it is no longer to be
			// used as a default router so invalidate it.
			ndp.invalidateDefaultRouter(ip)
		}
	}

	// TODO(b/141556115): Do (RetransTimer, ReachableTime)) Parameter
	//                    Discovery.

	// We know the options is valid as far as wire format is concerned since
	// we got the Router Advertisement, as documented by this fn. Given this
	// we do not check the iterator for errors on calls to Next.
	it, _ := ra.Options().Iter(false)
	for opt, done, _ := it.Next(); !done; opt, done, _ = it.Next() {
		switch opt.Type() {
		case header.NDPPrefixInformationType:
			if !ndp.configs.DiscoverOnLinkPrefixes {
				continue
			}

			pi := opt.(header.NDPPrefixInformation)

			prefix := pi.Subnet()

			// Is the prefix a link-local?
			if header.IsV6LinkLocalAddress(prefix.ID()) {
				// ...Yes, skip as per RFC 4861 section 6.3.4.
				continue
			}

			// Is the Prefix Length 0?
			if prefix.Prefix() == 0 {
				// ...Yes, skip as this is an invalid prefix
				// as all IPv6 addresses cannot be on-link.
				continue
			}

			if !pi.OnLinkFlag() {
				// Not on-link so don't "discover" it as an
				// on-link prefix.
				continue
			}

			prefixState, ok := ndp.onLinkPrefixes[prefix]
			vl := pi.ValidLifetime()
			switch {
			case !ok && vl == 0:
				// Don't know about this prefix but has a zero
				// valid lifetime, so just ignore.
				continue

			case !ok && vl != 0:
				// This is a new on-link prefix we are
				// discovering.
				//
				// Only remember it if we currently know about
				// less than MaxDiscoveredOnLinkPrefixes on-link
				// prefixes.
				if len(ndp.onLinkPrefixes) < MaxDiscoveredOnLinkPrefixes {
					ndp.rememberOnLinkPrefix(prefix, vl)
				}
				continue

			case ok && vl == 0:
				// We know about the on-link prefix, but it is
				// no longer to be considered on-link, so
				// invalidate it.
				ndp.invalidateOnLinkPrefix(prefix)
				continue
			}

			// This is an already discovered on-link prefix with a
			// new non-zero valid lifetime.
			// Update the invalidation timer.
			timer := prefixState.invalidationTimer

			if timer == nil && vl >= header.NDPPrefixInformationInfiniteLifetime {
				// Had infinite valid lifetime before and
				// continues to have an invalid lifetime. Do
				// nothing further.
				continue
			}

			if timer != nil && !timer.Stop() {
				// If we reach this point, then we know the
				// timer already fired after we took the NIC
				// lock. Inform the timer to not invalidate
				// the prefix once it obtains the lock as we
				// just got a new PI that refeshes its lifetime
				// to a non-zero value. See
				// onLinkPrefixState.doNotInvalidate for more
				// details.
				*prefixState.doNotInvalidate = true
			}

			if vl >= header.NDPPrefixInformationInfiniteLifetime {
				// Prefix is now valid forever so we don't need
				// an invalidation timer.
				prefixState.invalidationTimer = nil
				ndp.onLinkPrefixes[prefix] = prefixState
				continue
			}

			if timer != nil {
				// We already have a timer so just reset it to
				// expire after the new valid lifetime.
				timer.Reset(vl)
				continue
			}

			// We do not have a timer so just create a new one.
			prefixState.invalidationTimer = ndp.prefixInvalidationCallback(prefix, vl, prefixState.doNotInvalidate)
			ndp.onLinkPrefixes[prefix] = prefixState
		}

		// TODO(b/141556115): Do (MTU) Parameter Discovery.
	}
}

// invalidateDefaultRouter invalidates a discovered default router.
//
// The NIC that ndp belongs to and its associated stack MUST be locked.
func (ndp *ndpState) invalidateDefaultRouter(ip tcpip.Address) {
	rtr, ok := ndp.defaultRouters[ip]

	// Is the router still discovered?
	if !ok {
		// ...Nope, do nothing further.
		return
	}

	rtr.invalidationTimer.Stop()
	rtr.invalidationTimer = nil
	*rtr.doNotInvalidate = true
	rtr.doNotInvalidate = nil

	delete(ndp.defaultRouters, ip)

	// Let the integrator know a discovered default router is invalidated.
	if ndp.nic.stack.ndpDisp != nil {
		ndp.nic.stack.routeTable = ndp.nic.stack.ndpDisp.OnDefaultRouterInvalidated(ndp.nic.ID(), ip)
	}
}

// rememberDefaultRouter remembers a newly discovered default router with IPv6
// link-local address ip with lifetime rl.
//
// The router identified by ip MUST NOT already be known by the NIC.
//
// The NIC that ndp belongs to and its associated stack MUST be locked.
func (ndp *ndpState) rememberDefaultRouter(ip tcpip.Address, rl time.Duration) {
	if ndp.nic.stack.ndpDisp == nil {
		return
	}

	// Inform the integrator when we discovered a default router.
	remember, routeTable := ndp.nic.stack.ndpDisp.OnDefaultRouterDiscovered(ndp.nic.ID(), ip)
	if !remember {
		// Informed by the integrator to not remember the router, do
		// nothing further.
		return
	}

	// Used to signal the timer not to invalidate the default router (R) in
	// a race condition. See defaultRouterState.doNotInvalidate for more
	// details.
	var doNotInvalidate bool

	ndp.defaultRouters[ip] = defaultRouterState{
		invalidationTimer: time.AfterFunc(rl, func() {
			ndp.nic.stack.mu.Lock()
			defer ndp.nic.stack.mu.Unlock()
			ndp.nic.mu.Lock()
			defer ndp.nic.mu.Unlock()

			if doNotInvalidate {
				doNotInvalidate = false
				return
			}

			ndp.invalidateDefaultRouter(ip)
		}),
		doNotInvalidate: &doNotInvalidate,
	}

	ndp.nic.stack.routeTable = routeTable
}






// rememberOnLinkPrefix remembers a newly discovered on-link prefix with IPv6
// address with prefix prefix with lifetime l.
//
// The prefix identified by prefix MUST NOT already be known.
//
// The NIC that ndp belongs to and its associated stack MUST be locked.
func (ndp *ndpState) rememberOnLinkPrefix(prefix tcpip.Subnet, l time.Duration) {
	if ndp.nic.stack.ndpDisp == nil {
		return
	}

	// Inform the integrator when we discovered an on-link prefix.
	// 当发现一个 on-link 前缀时，通知 integrator 。
	remember, routeTable := ndp.nic.stack.ndpDisp.OnOnLinkPrefixDiscovered(ndp.nic.ID(), prefix)
	if !remember {
		// Informed by the integrator to not remember the prefix, do nothing further.
		// integrator 返回无需记录前缀，则无需执行任何其他操作。
		return
	}

	// Used to signal the timer not to invalidate the on-link prefix (P) in
	// a race condition. See onLinkPrefixState.doNotInvalidate for more details.
	//
	// 用于在竞争条件下向定时器发出不使 on-link prefix (P) 无效的信号。
	// 更多细节请参见 onLinkPrefixState.doNotInvalidate 。

	var doNotInvalidate bool
	var timer *time.Timer

	// Only create a timer if the lifetime is not infinite.
	// 只有在生命周期不是无限的情况下才会创建一个定时器。
	if l < header.NDPPrefixInformationInfiniteLifetime {
		timer = ndp.prefixInvalidationCallback(prefix, l, &doNotInvalidate)
	}

	//
	ndp.onLinkPrefixes[prefix] = onLinkPrefixState{
		invalidationTimer: timer,
		doNotInvalidate:   &doNotInvalidate,
	}

	//
	ndp.nic.stack.routeTable = routeTable
}





// invalidateOnLinkPrefix invalidates a discovered on-link prefix.
//
// The NIC that ndp belongs to and its associated stack MUST be locked.
//
//
// invalidateOnLinkPrefix 使已发现的 on-link 前缀失效。
// ndp 所属的 NIC 及其相关的协议栈必须被锁定。
func (ndp *ndpState) invalidateOnLinkPrefix(prefix tcpip.Subnet) {

	// 判断前缀是否在 OnLink 列表中
	s, ok := ndp.onLinkPrefixes[prefix]

	// Is the on-link prefix still discovered?
	if !ok {
		// ...Nope, do nothing further.
		return
	}

	// 重置定时器
	if s.invalidationTimer != nil {
		s.invalidationTimer.Stop()
		s.invalidationTimer = nil
		*s.doNotInvalidate = true
	}

	s.doNotInvalidate = nil

	delete(ndp.onLinkPrefixes, prefix)


	// Let the integrator know a discovered on-link prefix is invalidated.
	//
	// 让 integrator 知道已发现的 on-link prefix 已失效。
	if ndp.nic.stack.ndpDisp != nil {
		ndp.nic.stack.routeTable = ndp.nic.stack.ndpDisp.OnOnLinkPrefixInvalidated(ndp.nic.ID(), prefix)
	}
}

// prefixInvalidationCallback returns a new on-link prefix invalidation timer
// for prefix that fires after vl.
//
// doNotInvalidate is used to signal the timer when it fires at the same time
// that a prefix's valid lifetime gets refreshed. See
// onLinkPrefixState.doNotInvalidate for more details.
//
//
//
// prefixInvalidationCallback 返回一个新的 on-link prefix invalidation 定时器，在 vl 之后开火。
//
// doNotInvalidate 用于在前缀的有效寿命被刷新的同时触发定时器的信号。
// 更多细节请参见 onLinkPrefixState.doNotInvalidate 。
func (ndp *ndpState) prefixInvalidationCallback(prefix tcpip.Subnet, vl time.Duration, doNotInvalidate *bool) *time.Timer {
	return time.AfterFunc(vl, func() {

		//
		ndp.nic.stack.mu.Lock()
		defer ndp.nic.stack.mu.Unlock()

		//
		ndp.nic.mu.Lock()
		defer ndp.nic.mu.Unlock()

		//
		if *doNotInvalidate {
			*doNotInvalidate = false
			return
		}

		//
		ndp.invalidateOnLinkPrefix(prefix)
	})
}
