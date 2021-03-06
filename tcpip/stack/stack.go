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

// Package stack provides the glue between networking protocols and the
// consumers of the networking stack.
//
// For consumers, the only function of interest is New(), everything else is
// provided by the tcpip/public package.
package stack

import (
	"encoding/binary"
	"sync"
	"sync/atomic"
	"time"

	"github.com/blastbao/netstack/rand"
	"github.com/blastbao/netstack/sleep"
	"github.com/blastbao/netstack/tcpip"
	"github.com/blastbao/netstack/tcpip/buffer"
	"github.com/blastbao/netstack/tcpip/header"
	"github.com/blastbao/netstack/tcpip/iptables"
	"github.com/blastbao/netstack/tcpip/ports"
	"github.com/blastbao/netstack/tcpip/seqnum"
	"github.com/blastbao/netstack/waiter"
	"golang.org/x/time/rate"
)

const (

	// ageLimit is set to the same cache stale time used in Linux.
	ageLimit = 1 * time.Minute

	// resolutionTimeout is set to the same ARP timeout used in Linux.
	resolutionTimeout = 1 * time.Second

	// resolutionAttempts is set to the same ARP retries used in Linux.
	resolutionAttempts = 3

	// DefaultTOS is the default type of service value for network endpoints.
	DefaultTOS = 0
)

type transportProtocolState struct {
	proto          TransportProtocol
	defaultHandler func(r *Route, id TransportEndpointID, pkt tcpip.PacketBuffer) bool
}

// TCPProbeFunc is the expected function type for a TCP probe function to be
// passed to stack.AddTCPProbe.
type TCPProbeFunc func(s TCPEndpointState)

// TCPCubicState is used to hold a copy of the internal cubic state when the
// TCPProbeFunc is invoked.
type TCPCubicState struct {
	WLastMax                float64
	WMax                    float64
	T                       time.Time
	TimeSinceLastCongestion time.Duration
	C                       float64
	K                       float64
	Beta                    float64
	WC                      float64
	WEst                    float64
}

// TCPEndpointID is the unique 4 tuple that identifies a given endpoint.
//
// TCP 四元组
type TCPEndpointID struct {
	// LocalPort is the local port associated with the endpoint.
	LocalPort uint16

	// LocalAddress is the local [network layer] address associated with
	// the endpoint.
	LocalAddress tcpip.Address

	// RemotePort is the remote port associated with the endpoint.
	RemotePort uint16

	// RemoteAddress it the remote [network layer] address associated with
	// the endpoint.
	RemoteAddress tcpip.Address
}

// TCPFastRecoveryState holds a copy of the internal fast recovery state of a TCP endpoint.
//
// TCP 快速恢复状态
type TCPFastRecoveryState struct {
	// Active if true indicates the endpoint is in fast recovery.
	Active bool

	// First is the first unacknowledged sequence number being recovered.
	First seqnum.Value

	// Last is the 'recover' sequence number that indicates the point at
	// which we should exit recovery barring any timeouts etc.
	Last seqnum.Value

	// MaxCwnd is the maximum value we are permitted to grow the congestion
	// window during recovery. This is set at the time we enter recovery.
	MaxCwnd int

	// HighRxt is the highest sequence number which has been retransmitted
	// during the current loss recovery phase.
	// See: RFC 6675 Section 2 for details.
	HighRxt seqnum.Value

	// RescueRxt is the highest sequence number which has been
	// optimistically retransmitted to prevent stalling of the ACK clock
	// when there is loss at the end of the window and no new data is
	// available for transmission.
	// See: RFC 6675 Section 2 for details.
	RescueRxt seqnum.Value
}

// TCPReceiverState holds a copy of the internal state of the receiver for a given TCP endpoint.
//
//
type TCPReceiverState struct {
	// RcvNxt is the TCP variable RCV.NXT.
	RcvNxt seqnum.Value

	// RcvAcc is the TCP variable RCV.ACC.
	RcvAcc seqnum.Value

	// RcvWndScale is the window scaling to use for inbound segments.
	RcvWndScale uint8

	// PendingBufUsed is the number of bytes pending in the receive
	// queue.
	PendingBufUsed seqnum.Size

	// PendingBufSize is the size of the socket receive buffer.
	PendingBufSize seqnum.Size
}

// TCPSenderState holds a copy of the internal state of the sender for a given TCP Endpoint.
type TCPSenderState struct {
	// LastSendTime is the time at which we sent the last segment.
	LastSendTime time.Time

	// DupAckCount is the number of Duplicate ACK's received.
	DupAckCount int

	// SndCwnd is the size of the sending congestion window in packets.
	SndCwnd int

	// Ssthresh is the slow start threshold in packets.
	Ssthresh int

	// SndCAAckCount is the number of packets consumed in congestion
	// avoidance mode.
	SndCAAckCount int

	// Outstanding is the number of packets in flight.
	Outstanding int

	// SndWnd is the send window size in bytes.
	SndWnd seqnum.Size

	// SndUna is the next unacknowledged sequence number.
	SndUna seqnum.Value

	// SndNxt is the sequence number of the next segment to be sent.
	SndNxt seqnum.Value

	// RTTMeasureSeqNum is the sequence number being used for the latest RTT
	// measurement.
	RTTMeasureSeqNum seqnum.Value

	// RTTMeasureTime is the time when the RTTMeasureSeqNum was sent.
	RTTMeasureTime time.Time

	// Closed indicates that the caller has closed the endpoint for sending.
	Closed bool

	// SRTT is the smoothed round-trip time as defined in section 2 of
	// RFC 6298.
	SRTT time.Duration

	// RTO is the retransmit timeout as defined in section of 2 of RFC 6298.
	RTO time.Duration

	// RTTVar is the round-trip time variation as defined in section 2 of
	// RFC 6298.
	RTTVar time.Duration

	// SRTTInited if true indicates take a valid RTT measurement has been
	// completed.
	SRTTInited bool

	// MaxPayloadSize is the maximum size of the payload of a given segment.
	// It is initialized on demand.
	MaxPayloadSize int

	// SndWndScale is the number of bits to shift left when reading the send
	// window size from a segment.
	SndWndScale uint8

	// MaxSentAck is the highest acknowledgement number sent till now.
	MaxSentAck seqnum.Value

	// FastRecovery holds the fast recovery state for the endpoint.
	FastRecovery TCPFastRecoveryState

	// Cubic holds the state related to CUBIC congestion control.
	Cubic TCPCubicState
}

// TCPSACKInfo holds TCP SACK related information for a given TCP endpoint.
type TCPSACKInfo struct {
	// Blocks is the list of SACK Blocks that identify the out of order segments
	// held by a given TCP endpoint.
	Blocks []header.SACKBlock

	// ReceivedBlocks are the SACK blocks received by this endpoint
	// from the peer endpoint.
	ReceivedBlocks []header.SACKBlock

	// MaxSACKED is the highest sequence number that has been SACKED
	// by the peer.
	MaxSACKED seqnum.Value
}

// RcvBufAutoTuneParams holds state related to TCP receive buffer auto-tuning.
type RcvBufAutoTuneParams struct {
	// MeasureTime is the time at which the current measurement
	// was started.
	MeasureTime time.Time

	// CopiedBytes is the number of bytes copied to user space since
	// this measure began.
	CopiedBytes int

	// PrevCopiedBytes is the number of bytes copied to user space in
	// the previous RTT period.
	PrevCopiedBytes int

	// RcvBufSize is the auto tuned receive buffer size.
	RcvBufSize int

	// RTT is the smoothed RTT as measured by observing the time between
	// when a byte is first acknowledged and the receipt of data that is at
	// least one window beyond the sequence number that was acknowledged.
	RTT time.Duration

	// RTTVar is the "round-trip time variation" as defined in section 2
	// of RFC6298.
	RTTVar time.Duration

	// RTTMeasureSeqNumber is the highest acceptable sequence number at the
	// time this RTT measurement period began.
	RTTMeasureSeqNumber seqnum.Value

	// RTTMeasureTime is the absolute time at which the current RTT
	// measurement period began.
	RTTMeasureTime time.Time

	// Disabled is true if an explicit receive buffer is set for the
	// endpoint.
	Disabled bool
}

// TCPEndpointState is a copy of the internal state of a TCP endpoint.
type TCPEndpointState struct {
	// ID is a copy of the TransportEndpointID for the endpoint.
	ID TCPEndpointID

	// SegTime denotes the absolute time when this segment was received.
	SegTime time.Time

	// RcvBufSize is the size of the receive socket buffer for the endpoint.
	RcvBufSize int

	// RcvBufUsed is the amount of bytes actually held in the receive socket
	// buffer for the endpoint.
	RcvBufUsed int

	// RcvBufAutoTuneParams is used to hold state variables to compute
	// the auto tuned receive buffer size.
	RcvAutoParams RcvBufAutoTuneParams

	// RcvClosed if true, indicates the endpoint has been closed for reading.
	RcvClosed bool

	// SendTSOk is used to indicate when the TS Option has been negotiated.
	// When sendTSOk is true every non-RST segment should carry a TS as per
	// RFC7323#section-1.1.
	SendTSOk bool

	// RecentTS is the timestamp that should be sent in the TSEcr field of
	// the timestamp for future segments sent by the endpoint. This field is
	// updated if required when a new segment is received by this endpoint.
	RecentTS uint32

	// TSOffset is a randomized offset added to the value of the TSVal field
	// in the timestamp option.
	TSOffset uint32

	// SACKPermitted is set to true if the peer sends the TCPSACKPermitted
	// option in the SYN/SYN-ACK.
	SACKPermitted bool

	// SACK holds TCP SACK related information for this endpoint.
	SACK TCPSACKInfo

	// SndBufSize is the size of the socket send buffer.
	SndBufSize int

	// SndBufUsed is the number of bytes held in the socket send buffer.
	SndBufUsed int

	// SndClosed indicates that the endpoint has been closed for sends.
	SndClosed bool

	// SndBufInQueue is the number of bytes in the send queue.
	SndBufInQueue seqnum.Size

	// PacketTooBigCount is used to notify the main protocol routine how
	// many times a "packet too big" control packet is received.
	PacketTooBigCount int

	// SndMTU is the smallest MTU seen in the control packets received.
	SndMTU int

	// Receiver holds variables related to the TCP receiver for the endpoint.
	Receiver TCPReceiverState

	// Sender holds state related to the TCP Sender for the endpoint.
	Sender TCPSenderState
}

// ResumableEndpoint is an endpoint that needs to be resumed after restore.
type ResumableEndpoint interface {
	// Resume resumes an endpoint after restore. This can be used to restart
	// background workers such as protocol goroutines. This must be called after
	// all indirect dependencies of the endpoint has been restored, which
	// generally implies at the end of the restore process.
	Resume(*Stack)
}

// uniqueIDGenerator is a default unique ID generator.
type uniqueIDGenerator uint64

func (u *uniqueIDGenerator) UniqueID() uint64 {
	return atomic.AddUint64((*uint64)(u), 1)
}

// Stack is a networking stack, with all supported protocols, NICs, and route table.
//
// Stack 是一个网络堆栈，其中包含所支持的协议、网卡和路由表。
type Stack struct {

	transportProtocols map[tcpip.TransportProtocolNumber]*transportProtocolState
	networkProtocols   map[tcpip.NetworkProtocolNumber]NetworkProtocol
	linkAddrResolvers  map[tcpip.NetworkProtocolNumber]LinkAddressResolver

	// rawFactory creates raw endpoints. If nil, raw endpoints are disabled.
	// It is set during Stack creation and is immutable.
	//
	// rawFactory 创建原始端点。如果为零，则禁用原始端点。
	// rawFactory 是在创建堆栈时设置的，是不可改变的。
	rawFactory RawFactory

	// 传输层多路复用器
	demux *transportDemuxer

	stats tcpip.Stats

	linkAddrCache *linkAddrCache

	mu               sync.RWMutex
	nics             map[tcpip.NICID]*NIC
	forwarding       bool
	cleanupEndpoints map[TransportEndpoint]struct{}


	// routeTable is the route table passed in by the user via SetRouteTable(),
	// it is used by FindRoute() to build a route for a specific destination.
	//
	// routeTable 是通过 SetRouteTable() 设置的路由表，FindRoute() 使用它来为特定目标地址创建路由。
	routeTable []tcpip.Route

	*ports.PortManager

	// If not nil, then any new endpoints will have this probe function
	// invoked everytime they receive a TCP segment.
	tcpProbeFunc TCPProbeFunc

	// clock is used to generate user-visible times.
	clock tcpip.Clock

	// handleLocal allows non-loopback interfaces to loop packets.
	handleLocal bool

	// tables are the iptables packet filtering and manipulation rules.
	tables iptables.IPTables

	// resumableEndpoints is a list of endpoints that need to be resumed if the
	// stack is being restored.
	resumableEndpoints []ResumableEndpoint

	// icmpRateLimiter is a global rate limiter for all ICMP messages generated
	// by the stack.
	icmpRateLimiter *ICMPRateLimiter

	// seed is a one-time random value initialized at stack startup
	// and is used to seed the TCP port picking on active connections
	//
	// TODO(gvisor.dev/issue/940): S/R this field.
	seed uint32

	// ndpConfigs is the default NDP configurations used by interfaces.
	ndpConfigs NDPConfigurations

	// autoGenIPv6LinkLocal determines whether or not the stack will attempt
	// to auto-generate an IPv6 link-local address for newly enabled NICs.
	// See the AutoGenIPv6LinkLocal field of Options for more details.
	autoGenIPv6LinkLocal bool

	// ndpDisp is the NDP event dispatcher that is used to send the netstack
	// integrator NDP related events.
	ndpDisp NDPDispatcher

	// uniqueIDGenerator is a generator of unique identifiers.
	uniqueIDGenerator UniqueID
}

// UniqueID is an abstract generator of unique identifiers.
type UniqueID interface {
	UniqueID() uint64
}

// Options contains optional Stack configuration.
type Options struct {
	// NetworkProtocols lists the network protocols to enable.
	NetworkProtocols []NetworkProtocol

	// TransportProtocols lists the transport protocols to enable.
	TransportProtocols []TransportProtocol

	// Clock is an optional clock source used for timestampping packets.
	//
	// If no Clock is specified, the clock source will be time.Now.
	Clock tcpip.Clock

	// Stats are optional statistic counters.
	Stats tcpip.Stats

	// HandleLocal indicates whether packets destined to their source
	// should be handled by the stack internally (true) or outside the
	// stack (false).
	HandleLocal bool

	// UniqueID is an optional generator of unique identifiers.
	UniqueID UniqueID

	// NDPConfigs is the default NDP configurations used by interfaces.
	//
	// By default, NDPConfigs will have a zero value for its
	// DupAddrDetectTransmits field, implying that DAD will not be performed
	// before assigning an address to a NIC.
	NDPConfigs NDPConfigurations

	// AutoGenIPv6LinkLocal determins whether or not the stack will attempt
	// to auto-generate an IPv6 link-local address for newly enabled NICs.
	// Note, setting this to true does not mean that a link-local address
	// will be assigned right away, or at all. If Duplicate Address
	// Detection is enabled, an address will only be assigned if it
	// successfully resolves. If it fails, no further attempt will be made
	// to auto-generate an IPv6 link-local address.
	//
	// The generated link-local address will follow RFC 4291 Appendix A
	// guidelines.
	AutoGenIPv6LinkLocal bool

	// NDPDisp is the NDP event dispatcher that an integrator can provide to
	// receive NDP related events.
	NDPDisp NDPDispatcher

	// RawFactory produces raw endpoints. Raw endpoints are enabled only if
	// this is non-nil.
	RawFactory RawFactory
}

// TransportEndpointInfo holds useful information about a transport endpoint
// which can be queried by monitoring tools.
//
// +stateify savable
type TransportEndpointInfo struct {

	// The following fields are initialized at creation time and are immutable.
	NetProto   tcpip.NetworkProtocolNumber
	TransProto tcpip.TransportProtocolNumber

	// The following fields are protected by endpoint mu.
	ID TransportEndpointID

	// BindNICID and bindAddr are set via calls to Bind().
	// They are used to reject attempts to send data or connect via a different NIC or address
	//
	// BindNICID 和 BindAddr 是通过调用 Bind() 来设置的。
	// 用于绑定连接、发送所使用的 NIC 和地址。
	BindNICID tcpip.NICID
	BindAddr  tcpip.Address

	// RegisterNICID is the default NICID registered as a side-effect of
	// connect or datagram write.
	//

	RegisterNICID tcpip.NICID
}

// IsEndpointInfo is an empty method to implement the tcpip.EndpointInfo
// marker interface.
func (*TransportEndpointInfo) IsEndpointInfo() {}





// New allocates a new networking stack with only the requested networking and
// transport protocols configured with default options.
//
// Note, NDPConfigurations will be fixed before being used by the Stack. That
// is, if an invalid value was provided, it will be reset to the default value.
//
// Protocol options can be changed by calling the
// SetNetworkProtocolOption/SetTransportProtocolOption methods provided by the
// stack. Please refer to individual protocol implementations as to what options
// are supported.
//
//
// New 构造一个新的网络协议栈。
//
// 可以通过调用堆栈提供的 SetNetworkProtocolOption/SetTransportProtocolOption 方法来更改协议选项。
//
// 请参阅各个协议的实现，以了解支持哪些选项。
func New(opts Options) *Stack {

	// 定时器
	clock := opts.Clock
	if clock == nil {
		clock = &tcpip.StdClock{}
	}

	// 唯一 ID 生成器
	if opts.UniqueID == nil {
		opts.UniqueID = new(uniqueIDGenerator)
	}

	// Make sure opts.NDPConfigs contains valid values only.
	// 确保 opts.NDPConfigs 只包含有效值。
	opts.NDPConfigs.validate()

	// 初始化构造 stack
	s := &Stack{
		transportProtocols:   make(map[tcpip.TransportProtocolNumber]*transportProtocolState),
		networkProtocols:     make(map[tcpip.NetworkProtocolNumber]NetworkProtocol),
		linkAddrResolvers:    make(map[tcpip.NetworkProtocolNumber]LinkAddressResolver),
		nics:                 make(map[tcpip.NICID]*NIC),
		cleanupEndpoints:     make(map[TransportEndpoint]struct{}),
		linkAddrCache:        newLinkAddrCache(ageLimit, resolutionTimeout, resolutionAttempts),
		PortManager:          ports.NewPortManager(),
		clock:                clock,
		stats:                opts.Stats.FillIn(),
		handleLocal:          opts.HandleLocal,
		icmpRateLimiter:      NewICMPRateLimiter(),
		seed:                 generateRandUint32(),
		ndpConfigs:           opts.NDPConfigs,
		autoGenIPv6LinkLocal: opts.AutoGenIPv6LinkLocal,
		uniqueIDGenerator:    opts.UniqueID,
		ndpDisp:              opts.NDPDisp,
	}

	// Add specified network protocols.
	// 添加网络层协议
	for _, netProto := range opts.NetworkProtocols {
		s.networkProtocols[netProto.Number()] = netProto
		// ???
		if r, ok := netProto.(LinkAddressResolver); ok {
			s.linkAddrResolvers[r.LinkAddressProtocol()] = r
		}
	}

	// Add specified transport protocols.
	// 添加传输层协议
	for _, transProto := range opts.TransportProtocols {
		s.transportProtocols[transProto.Number()] = &transportProtocolState{proto: transProto}
	}


	// Add the factory for raw endpoints, if present.
	// 如果存在的话，设置原始端点的工厂。
	s.rawFactory = opts.RawFactory

	// Create the global transport demuxer.
	// 创建全局传输解调器。
	s.demux = newTransportDemuxer(s)

	return s
}

// UniqueID returns a unique identifier.
func (s *Stack) UniqueID() uint64 {
	return s.uniqueIDGenerator.UniqueID()
}

// SetNetworkProtocolOption allows configuring individual protocol level
// options. This method returns an error if the protocol is not supported or
// option is not supported by the protocol implementation or the provided value
// is incorrect.
func (s *Stack) SetNetworkProtocolOption(network tcpip.NetworkProtocolNumber, option interface{}) *tcpip.Error {
	netProto, ok := s.networkProtocols[network]
	if !ok {
		return tcpip.ErrUnknownProtocol
	}
	return netProto.SetOption(option)
}

// NetworkProtocolOption allows retrieving individual protocol level option
// values. This method returns an error if the protocol is not supported or
// option is not supported by the protocol implementation.
// e.g.
// var v ipv4.MyOption
// err := s.NetworkProtocolOption(tcpip.IPv4ProtocolNumber, &v)
// if err != nil {
//   ...
// }
func (s *Stack) NetworkProtocolOption(network tcpip.NetworkProtocolNumber, option interface{}) *tcpip.Error {
	netProto, ok := s.networkProtocols[network]
	if !ok {
		return tcpip.ErrUnknownProtocol
	}
	return netProto.Option(option)
}

// SetTransportProtocolOption allows configuring individual protocol level
// options. This method returns an error if the protocol is not supported or
// option is not supported by the protocol implementation or the provided value
// is incorrect.
func (s *Stack) SetTransportProtocolOption(transport tcpip.TransportProtocolNumber, option interface{}) *tcpip.Error {
	transProtoState, ok := s.transportProtocols[transport]
	if !ok {
		return tcpip.ErrUnknownProtocol
	}
	return transProtoState.proto.SetOption(option)
}

// TransportProtocolOption allows retrieving individual protocol level option
// values. This method returns an error if the protocol is not supported or
// option is not supported by the protocol implementation.
// var v tcp.SACKEnabled
// if err := s.TransportProtocolOption(tcpip.TCPProtocolNumber, &v); err != nil {
//   ...
// }
func (s *Stack) TransportProtocolOption(transport tcpip.TransportProtocolNumber, option interface{}) *tcpip.Error {
	transProtoState, ok := s.transportProtocols[transport]
	if !ok {
		return tcpip.ErrUnknownProtocol
	}
	return transProtoState.proto.Option(option)
}

// SetTransportProtocolHandler sets the per-stack default handler for the given
// protocol.
//
// It must be called only during initialization of the stack. Changing it as the
// stack is operating is not supported.
func (s *Stack) SetTransportProtocolHandler(p tcpip.TransportProtocolNumber, h func(*Route, TransportEndpointID, tcpip.PacketBuffer) bool) {
	state := s.transportProtocols[p]
	if state != nil {
		state.defaultHandler = h
	}
}

// NowNanoseconds implements tcpip.Clock.NowNanoseconds.
func (s *Stack) NowNanoseconds() int64 {
	return s.clock.NowNanoseconds()
}

// Stats returns a mutable copy of the current stats.
//
// This is not generally exported via the public interface, but is available
// internally.
func (s *Stack) Stats() tcpip.Stats {
	return s.stats
}

// SetForwarding enables or disables the packet forwarding between NICs.
func (s *Stack) SetForwarding(enable bool) {
	// TODO(igudger, bgeffon): Expose via /proc/sys/net/ipv4/ip_forward.
	s.mu.Lock()
	s.forwarding = enable
	s.mu.Unlock()
}

// Forwarding returns if the packet forwarding between NICs is enabled.
// 如果启用了 NIC 之间的数据包转发，则返回 true 。
func (s *Stack) Forwarding() bool {
	// TODO(igudger, bgeffon): Expose via /proc/sys/net/ipv4/ip_forward.
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.forwarding
}

// SetRouteTable assigns the route table to be used by this stack. It
// specifies which NIC to use for given destination address ranges.
func (s *Stack) SetRouteTable(table []tcpip.Route) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.routeTable = table
}

// GetRouteTable returns the route table which is currently in use.
func (s *Stack) GetRouteTable() []tcpip.Route {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]tcpip.Route(nil), s.routeTable...)
}

// NewEndpoint creates a new transport layer endpoint of the given protocol.
func (s *Stack) NewEndpoint(transport tcpip.TransportProtocolNumber, network tcpip.NetworkProtocolNumber, waiterQueue *waiter.Queue) (tcpip.Endpoint, *tcpip.Error) {
	t, ok := s.transportProtocols[transport]
	if !ok {
		return nil, tcpip.ErrUnknownProtocol
	}

	return t.proto.NewEndpoint(s, network, waiterQueue)
}

// NewRawEndpoint creates a new raw transport layer endpoint of the given
// protocol. Raw endpoints receive all traffic for a given protocol regardless
// of address.
func (s *Stack) NewRawEndpoint(transport tcpip.TransportProtocolNumber, network tcpip.NetworkProtocolNumber, waiterQueue *waiter.Queue, associated bool) (tcpip.Endpoint, *tcpip.Error) {
	if s.rawFactory == nil {
		return nil, tcpip.ErrNotPermitted
	}

	if !associated {
		return s.rawFactory.NewUnassociatedEndpoint(s, network, transport, waiterQueue)
	}

	t, ok := s.transportProtocols[transport]
	if !ok {
		return nil, tcpip.ErrUnknownProtocol
	}

	return t.proto.NewRawEndpoint(s, network, waiterQueue)
}

// NewPacketEndpoint creates a new packet endpoint listening for the given
// netProto.
func (s *Stack) NewPacketEndpoint(cooked bool, netProto tcpip.NetworkProtocolNumber, waiterQueue *waiter.Queue) (tcpip.Endpoint, *tcpip.Error) {
	if s.rawFactory == nil {
		return nil, tcpip.ErrNotPermitted
	}

	return s.rawFactory.NewPacketEndpoint(s, cooked, netProto, waiterQueue)
}


// createNIC creates a NIC with the provided id and link-layer endpoint, and optionally enable it.
// createNIC 使用提供的 ID 和链路层端点创建 NIC ，并可以选择启用它。
func (s *Stack) createNIC(id tcpip.NICID, name string, ep LinkEndpoint, enabled, loopback bool) *tcpip.Error {

	s.mu.Lock()
	defer s.mu.Unlock()

	// Make sure id is unique.
	// 确保 id 唯一性
	if _, ok := s.nics[id]; ok {
		return tcpip.ErrDuplicateNICID
	}

	// 创建 NIC
	n := newNIC(s, id, name, ep, loopback)

	// 保存 NIC
	s.nics[id] = n

	// 启动 NIC
	if enabled {
		return n.enable()
	}

	return nil
}

// CreateNIC creates a NIC with the provided id and link-layer endpoint.
// CreateNIC 使用所提供的网卡 id 和链路层端点 ep 创建 NIC 。
func (s *Stack) CreateNIC(id tcpip.NICID, ep LinkEndpoint) *tcpip.Error {
	return s.createNIC(id, "", ep, true, false)
}

// CreateNamedNIC creates a NIC with the provided id and link-layer endpoint, and a human-readable name.
// CreateNamedNIC 使用提供的网卡 id 和链路层端点 ep 以及易于理解的名称创建 NIC 。
func (s *Stack) CreateNamedNIC(id tcpip.NICID, name string, ep LinkEndpoint) *tcpip.Error {
	return s.createNIC(id, name, ep, true, false)
}

// CreateNamedLoopbackNIC creates a NIC with the provided id and link-layer endpoint, and a human-readable name.
// CreateNamedLoopbackNIC 使用提供的网卡 id 和链路层端点 ep 以及易于理解的名称创建 NIC 。
func (s *Stack) CreateNamedLoopbackNIC(id tcpip.NICID, name string, ep LinkEndpoint) *tcpip.Error {
	return s.createNIC(id, name, ep, true, true)
}

// CreateDisabledNIC creates a NIC with the provided id and link-layer endpoint, but leave it disable.
// Stack.EnableNIC must be called before the link-layer endpoint starts delivering packets to it.
//
// CreateDisabledNIC 使用提供的 ID 和链路层端点 ep 创建 NIC ，但将其禁用。
// 在链路层端点开始向其传递数据包之前，必须先调用 Stack.EnableNIC 。
func (s *Stack) CreateDisabledNIC(id tcpip.NICID, ep LinkEndpoint) *tcpip.Error {
	return s.createNIC(id, "", ep, false, false)
}

// CreateDisabledNamedNIC is a combination of CreateNamedNIC and CreateDisabledNIC.
//
// CreateDisabledNamedNIC 是 CreateNamedNIC 和 CreateDisabledNIC 的组合。
func (s *Stack) CreateDisabledNamedNIC(id tcpip.NICID, name string, ep LinkEndpoint) *tcpip.Error {
	return s.createNIC(id, name, ep, false, false)
}

// EnableNIC enables the given NIC so that the link-layer endpoint can start delivering packets to it.
//
// EnableNIC 启用给定的 NIC ，以便链路层端点可以开始向其传递数据包。
func (s *Stack) EnableNIC(id tcpip.NICID) *tcpip.Error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	nic := s.nics[id]
	if nic == nil {
		return tcpip.ErrUnknownNICID
	}

	return nic.enable()
}

// CheckNIC checks if a NIC is usable.
// CheckNIC 检查 NIC 是否可用。
func (s *Stack) CheckNIC(id tcpip.NICID) bool {
	s.mu.RLock()
	nic, ok := s.nics[id]
	s.mu.RUnlock()
	if ok {
		return nic.linkEP.IsAttached()
	}
	return false
}

// NICSubnets returns a map of NICIDs to their associated subnets.
// NICSubnets 返回 NICID 到其关联子网的映射。
func (s *Stack) NICAddressRanges() map[tcpip.NICID][]tcpip.Subnet {
	s.mu.RLock()
	defer s.mu.RUnlock()

	nics := map[tcpip.NICID][]tcpip.Subnet{}
	for id, nic := range s.nics {
		nics[id] = append(nics[id], nic.AddressRanges()...)
	}
	return nics
}

// NICInfo captures the name and addresses assigned to a NIC.
// NICInfo 包含网卡名称和地址。
type NICInfo struct {
	// 名称
	Name              string
	// MAC 地址
	LinkAddress       tcpip.LinkAddress
	// IP 地址
	ProtocolAddresses []tcpip.ProtocolAddress
	// Flags indicate the state of the NIC.
	// 网卡状态(启动、停止、混淆、回环)
	Flags NICStateFlags
	// MTU is the maximum transmission unit.
	// 最大传输单元
	MTU uint32
	// 统计信息(发送/接收的字节数、包数)
	Stats NICStats
}

// NICInfo returns a map of NICIDs to their associated information.
//
// NICInfo 返回 NICIDs 与其相关信息的 Map 。
func (s *Stack) NICInfo() map[tcpip.NICID]NICInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()

	nics := make(map[tcpip.NICID]NICInfo)
	for id, nic := range s.nics {
		flags := NICStateFlags{
			Up:          true, // Netstack interfaces are always up.
			Running:     nic.linkEP.IsAttached(),
			Promiscuous: nic.isPromiscuousMode(),
			Loopback:    nic.linkEP.Capabilities()&CapabilityLoopback != 0,
		}
		nics[id] = NICInfo{
			Name:              nic.name,
			LinkAddress:       nic.linkEP.LinkAddress(),
			ProtocolAddresses: nic.PrimaryAddresses(),
			Flags:             flags,
			MTU:               nic.linkEP.MTU(),
			Stats:             nic.stats,
		}
	}
	return nics
}

// NICStateFlags holds information about the state of an NIC.
// NICStateFlags 保存 NIC 的状态信息。
type NICStateFlags struct {

	// Up indicates whether the interface is running.
	// Up 标识网卡是否正在运行。
	Up bool

	// Running indicates whether resources are allocated.
	// Running 标识是否已分配资源。
	Running bool

	// Promiscuous indicates whether the interface is in promiscuous mode.
	// Promiscuous 标识网卡是否处于混杂模式。
	Promiscuous bool

	// Loopback indicates whether the interface is a loopback.
	// Loopback 标识网卡是否为环回。
	Loopback bool
}


// AddAddress adds a new network-layer address to the specified NIC.
// AddAddress 将新的网络层地址添加到指定的 NIC 。
func (s *Stack) AddAddress(id tcpip.NICID, protocol tcpip.NetworkProtocolNumber, addr tcpip.Address) *tcpip.Error {
	return s.AddAddressWithOptions(id, protocol, addr, CanBePrimaryEndpoint)
}


// AddProtocolAddress adds a new network-layer protocol address to the specified NIC.
func (s *Stack) AddProtocolAddress(id tcpip.NICID, protocolAddress tcpip.ProtocolAddress) *tcpip.Error {
	return s.AddProtocolAddressWithOptions(id, protocolAddress, CanBePrimaryEndpoint)
}


// AddAddressWithOptions is the same as AddAddress, but allows you to specify
// whether the new endpoint can be primary or not.
//
// AddAddressWithOptions 与 AddAddress 相同，但是允许您指定新端点是否可以是主要端点。
func (s *Stack) AddAddressWithOptions(
	id tcpip.NICID,
	protocol tcpip.NetworkProtocolNumber,
	addr tcpip.Address,
	peb PrimaryEndpointBehavior,
) *tcpip.Error {

	// 是否支持该网络协议
	netProto, ok := s.networkProtocols[protocol]
	if !ok {
		return tcpip.ErrUnknownProtocol
	}

	//
	return s.AddProtocolAddressWithOptions(
		id,
		tcpip.ProtocolAddress{
			Protocol: protocol,
			AddressWithPrefix: tcpip.AddressWithPrefix{
				Address:   addr,
				PrefixLen: netProto.DefaultPrefixLen(),
			},
		},
		peb,
	)
}

// AddProtocolAddressWithOptions is the same as AddProtocolAddress,
// but allows you to specify whether the new endpoint can be primary or not.
//
// AddProtocolAddressWithOptions 与 AddProtocolAddress 相同，但是允许您指定新端点是否可以是主要端点。
//
func (s *Stack) AddProtocolAddressWithOptions(id tcpip.NICID, protocolAddress tcpip.ProtocolAddress, peb PrimaryEndpointBehavior) *tcpip.Error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// 根据 id 取得 NIC
	nic := s.nics[id]
	if nic == nil {
		return tcpip.ErrUnknownNICID
	}

	// 把 addr 添加到 NIC ，指定是否为 primary 端点
	return nic.AddAddress(protocolAddress, peb)
}

// AddAddressRange adds a range of addresses to the specified NIC. The range is
// given by a subnet address, and all addresses contained in the subnet are
// used except for the subnet address itself and the subnet's broadcast address.
func (s *Stack) AddAddressRange(id tcpip.NICID, protocol tcpip.NetworkProtocolNumber, subnet tcpip.Subnet) *tcpip.Error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if nic, ok := s.nics[id]; ok {
		nic.AddAddressRange(protocol, subnet)
		return nil
	}

	return tcpip.ErrUnknownNICID
}

// RemoveAddressRange removes the range of addresses from the specified NIC.
func (s *Stack) RemoveAddressRange(id tcpip.NICID, subnet tcpip.Subnet) *tcpip.Error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if nic, ok := s.nics[id]; ok {
		nic.RemoveAddressRange(subnet)
		return nil
	}

	return tcpip.ErrUnknownNICID
}

// RemoveAddress removes an existing network-layer address from the specified NIC.
func (s *Stack) RemoveAddress(id tcpip.NICID, addr tcpip.Address) *tcpip.Error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if nic, ok := s.nics[id]; ok {
		return nic.RemoveAddress(addr)
	}

	return tcpip.ErrUnknownNICID
}

// AllAddresses returns a map of NICIDs to their protocol addresses (primary and non-primary).
func (s *Stack) AllAddresses() map[tcpip.NICID][]tcpip.ProtocolAddress {
	s.mu.RLock()
	defer s.mu.RUnlock()

	nics := make(map[tcpip.NICID][]tcpip.ProtocolAddress)
	for id, nic := range s.nics {
		nics[id] = nic.AllAddresses()
	}
	return nics
}

// GetMainNICAddress returns the first primary address and prefix for the given NIC and protocol.
// Returns an error if the NIC doesn't exist and an empty value if the NIC doesn't have a primary
// address for the given protocol.
func (s *Stack) GetMainNICAddress(id tcpip.NICID, protocol tcpip.NetworkProtocolNumber) (tcpip.AddressWithPrefix, *tcpip.Error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	nic, ok := s.nics[id]
	if !ok {
		return tcpip.AddressWithPrefix{}, tcpip.ErrUnknownNICID
	}

	for _, a := range nic.PrimaryAddresses() {
		if a.Protocol == protocol {
			return a.AddressWithPrefix, nil
		}
	}
	return tcpip.AddressWithPrefix{}, nil
}

//
func (s *Stack) getRefEP(nic *NIC, localAddr tcpip.Address, netProto tcpip.NetworkProtocolNumber) (ref *referencedNetworkEndpoint) {

	// 如果没有指定本地 IP 地址
	if len(localAddr) == 0 {
		// 获取网卡 nic 上与网络协议号 netProto 关联的主端点
		return nic.primaryEndpoint(netProto)
	}

	// 如果指定了本地 IP 地址，根据该地址查询关联 ep
	return nic.findEndpoint(netProto, localAddr, CanBePrimaryEndpoint)
}


// FindRoute creates a route to the given destination address,
// leaving through the given nic and local address (if provided).
//
// FindRoute() 创建一条通往给定目标地址的路由，通过给定的 nic 和本地地址（如果提供）来发包。
//
// [重要] FindRoute() 它根据网卡 nic、本地和远端地址、网络层协议、是否广播等参数，
// 从注册到网卡 nic 上的网络层 eps 选择合适的端点的 ref ，封装成 Route 对象，以支持网络层数据包的发送。
//
//
//
func (s *Stack) FindRoute(
	id tcpip.NICID, 						// 网卡 ID
	localAddr, remoteAddr tcpip.Address, 	// 本地/远端 IP 地址
	netProto tcpip.NetworkProtocolNumber,	// 网络层协议号
	multicastLoop bool,						// 广播模式
) (Route, *tcpip.Error) {

	s.mu.RLock()
	defer s.mu.RUnlock()

	// 判断数据的传递方式: 1.广播 2.多播 3.单播
	isBroadcast := remoteAddr == header.IPv4Broadcast
	isMulticast := header.IsV4MulticastAddress(remoteAddr) || header.IsV6MulticastAddress(remoteAddr)

	// 是否需要路由: 非广播、非多播、非 IPv6 回环地址
	needRoute := !(isBroadcast || isMulticast || header.IsV6LinkLocalAddress(remoteAddr))

	// 如果指定了网卡 ID 且不需路由解析（广播、多播、回环地址），则 ...
	if id != 0 && !needRoute {

		// 根据网卡 ID 取出 nic
		if nic, ok := s.nics[id]; ok {

			// 根据本地 IP、网络协议号来获取网卡 nic 上关联的 ep ref
			if ref := s.getRefEP(nic, localAddr, netProto); ref != nil {

				// 构造路由对象
				return makeRoute(
					netProto,							// 网络层协议号
					ref.ep.ID().LocalAddress,			// 本地 IP 地址
					remoteAddr, 						// 目的 IP 地址
					nic.linkEP.LinkAddress(),			// 本地 MAC 地址
					ref,								// 远端 RefNetworkEndpoint
					s.handleLocal && !nic.loopback, 	// 回环处理
					multicastLoop && !nic.loopback,     // 多播处理
				), nil
			}
		}
	} else {

		// 遍历路由表
		for _, route := range s.routeTable {

			// [不匹配]：若网卡 ID 不匹配，或目标地址不匹配，则跳过当前表项
			if (id != 0 && id != route.NIC) || (len(remoteAddr) != 0 && !route.Destination.Contains(remoteAddr)) {
				continue
			}

			// [匹配]：取出网卡信息，
			if nic, ok := s.nics[route.NIC]; ok {

				// 根据本地 IP、网络协议号来获取网卡 nic 上关联的 ep ref
				if ref := s.getRefEP(nic, localAddr, netProto); ref != nil {


					// 如果没有设置 remoteAddr ，则将其设置为本地 mac 地址（loop back）。
					if len(remoteAddr) == 0 {
						// If no remote address was provided, then the route provided will refer to the link local address.
						remoteAddr = ref.ep.ID().LocalAddress
					}

					// 构造路由对象
					r := makeRoute(
						netProto,                       // 网络协议
						ref.ep.ID().LocalAddress,       // 本地 ip 地址
						remoteAddr,                     // 远端 ip 地址
						nic.linkEP.LinkAddress(),       // 本地 mac 地址
						ref,                            // 远端 RefNetworkEndpoint
						s.handleLocal && !nic.loopback, // 回环
						multicastLoop && !nic.loopback, // 多播
					)

					// 设置下一跳为网关 ip 地址
					if needRoute {
						r.NextHop = route.Gateway
					}

					return r, nil
				}
			}
		}
	}

	//
	if !needRoute {
		return Route{}, tcpip.ErrNetworkUnreachable
	}

	return Route{}, tcpip.ErrNoRoute
}

// CheckNetworkProtocol checks if a given network protocol is enabled in the stack.
func (s *Stack) CheckNetworkProtocol(protocol tcpip.NetworkProtocolNumber) bool {
	_, ok := s.networkProtocols[protocol]
	return ok
}

// CheckLocalAddress determines if the given local address exists, and if it
// does, returns the id of the NIC it's bound to. Returns 0 if the address
// does not exist.
//
//
// 确定给定的本地地址是否存在，如果存在，则返回它所绑定的 NIC 的 id 。如果地址不存在，则返回 0 。
func (s *Stack) CheckLocalAddress(nicID tcpip.NICID, protocol tcpip.NetworkProtocolNumber, addr tcpip.Address) tcpip.NICID {

	s.mu.RLock()
	defer s.mu.RUnlock()

	// If a NIC is specified, we try to find the address there only.
	// 如果指定了网卡，则只在该网卡上查找地址。
	if nicID != 0 {

		// 取出网卡信息
		nic := s.nics[nicID]
		if nic == nil {
			return 0
		}

		// 根据网络协议号、本地 IP 地址、端点类型确定 ENndPoint
		ref := nic.findEndpoint(protocol, addr, CanBePrimaryEndpoint)
		if ref == nil {
			return 0
		}

		// 减引用
		ref.decRef()

		// 返回网卡 ID
		return nic.id
	}

	// Go through all the NICs.
	//
	// 如果未指定网卡，则遍历所有网卡来查找地址。
	for _, nic := range s.nics {
		ref := nic.findEndpoint(protocol, addr, CanBePrimaryEndpoint)
		if ref != nil {
			ref.decRef()
			return nic.id
		}

	}

	return 0
}

// SetPromiscuousMode enables or disables promiscuous mode in the given NIC.
//
// 启用或禁用指定 NIC 上的混杂模式。
func (s *Stack) SetPromiscuousMode(nicID tcpip.NICID, enable bool) *tcpip.Error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	// 检查网卡是否存在
	nic := s.nics[nicID]
	if nic == nil {
		return tcpip.ErrUnknownNICID
	}
	// 设置混杂模式
	nic.setPromiscuousMode(enable)
	return nil
}

// SetSpoofing enables or disables address spoofing in the given NIC, allowing
// endpoints to bind to any address in the NIC.
//
// 启用或禁用指定 NIC 上的地址欺诈，允许端点绑定到 NIC 中的任何地址。
func (s *Stack) SetSpoofing(nicID tcpip.NICID, enable bool) *tcpip.Error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	// 检查网卡是否存在
	nic := s.nics[nicID]
	if nic == nil {
		return tcpip.ErrUnknownNICID
	}
	// 设置地址欺诈
	nic.setSpoofing(enable)
	return nil
}

// AddLinkAddress adds a link address to the stack link cache.
// AddLinkAddress 将 Mac 地址添加到协议栈的 ARP 缓存。
func (s *Stack) AddLinkAddress(nicID tcpip.NICID, addr tcpip.Address, linkAddr tcpip.LinkAddress) {
	fullAddr := tcpip.FullAddress{NIC: nicID, Addr: addr}
	s.linkAddrCache.add(fullAddr, linkAddr)
	// TODO: provide a way for a transport endpoint to receive a signal
	// that AddLinkAddress for a particular address has been called.
}

// GetLinkAddress implements LinkAddressCache.GetLinkAddress.
func (s *Stack) GetLinkAddress(nicID tcpip.NICID, addr, localAddr tcpip.Address, protocol tcpip.NetworkProtocolNumber, waker *sleep.Waker) (tcpip.LinkAddress, <-chan struct{}, *tcpip.Error) {

	// 根据 nicID 取出网卡信息
	s.mu.RLock()
	nic := s.nics[nicID]
	if nic == nil {
		s.mu.RUnlock()
		return "", nil, tcpip.ErrUnknownNICID
	}
	s.mu.RUnlock()

	// 构造 addr 地址
	fullAddr := tcpip.FullAddress{ NIC: nicID, Addr: addr }

	// 根据网络层协议号取出对应的地址解析器
	linkRes := s.linkAddrResolvers[protocol]

	// ...
	return s.linkAddrCache.get(fullAddr, linkRes, localAddr, nic.linkEP, waker)
}

// RemoveWaker implements LinkAddressCache.RemoveWaker.
func (s *Stack) RemoveWaker(nicID tcpip.NICID, addr tcpip.Address, waker *sleep.Waker) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if nic := s.nics[nicID]; nic == nil {
		fullAddr := tcpip.FullAddress{NIC: nicID, Addr: addr}
		s.linkAddrCache.removeWaker(fullAddr, waker)
	}
}

// RegisterTransportEndpoint registers the given endpoint with the stack
// transport dispatcher. Received packets that match the provided id will be
// delivered to the given endpoint; specifying a nic is optional, but
// nic-specific IDs have precedence over global ones.
//
// RegisterTransportEndpoint 将给定的 endpoint 注册到协议栈传输层调度器上。
// 接收到的 id 的数据包将被传送到给定的 endpoint ；
// 指定 nic 是可选的，但 nic 特定的 id 比全局的 id 优先。
//
func (s *Stack) RegisterTransportEndpoint(
	nicID tcpip.NICID, // 网卡 ID
	netProtos []tcpip.NetworkProtocolNumber, // 网络层协议
	protocol tcpip.TransportProtocolNumber,	// 传输层协议
	id TransportEndpointID, // 传输层四元组
	ep TransportEndpoint,	// 传输层 ep
	reusePort bool, // 端口重用标识
	bindToDevice tcpip.NICID, // 绑定到设备(网卡)
) *tcpip.Error {
	// 将 ep 注册到 transportDemuxer 。
	return s.demux.registerEndpoint(netProtos, protocol, id, ep, reusePort, bindToDevice)

}

// UnregisterTransportEndpoint removes the endpoint with the given id from the
// stack transport dispatcher.
func (s *Stack) UnregisterTransportEndpoint(
	nicID tcpip.NICID,
	netProtos []tcpip.NetworkProtocolNumber,
	protocol tcpip.TransportProtocolNumber,
	id TransportEndpointID,
	ep TransportEndpoint,
	bindToDevice tcpip.NICID,
) {
	s.demux.unregisterEndpoint(netProtos, protocol, id, ep, bindToDevice)
}

// StartTransportEndpointCleanup removes the endpoint with the given id from the stack transport dispatcher.
// It also transitions it to the cleanup stage.
//
// 从堆栈传输调度器中删除给定id的端点。
func (s *Stack) StartTransportEndpointCleanup(
	nicID tcpip.NICID,
	netProtos []tcpip.NetworkProtocolNumber,
	protocol tcpip.TransportProtocolNumber,
	id TransportEndpointID,
	ep TransportEndpoint,
	bindToDevice tcpip.NICID,
) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.cleanupEndpoints[ep] = struct{}{}

	s.demux.unregisterEndpoint(netProtos, protocol, id, ep, bindToDevice)
}

// CompleteTransportEndpointCleanup removes the endpoint from the cleanup stage.
func (s *Stack) CompleteTransportEndpointCleanup(ep TransportEndpoint) {
	s.mu.Lock()
	delete(s.cleanupEndpoints, ep)
	s.mu.Unlock()
}

// FindTransportEndpoint finds an endpoint that most closely matches the provided id.
// If no endpoint is found it returns nil.
func (s *Stack) FindTransportEndpoint(
	netProto tcpip.NetworkProtocolNumber,
	transProto tcpip.TransportProtocolNumber,
	id TransportEndpointID,
	r *Route,
) TransportEndpoint {
	return s.demux.findTransportEndpoint(netProto, transProto, id, r)
}

// RegisterRawTransportEndpoint registers the given endpoint with the stack
// transport dispatcher. Received packets that match the provided transport
// protocol will be delivered to the given endpoint.
//
// RegisterRawTransportEndpoint() 将给定的端点注册到协议栈传输层分发器中。
// 当协议栈接收到与 netProto、transProto 协议相匹配的数据包时，会投递给这些 ep 。
func (s *Stack) RegisterRawTransportEndpoint(
	nicID tcpip.NICID,
	netProto tcpip.NetworkProtocolNumber,
	transProto tcpip.TransportProtocolNumber,
	ep RawTransportEndpoint,
) *tcpip.Error {
	return s.demux.registerRawEndpoint(netProto, transProto, ep)
}

// UnregisterRawTransportEndpoint removes the endpoint for the transport
// protocol from the stack transport dispatcher.
func (s *Stack) UnregisterRawTransportEndpoint(
	nicID tcpip.NICID,
	netProto tcpip.NetworkProtocolNumber,
	transProto tcpip.TransportProtocolNumber,
	ep RawTransportEndpoint,
) {
	s.demux.unregisterRawEndpoint(netProto, transProto, ep)
}

// RegisterRestoredEndpoint records e as an endpoint that has been restored on
// this stack.
func (s *Stack) RegisterRestoredEndpoint(e ResumableEndpoint) {
	s.mu.Lock()
	s.resumableEndpoints = append(s.resumableEndpoints, e)
	s.mu.Unlock()
}

// RegisteredEndpoints returns all endpoints which are currently registered.
func (s *Stack) RegisteredEndpoints() []TransportEndpoint {
	s.mu.Lock()
	defer s.mu.Unlock()
	var es []TransportEndpoint
	for _, e := range s.demux.protocol {
		es = append(es, e.transportEndpoints()...)
	}
	return es
}

// CleanupEndpoints returns endpoints currently in the cleanup state.
func (s *Stack) CleanupEndpoints() []TransportEndpoint {
	s.mu.Lock()
	es := make([]TransportEndpoint, 0, len(s.cleanupEndpoints))
	for e := range s.cleanupEndpoints {
		es = append(es, e)
	}
	s.mu.Unlock()
	return es
}

// RestoreCleanupEndpoints adds endpoints to cleanup tracking. This is useful
// for restoring a stack after a save.
func (s *Stack) RestoreCleanupEndpoints(es []TransportEndpoint) {
	s.mu.Lock()
	for _, e := range es {
		s.cleanupEndpoints[e] = struct{}{}
	}
	s.mu.Unlock()
}

// Close closes all currently registered transport endpoints.
//
// Endpoints created or modified during this call may not get closed.
func (s *Stack) Close() {
	for _, e := range s.RegisteredEndpoints() {
		e.Close()
	}
}

// Wait waits for all transport and link endpoints to halt their worker
// goroutines.
//
// Endpoints created or modified during this call may not get waited on.
//
// Note that link endpoints must be stopped via an implementation specific
// mechanism.
func (s *Stack) Wait() {

	//
	for _, e := range s.RegisteredEndpoints() {
		e.Wait()
	}

	//
	for _, e := range s.CleanupEndpoints() {
		e.Wait()
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	//
	for _, n := range s.nics {
		n.linkEP.Wait()
	}
}

// Resume restarts the stack after a restore. This must be called after the
// entire system has been restored.
func (s *Stack) Resume() {
	// ResumableEndpoint.Resume() may call other methods on s,
	// so we can't hold s.mu while resuming the endpoints.
	s.mu.Lock()
	eps := s.resumableEndpoints
	s.resumableEndpoints = nil
	s.mu.Unlock()
	for _, e := range eps {
		e.Resume(s)
	}
}

// RegisterPacketEndpoint registers ep with the stack, causing it to receive
// all traffic of the specified netProto on the given NIC. If nicID is 0, it
// receives traffic from every NIC.
func (s *Stack) RegisterPacketEndpoint(nicID tcpip.NICID, netProto tcpip.NetworkProtocolNumber, ep PacketEndpoint) *tcpip.Error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// If no NIC is specified, capture on all devices.
	if nicID == 0 {
		// Register with each NIC.
		for _, nic := range s.nics {
			if err := nic.registerPacketEndpoint(netProto, ep); err != nil {
				s.unregisterPacketEndpointLocked(0, netProto, ep)
				return err
			}
		}
		return nil
	}

	// Capture on a specific device.
	nic, ok := s.nics[nicID]
	if !ok {
		return tcpip.ErrUnknownNICID
	}
	if err := nic.registerPacketEndpoint(netProto, ep); err != nil {
		return err
	}

	return nil
}

// UnregisterPacketEndpoint unregisters ep for packets of the specified
// netProto from the specified NIC. If nicID is 0, ep is unregistered from all NICs.
func (s *Stack) UnregisterPacketEndpoint(nicID tcpip.NICID, netProto tcpip.NetworkProtocolNumber, ep PacketEndpoint) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.unregisterPacketEndpointLocked(nicID, netProto, ep)
}

func (s *Stack) unregisterPacketEndpointLocked(nicID tcpip.NICID, netProto tcpip.NetworkProtocolNumber, ep PacketEndpoint) {
	// If no NIC is specified, unregister on all devices.
	if nicID == 0 {
		// Unregister with each NIC.
		for _, nic := range s.nics {
			nic.unregisterPacketEndpoint(netProto, ep)
		}
		return
	}

	// Unregister in a single device.
	nic, ok := s.nics[nicID]
	if !ok {
		return
	}
	nic.unregisterPacketEndpoint(netProto, ep)
}

// WritePacket writes data directly to the specified NIC.
// It adds an ethernet header based on the arguments.
func (s *Stack) WritePacket(nicID tcpip.NICID, dst tcpip.LinkAddress, netProto tcpip.NetworkProtocolNumber, payload buffer.VectorisedView) *tcpip.Error {
	s.mu.Lock()
	nic, ok := s.nics[nicID]
	s.mu.Unlock()
	if !ok {
		return tcpip.ErrUnknownDevice
	}

	// Add our own fake ethernet header.
	ethFields := header.EthernetFields{
		SrcAddr: nic.linkEP.LinkAddress(),
		DstAddr: dst,
		Type:    netProto,
	}

	fakeHeader := make(header.Ethernet, header.EthernetMinimumSize)
	fakeHeader.Encode(&ethFields)
	vv := buffer.View(fakeHeader).ToVectorisedView()
	vv.Append(payload)

	if err := nic.linkEP.WriteRawPacket(vv); err != nil {
		return err
	}

	return nil
}

// WriteRawPacket writes data directly to the specified NIC without adding any headers.
func (s *Stack) WriteRawPacket(nicID tcpip.NICID, payload buffer.VectorisedView) *tcpip.Error {
	s.mu.Lock()
	nic, ok := s.nics[nicID]
	s.mu.Unlock()
	if !ok {
		return tcpip.ErrUnknownDevice
	}

	if err := nic.linkEP.WriteRawPacket(payload); err != nil {
		return err
	}

	return nil
}

// NetworkProtocolInstance returns the protocol instance in the stack for the
// specified network protocol.
//
// This method is public for protocol implementers and tests to use.
func (s *Stack) NetworkProtocolInstance(num tcpip.NetworkProtocolNumber) NetworkProtocol {
	if p, ok := s.networkProtocols[num]; ok {
		return p
	}
	return nil
}

// TransportProtocolInstance returns the protocol instance in the stack for the
// specified transport protocol.
//
// This method is public for protocol implementers and tests to use.
func (s *Stack) TransportProtocolInstance(num tcpip.TransportProtocolNumber) TransportProtocol {
	if pState, ok := s.transportProtocols[num]; ok {
		return pState.proto
	}
	return nil
}

// AddTCPProbe installs a probe function that will be invoked on every segment
// received by a given TCP endpoint. The probe function is passed a copy of the
// TCP endpoint state before and after processing of the segment.
//
// NOTE: TCPProbe is added only to endpoints created after this call. Endpoints
// created prior to this call will not call the probe function.
//
// Further, installing two different probes back to back can result in some
// endpoints calling the first one and some the second one. There is no
// guarantee provided on which probe will be invoked. Ideally this should only
// be called once per stack.
func (s *Stack) AddTCPProbe(probe TCPProbeFunc) {
	s.mu.Lock()
	s.tcpProbeFunc = probe
	s.mu.Unlock()
}

// GetTCPProbe returns the TCPProbeFunc if installed with AddTCPProbe, nil
// otherwise.
func (s *Stack) GetTCPProbe() TCPProbeFunc {
	s.mu.Lock()
	p := s.tcpProbeFunc
	s.mu.Unlock()
	return p
}

// RemoveTCPProbe removes an installed TCP probe.
//
// NOTE: This only ensures that endpoints created after this call do not
// have a probe attached. Endpoints already created will continue to invoke
// TCP probe.
func (s *Stack) RemoveTCPProbe() {
	s.mu.Lock()
	s.tcpProbeFunc = nil
	s.mu.Unlock()
}

// JoinGroup joins the given multicast group on the given NIC.
func (s *Stack) JoinGroup(protocol tcpip.NetworkProtocolNumber, nicID tcpip.NICID, multicastAddr tcpip.Address) *tcpip.Error {
	// TODO: notify network of subscription via igmp protocol.
	s.mu.RLock()
	defer s.mu.RUnlock()

	if nic, ok := s.nics[nicID]; ok {
		return nic.joinGroup(protocol, multicastAddr)
	}
	return tcpip.ErrUnknownNICID
}

// LeaveGroup leaves the given multicast group on the given NIC.
func (s *Stack) LeaveGroup(protocol tcpip.NetworkProtocolNumber, nicID tcpip.NICID, multicastAddr tcpip.Address) *tcpip.Error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if nic, ok := s.nics[nicID]; ok {
		return nic.leaveGroup(multicastAddr)
	}
	return tcpip.ErrUnknownNICID
}

// IPTables returns the stack's iptables.
func (s *Stack) IPTables() iptables.IPTables {
	return s.tables
}

// SetIPTables sets the stack's iptables.
func (s *Stack) SetIPTables(ipt iptables.IPTables) {
	s.tables = ipt
}

// ICMPLimit returns the maximum number of ICMP messages that can be sent
// in one second.
func (s *Stack) ICMPLimit() rate.Limit {
	return s.icmpRateLimiter.Limit()
}

// SetICMPLimit sets the maximum number of ICMP messages that be sent
// in one second.
func (s *Stack) SetICMPLimit(newLimit rate.Limit) {
	s.icmpRateLimiter.SetLimit(newLimit)
}

// ICMPBurst returns the maximum number of ICMP messages that can be sent
// in a single burst.
func (s *Stack) ICMPBurst() int {
	return s.icmpRateLimiter.Burst()
}

// SetICMPBurst sets the maximum number of ICMP messages that can be sent
// in a single burst.
func (s *Stack) SetICMPBurst(burst int) {
	s.icmpRateLimiter.SetBurst(burst)
}

// AllowICMPMessage returns true if we the rate limiter allows at least one
// ICMP message to be sent at this instant.
func (s *Stack) AllowICMPMessage() bool {
	return s.icmpRateLimiter.Allow()
}

// IsAddrTentative returns true if addr is tentative on the NIC with ID id.
//
// Note that if addr is not associated with a NIC with id ID, then this
// function will return false. It will only return true if the address is
// associated with the NIC AND it is tentative.
func (s *Stack) IsAddrTentative(id tcpip.NICID, addr tcpip.Address) (bool, *tcpip.Error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	nic, ok := s.nics[id]
	if !ok {
		return false, tcpip.ErrUnknownNICID
	}

	return nic.isAddrTentative(addr), nil
}

// DupTentativeAddrDetected attempts to inform the NIC with ID id that a
// tentative addr on it is a duplicate on a link.
func (s *Stack) DupTentativeAddrDetected(id tcpip.NICID, addr tcpip.Address) *tcpip.Error {
	s.mu.Lock()
	defer s.mu.Unlock()

	nic, ok := s.nics[id]
	if !ok {
		return tcpip.ErrUnknownNICID
	}

	return nic.dupTentativeAddrDetected(addr)
}

// SetNDPConfigurations sets the per-interface NDP configurations on the NIC
// with ID id to c.
//
// Note, if c contains invalid NDP configuration values, it will be fixed to
// use default values for the erroneous values.
func (s *Stack) SetNDPConfigurations(id tcpip.NICID, c NDPConfigurations) *tcpip.Error {
	s.mu.Lock()
	defer s.mu.Unlock()

	nic, ok := s.nics[id]
	if !ok {
		return tcpip.ErrUnknownNICID
	}

	nic.setNDPConfigs(c)

	return nil
}

// HandleNDPRA provides a NIC with ID id a validated NDP Router Advertisement
// message that it needs to handle.
func (s *Stack) HandleNDPRA(id tcpip.NICID, ip tcpip.Address, ra header.NDPRouterAdvert) *tcpip.Error {
	s.mu.Lock()
	defer s.mu.Unlock()

	nic, ok := s.nics[id]
	if !ok {
		return tcpip.ErrUnknownNICID
	}

	nic.handleNDPRA(ip, ra)

	return nil
}

// Seed returns a 32 bit value that can be used as a seed value for port
// picking, ISN generation etc.
//
// NOTE: The seed is generated once during stack initialization only.
func (s *Stack) Seed() uint32 {
	return s.seed
}

func generateRandUint32() uint32 {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return binary.LittleEndian.Uint32(b)
}
