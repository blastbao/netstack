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

package tcp

import (
	"math"
	"sync"
	"sync/atomic"
	"time"

	"github.com/blastbao/netstack/sleep"
	"github.com/blastbao/netstack/tcpip"
	"github.com/blastbao/netstack/tcpip/buffer"
	"github.com/blastbao/netstack/tcpip/header"
	"github.com/blastbao/netstack/tcpip/seqnum"
)

const (

	// minRTO is the minimum allowed value for the retransmit timeout.
	//
	// minRTO 是重传超时的最小值。
	minRTO = 200 * time.Millisecond

	// InitialCwnd is the initial congestion window.
	//
	// InitialCwnd 是初始拥塞窗口。
	InitialCwnd = 10

	// nDupAckThreshold is the number of duplicate ACK's required before fast-retransmit is entered.
	//
	// nDupAckThreshold 是指进入快速重传前所需的重复 ACK 数量，默认为 3 。
	nDupAckThreshold = 3
)


// ccState indicates the current congestion control state for this sender.
//
// 拥塞控制状态。
//
// 当 sender 收到一个 ack 时，Linux TCP 通过状态机(state)来决定发送行为，
// 是应该降低 cwnd 呢，还是保持 cwnd 不变，还是继续增加 cwnd ，这很重要。
// 如果处理不当，可能会导致丢包或者 timeout 。
//
// 主要有五种状态，分别是：Open，Disorder，CWR，Recovery 和 Loss 。
//
//
type ccState int

const (

	// Open indicates that the sender is receiving acks in order and
	// no loss or dupACK's etc have been detected.
	//
	// Open 表示发送方正在按顺序接收 ACK ，没有发现丢失或 dupACKs 等情况。
	// 当网络中没有发生丢包，也就不需要重传，sender 按照正常的流程处理到来的ACK。
	Open ccState = iota



	// RTORecovery indicates that an RTO has occurred and the sender
	// has entered an RTO based recovery phase.
	//
	// RTORecovery 表示发生了超时(RTO)，发送方进入了基于 RTO 的恢复阶段。
	//
	// 当超时后，TCP sender 进入 RTORecovery 状态，所有在网络中的包被标记为 lost ，
	// cwnd 重置为1，通过 slow start 重新增加 cwnd ，
	// RTORecovery 与 FastRecovery 状态的不同点在于，cwnd 会重置为 1 ，
	// 但是 FastRecovery 状态不会，它会降到之前的一半。
	//
	// RTORecovery 状态不能被其它任何状态中断，只有当网络中所有的包被成功 ACK 后，才能重新进入 Open 状态。
	RTORecovery


	// FastRecovery indicates that the sender has entered FastRecovery
	// based on receiving nDupAck's. This state is entered only when
	// SACK is not in use.
	//
	// FastRecovery 表示发送方在收到 nDupAck 的基础上进入 FastRecovery 状态。
	// 这个状态只有在 SACK 不使用时才会进入。
	//
	// 当 sender 连续收到多个（默认3）Dup ACK 时，意味着丢包了，
	// 这时 sender 会重传第一个未被 ACK 的包，并进入 Recovery 状态。
	// 在 Recovery 状态期间，cwnd 不会降低，要么重传标记了 lost 的包，要么根据保守原则发送新包。
	// 直到网络中所有的包都被 ACK ，才会退出 Recovery 进入 Open 状态，Recovery 状态可以被 RTORecovery 状态打断。
	FastRecovery


	// SACKRecovery indicates that the sender has entered SACK based recovery.
	//
	// SACKRecovery 表示发送方已进入基于 SACK 的恢复。
	SACKRecovery



	// Disorder indicates the sender either received some SACK blocks or dupACK's.
	//
	// Disorder 表示发送方要么收到一些 SACK 块，要么收到 dup ACK 。
	//
	// 当 sender 检测到 Dup ACK 或者 SACK ，将会转移到 Disorder 状态，当处在这个这个状态中时，
	// cwnd 将不做调整，但每收到一个 Dup ACK 或 SACK ，sender 将发送一个新包。
	Disorder

)

// congestionControl is an interface that must be implemented by any supported
// congestion control algorithm.
type congestionControl interface {

	// HandleNDupAcks is invoked when sender.dupAckCount >= nDupAckThreshold
	// just before entering fast retransmit.
	//
	// 当 sender.dupAckCount >= nDupAckThreshold 刚好进入快速重传之前，将调用 HandleNDupAcks 。
	HandleNDupAcks()

	// HandleRTOExpired is invoked when the retransmit timer expires.
	//
	// 重传计时器到期时，将调用 HandleRTOExpired 。
	HandleRTOExpired()

	// Update is invoked when processing inbound acks. It's passed the
	// number of packet's that were acked by the most recent cumulative
	// acknowledgement.
	//
	// Update 是在处理入栈的 ACK 时调用的，它的入参是最近累积的 ACK 。
	Update(packetsAcked int)

	// PostRecovery is invoked when the sender is exiting a fast retransmit/
	// recovery phase. This provides congestion control algorithms a way
	// to adjust their state when exiting recovery.
	//
	// 当发送方退出 快重传/快恢复 阶段时，将调用 PostRecovery 。
	// 这为拥塞控制算法提供了一种在退出恢复时调整其状态的方法。
	PostRecovery()
}

// sender holds the state necessary to send TCP segments.
//
// +stateify savable
type sender struct {
	ep *endpoint

	// lastSendTime is the timestamp when the last packet was sent.
	//
	// lastSendTime 是最后一个数据包发送的时间戳。
	lastSendTime time.Time

	// dupAckCount is the number of duplicated acks received.
	// It is used for fast retransmit.
	//
	// dupAckCount 是收到的重复的 acks 的数量。它用于快速重传。
	dupAckCount int

	// fr holds state related to fast recovery.
	//
	// 快速恢复相关状态。
	fr fastRecovery

	// sndCwnd is the congestion window, in packets.
	// 拥塞窗口，它是对发送端收到确认(ACK)前能向网络传送的最大数据量的限制。
	sndCwnd int

	// sndSsthresh is the threshold between slow start and congestion avoidance.
	//
	// 慢启动阈值，用于确定是用慢启动还是拥塞避免算法来控制数据传送，具体用法如下:
	// 	当 cwnd < ssthresh 时，使用慢启动算法；
	// 	当 cwnd > ssthresh 时，使用拥塞避免算法；
	// 	当 cwnd = ssthresh 时，发送端既可以使用慢启动也可以使用拥塞避免。
	// ssthresh 的初始值可以任意大(比如，一些实现中使用接收端通知窗口 rcvWnd 的d大小)，但是一旦对拥塞响应之后，其大小可能会被减小。
	sndSsthresh int

	// sndCAAckCount is the number of packets acknowledged during congestion avoidance.
	// When enough packets have been ack'd (typically cwnd packets),
	// the congestion window is incremented by one.
	//
	// sndCAAckCount 是指在拥塞避免过程中确认的数据包数量。
	// 当有足够多的数据包被 ack'd（通常是 cwnd 个数据包）时，拥塞窗口会增加。
	//
	sndCAAckCount int

	// outstanding is the number of outstanding packets, that is, packets
	// that have been sent but not yet acknowledged.
	//
	// outstanding 是已发送但尚未被确认的数据包。
	outstanding int





	//						 +-------> sndWnd <-------+
	//						 |                        |
	//	---------------------+-------------+----------+--------------------
	//	|      acked         | * * * * * * | # # # # #|   unable send
	//	---------------------+-------------+----------+--------------------
	//						 ^             ^
	//						 |             |
	// 					   sndUna        sndNxt
	//
	//
	// (-, sndUna) 					: old sequence numbers which have been acknowledged
	// [sndUna, sndNxt) 			: sequence numbers of unacknowledged data
	// [sndNxt, sndUna + sndWnd) 	: sequence numbers allowed for new data transmission
	// [sndUna + sndWnd, -) 		: future sequence numbers which are not yet allowed
	//





	// sndWnd is the send window size.
	// sndWnd 是接受端通告的窗口大小。
	sndWnd seqnum.Size

	// sndUna is the next unacknowledged sequence number.
	// sndUna 表示是下一个未确认的序列号。
	sndUna seqnum.Value

	// sndNxt is the sequence number of the next segment to be sent.
	// sndNxt 是要发送的下一个段的序列号。
	sndNxt seqnum.Value

	// sndNxtList is the sequence number of the next segment to be added to the send list.
	sndNxtList seqnum.Value

	// rttMeasureSeqNum is the sequence number being used for the latest RTT measurement.
	// rttMeasureSeqNum 是用于测量 RTT 的最新序列号。
	rttMeasureSeqNum seqnum.Value

	// rttMeasureTime is the time when the rttMeasureSeqNum was sent.
	// rttMeasureTime 是发送 rtMeasureSeqNum 的时间。
	rttMeasureTime time.Time

	closed      bool
	writeNext   *segment
	writeList   segmentList
	resendTimer timer
	resendWaker sleep.Waker

	// rtt.srtt, rtt.rttvar, and rto are the "smoothed round-trip time",
	// "round-trip time variation" and "retransmit timeout", as defined in
	// section 2 of RFC 6298.
	rtt rtt  			//
	rto time.Duration   // resend timeout

	// maxPayloadSize is the maximum size of the payload of a given segment.
	// It is initialized on demand.
	//
	// maxPayloadSize 指定段的最大有效载荷。
	maxPayloadSize int

	// gso is set if generic segmentation offload is enabled.
	//
	// TSO(TCP Segmentation Offload): 是一种利用网卡来对大数据包进行自动分段，降低 CPU 负载的技术。其主要是延迟分段。
	// GSO(Generic Segmentation Offload): GSO 是协议栈是否推迟分段，在发送到网卡之前判断网卡是否支持 TSO ，如果网卡支持TSO则让网卡分段，否则协议栈分完段再交给驱动。
	//
	// 如果 TSO 开启，GSO 会自动开启，以下是 TSO 和 GSO 的组合关系：
	//  GSO开启，TSO开启: 协议栈推迟分段，并直接传递大数据包到网卡，让网卡自动分段
	//  GSO开启，TSO关闭: 协议栈推迟分段，在最后发送到网卡前才执行分段
	//  GSO关闭，TSO开启: 同 GSO 开启， TSO 开启
	//  GSO关闭，TSO关闭: 不推迟分段，在 tcp_sendmsg 中直接发送 MSS 大小的数据包
	gso bool

	// sndWndScale is the number of bits to shift left when reading the send
	// window size from a segment.
	//
	// 对端接收窗口扩大因子
	sndWndScale uint8

	// maxSentAck is the maxium acknowledgement actually sent.
	//
	// maxSentAck 保存了最近一次发送的数据包中的 ACK 确认序号。
	// 只要不是延迟 ACK ，maxSentAck 的值总是和 e.rcvNxt 相等的 。
	maxSentAck seqnum.Value

	// state is the current state of congestion control for this endpoint.
	state ccState

	// cc is the congestion control algorithm in use for this sender.
	cc congestionControl
}


// rtt is a synchronization wrapper used to appease stateify. See the comment
// in sender, where it is used.
//
// +stateify savable
type rtt struct {
	sync.Mutex

	srtt       time.Duration
	rttvar     time.Duration
	srttInited bool
}


// fastRecovery holds information related to fast recovery from a packet loss.
// fastRecovery 保存了与数据包丢失后快速恢复相关的信息。
//
//
// +stateify savable
type fastRecovery struct {

	// active whether the endpoint is in fast recovery.
	// The following fields are only meaningful when active is true.
	//
	// active 表示 endpoint 是否处于快速恢复状态，以下字段只有在 active 为 true 时才有意义。
	active bool


	// first and last represent the inclusive sequence number range being recovered.
	//
	// first 和 last 代表正在恢复的序列号范围。
	first seqnum.Value	//  s.sndUna
	last  seqnum.Value  //  s.sndNxt - 1

	// maxCwnd is the maximum value the congestion window may be inflated to
	// due to duplicate acks. This exists to avoid attacks where the receiver
	// intentionally sends duplicate acks to artificially inflate the sender's cwnd.
	//
	// maxCwnd 是由于重复的 acks 而可能导致拥塞窗口膨胀的最大值。
	// 这个值的存在是为了避免攻击，因为接收方会故意发送重复的 ack 来人为地增加发送方的cwnd。
	//
	maxCwnd int


	// highRxt is the highest sequence number which has been retransmitted
	// during the current loss recovery phase.
	// See: RFC 6675 Section 2 for details.
	//
	// highRxt 是重传的最大序列号。
	highRxt seqnum.Value


	// rescueRxt is the highest sequence number which has been
	// optimistically retransmitted to prevent stalling of the ACK clock
	// when there is loss at the end of the window and no new data is
	// available for transmission.
	// See: RFC 6675 Section 2 for details.
	//
	// rescueRxt 是最高序列号，当窗口结束时有丢失，没有新数据可供传输时，为了防止 ACK 时钟停滞，该序列号被优化重传。
	//
	rescueRxt seqnum.Value
}



func newSender(ep *endpoint, iss, irs seqnum.Value, sndWnd seqnum.Size, mss uint16, sndWndScale int) *sender {

	// The sender MUST reduce the TCP data length to account for any IP or
	// TCP options that it is including in the packets that it sends.
	// See: https://tools.ietf.org/html/rfc6691#section-2
	maxPayloadSize := int(mss) - ep.maxOptionSize()

	s := &sender{
		ep:               ep,
		sndWnd:           sndWnd,
		sndUna:           iss + 1,
		sndNxt:           iss + 1,
		sndNxtList:       iss + 1,
		rto:              1 * time.Second,
		rttMeasureSeqNum: iss + 1,
		lastSendTime:     time.Now(),
		maxPayloadSize:   maxPayloadSize,
		maxSentAck:       irs + 1,

		// 快速恢复
		fr: fastRecovery{
			// See: https://tools.ietf.org/html/rfc6582#section-3.2 Step 1.
			last:      iss,
			highRxt:   iss,
			rescueRxt: iss,
		},

		//
		gso: ep.gso != nil,
	}

	if s.gso {
		s.ep.gso.MSS = uint16(maxPayloadSize)
	}

	s.cc = s.initCongestionControl(ep.cc)

	// A negative sndWndScale means that no scaling is in use, otherwise we store the scaling value.
	// 负的 sndWndScale 表示没有使用缩放。
	if sndWndScale > 0 {
		s.sndWndScale = uint8(sndWndScale)
	}

	s.resendTimer.init(&s.resendWaker)

	s.updateMaxPayloadSize(int(ep.route.MTU()), 0)

	// Initialize SACK Scoreboard after updating max payload size as we use
	// the maxPayloadSize as the smss when determining if a segment is lost etc.
	//
	//
	//
	//
	s.ep.scoreboard = NewSACKScoreboard(uint16(s.maxPayloadSize), iss)

	return s
}

// initCongestionControl initializes the specified congestion control module and
// returns a handle to it. It also initializes the sndCwnd and sndSsThresh to
// their initial values.
//
// initCongestionControl 初始化拥塞控制模块并返回一个接口。
func (s *sender) initCongestionControl(congestionControlName tcpip.CongestionControlOption) congestionControl {

	s.sndCwnd = InitialCwnd				// 初始拥塞窗口，默认 10 个 segment 。
	s.sndSsthresh = math.MaxInt64 		// 慢启动和拥塞避免之间的阈值，初始可以是任意值，后面会趋于稳定。

	switch congestionControlName {      // 创建拥塞控制对象，默认为 Reno 算法。
	case ccCubic:
		return newCubicCC(s)
	case ccReno:
		fallthrough
	default:
		return newRenoCC(s)
	}
}

// updateMaxPayloadSize updates the maximum payload size based on the given
// MTU. If this is in response to "packet too big" control packets (indicated
// by the count argument), it also reduces the number of outstanding packets and
// attempts to retransmit the first packet above the MTU size.
//
// MTU 最大传输单元是指一种通信协议的某一层上面所能通过的最大数据包大小（以字节为单位）。
// MTU 最大传输单元通常与通信接口有关（网络接口卡、串口等）。
//
// updateMaxPayloadSize 根据给定的 MTU 更新最大有效载荷大小。
// 如果这是为了响应 "数据包过大" 的控制数据包（由 count 参数指示），它还会减少未发送数据包的数量，
// 并尝试重传第一个超过 MTU 大小的数据包。
//
func (s *sender) updateMaxPayloadSize(mtu, count int) {

	// 根据 mtu 计算可用的 tcp 载荷
	m := mtu - header.TCPMinimumSize
	m -= s.ep.maxOptionSize()

	// We don't adjust up for now.
	if m >= s.maxPayloadSize {
		return
	}

	// Make sure we can transmit at least one byte.
	if m <= 0 {
		m = 1
	}

	// 如果最大有效载荷减小了，则更新
	s.maxPayloadSize = m

	//
	if s.gso {
		s.ep.gso.MSS = uint16(m)
	}


	if count == 0 {
		// updateMaxPayloadSize is also called when the sender is created.
		// and there is no data to send in such cases. Return immediately.
		return
	}

	// Update the scoreboard's smss to reflect the new lowered maxPayloadSize.
	s.ep.scoreboard.smss = uint16(m)

	s.outstanding -= count
	if s.outstanding < 0 {
		s.outstanding = 0
	}

	// Rewind writeNext to the first segment exceeding the MTU.
	// Do nothing if it is already before such a packet.
	for seg := s.writeList.Front(); seg != nil; seg = seg.Next() {



		if seg == s.writeNext {
			// We got to writeNext before we could find a segment exceeding the MTU.
			break
		}

		if seg.data.Size() > m {
			// We found a segment exceeding the MTU.
			// Rewind writeNext and try to retransmit it.
			s.writeNext = seg
			break
		}
	}

	// Since we likely reduced the number of outstanding packets,
	// we may be ready to send some more.
	s.sendData()
}

// sendAck sends an ACK segment.
func (s *sender) sendAck() {
	s.sendSegmentFromView(buffer.VectorisedView{}, header.TCPFlagAck, s.sndNxt)
}



// updateRTO updates the retransmit timeout when a new roud-trip time is available.
// This is done in accordance with section 2 of RFC 6298.
//
// 根据 rtt 计算 rto ，并更新到 s.rto 上。
func (s *sender) updateRTO(rtt time.Duration) {
	s.rtt.Lock()

	if !s.rtt.srttInited {
		s.rtt.rttvar = rtt / 2
		s.rtt.srtt = rtt
		s.rtt.srttInited = true
	} else {
		diff := s.rtt.srtt - rtt
		if diff < 0 {
			diff = -diff
		}
		// Use RFC6298 standard algorithm to update rttvar and srtt when
		// no timestamps are available.
		if !s.ep.sendTSOk {
			s.rtt.rttvar = (3*s.rtt.rttvar + diff) / 4
			s.rtt.srtt = (7*s.rtt.srtt + rtt) / 8
		} else {
			// When we are taking RTT measurements of every ACK then
			// we need to use a modified method as specified in
			// https://tools.ietf.org/html/rfc7323#appendix-G
			if s.outstanding == 0 {
				s.rtt.Unlock()
				return
			}
			// Netstack measures congestion window/inflight all in
			// terms of packets and not bytes. This is similar to
			// how linux also does cwnd and inflight. In practice
			// this approximation works as expected.
			expectedSamples := math.Ceil(float64(s.outstanding) / 2)

			// alpha & beta values are the original values as recommended in
			// https://tools.ietf.org/html/rfc6298#section-2.3.
			const alpha = 0.125
			const beta = 0.25
			alphaPrime := alpha / expectedSamples
			betaPrime := beta / expectedSamples
			rttVar := (1-betaPrime)*s.rtt.rttvar.Seconds() + betaPrime*diff.Seconds()
			srtt := (1-alphaPrime)*s.rtt.srtt.Seconds() + alphaPrime*rtt.Seconds()
			s.rtt.rttvar = time.Duration(rttVar * float64(time.Second))
			s.rtt.srtt = time.Duration(srtt * float64(time.Second))
		}
	}

	s.rto = s.rtt.srtt + 4*s.rtt.rttvar
	s.rtt.Unlock()
	if s.rto < minRTO {
		s.rto = minRTO
	}
}

// resendSegment resends the first unacknowledged segment.
// resendSegment 重新发送第一个未确认的段。
func (s *sender) resendSegment() {

	// Don't use any segments we already sent to measure RTT as they may
	// have been affected by packets being lost.
	//
	// 不要使用已经发送的段来测量 RTT，因为它们可能会受到数据包丢失的影响。
	s.rttMeasureSeqNum = s.sndNxt

	// Resend the segment.
	if seg := s.writeList.Front(); seg != nil {

		// 拆分大包
		if seg.data.Size() > s.maxPayloadSize {
			s.splitSeg(seg, s.maxPayloadSize)
		}

		// See: RFC 6675 section 5 Step 4.3
		//
		// To prevent retransmission, set both the HighRXT and RescueRXT
		// to the highest sequence number in the retransmitted segment.
		//
		// 为了防止重传，将 HighRXT 和 RescueRXT 都设置为重传段中的最高序列号。
		//
		s.fr.highRxt = seg.sequenceNumber.Add(seqnum.Size(seg.data.Size())) - 1
		s.fr.rescueRxt = seg.sequenceNumber.Add(seqnum.Size(seg.data.Size())) - 1
		s.sendSegment(seg)
		s.ep.stack.Stats().TCP.FastRetransmit.Increment()
		s.ep.stats.SendErrors.FastRetransmit.Increment()

		// Run SetPipe() as per RFC 6675 section 5 Step 4.4
		s.SetPipe()
	}
}

// retransmitTimerExpired is called when the retransmit timer expires, and
// unacknowledged segments are assumed lost, and thus need to be resent.
// Returns true if the connection is still usable, or false if the connection
// is deemed lost.
//
// retransmitTimerExpired 在重传计时器过期时被调用，未被确认的段认为是丢失了，需要重新发送。
// 如果连接仍然可用，retransmitTimerExpired 返回 true ，否则返回 false 。
//
func (s *sender) retransmitTimerExpired() bool {

	// Check if the timer actually expired or if it's a spurious wake due
	// to a previously orphaned runtime timer.
	//
	// 检查定时器是否真的过期，还是虚假唤醒。
	if !s.resendTimer.checkExpiration() {
		return true
	}

	s.ep.stack.Stats().TCP.Timeouts.Increment() // 超时统计
	s.ep.stats.SendErrors.Timeouts.Increment()	// 超时统计

	// Give up if we've waited more than a minute since the last resend.
	//
	// 如果自上次重发后，已经等待超过一分钟，就放弃吧。
	if s.rto >= 60*time.Second {
		return false
	}

	// Set new timeout.
	// The timer will be restarted by the call to sendData below.
	//
	// 下面调用 sendData 将重新启动定时器。
	s.rto *= 2

	// See: https://tools.ietf.org/html/rfc6582#section-3.2 Step 4.
	//
	// Retransmit timeouts:
	//     After a retransmit timeout, record the highest sequence number
	//     transmitted in the variable recover, and exit the fast recovery
	//     procedure if applicable.
	//
	//
	//
	s.fr.last = s.sndNxt - 1

	// active 为 true 表示 endpoint 正处于 `快速恢复` 状态中，
	// 但此函数被调，意味着发生超时，即在 `快速恢复` 状态中发生丢包，需要退出 `快速恢复` 状态。
	if s.fr.active {
		// We were attempting fast recovery but were not successful.
		// Leave the state. We don't need to update ssthresh because it
		// has already been updated when entered fast-recovery.
		s.leaveFastRecovery()
	}


	// 发生重传超时，设置状态，表示进入了基于 RTO 的恢复阶段。
	s.state = RTORecovery

	// 重传定时器超时，意味着出现丢包，调用 cc.HandleRTOExpired() 方法。
	// 以 reno 算法为例，需要：
	// 	(1) 减少 ssthresh 到 1/2
	//	(2) 进入慢启动
	s.cc.HandleRTOExpired()


	// Mark the next segment to be sent as the first unacknowledged one and
	// start sending again. Set the number of outstanding packets to 0 so
	// that we'll be able to retransmit.
	//
	// We'll keep on transmitting (or retransmitting) as we get acks for
	// the data we transmit.
	//
	// outstanding 是已发送但尚未被确认的数据包，这里把其置 0 ，是因为当前要重传超时的包，
	// 意味着无需再等待这些包的 ACK ，也意味着所有已发送的包的 ACK 均已收到。
	s.outstanding = 0


	// Expunge all SACK information as per https://tools.ietf.org/html/rfc6675#section-5.1
	//
	//  In order to avoid memory deadlocks, the TCP receiver is allowed to
	//  discard data that has already been selectively acknowledged. As a
	//  result, [RFC2018] suggests that a TCP sender SHOULD expunge the SACK
	//  information gathered from a receiver upon a retransmission timeout
	//  (RTO) "since the timeout might indicate that the data receiver has
	//  reneged." Additionally, a TCP sender MUST "ignore prior SACK
	//  information in determining which data to retransmit."
	//
	// NOTE: We take the stricter interpretation and just expunge all
	// information as we lack more rigorous checks to validate if the SACK
	// information is usable after an RTO.
	s.ep.scoreboard.Reset()
	s.writeNext = s.writeList.Front()



	s.sendData()


	return true
}

// pCount returns the number of packets in the segment. Due to GSO, a segment
// can be composed of multiple packets.
func (s *sender) pCount(seg *segment) int {
	size := seg.data.Size()
	if size == 0 {
		return 1
	}

	return (size-1)/s.maxPayloadSize + 1
}

// splitSeg splits a given segment at the size specified and inserts the
// remainder as a new segment after the current one in the write list.
//
// splitSeg 以指定的大小分割一个给定的段，并将剩余的段作为一个新段插入到写列表中的当前段之后。
func (s *sender) splitSeg(seg *segment, size int) {

	// 参数检查
	if seg.data.Size() <= size {
		return
	}

	// Split this segment up.

	// 拷贝生成新段 nSeg ，删除其前 size 字节后，插入到当前段 seg 后面。
	nSeg := seg.clone()
	nSeg.data.TrimFront(size)
	nSeg.sequenceNumber.UpdateForward(seqnum.Size(size))
	s.writeList.InsertAfter(seg, nSeg)
	// 用 size 截断当前 seg ，完成段的分割。
	seg.data.CapLength(size)
}

// NextSeg implements the RFC6675 NextSeg() operation. It returns segments that
// match rule 1, 3 and 4 of the NextSeg() operation defined in RFC6675. Rule 2
// is handled by the normal send logic.
//
// NextSeg() 需要根据 SACK 信息，决定快速恢复阶段那个分段可以被发送，规则为：
//（1）如果存在满足以下三个条件的 “最小未SACK序列号” ，那么该分段被发送：
// 		a. 序列号大于HighRxt；
// 		b. 比已收到的SACK最大值要小；
// 		c. IsLost返回true，即该报文段判定为丢失。
//（2）发送 HighData + 1 的新数据；
//（3）满足 1.1 和 1.2 ，但不满足 1.3 的数据段。
//
func (s *sender) NextSeg() (nextSeg1, nextSeg3, nextSeg4 *segment) {
	var s3 *segment
	var s4 *segment
	smss := s.ep.scoreboard.SMSS()

	// Step 1.
	//
	// 遍历所有已发送的 segment 。
	for seg := s.writeList.Front(); seg != nil; seg = seg.Next() {

		// 若 seg 尚未发送，则 break ，后面的 seg 也均未发送，无需遍历。
		if !s.isAssignedSequenceNumber(seg) {
			break
		}

		// 获取 seg 的起始序号。
		segSeq := seg.sequenceNumber

		// 段最大不超过 smss ，若超过则 split 。
		if seg.data.Size() > int(smss) {
			s.splitSeg(seg, int(smss))
		}


		// See RFC 6675 Section 4
		//
		//     1. If there exists a smallest unSACKED sequence number
		//     'S2' that meets the following 3 criteria for determinig
		//     loss, the sequence range of one segment of up to SMSS
		//     octects starting with S2 MUST be returned.
		//
		//
		// 若当前 seg 被 sacked ，则需要重传。
		//
		if !s.ep.scoreboard.IsSACKED(header.SACKBlock{segSeq, segSeq.Add(1)}) {



			// NextSeg():
			//
			//    (1.a) S2 is greater than HighRxt
			//    (1.b) S2 is less than highest octect covered by any received SACK.
			//
			//
			//
			//
			if s.fr.highRxt.LessThan(segSeq) && segSeq.LessThan(s.ep.scoreboard.maxSACKED) {

				// NextSeg():
				//     (1.c) IsLost(S2) returns true.
				//
				// 若给定序号已经丢失，就直接返回。
				if s.ep.scoreboard.IsLost(segSeq) {
					return seg, s3, s4
				}


				// NextSeg():
				//
				// (3): If the conditions for rules (1) and (2)
				// fail, but there exists an unSACKed sequence
				// number S3 that meets the criteria for
				// detecting loss given in steps 1.a and 1.b
				// above (specifically excluding (1.c)) then one
				// segment of upto SMSS octets starting with S3
				// SHOULD be returned.
				if s3 == nil {
					s3 = seg
				}
			}



			// NextSeg():
			//
			//     (4) If the conditions for (1), (2) and (3) fail,
			//     but there exists outstanding unSACKED data, we
			//     provide the opportunity for a single "rescue"
			//     retransmission per entry into loss recovery. If
			//     HighACK is greater than RescueRxt, the one
			//     segment of upto SMSS octects that MUST include
			//     the highest outstanding unSACKed sequence number
			//     SHOULD be returned.
			//
			//
			//
			//
			if s.fr.rescueRxt.LessThan(s.sndUna - 1) {
				if s4 != nil {
					if s4.sequenceNumber.LessThan(segSeq) {
						s4 = seg
					}
				} else {
					s4 = seg
				}
				s.fr.rescueRxt = s.fr.last
			}

		}
	}

	return nil, s3, s4
}

// maybeSendSegment tries to send the specified segment and either coalesces
// other segments into this one or splits the specified segment based on the
// lower of the specified limit value or the receivers window size specified by
// end.
//
// maybeSendSegment 试图发送指定的段，并将其他段合并到这个段中，
// 或者根据指定的限制值或 end 指定的接收者窗口大小中的较低值来分割指定的段。
//
// 参数说明：
// 	limit 是当前能发送的最大载荷（字节数）。
// 	end 是发送窗口 [sndUna, sndUna+sndWnd) 的右端，也即发送窗口能容纳的最大序号。
//
// 返回值：
//  false:
//		(a) Nagle 算法或者 cork 标记位，决定对小段进行延迟发送。
// 		(b) 发送窗口无法容纳新的段。
//  true:
//		成功执行段的发送。
func (s *sender) maybeSendSegment(seg *segment, limit int, end seqnum.Value) (sent bool) {


	// We abuse the flags field to determine if we have already
	// assigned a sequence number to this segment.

	// 确定是否已经为该段分配了序列号，如果尚未分配，则分配给它新的序号，并设置 flag 。
	if !s.isAssignedSequenceNumber(seg) {

		// Merge segments if allowed.
		// 段合并：将小 seg 合并成大 seg 再发送出去。

		// 若 `eg.data.Size() == 0` 意味着是一个 FIN 段，它是 TCP 连接上的最后一个段，且不含数据，无需合并。
		if seg.data.Size() != 0 {
			// 发送窗口的最大序号，减去当前分配序号，即本次所能发送的字节数 available 。
			available := int(seg.sequenceNumber.Size(end))
			// 如果本次所能发送字节数，超过单个段的最大载荷，则限制到最大载荷数。
			if available > limit {
				available = limit
			}

			// nextTooBig indicates that the next segment was too
			// large to entirely fit in the current segment. It
			// would be possible to split the next segment and merge
			// the portion that fits, but unexpectedly splitting
			// segments can have user visible side-effects which can
			// break applications. For example, RFC 7766 section 8
			// says that the length and data of a DNS response
			// should be sent in the same TCP segment to avoid
			// triggering bugs in poorly written DNS
			// implementations.
			//
			// nextTooBig 表示下一个段太大，无法完全容纳在当前段中。
			// 可以拆分下个段，并合并适合的部分，但是意外地拆分片段可能会给用户带来明显的副作用，从而破坏应用程序，
			// 所以，当下个段过大时，不进行合并，直接发送当前段。
			//
			// 例如，RFC 7766 第 8 节指出，DNS 响应的长度和数据应该在同一个TCP段中发送，以避免在编写不佳的 DNS 实现中引发 bug 。


			// 执行相邻段的合并，直到合并数据将超过 available 或者无可合并的段为止。
			var nextTooBig bool
			for seg.Next() != nil && seg.Next().data.Size() != 0 {
				// 当下个段过大时，不进行合并，直接发送当前段。否则，进行段的合并。
				if seg.data.Size()+seg.Next().data.Size() > available {
					nextTooBig = true
					break
				}
				seg.data.Append(seg.Next().data)	// 段的数据合并
				s.writeList.Remove(seg.Next()) 		// 将已合并段从 s.writeList 中移除    //Consume the segment that we just merged in.
			}

			// 条件判断:
			// 	(1) nextTooBig == false ，意味着要么 s.writeList 中仅此一个 seg ，要么 s.writeList 中所有 seg 合并后也不足 available 字节。
			// 	(2) seg.data.Size() < available ，意味着当前 seg 的载荷不足 available 字节。
			if !nextTooBig && seg.data.Size() < available {

				// Segment is not full.
				// 至此，当前 segment 不满。

				// Nagle 检测
				//
				// 条件判断:
				// 	(1) outstanding > 0 ，意味着存在已发送但尚未被确认的数据包。
				// 	(2) delay != 0 ，意味着开启 Nagle 算法。
				//
				// 此二条件同时发生，意味着满足 Nagle 算法触发条件，当前包应该被缓存，延迟发送。
				if s.outstanding > 0 && atomic.LoadUint32(&s.ep.delay) != 0 {

					// Nagle's algorithm. From Wikipedia:
					//   Nagle's algorithm works by
					//   combining a number of small
					//   outgoing messages and sending them
					//   all at once. Specifically, as long
					//   as there is a sent packet for which
					//   the sender has received no
					//   acknowledgment, the sender should
					//   keep buffering its output until it
					//   has a full packet's worth of
					//   output, thus allowing output to be
					//   sent all at once.

					// Nagle 算法的工作原理是将一些小的数据合并起来，然后一次性发出去。
					// 具体来说，只要存在尚未收到确认的已发送数据包，发送方就应持续缓存待输出数据，
					// 直到获得一个完整的数据包为止，从而一次性发送这个完整的数据包。
					//
					// Nagle 能够有效减少小数据包的发送，提高信道利用率（提高有效数据占比）。
					return false
				}

				// 如果设置了 cork 标记位，则必须等到 segment 满才能发送。
				if atomic.LoadUint32(&s.ep.cork) != 0 {
					// Hold back the segment until full.
					return false
				}
				// 至此，即便当前 segment 不满，也应该发送出去。
			}
			// 至此，或者当前段已经足够大；或者当前段不够大，但下个段过大，不适宜合并到当前段；或者当前段不够大，但是 tcp 选项指明要立即发送，则直接发送。
		}

		// Assign flags.
		// We don't do it above so that we can merge additional data if Nagle holds the segment.
		//
		// 设置标记位。
		// 我们不在上面设置，是因为如果 Nagle 持有该段数据，我们可以合并这些额外数据。

		seg.sequenceNumber = s.sndNxt						// 设置要发送的段的序号
		seg.flags = header.TCPFlagAck | header.TCPFlagPsh	// 设置 ACK/PSH 标记位
	}


	var segEnd seqnum.Value
	if seg.data.Size() == 0 {

		// We're sending a FIN segment.
		// 正在发送 FIN 段。

		// FIN 段必须是写入列表中的最后一个段。
		if s.writeList.Back() != seg {
			panic("FIN segments must be the final segment in the write list.")
		}

		// 设置标记位为 ACK | FIN 。
		seg.flags = header.TCPFlagAck | header.TCPFlagFin

		// 增加报文序号
		segEnd = seg.sequenceNumber.Add(1)

		// Transition to FIN-WAIT1 state since we're initiating an active close.
		// 调整状态机 。
		s.ep.mu.Lock()
		switch s.ep.state {
		case StateCloseWait:
			// We've already received a FIN and are now sending our own.
			// The sender is now awaiting a final ACK for this FIN.
			//
			// 对方主动四次挥手，我们收到了 FIN 则会进入到 CLOSE_WAIT 状态，现在要发送我们自己的 FIN ，并进入状态 LAST_ACK 。
			s.ep.state = StateLastAck
		default:
			// 本方主动四次挥手，进入 FIN-WAIT1 状态。
			s.ep.state = StateFinWait1
		}

		s.ep.stack.Stats().TCP.CurrentEstablished.Decrement()
		s.ep.mu.Unlock()

	} else {

		// We're sending a non-FIN segment.
		// 正在发送非 FIN 段。
		if seg.flags&header.TCPFlagFin != 0 {
			panic("Netstack queues FIN segments without data.")
		}

		// 要发送的段的序号不能超过发送窗口的最大值。
		if !seg.sequenceNumber.LessThan(end) {
			return false
		}

		// 计算发送窗口可容纳的字节数
		available := int(seg.sequenceNumber.Size(end))
		if available == 0 {
			return false
		}

		// 计算可发送字节数 available = min(available, limit)
		if available > limit {
			available = limit
		}

		// 如果当前 segment 数据量较大，需要拆分成两个段，保存到 s.writeList 中。（备注：如果当前 segment 过大，前面并不会处理，会在这里进行 split）
		if seg.data.Size() > available {
			s.splitSeg(seg, available)
		}

		// 更新 sndNxt
		segEnd = seg.sequenceNumber.Add(seqnum.Size(seg.data.Size()))
	}

	// 执行 seg 的发送
	s.sendSegment(seg)

	// Update sndNxt if we actually sent new data (as opposed to retransmitting some previously sent data).
	// 如果确实发送了新数据，则需要更新 sndNxt（而不是重传一些之前发送的数据）。
	if s.sndNxt.LessThan(segEnd) {
		s.sndNxt = segEnd
	}

	return true
}

// handleSACKRecovery implements the loss recovery phase as described in RFC6675
// section 5, step C.
//
//
// 发送端根据接收到的 SACK 信息执行选择性重传(selective retransmisson 或者叫做 selective repeat)。
// 首先根据 SACK 信息来填充洞，然后在传递新数据(RFC6675)，但是具体实现上可能会有一些差异 。
// 另外按照RFC2018, 当 TCP 初始化一个 RTO 超时重传的时候，需要清空 SACK 信息，
// 但是 RFC6675 认为 RTO 超时保留 SACK 信息也是有一定必要性的。
//
// RFC2018 还要求发送端只有收到 TCP 头中的累计 ack number 的时候才能释放对应的发送缓存，
// 而不能根据 SACK 信息释放，原因是接收端有可能先发送一个 SACK 块，然后后面又不在反馈这个 SACK 块(SACK reneging)。
//
// (实际上按照协议发送端接收到的 SACK 块可能是接收端已经丢弃的 TCP 报文，
// 虽然这个报文丢弃了但是特定情况下接收端仍然可以在SACK块中携带这个报文信息，
// 而在实现上如果linux内存不足，那么有可能会丢掉已经收到的乱序TCP报文)。
//
//
func (s *sender) handleSACKRecovery(limit int, end seqnum.Value) (dataSent bool) {

	s.SetPipe()



	//
	for s.outstanding < s.sndCwnd {

		nextSeg, s3, s4 := s.NextSeg()

		if nextSeg == nil {

			// NextSeg():
			//
			// Step (2): "If no sequence number 'S2' per rule (1)
			// exists but there exists available unsent data and the
			// receiver's advertised window allows, the sequence
			// range of one segment of up to SMSS octets of
			// previously unsent data starting with sequence number
			// HighData+1 MUST be returned."
			//
			for seg := s.writeNext; seg != nil; seg = seg.Next() {

				if s.isAssignedSequenceNumber(seg) && seg.sequenceNumber.LessThan(s.sndNxt) {
					continue
				}

				// Step C.3 described below is handled by
				// maybeSendSegment which increments sndNxt when
				// a segment is transmitted.
				//
				// Step C.3 "If any of the data octets sent in
				// (C.1) are above HighData, HighData must be
				// updated to reflect the transmission of
				// previously unsent data."
				if sent := s.maybeSendSegment(seg, limit, end); !sent {
					break
				}

				dataSent = true
				s.outstanding++
				s.writeNext = seg.Next()
				nextSeg = seg
				break
			}

			if nextSeg != nil {
				continue
			}
		}


		rescueRtx := false
		if nextSeg == nil && s3 != nil {
			nextSeg = s3
		}

		if nextSeg == nil && s4 != nil {
			nextSeg = s4
			rescueRtx = true
		}

		if nextSeg == nil {
			break
		}

		segEnd := nextSeg.sequenceNumber.Add(nextSeg.logicalLen())
		if !rescueRtx && nextSeg.sequenceNumber.LessThan(s.sndNxt) {
			// RFC 6675, Step C.2
			//
			// "If any of the data octets sent in (C.1) are below
			// HighData, HighRxt MUST be set to the highest sequence
			// number of the retransmitted segment unless NextSeg ()
			// rule (4) was invoked for this retransmission."
			s.fr.highRxt = segEnd - 1
		}


		// RFC 6675, Step C.4.
		//
		// "The estimate of the amount of data outstanding in the network
		// must be updated by incrementing pipe by the number of octets
		// transmitted in (C.1)."
		s.outstanding++
		dataSent = true
		s.sendSegment(nextSeg)
	}

	return dataSent
}




// sendData sends new data segments.
// It is called when data becomes available or when the send window opens up.
//
//
// sendData
//    maybeSendSegment
//        sendSegment
//            sendSegmentFromView
//                sendRaw        --connect.go
//                    sendTCP
//                        r.WritePacket(gso, hdr, data, ProtocolNumber, ttl)
//                            WritePacket        --third_party\golibs\github.com\google\netstack\tcpip\stack\route.go
//                                r.ref.ep.WritePacket //TODO,后面的分析不对，到此截止。
//                            e.linkEP.WritePacket    --third_party\golibs\github.com\google\netstack\tcpip\link\fdbased\endpoint.go
//                                rawfile.NonBlockingWrite3    --third_party\golibs\github.com\google\netstack\tcpip\link\rawfile\rawfile_unsafe.go
//                                    NonBlockingWrite
//                                        syscall.RawSyscall(syscall.SYS_WRITE, uintptr(fd), uintptr(ptr), uintptr(len(buf)))
//
//
func (s *sender) sendData() {

	// 段的最大有效载荷
	limit := s.maxPayloadSize

	// 如果设置了 gso (通用延迟分段) ，则业务侧可以发送更大的包
	if s.gso {
		limit = int(s.ep.gso.MaxSize - header.TCPHeaderMaximumSize)
	}

	// 计算发送窗口 [sndUna, sndUna+sndWnd) 的右端，即所能发送的最大序号。
	end := s.sndUna.Add(s.sndWnd)

	// Reduce the congestion window to min(IW, cwnd) per RFC 5681, page 10.
	// "A TCP SHOULD set cwnd to no more than RW before beginning
	// transmission if the TCP has not sent data in the interval exceeding
	// the retrasmission timeout."
	//
	// TCP 拥塞控制算法的一个已知问题是，它允许在 TCP 闲置相对较长的时间后，发送出暴涨的流量。
	// 因为，在闲置过程中，TCP 不能使用 ACK 包的时钟来评估拥链路塞情况，导致 TCP 有可能在空闲
	// 期后向网络中发送一个 cwnd 大小的突发流量。
	//
	// 在闲置过程中，网络状况可能发生变化，若此时发送超大流量，可能会增加丢包情况。
	//
	// 根据 RFC 5681 第 10 页的规定，如果连接闲置了相对长的时间(这里是 RTO)，再次发送时，
	// 需要将拥塞窗口减少到 min(InitialCwnd, cwnd)，避免因为拥塞评估的不准确，造成链路因拥塞而丢包。
	if !s.fr.active && time.Now().Sub(s.lastSendTime) > s.rto {
		if s.sndCwnd > InitialCwnd {
			s.sndCwnd = InitialCwnd
		}
	}

	var dataSent bool

	// RFC 6675 recovery algorithm step C 1-5.
	//
	// 如果当前处于快速恢复阶段，且开启了 sack 选项，需要执行 快速恢复+选择重传 逻辑。
	if s.fr.active && s.ep.sackPermitted {
		//
		dataSent = s.handleSACKRecovery(s.maxPayloadSize, end)
	} else {

		// 逐个段的发送，如果发送窗口被填满，或者触发了延迟发送（小包），则 break 退出。
		for seg := s.writeNext; seg != nil && s.outstanding < s.sndCwnd; seg = seg.Next() {

			// 由 s.sndCwnd - s.outstanding 计算出还可以发送的段数目，乘以 s.maxPayloadSize 得到能发送的最大字节数 cwndLimit 。
			cwndLimit := (s.sndCwnd - s.outstanding) * s.maxPayloadSize
			// min(cwndLimit, limit) 计算出当前能发送的实际字节数。
			if cwndLimit < limit {
				limit = cwndLimit
			}

			// 判断是否已经分配序号
			if s.isAssignedSequenceNumber(seg) && s.ep.sackPermitted && s.ep.scoreboard.IsSACKED(seg.sackBlock()) {
				continue
			}

			// 执行 seg 的发送，内部可能会进行拆分和合并。
			// 注：如果 sent 为 false，则要么发送窗口无法容纳新的段，要么当前所有段不足以构成一个包大小(nagle)，需要延迟发送，因此 break 掉。
			if sent := s.maybeSendSegment(seg, limit, end); !sent {
				break
			}

			// 至此，当前 seg 被成功发送。
			dataSent = true
			s.outstanding += s.pCount(seg) 	// 更新 outstanding (已发送但尚未被确认的包数目)。
			s.writeNext = seg.Next() 		// 当前段已经完成发送，移动到下个段进行写入。

		}
	}

	// 如果数据被成功发送，应该停止 keepalive 定时器，以确保在有待处理数据(已发送未确认)时不发送 keepalive 报文。
	if dataSent {
		// We sent data, so we should stop the keepalive timer to ensure
		// that no keepalives are sent while there is pending data.
		s.ep.disableKeepaliveTimer()
	}

	// Enable the timer if we have pending data and it's not enabled yet.
	// 如果我们有待处理的数据(s.sndUna != s.sndNxt)，并且尚未启用重传定时器(!s.resendTimer.enabled())，则启用重传定时器(定时间隔为s.rto)。
	if !s.resendTimer.enabled() && s.sndUna != s.sndNxt {
		s.resendTimer.enable(s.rto)
	}

	// If we have no more pending data, start the keepalive timer.
	// 如果没有待处理(已发送未确认)的数据，就启动 keepalive 定时器。
	if s.sndUna == s.sndNxt {
		s.ep.resetKeepaliveTimer(false)
	}
}


// 进入快重传阶段。
//
// 快速重传和快速恢复算法一般同时使用。
// 快速恢复算法是认为，你还有 3 个 Duplicated Acks 说明网络也不那么糟糕，
// 所以没有必要像 RTO 超时那么强烈，并不需要重新回到慢启动进行，这样可能降低效率。
//
// 启动快速恢复算法：
// 	1. 设置 cwnd = ssthresh ＋ ACK 个数＊MSS（一般情况下会是 3 个 dup ACK ）
// 	2. 重传丢失的数据包（对于重传丢失的那个数据包，可以参考TCP-IP详解：SACK选项）
// 	3. 如果只收到 Dup ACK ，那么 cwnd = cwnd + 1 ， 并且在允许的条件下发送一个报文段
// 	4. 如果收到新的 ACK , 设置 cwnd = ssthresh ， 退出快速恢复，进入拥塞避免阶段
func (s *sender) enterFastRecovery() {

	// 设置 `快速恢复` 状态为 true
	s.fr.active = true

	// Save state to reflect we're now in fast recovery.
	//
	// See : https://tools.ietf.org/html/rfc5681#section-3.2 Step 3.
	// We inflate the cwnd by 3 to account for the 3 packets which triggered
	// the 3 duplicate ACKs and are now not in flight.

	// 适当缩小发送拥塞窗口，用来控制发送端在收到 ACK 前能向网络传送的最大数据量的限制。
	s.sndCwnd = s.sndSsthresh + 3

	// 快速恢复的序号区间为 [first, last]，其初始值为进入快速恢复时的 [sndUna, sndNxt - 1] ，
	// 在快速恢复阶段，若收到 dup ack ，即 ack < first ，忽略或者 cnd+1（算法不同，行为不同），
	// 若收到新的有效 ack ，若 ack in [first, last] 则为部分确认，则将 first 右移相应位，
	// 若 ack > last ，则为全部确认，直接退出快速恢复，进入拥塞避免。
	//
	//
	// 设置起始序号，sndUna 表示是下一个未确认的序列号
	s.fr.first = s.sndUna
	// 设置结束序号，sndNxt 表示要发送的下一个段的序列号
	s.fr.last = s.sndNxt - 1

	// 设置快速恢复阶段，拥塞窗口能增加的最大值。
	//
	// 在快速恢复阶段，重复的 acks 而可能导致拥塞窗口不断增加，
	// 为了避免恶意接收方故意发送重复的 ack 来人为地增加发送方的 cwnd ，带来安全隐患，设置了最大值。
	s.fr.maxCwnd = s.sndCwnd + s.outstanding

	// 修改拥塞控制状态为 "快速重传"。
	// (1) 如果允许 sack 选择重传，则修改状态为 SACKRecovery 。
	if s.ep.sackPermitted {
		s.state = SACKRecovery
		s.ep.stack.Stats().TCP.SACKRecovery.Increment()
		return
	}
	// (2) 否则，修改状态为 FastRecovery 。
	s.state = FastRecovery
	s.ep.stack.Stats().TCP.FastRecovery.Increment()
}

// 退出 `快速恢复` ，重置关联状态，并将 sndCwnd 设置为 ssthresh，重新进入 `拥塞避免` 阶段。
func (s *sender) leaveFastRecovery() {
	s.fr.active = false
	s.fr.maxCwnd = 0
	s.dupAckCount = 0

	// Deflate cwnd. It had been artificially inflated when new dups arrived.
	s.sndCwnd = s.sndSsthresh
	s.cc.PostRecovery()
}




// 本函数调用路径： handleRcvdSegment -> checkDuplicateAck -> handleFastRecovery
//
//
//
// 快速恢复
//
// `快速恢复` 遵循数据包守恒原则，即同一个时刻在网络中的数据包数量恒定，“老” 数据包离开后，才能向网络中发送 “新” 的数据包。
// 如果发送方收到一个 DUP ACK ，就表明有一个数据包从网络中离开，此时 cwnd 加 1 。
//
//
//
// Reno 算法：
//
// Reno 算法在完成快速重传后，进入了拥塞避免阶段，而不像 Tahoe 进入慢启动阶段。
// Reno 算法描述：
//	step1：
//  	if ( dupacks >= 3 ) {
//			ssthresh = max( 2 , cwnd / 2 ) ;
//  		cwnd = ssthresh + 3 * SMSS ;
// 		}
//	step2：[快速重传] 重传丢失的分组
//	step3：[快速恢复] 此后每收到一个重复的 ACK 确认时，cwnd++
//	step4：[快速恢复 -> 拥塞避免] 当收到新的数据包的 ACK 时，也即非重复 ACK 时，cwnd = ssthresh，转入拥塞避免阶段。
//		   原因是因为该 ACK 确认了新的数据，说明从重复 ACK 时的数据都已收到，该恢复过程已经结束，能再次进入拥塞避免状态。
//
// 在过程中，如果发生超时重传，则置 ssthresh 为当前 cwnd 的一半，设置 cwnd = 1，重新进入慢启动阶段。
//
//
//
// NewReno 算法：
//
// NewReno 修改了 Reno 的快速恢复算法，使能处理一个窗口中的多个报文段同时丢失时出现的 “部分确认” 情况，
//（Partial ACKs，它在快速恢复阶段到达并且确认新数据，但它只确认进入快速重传之前所发送的一部分数据，而非全部）。
//
// 在这种情况下，Reno 会退出快速恢复状态，进入拥塞避免状态，等待定时器溢出(如果没有后续包的发送)或者重复的确认 ACK 到达(再次触发快速重传)，
// 但是 NewReno 并不退出快速恢复状态，而是：
// 	step1：重传紧接着那个部分 ACK 之后的报文段，拥塞窗口等于其减去 partial ACK 的部分。
// 	step2：对于得到确认的新数据，cwnd++
// 	step3：对于第一个或每一个 Partial ACK ，重传定时器复位。且每次都重置 cwnd = 原cwnd/2。
//
// NewReno 算法中有变量 recover ，其值为检测到丢包时的最大发送序列号。
// 只有当 recover 之前的数据报都确认完后，才能退出快速恢复，进入拥塞避免阶段。
// 当超时时，将发送的最大序列号保存在 recover 变量中，结束快速恢复过程。
//
// 注意，NewReno 不支持 SACK 。
//
// SACK 算法：
// 	step 1:
//		Fast Recovery is initiated,
//      	pipe -1 ( for the packet assumed to have been dropped).
//      	pipe +1 ( for the packet retransmitted)
//         	cwnd = cwnd / 2
//	step 2 :
//   	If pipe <= cwnd，sender retransmits packets inferred to be missing.
//    	If there are no such packets, sender sends new packets.
//	step 3:
//    	when sender receives a dup ACK, pipe = pipe - 1
//   	when sender sends a new / retransmit an old packet, pipe = pipe +1
//	step 4:
//   	For partial ACKs ：pipe = pipe - 2 (one for original dropped packet，one for retransmitted packet)
//	step 5:
//   	all packets outstanding before Fast Recovery were ACKed, exit Fast Recovery.
// 		当退出 Fast Recovery 时，cwnd 同样恢复成 ssthresh ，进入拥塞避免。
//
// SACK 与 Reno 的不同是：
//	（1）when to send packet：由计算 pipe 变化决定，不再是计算 cwnd 变化。
//	（2）which packet to send：由 SACK 携带信息决定，反应更迅速。
//
// SACK 重传
//
//  1. 未启用 SACK 时，TCP 重复 ACK 定义为收到连续相同的 ACK seq 。[RFC5681]
//  2. 启用 SACK 时，携带 SACK 的 ACK 也被认为重复 ACK 。[RFC6675]
//
//
// 性能对比：
// NewReno 每个 RTT 内只能恢复一个丢失的数据包，所以如果丢失了 N 个数据包，那么 Fast Recovery 就要持续 N*RTT 的时间，
// 当 N 比较大时，这是一段相当长的时间。而 SACK 则没有这个限制，依靠 SACK option 的信息，它能够同时恢复多个数据包，
// 且可以避免不必要的延迟和重传，从而提高吞吐量。
//
// 当发生同一窗口多个丢包时，SACK 和 NewReno 最终都能够较为快速和平稳的恢复过来。而 Reno 则经常出现超时，然后再用慢启动来恢复，
// 这个时候 Reno 的表现就如同 Tahoe ，会造成已接受数据的重复传送。
// Reno 恢复期间会出现吞吐量低、恢复时间长、不必要重发数据、恢复结束后阈值过低等一些问题，严重的影响性能。
//
//
// SACK的不足
//
// 上面说了很多SACK的好话，现在来谈谈它的不足之处。
//
//	For a large BDP network where the number of packets are in flight, the procesing overhead of
//	SACK information at the end points can be quite overhelming because each SACK block invokes
//	a research into the large packet buffers of the sender for acked packets in the block, and every
//	recovery of a loss packet causes the same search at the receiver.
//
//	在BDP网络，这个问题尤其明显，会严重的消耗CPU而导致一系列问题。在一定程度上来说，此时
//	的SACK就像DOS攻击一样，每次遍历都要消耗大量CPU，时间复杂度为O（n^2），n为packets in
//	flight的数量。
//
//	The system overload can cause serious problem : it can cause multiple timeouts (as even packet
//	retransmission and receptions are delayed) and a long period of zero throughput.
//
//	当然，这是中等规模的BDP（100~1000）或大规模的BDP网络才需考虑的问题，对于一般的BDP而言不会出现太大的问题。
//
//
// 问题 1 ：Reno 算法中，在一个窗口内重复丢包会造成影响吗？
// 答案：会。
// 	(1) 如果只丢一个包，那么收到非重复 ACK 时，就能确认完本窗口内所有的包，然后进入拥塞避免阶段，这就是 Reno 想达到的。
// 	(2) 如果丢失多个包，那么收到非重复 ACK 时，不能确认完本窗口内所有的包，但是，若此时也退出快速恢复，进入拥塞避免阶段，可能会发生两种情况：
//		(a) 如果后续继续发包，可能会频繁触发快速重传和快速恢复。
//		注意，每次进入快速重传和快速恢复时，ssthresh 和 cwnd 都要减半，导致之后进入拥塞避免的起点非常低，影响吞吐量。
//		(b) 如果后续不再发包，会导致 RTO 超时，然后进入慢启动，影响吞吐量。
//
//
//
//
func (s *sender) handleFastRecovery(seg *segment) (rtx bool) {

	// 获取 ack 序号
	ack := seg.ackNumber

	// We are in fast recovery mode. Ignore the ack if it's out of range.
	//
	//「冗余 ACK 过滤」
	// 检查 ack 序号是否位于 [sndUna, sndNxt+1) 区间，如果不处于该区间，意味着收到过期的重复 ack 。
	// 在快速恢复状态下，对这种 ack 包直接忽略，并返回 false（无需重传）。
	if !ack.InRange(s.sndUna, s.sndNxt+1) {
		return false
	}

	// Leave fast recovery if it acknowledges all the data covered by this fast recovery session.
	//
	//「全部 ACK - 退出快速恢复」
	// 至此，ack 序号位于 [sndUna, sndNxt+1) 区间，如果当前 ack 能覆盖 [..., s.fr.last)，
	// 则 [fr.first, fr.last] 区间的所有包都已 ack ，退出快速恢复阶段，进入 `拥塞避免` 阶段，并返回 false（无需重传）。
	if s.fr.last.LessThan(ack) { // 备注：s.fr.last = s.sndNxt - 1
		s.leaveFastRecovery()
		return false
	}

	//「部分 ACK 」
	//
	// 至此，ack 序号位于 [sndUna, sndNxt+1) 区间，且当前 ack 无法覆盖 [..., s.fr.last)，则为部分确认，分两种情况
	//	(a) ack == s.fr.first: 此时为重复 ack 。
	//  (b) ack in [sndUna, sndNxt]: 此时为部分 ack 。


	//「 SACK 快速恢复算法」
	if s.ep.sackPermitted {
		// 当前处于快速恢复阶段，如果同时开启了 sack 选项，这里直接 return ，交由上层
		// `handleRcvdSegment(seg *segment) -> s.sendData() -> s.handleSACKRecovery(s.maxPayloadSize, end)`
		// 来处理重传和快速恢复，不必在本函数中处理。

		// When SACK is enabled we let retransmission be governed by the SACK logic.
		return false
	}

	//「 NewReno 快速恢复算法」
	//
	// 至此，未开启 sack 选择重传，使用 NewReno 快速恢复算法：
	// (a) 对于非 ack 包，直接忽略。
	// (b) 对于 dup ack ，执行 s.sndCwnd++ ，直到 maxCwnd 。
	// (c) 对于部分 ack ，更新 [fr.first, fr.last] 快速恢复区间，重置 s.dupAckCount 变量，需要重传最近的 segment ，返回 true 。

	// Don't count this as a duplicate if it is carrying data or updating the window.
	//
	// (a) 如果当前 seg 携带了数据、或者更新了流量窗口，不认为是 dup 包。
	if seg.logicalLen() != 0 || s.sndWnd != seg.window {
		return false
	}

	// Inflate the congestion window if we're getting duplicate acks for the packet we retransmitted.
	//
	// (b) 收到重复 ACK 时，拥塞窗口增加 1 。
	if ack == s.fr.first { 	// s.fr.first 值是 s.sndUna ，如果 ack == s.fr.first ，则肯定是重复的 ack ，因为能更新 s.sndUna ，肯定是此前收到过 ack 。
		// We received a dup, inflate the congestion window by 1 packet if we're not at the max yet.
		// Only inflate the window if regular FastRecovery is in use, RFC6675 does not require inflating cwnd on duplicate ACKs.
		//
		// 收到了 dup ack ，如果此时 sndCwnd 还没有达到最大值，就 +1 。
		// 注意，只有在使用常规 FastRecovery 算法时才会对窗口 +1 ，而 RFC6675 不要求对重复的 ACK 进行 cwnd+1 。
		if s.sndCwnd < s.fr.maxCwnd {
			s.sndCwnd++
		}
		return false
	}


	// A partial ack was received. Retransmit this packet and remember it so that we don't retransmit it again.
	// We don't inflate the window because we're putting the same packet back onto the wire.
	// N.B. The retransmit timer will be reset by the caller.

	// (c) 至此，ack in [sndUna, sndNxt)，为部分 ack 。由于不是 full ack ，所以需要重传最近的 segment 。
	// 这里不扩大拥塞窗口 s.sndCwnd ，是因为马上要重发一个数据包到网络上，且重传定时器也相应被重置。 // 相见 NewReno 算法细节。
	//
	s.fr.first = ack 	// 变更 [fr.first, fr.last] 区间。
	s.dupAckCount = 0   // 收到了有效 ack ，重置连续 dup ack 变量。
	return true
}

// isAssignedSequenceNumber relies on the fact that we only set flags once a
// sequencenumber is assigned and that is only done right before we send the
// segment. As a result any segment that has a non-zero flag has a valid
// sequence number assigned to it.
//
// isAssignedSequenceNumber 依赖于这样的事实，即我们只在序列号被分配后才设置 flags 标志，
// 而且只有在发送段之前才会完成。因此，任何具有非零标志的段都具有有效的序列号。

func (s *sender) isAssignedSequenceNumber(seg *segment) bool {
	return seg.flags != 0
}

// SetPipe implements the SetPipe() function described in RFC6675. Netstack
// maintains the congestion window in number of packets and not bytes, so
// SetPipe() here measures number of outstanding packets rather than actual
// outstanding bytes in the network.
//
//
// SetPipe 实现了 RFC6675 中描述的 SetPipe() 函数。
// Netstack 维护拥塞窗口的单位是数据包数而不是字节数，所以这里的 SetPipe() 测量的是网络中未完成的数据包数而不是实际未完成的字节数。
//
//
// 在快速恢复过程中，SACK 会维护一个名为 pipe 的变量，它代表了网络中已发送数据包的估计数量。
// 只有当网络中估计的数据包数量小于拥塞窗口时，发送方才会发送新的或重传的数据。
// 当发送方发送新数据包或重传旧数据包时，pipe 会递增 +1 ，当发送方接收到带有 SACK 选项的 DUP ACK 数据包，报告接收方已接收到新数据时，它将递减 -1。
//
// 使用 pipe 变量将何时发送数据包的决定与发送哪个数据包的决定解耦。
//
// 发送方维护一个数据结构，即 scoreboard ，它可以记住以前 SACK 选项中的确认信息。
// 当发送方被允许发送一个数据包时，它将从被推断为在接收方丢失的包列表中重新发送下一个包。
// 如果没有这样的数据包，并且接收者通告的接收窗口足够大，发送者发送一个新的信息包。
//
// 当重新传输的包被丢弃时，SACK 的实现通过 RTO 检测到丢失的包，重新传输丢失的包，然后慢启动。
// 当接收到确认输入快速恢复时所有未处理数据的恢复确认时，发送方退出快速恢复。
// 当发送方收到进入快速恢复时所待确认的所有包的 ACK 确认信息时，退出快速恢复。
func (s *sender) SetPipe() {

	// If SACK isn't permitted or it is permitted but recovery is not active
	// then ignore pipe calculations.
	//
	// 如果不允许使用 SACK ，或者允许使用 SACK 但当前不处于快速恢复阶段，则忽略 pipe 计算。
	if !s.ep.sackPermitted || !s.fr.active {
		return
	}

	//
	pipe := 0
	smss := seqnum.Size(s.ep.scoreboard.SMSS())

	for s1 := s.writeList.Front(); s1 != nil && s1.data.Size() != 0 && s.isAssignedSequenceNumber(s1); s1 = s1.Next() {

		// With GSO each segment can be much larger than SMSS.
		// So check the segment in SMSS sized ranges.


		//
		segEnd := s1.sequenceNumber.Add(seqnum.Size(s1.data.Size()))

		for startSeq := s1.sequenceNumber; startSeq.LessThan(segEnd); startSeq = startSeq.Add(smss) {

			endSeq := startSeq.Add(smss)
			if segEnd.LessThan(endSeq) {
				endSeq = segEnd
			}

			sb := header.SACKBlock{startSeq, endSeq}


			// SetPipe():
			//
			// After initializing pipe to zero, the following steps are
			// taken for each octet 'S1' in the sequence space between
			// HighACK and HighData that has not been SACKed:
			//
			// 将 pipe 初始化为零后，对 HighACK 和 HighData 之间的序列空间中
			// 未被 SACK 的每个八位数 'S1' 采取以下步骤。
			if !s1.sequenceNumber.LessThan(s.sndNxt) {
				break
			}

			// 已被 SACK 的序列号区间不属于 Pipe 。
			if s.ep.scoreboard.IsSACKED(sb) {
				continue
			}

			// SetPipe():
			//    (a) If IsLost(S1) returns false, Pipe is incremened by 1.
			//
			// NOTE: here we mark the whole segment as lost. We do not try
			// and test every byte in our write buffer as we maintain our
			// pipe in terms of oustanding packets and not bytes.
			//
			//
			// 如果 IsLost(S1) 返回 false ，即该报文段未丢失，则 Pipe 递增 1 。
			//
			// 注意：这里我们将整个 segment 标记为丢失。
			// 我们不尝试测试写入缓冲区中的每一个字节，因为我们 pipe 记录的是未完成的数据包而不是字节。
			if !s.ep.scoreboard.IsRangeLost(sb) {
				pipe++
			}

			// SetPipe():
			//    (b) If S1 <= HighRxt, Pipe is incremented by 1.
			//
			// 如果 SeqNum <= HighRxt ，则 Pipe 递增 1 ，即当发生重传时，Pipe 需要被增加。
			if s1.sequenceNumber.LessThanEq(s.fr.highRxt) {
				pipe++
			}

		}
	}
	s.outstanding = pipe
}

// checkDuplicateAck is called when an ack is received. It manages the state
// related to duplicate acks and determines if a retransmit is needed according
// to the rules in RFC 6582 (NewReno).
//
// checkDuplicateAck 在收到 ACK 时被调用。 它管理与重复 ACK 相关的状态，
// 并根据 RFC 6582（NewReno）中的规则确定是否需要重传。
//
//
// 一般如果一个 TCP 报文满足下面三个条件之一的话，就认定这个报文是 window update 消息，
// 被认定为 window update 的 ACK 包是不会统计到 dup ACK 里面的:
//	1、ack number 比之前接收的最大的 ack number 还要大
//	2、系列号 seq 比之前接收到的最大系列号还要大
//	3、系列号 seq 与之前接收到的系列号相同，但是 TCP 头中的 window size 字段发生了变化
//
func (s *sender) checkDuplicateAck(seg *segment) (rtx bool) {

	// 获取确认序号
	ack := seg.ackNumber

	// 若正处于 `快速恢复` 状态，则调用 handleFastRecovery() 处理，并返回是否需要重传最近的未确认的 segment 。
	if s.fr.active {
		return s.handleFastRecovery(seg)
	}

	// We're not in fast recovery yet. A segment is considered a duplicate
	// only if it doesn't carry any data and doesn't update the send window,
	// because if it does, it wasn't sent in response to an out-of-order
	// segment. If SACK is enabled then we have an additional check to see
	// if the segment carries new SACK information. If it does then it is
	// considered a duplicate ACK as per RFC6675.
	//
	// 当前尚未进入 `快速恢复` 阶段，需要检测连续的 dup ack 数目，决定是否需要进入 `快速恢复` 。
	//
	// 如果同时满足以下条件，则肯定是 dup ACK ：
	// 	1. ack == s.sndUna
	// 	2. 不携带数据
	// 	3. 不更新流量窗口
	// 	4. ack != s.sndNxt
	//
	// 如果不同时满足以上条件，但开启了 sack 选项，需要检测 seg 是否携带了新的 SACK 信息，
	// 如果 seg 携带了新的 SACK 信息，也被认为是 dup ACK ，这是与关闭 SACK 场景下认定 dup ACK 方法的重大区别。

	// 满足这几个条件，意味着当前包不是 dup ack 包；但如果启用了 SACK ，那么还要检查该段是否携带了新的 SACK 信息。
	if ack != s.sndUna || seg.logicalLen() != 0 || s.sndWnd != seg.window || ack == s.sndNxt {
		if !s.ep.sackPermitted || !seg.hasNewSACKInfo {
			s.dupAckCount = 0
			return false
		}
		// 相当于以下代码片段：
		//
		// 	// 如果启用了 SACK ，要检查该段是否携带了新的 SACK 信息，若携带则认为是 dup ack 。
		// 	if s.ep.sackPermitted && seg.hasNewSACKInfo {
		//	 	// 为 dup ACK , 进入下面的处理逻辑。
		// 	} else {
		// 		// 非 dup ACK ，直接返回。
		//		s.dupAckCount = 0
		//		return false
		// 	}
	}

	// 至此，意味 seg 是 dup ack 包，更新连续重复的 ack 数量。
	s.dupAckCount++

	// Do not enter fast recovery until we reach nDupAckThreshold or the
	// first unacknowledged byte is considered lost as per SACK scoreboard.
	//
	// 满足下面条件，则无需进入快速恢复：
	// (1) 连续重复的 ack 数不超过 3 。
	// (2) 连续重复的 ack 数超过 3 ，但是开启了 sack 选项且 s.sndUna 没有记录在 sack scoreboard 中。
	if s.dupAckCount < nDupAckThreshold || (s.ep.sackPermitted && !s.ep.scoreboard.IsLost(s.sndUna)) {
		// RFC 6675 Step 3.
		// highRxt 是重传的最大序列号。
		s.fr.highRxt = s.sndUna - 1

		// Do run SetPipe() to calculate the outstanding segments.
		// 调用 SetPipe() 计算传输中的段数目，控制拥塞窗口。
		s.SetPipe()

		// 收到 dup ACK 或者 SACK ，转移到 Disorder 状态。
		s.state = Disorder
		return false
	}

	// 至此，需要进入快速恢复。

	// See: https://tools.ietf.org/html/rfc6582#section-3.2 Step 2
	//
	// We only do the check here, the incrementing of last to the highest sequence
	// number transmitted till now is done when enterFastRecovery is invoked.
	//
	// 这块确实不太懂。
	if !s.fr.last.LessThan(seg.ackNumber) {
		s.dupAckCount = 0
		return false
	}


	// 进入 `快速恢复` 阶段，需要立即重传丢失报文，所以需要返回 true 。
	s.cc.HandleNDupAcks()
	s.enterFastRecovery()
	s.dupAckCount = 0

	return true
}

// handleRcvdSegment is called when a segment is received;
// it is responsible for updating the send-related state.
func (s *sender) handleRcvdSegment(seg *segment) {

	// Check if we can extract an RTT measurement from this ack.
	//
	// 检查我们是否能从这个 ACK 中提取出 RTT 测量值。
	// 	(a) !seg.parsedOptions.TS : 没有开启 timestamp 选项，若开启则不走这里的逻辑。
	// 	(b) s.rttMeasureSeqNum.LessThan(seg.ackNumber) :
	//	    rttMeasureSeqNum 值在上次 rtt 测试时设置为 s.sndNxt，如果此时的 ack 超过 rttMeasureSeqNum，
	//	    意味着自上次测试 rtt 之后，有新报文发送，从而有新的 ack 到达，便可以用新 ack 来计算新 rtt 。
	if !seg.parsedOptions.TS && s.rttMeasureSeqNum.LessThan(seg.ackNumber) {
		s.updateRTO(time.Now().Sub(s.rttMeasureTime)) 	// 根据 rtt 更新 s.rto
		s.rttMeasureSeqNum = s.sndNxt 					// 收到新的 ack ，便用来更新 s.rttMeasureSeqNum
	}

	// Update Timestamp if required. See RFC7323, section-4.3.
	//
	// 必要时，更新 e.recentTS 时间戳。
	//  (a) seg.parsedOptions.TS: 段携带了 timestamp 选项。
	//  (b) s.ep.sendTSOk: 端点的 timestamp 选项已开启。
	if s.ep.sendTSOk && seg.parsedOptions.TS {
		s.ep.updateRecentTimestamp(seg.parsedOptions.TSVal, s.maxSentAck, seg.sequenceNumber)
	}

	// Insert SACKBlock information into our scoreboard.
	//
	// 如果开启了 sack ，把当前段的 sack 信息添加到 s.ep.scoreboard 中，。
	if s.ep.sackPermitted {

		// 遍历当前段 seg 所包含的 sack 块
		for _, sb := range seg.parsedOptions.SACKBlocks {

			// Only insert the SACK block if the following holds true:
			//  * SACK block acks data after the ack number in the current segment.
			//  * SACK block represents a sequence between sndUna and sndNxt (i.e. data that is currently unacked and in-flight).
			//  * SACK block that has not been SACKed already.
			//
			// NOTE:
			// This check specifically excludes DSACK blocks which have start/end before sndUna
			// and are used to indicate spurious retransmissions.
			//
			//
			// 注意：
			// 这项检查特别排除了 [Start, End] 块在 sndUna 之前的 D-SACK 块，这些块用于指示虚假重传。
			//
			// D-SACK 是指使用 SACK 来告诉「发送方」有哪些数据被重复接收了，举例来说：
			// 例一，ACK 丢包：
			// (a)「接收方」发给「发送方」的两个 ACK 确认应答都丢失了，在发送方超时后，重传第一个数据包（3000 ~ 3499）
			// (b) 于是「接收方」发现数据是重复收到的，于是回了一个 SACK = 3000~3500、ACK = 4000，告诉「发送方」3000~3500 的数据早已被接收了，
			//     且 ACK 都到了 4000 了，已经意味着 4000 之前的所有数据都已收到，所以这个 SACK 就代表着 D-SACK。
			// (c) 这样「发送方」就知道了，数据没有丢，是「接收方」的 ACK 确认报文丢了。
			//
			// 例二，网络延时：
			// (a) 数据包（1000~1499）被网络延迟了，而数据包（1500~1999）、（2000~2499）、（2500~2999）成功到达，导致「发送方」没有收到 Ack 1500 的确认报文。
			// (b) 而后面到达的报文触发了三个相同的 ACK 确认报文，就触发了「发送方」快速重传机制，但是在重传后（被接收前），被延迟的数据包（1000~1499）又到了「接收方」；
			// (c) 所以「接收方」回了一个 SACK=1000~1500、ACK = 3000，因为 ACK 已经到了 3000，所以这个 SACK 是 D-SACK，表示收到了重复的包。
			// (d) 这样发送方就知道快速重传触发的原因不是发出去的包丢了，也不是因为回应的 ACK 包丢了，而是因为网络延迟了。
			//
			// 可见，D-SACK 有这么几个好处：
			//  (a) 可以让「发送方」知道，是发出去的包丢了，还是接收方回应的 ACK 包丢了;
			//  (b) 可以知道是不是「发送方」的数据包被网络延迟了;
			//  (c) 可以知道网络中是不是把「发送方」的数据包给复制了;


			// 只有当以下情况为真时，才会插入 SACK 块。
			// 	(a) SACK 块 [Start, End] 的 Start > Ack，则表明 [Ack, Start) 中的数据未收到，发送方只需重传这部分。
			// 	(b) SACK 块 [Start, End] 是 [sndUna, sndNxt] 的子集，只有在这个区间里的数据才需要 ACK 。
			// 	(c) SACK 块若此前已经添加过，则无需重复添加。
			if  seg.ackNumber.LessThan(sb.Start) && // (a)
				s.sndUna.LessThan(sb.Start) && sb.End.LessThanEq(s.sndNxt) && // (b)
				!s.ep.scoreboard.IsSACKED(sb) { // (c)
				s.ep.scoreboard.Insert(sb) 	// 添加当前 sack 块。
				seg.hasNewSACKInfo = true   // 设置 sack 标识为 true 。
			}
		}

		// pipe 的变量代表了网络中已发送数据包的估计数。
		s.SetPipe()
	}

	// Count the duplicates and do the fast retransmit if needed.
	//
	// 1. 如果当前已处于 `快速恢复` 状态
	//		1.1 如果当前 seg 的 ack 确认了所有 pending 数据，则退出 `快速恢复` 状态，进入拥塞避免阶段。
	//		1.2 否则，继续呆在 `快速恢复` 阶段，且 ...
	// 			1.2.1 如果开启了 sack 选项，则直接退出并返回 false ，重传的逻辑由后续的 sendData() 中负责。
	// 			1.2.2 如果未开启 sack 选项，则默认使用 newReno 算法，其处理逻辑：
	//				1.2.2.1 若从 seg 得到了无效 ack 包，则啥也不干 ，返回 false ，无需重传。
	//				1.2.2.2 若从 seg 得到了重复 ack 包，则 cwnd++ ，返回 false ，无需重传。
	//				1.2.2.3 若从 seg 得到了部分 ack 包，则需要重发最近的 segment ，此时返回 true 。
	//
	// 2. 如果当前不处于 `快速恢复` 状态，需要检测连续的 dup ack 数目，决定是否需要进入 `快速恢复` 。
	// 	  如果需要进入 `快速恢复` 则需要执行 `快速重传` 来重传首个待确认的 seg 。
	rtx := s.checkDuplicateAck(seg)

	// [重要]
	// 首先要处理接收方的窗口通告，当收到报文时，一定会带有接收窗口 seg.window 和确认号 seg.ackNumber ，
	// 此时先更新发送器的发送窗口大小 s.sndWnd 为接收窗口大小 seg.window 。

	// Stash away the current window size.
	// 更新发送窗口大小，seg.window 值是接收端通告的最新接收窗口大小。
	s.sndWnd = seg.window

	// Ignore ack if it doesn't acknowledge any new data.
	// 如果它不应答任何新数据，就忽略 ACK 。

	// 获取确认号
	ack := seg.ackNumber

	// 如果收到有效的 ack ，需要:
	// 	(1) 重置 dupAck 计数
	//	(2) 根据往返耗时更新 rto
	//  (3) 重置 RTO 定时器
	// 	(4) 右移发送窗口 sndUna
	//	(5) 从 writeList 中移除被 ack 的 seg (可能是部分 ack)
	//  (6) 更新发送缓冲区大小
	// 	(7) 清除已 ACKED 数据的 SACK 信息
	//	(8) 更新拥塞窗口 sndCwnd 大小
	//  (9) 如果发送窗口中的所有数据都被确认，则禁用 RTO 定时器
	if (ack - 1).InRange(s.sndUna, s.sndNxt) {

		// 收到了有效的 ack ，则重置 dupAck 计数，避免快速重传+快速恢复。
		s.dupAckCount = 0

		// See : https://tools.ietf.org/html/rfc1323#section-3.3.
		//
		// Specifically we should only update the RTO using TSEcr if the
		// following condition holds:
		//
		//    A TSecr value received in a segment is used to update the
		//    averaged RTT measurement only if the segment acknowledges
		//    some new data, i.e., only if it advances the left edge of
		//    the send window.

		// 如果设置了 timestamp 选项，且段 seg 携带了 TSEcr ，则根据往返耗时更新 rto 。
		if s.ep.sendTSOk && seg.parsedOptions.TSEcr != 0 {
			// TSVal/Ecr values sent by Netstack are at a millisecond granularity.
			// TSVal/Ecr 值是以毫秒为粒度的。

			// 计算 RTT := time.Now() - TSEcr
			elapsed := time.Duration(s.ep.timestamp()-seg.parsedOptions.TSEcr) * time.Millisecond
			// 更新超时重传定时器。
			s.updateRTO(elapsed)
		}

		// When an ack is received we must rearm the timer. RFC 6298 5.2
		// 收到有效 ACK 后，需要重置超时重传定时器(RTO)。
		s.resendTimer.enable(s.rto)

		// Remove all acknowledged data from the write list.
		// 从写入列表 write list 中删除所有已 ack 的数据。

		// [重要] 计算本次 acked 的字节数。
		acked := s.sndUna.Size(ack)

		// [重要] 右移发送窗口。
		s.sndUna = ack

		ackLeft := acked
		originalOutstanding := s.outstanding
		for ackLeft > 0 {

			// We use logicalLen here because we can have FIN
			// segments (which are always at the end of list) that
			// have no data, but do consume a sequence number.

			// 取出首个已发送未确认的 segment
			seg := s.writeList.Front()

			// 取出该 segment 的数据长度
			datalen := seg.logicalLen()

			// 如果当前 segment 的数据长度比本次 acked 数据大，则为部分确认，需要：
			// 	1. 从当前 segment 的 data 中移除 acked 个字节
			// 	2. 更新 segment 的起始序号
			// 	3. 更新 sender 的待 ack 的数据量
			// 然后用 break 结束 for 循环的确认过程。
			if datalen > ackLeft {
				prevCount := s.pCount(seg)
				seg.data.TrimFront(int(ackLeft))
				seg.sequenceNumber.UpdateForward(ackLeft)
				s.outstanding -= prevCount - s.pCount(seg)
				break
			}

			// 至此，则 seg.datalen <= ackLeft，当前 segment 被全部 ack 确认，可以移除它。
			if s.writeNext == seg {
				s.writeNext = seg.Next()
			}

			// 当前 segment 确认完毕，从 write list 中移除它。
			s.writeList.Remove(seg)

			// if SACK is enabled then Only reduce outstanding if
			// the segment was not previously SACKED as these have
			// already been accounted for in SetPipe().
			//
			// 如果当 s.ep.sackPermitted 为 false ，
			// 或者当 s.ep.sackPermitted 为 true 且此前未对 seg 进行 sacked 的情况下，
			// 对 outstanding 进行减少操作，因为在 SetPipe() 中已经考虑了这些问题。
			//
			//
			// 这块不是很懂，因为前面 if 里面没有做类似判断，感觉这里的判断可以直接删除掉，不影响理解。
			if !s.ep.sackPermitted || !s.ep.scoreboard.IsSACKED(seg.sackBlock()) {
				s.outstanding -= s.pCount(seg)
			}

			// 减引用，以便在合适的时候彻底释放。
			seg.decRef()
			// 更新待 ack 数据。
			ackLeft -= datalen
		}

		// Update the send buffer usage and notify potential waiters.
		// 更新发送缓冲区的使用情况，并通知潜在的等待者。
		s.ep.updateSndBufferUsage(int(acked))

		// Clear SACK information for all acked data.
		// 清除已 ACKED 数据的 SACK 信息。
		s.ep.scoreboard.Delete(s.sndUna)

		// If we are not in fast recovery then update the congestion
		// window based on the number of acknowledged packets.
		//
		// 如果当前不处于 `快速恢复` 中，就根据本次 ACK 确认的数据数更新拥塞窗口，否则，`快速恢复` 内部会根据 dup ack 来更新。
		if !s.fr.active {
			s.cc.Update(originalOutstanding - s.outstanding) // 根据被确认包数量更新拥塞窗口 s.sndCwnd 。
			if s.fr.last.LessThan(s.sndUna) {
				s.state = Open 	// Open 表示发送方正在按顺序接收 ACK ，没有发现丢失或 dupACKs 等情况。
			}
		}


		// It is possible for s.outstanding to drop below zero if we get
		// a retransmit timeout, reset outstanding to zero but later
		// get an ack that cover previously sent data.
		//
		// ????
		// 如果我们得到一个重传超时，将未发送的数据重置为零，但后来得到的 ACK 覆盖了之前发送的数据，那么 s.Outstanding 有可能降到零以下。
		//
		if s.outstanding < 0 {
			s.outstanding = 0
		}

		s.SetPipe()


		// If all outstanding data was acknowledged the disable the timer. RFC 6298 Rule 5.3
		//
		// 如果所有数据都被确认，则禁用定时器。
		if s.sndUna == s.sndNxt {
			s.outstanding = 0
			s.resendTimer.disable()
		}
	}

	// Now that we've popped all acknowledged data from the retransmit queue, retransmit if needed.
	// 如果需要执行快速重传，则重传首个未确认的 segment 。
	// 这个重传逻辑放到上面 if(ack segment) 代码块的后面，是因为上面可能会释放发送缓冲和扩大拥塞窗口，避免无法发包的情况。
	if rtx {
		s.resendSegment()
	}


	// Send more data now that some of the pending data has been ack'd, or
	// that the window opened up, or the congestion window was inflated due
	// to a duplicate ack during fast recovery. This will also re-enable
	// the retransmit timer if needed.
	//
	// 现在发送更多的数据，有些 inflight 的数据已经被 ack 了，或者窗口打开了，
	// 或者在快速恢复过程中由于重复 ack 而导致拥塞窗口膨胀了。
	//
	// 如果需要的话，这也会重新启用重传定时器。
	//
	//
	//
	//
	//
	//
	//
	//
	//
	if !s.ep.sackPermitted || s.fr.active || s.dupAckCount == 0 || seg.hasNewSACKInfo {
		s.sendData()
	}



}

// sendSegment sends the specified segment.
func (s *sender) sendSegment(seg *segment) *tcpip.Error {
	// seg.xmitTime 是该 seg 的最后一次发送时间，零值表示该 segment 尚未被发送，非零表示此前已发送过，当前为重复发送。
	if !seg.xmitTime.IsZero() {
		s.ep.stack.Stats().TCP.Retransmits.Increment()
		s.ep.stats.SendErrors.Retransmits.Increment()
		if s.sndCwnd < s.sndSsthresh {
			s.ep.stack.Stats().TCP.SlowStartRetransmits.Increment()
		}
	}
	// 更新 seg 的最后一次发送时间
	seg.xmitTime = time.Now()
	// 执行 seg 的发送
	return s.sendSegmentFromView(seg.data, seg.flags, seg.sequenceNumber)
}

// sendSegmentFromView sends a new segment containing the given payload, flags and sequence number.
// sendSegmentFromView 发送一个包含给定数据 data 、标志 flags 和序列号 seq 的新 segment 。
func (s *sender) sendSegmentFromView(data buffer.VectorisedView, flags byte, seq seqnum.Value) *tcpip.Error {

	// 每次发送 segment 都要更新 sender 的发送时间戳。
	s.lastSendTime = time.Now()

	// 如果当前 seq 为测量 rtt 的 segment seq，则记录本 segment 的发送时间戳到 s.rttMeasureTime 。
	if seq == s.rttMeasureSeqNum {
		s.rttMeasureTime = s.lastSendTime
	}

	// 获取发送参数：（1）期待接收的段序号；（2）当前接收窗口大小。
	rcvNxt, rcvWnd := s.ep.rcv.getSendParams()

	// Remember the max sent ack.
	s.maxSentAck = rcvNxt

	// Every time a packet containing data is sent (including a retransmission),
	// if SACK is enabled then use the conservative timer described in RFC6675 Section 4.0,
	// otherwise follow the standard time described in RFC6298 Section 5.2.
	if data.Size() != 0 {
		if s.ep.sackPermitted {
			s.resendTimer.enable(s.rto)
		} else {
			if !s.resendTimer.enabled() {
				s.resendTimer.enable(s.rto)
			}
		}
	}

	//
	return s.ep.sendRaw(data, flags, seq, rcvNxt, rcvWnd)
}
