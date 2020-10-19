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
	"encoding/binary"
	"sync"
	"time"

	"github.com/blastbao/netstack/rand"
	"github.com/blastbao/netstack/sleep"
	"github.com/blastbao/netstack/tcpip"
	"github.com/blastbao/netstack/tcpip/buffer"
	"github.com/blastbao/netstack/tcpip/hash/jenkins"
	"github.com/blastbao/netstack/tcpip/header"
	"github.com/blastbao/netstack/tcpip/seqnum"
	"github.com/blastbao/netstack/tcpip/stack"
	"github.com/blastbao/netstack/waiter"
)

// maxSegmentsPerWake is the maximum number of segments to process in the main
// protocol goroutine per wake-up. Yielding [after this number of segments are
// processed] allows other events to be processed as well (e.g., timeouts,
// resets, etc.).
//
// maxSegmentsPerWake 是主协程每次唤醒时要处理的最大段数。在这些段处理完后，允许处理其他事件（如超时、复位等）。
const maxSegmentsPerWake = 100

type handshakeState int

// The following are the possible states of the TCP connection during a 3-way handshake.
// A depiction of the states and transitions can be found in RFC 793, page 23.
//
// 以下是 TCP 连接在 3 路握手过程中可能出现的状态。
// 这些状态和转换的描述可以在 RFC 793 中找到，第23页。
const (
	handshakeSynSent handshakeState = iota
	handshakeSynRcvd
	handshakeCompleted
)

// The following are used to set up sleepers.
const (
	wakerForNotification = iota
	wakerForNewSegment
	wakerForResend
	wakerForResolution
)

const (
	// Maximum space available for options.
	maxOptionSize = 40
)

// handshake holds the state used during a TCP 3-way handshake.
type handshake struct {

	// 对端
	ep     *endpoint

	// 握手状态
	state  handshakeState

	//
	active bool

	//
	flags  uint8

	//
	ackNum seqnum.Value

	// iss is the initial send sequence number, as defined in RFC 793.
	// iss 初始发送序列号，定义在 RFC 793 中。
	iss seqnum.Value

	// rcvWnd is the receive window, as defined in RFC 793.
	// rcvWnd 接收窗口，定义在 RFC 793 中。
	rcvWnd seqnum.Size

	// sndWnd is the send window, as defined in RFC 793.
	// sndWnd 发送窗口，定义在 RFC 793 中。
	sndWnd seqnum.Size

	// mss is the maximum segment size received from the peer.
	// mss 从对端收到的最大报文段大小。
	mss uint16

	// sndWndScale is the send window scale, as defined in RFC 1323.
	// A negative value means no scaling is supported by the peer.
	//
	// 对端接收窗口扩大因子。负值表示对端不支持扩大。
	sndWndScale int

	// rcvWndScale is the receive window scale, as defined in RFC 1323.
	//
	// 本端接收窗口扩大因子
	rcvWndScale int
}

func newHandshake(ep *endpoint, rcvWnd seqnum.Size) handshake {

	// 计算接收窗口缩放比例
	rcvWndScale := ep.rcvWndScaleForHandshake()

	// Round-down the rcvWnd to a multiple of wndScale. This ensures that the
	// window offered in SYN won't be reduced due to the loss of precision if
	// window scaling is enabled after the handshake.
	//
	// 将接收窗口 rcvWnd 按 rcvWndScale 进行缩放，并对齐
	rcvWnd = (rcvWnd >> uint8(rcvWndScale)) << uint8(rcvWndScale)

	// Ensure we can always accept at least 1 byte if the scale specified
	// was too high for the provided rcvWnd.
	//
	// 如果 rcvWndScale 相比 rcvWnd 来说太高，则需要设置至少 1 个字节。
	if rcvWnd == 0 {
		rcvWnd = 1
	}

	//
	h := handshake{
		ep:          ep,
		active:      true,
		rcvWnd:      rcvWnd,
		rcvWndScale: int(rcvWndScale),
	}

	h.resetState()
	return h
}

// FindWndScale determines the window scale to use for the given maximum window size.
//
// FindWndScale() 根据给定的最大窗口大小 wnd 确定窗口的缩放比例。
//
// 备注：
//  0xffff  = 65535
//  0x10000 = 65536
func FindWndScale(wnd seqnum.Size) int {

	// 如果最大窗口 wnd < 65536 ，则不缩放，返回 0 。
	if wnd < 0x10000 {
		return 0
	}

	// 不断用 0xffff 乘 s++ 去逼近 wnd ，最后估算出 wnd 是 0xffff 的 s 倍，得到缩放倍数 s 。
	max := seqnum.Size(0xffff)
	s := 0
	for wnd > max && s < header.MaxWndScale {
		s++
		max <<= 1
	}

	return s
}

// resetState resets the state of the handshake object such that it becomes
// ready for a new 3-way handshake.
func (h *handshake) resetState() {

	// 读取四字节随机数
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}

	//
	h.state = handshakeSynSent
	h.flags = header.TCPFlagSyn
	h.ackNum = 0
	h.mss = 0
	h.iss = generateSecureISN(h.ep.ID, h.ep.stack.Seed())
}

// generateSecureISN generates a secure Initial Sequence number based on the
// recommendation here https://tools.ietf.org/html/rfc6528#page-3.
func generateSecureISN(id stack.TransportEndpointID, seed uint32) seqnum.Value {

	// isn = hash(seed + LocalAddress + RemoteAddress + LocalPort + RemotePort) + time.NowInMs
	isnHasher := jenkins.Sum32(seed)
	isnHasher.Write([]byte(id.LocalAddress))
	isnHasher.Write([]byte(id.RemoteAddress))
	portBuf := make([]byte, 2)
	binary.LittleEndian.PutUint16(portBuf, id.LocalPort)
	isnHasher.Write(portBuf)
	binary.LittleEndian.PutUint16(portBuf, id.RemotePort)
	isnHasher.Write(portBuf)
	// The time period here is 64ns. This is similar to what linux uses
	// generate a sequence number that overlaps less than one
	// time per MSL (2 minutes).
	//
	// A 64ns clock ticks 10^9/64 = 15625000) times in a second.
	// To wrap the whole 32 bit space would require
	// 2^32/1562500 ~ 274 seconds.
	//
	// Which sort of guarantees that we won't reuse the ISN for a new
	// connection for the same tuple for at least 274s.
	isn := isnHasher.Sum32() + uint32(time.Now().UnixNano()>>6)
	return seqnum.Value(isn)
}

// effectiveRcvWndScale returns the effective receive window scale to be used.
// If the peer doesn't support window scaling, the effective rcv wnd scale is
// zero; otherwise it's the value calculated based on the initial rcv wnd.
func (h *handshake) effectiveRcvWndScale() uint8 {

	// 如果对端接收窗口扩大因子为负数，则不支持窗口扩大。
	if h.sndWndScale < 0 {
		return 0
	}

	return uint8(h.rcvWndScale)
}

// resetToSynRcvd resets the state of the handshake object to the SYN-RCVD state.
// resetToSynRcvd 将 handshake 对象的 state 重置为 SYN-RCVD 状态。
func (h *handshake) resetToSynRcvd(iss seqnum.Value, irs seqnum.Value, opts *header.TCPSynOptions) {

	h.active = false
	h.state = handshakeSynRcvd
	h.flags = header.TCPFlagSyn | header.TCPFlagAck
	h.iss = iss
	h.ackNum = irs + 1
	h.mss = opts.MSS
	h.sndWndScale = opts.WS
	h.ep.mu.Lock()
	h.ep.state = StateSynRecv
	h.ep.mu.Unlock()
}

// checkAck checks if the ACK number, if present, of a segment received during
// a TCP 3-way handshake is valid. If it's not, a RST segment is sent back in response.
//
// checkAck 检查在 TCP 三次握手过程中收到的段的 ACK 号（如果存在）是否有效。如果无效，则会发回一个 RST 段作为回应。

func (h *handshake) checkAck(s *segment) bool {

	if s.flagIsSet(header.TCPFlagAck) && s.ackNumber != h.iss+1 {
		// RFC 793, page 36, states that a reset must be generated when
		// the connection is in any non-synchronized state and an
		// incoming segment acknowledges something not yet sent. The
		// connection remains in the same state.
		ack := s.sequenceNumber.Add(s.logicalLen())
		h.ep.sendRaw(buffer.VectorisedView{}, header.TCPFlagRst|header.TCPFlagAck, s.ackNumber, ack, 0)
		return false
	}

	return true
}

// synSentState handles a segment received when the TCP 3-way handshake is in the SYN-SENT state.
//
// synSentState 处理 TCP 三次握手过程中，处于 SYN-SENT 状态时收到的段。
func (h *handshake) synSentState(s *segment) *tcpip.Error {

	// RFC 793, page 37, states that in the SYN-SENT state,
	// a reset is acceptable if the ack field acknowledges the SYN.
	if s.flagIsSet(header.TCPFlagRst) {
		if s.flagIsSet(header.TCPFlagAck) && s.ackNumber == h.iss+1 {
			return tcpip.ErrConnectionRefused
		}
		return nil
	}

	if !h.checkAck(s) {
		return nil
	}

	// We are in the SYN-SENT state. We only care about segments that have the SYN flag.
	// 当前处于 SYN-SENT 状态，只关心有 SYN 标志的段。
	if !s.flagIsSet(header.TCPFlagSyn) {
		return nil
	}

	// Parse the SYN options.
	rcvSynOpts := parseSynSegmentOptions(s)

	// Remember if the Timestamp option was negotiated.
	h.ep.maybeEnableTimestamp(&rcvSynOpts) 		// 设置是否允许时间戳选项

	// Remember if the SACKPermitted option was negotiated.
	h.ep.maybeEnableSACKPermitted(&rcvSynOpts)	//

	// Remember the sequence we'll ack from now on.
	h.ackNum = s.sequenceNumber + 1
	h.flags |= header.TCPFlagAck
	h.mss = rcvSynOpts.MSS
	h.sndWndScale = rcvSynOpts.WS

	// If this is a SYN ACK response, we only need to acknowledge the SYN and the handshake is completed.
	//
	// 发出 SYN 后收到了 SYN + ACK，再发送一个 ACK，连接就完成建立了。
	if s.flagIsSet(header.TCPFlagAck) {
		h.state = handshakeCompleted
		h.ep.sendRaw(buffer.VectorisedView{}, header.TCPFlagAck, h.iss+1, h.ackNum, h.rcvWnd>>h.effectiveRcvWndScale())
		return nil
	}

	// 以下这一端对应的是状态机那张图里的 ‘同时连接’ 的情况，
	// 此时作为主动方已经发出了一个 SYN，然后又收到了一个 SYN，此时只要发送一个 SYN + ACK，
	// 对于对方来说这个连接就已经建立了，对于自己来说，再收到一个 SYN + ACK 也算完成连接。

	// A SYN segment was received, but no ACK in it. We acknowledge the SYN
	// but resend our own SYN and wait for it to be acknowledged in the SYN-RCVD state.

	h.state = handshakeSynRcvd
	h.ep.mu.Lock()
	h.ep.state = StateSynRecv
	ttl := h.ep.ttl
	h.ep.mu.Unlock()
	synOpts := header.TCPSynOptions{
		WS:    int(h.effectiveRcvWndScale()),
		TS:    rcvSynOpts.TS,
		TSVal: h.ep.timestamp(),
		TSEcr: h.ep.recentTS,

		// We only send SACKPermitted if the other side indicated it permits SACK.
		// This is not explicitly defined in the RFC but this is the behaviour implemented by Linux.
		SACKPermitted: rcvSynOpts.SACKPermitted,
		MSS:           h.ep.amss,
	}
	if ttl == 0 {
		ttl = s.route.DefaultTTL()
	}

	//
	h.ep.sendSynTCP(&s.route, h.ep.ID, ttl, h.ep.sendTOS, h.flags, h.iss, h.ackNum, h.rcvWnd, synOpts)
	return nil
}

// synRcvdState handles a segment received when the TCP 3-way handshake is in the SYN-RCVD state.
// synRcvdState 处理 TCP 三次握手过程中，处于 SYN-RCVD 状态时收到的段。
func (h *handshake) synRcvdState(s *segment) *tcpip.Error {

	// 先判断是否是一个 RST 包，用来异常的关闭连接。
	//
	// 那么哪些情况会导致 RST 呢？
	// • 目标端口未监听
	// • 目的主机或网络路径中防火墙拦截
	// • 在 recvQueue 中缓存，但是未被应用就断开连接
	// • 向已经关闭的 Socket 发送数据
	// • 向已经关闭的 Socket 发送 FIN
	// • 向已经断开的连接发送数据
	// • 向半打开的连接中进行 Send 操作
	// • ...
	//
	if s.flagIsSet(header.TCPFlagRst) {
		// RFC 793, page 37, states that in the SYN-RCVD state, a reset
		// is acceptable if the sequence number is in the window.
		if s.sequenceNumber.InWindow(h.ackNum, h.rcvWnd) {
			return tcpip.ErrConnectionRefused
		}
		return nil
	}

	// 判断 Segment 是 Syn 还是 Ack。
	if !h.checkAck(s) {
		return nil
	}

	//
	if s.flagIsSet(header.TCPFlagSyn) && s.sequenceNumber != h.ackNum-1 {

		// 之前已经收到过了一个 SYN，然后又收到了一个 SYN，并且两次 seq 不同，那么认为对方抽风，发送 RST 关闭连接。


		// We received two SYN segments with different sequence
		// numbers, so we reset this and restart the whole
		// process, except that we don't reset the timer.
		ack := s.sequenceNumber.Add(s.logicalLen())
		seq := seqnum.Value(0)
		if s.flagIsSet(header.TCPFlagAck) {
			seq = s.ackNumber
		}
		h.ep.sendRaw(buffer.VectorisedView{}, header.TCPFlagRst|header.TCPFlagAck, seq, ack, 0)

		if !h.active {
			return tcpip.ErrInvalidEndpointState
		}

		h.resetState()
		synOpts := header.TCPSynOptions{
			WS:            h.rcvWndScale,
			TS:            h.ep.sendTSOk,
			TSVal:         h.ep.timestamp(),
			TSEcr:         h.ep.recentTS,
			SACKPermitted: h.ep.sackPermitted,
			MSS:           h.ep.amss,
		}

		h.ep.sendSynTCP(&s.route, h.ep.ID, h.ep.ttl, h.ep.sendTOS, h.flags, h.iss, h.ackNum, h.rcvWnd, synOpts)
		return nil
	}

	// We have previously received (and acknowledged) the peer's SYN.
	// If the peer acknowledges our SYN, the handshake is completed.
	if s.flagIsSet(header.TCPFlagAck) {

		// 如果之前协商好了要带上 timeStamp 选项，但是握手第三步没有带上时间戳，那么丢弃这个 ACK 数据包。

		// If the timestamp option is negotiated and the segment does
		// not carry a timestamp option then the segment must be dropped
		// as per https://tools.ietf.org/html/rfc7323#section-3.2.
		if h.ep.sendTSOk && !s.parsedOptions.TS {
			h.ep.stack.Stats().DroppedPackets.Increment()
			return nil
		}

		// Update timestamp if required. See RFC7323, section-4.3.
		//
		// 更新时间戳
		if h.ep.sendTSOk && s.parsedOptions.TS {
			h.ep.updateRecentTimestamp(s.parsedOptions.TSVal, h.ackNum, s.sequenceNumber)
		}
		h.state = handshakeCompleted
		return nil
	}

	return nil
}

func (h *handshake) handleSegment(s *segment) *tcpip.Error {
	// 对 SendWindow 进行拓展
	h.sndWnd = s.window
	if !s.flagIsSet(header.TCPFlagSyn) && h.sndWndScale > 0 {
		h.sndWnd <<= uint8(h.sndWndScale)
	}

	//
	switch h.state {
	case handshakeSynRcvd:
		return h.synRcvdState(s)
	case handshakeSynSent:
		return h.synSentState(s)
	}
	return nil
}

// processSegments goes through the segment queue and processes up to
// maxSegmentsPerWake (if they're available).
func (h *handshake) processSegments() *tcpip.Error {


	// 每次最多处理 maxSegmentsPerWake 默认 100 个 segment 。
	for i := 0; i < maxSegmentsPerWake; i++ {
		// 取出 segment
		s := h.ep.segmentQueue.dequeue()
		if s == nil {
			return nil
		}
		// 处理 segment
		err := h.handleSegment(s)
		s.decRef()
		if err != nil {
			return err
		}
		// We stop processing packets once the handshake is completed,
		// otherwise we may process packets meant to be processed by
		// the main protocol goroutine.
		//
		// 当握手完成时，就停止处理数据包，否则可能会处理本应由主协程负责处理的数据包。
		if h.state == handshakeCompleted {
			break
		}
	}

	// If the queue is not empty, make sure we'll wake up in the next
	// iteration.
	if !h.ep.segmentQueue.empty() {
		h.ep.newSegmentWaker.Assert()
	}

	return nil
}

func (h *handshake) resolveRoute() *tcpip.Error {
	// Set up the wakers.
	s := sleep.Sleeper{}
	resolutionWaker := &sleep.Waker{}
	s.AddWaker(resolutionWaker, wakerForResolution)
	s.AddWaker(&h.ep.notificationWaker, wakerForNotification)
	defer s.Done()

	// Initial action is to resolve route.
	index := wakerForResolution
	for {
		switch index {
		case wakerForResolution:
			if _, err := h.ep.route.Resolve(resolutionWaker); err != tcpip.ErrWouldBlock {
				if err == tcpip.ErrNoLinkAddress {
					h.ep.stats.SendErrors.NoLinkAddr.Increment()
				} else if err != nil {
					h.ep.stats.SendErrors.NoRoute.Increment()
				}
				// Either success (err == nil) or failure.
				return err
			}
			// Resolution not completed. Keep trying...

		case wakerForNotification:
			n := h.ep.fetchNotifications()
			if n&notifyClose != 0 {
				h.ep.route.RemoveWaker(resolutionWaker)
				return tcpip.ErrAborted
			}
			if n&notifyDrain != 0 {
				close(h.ep.drainDone)
				<-h.ep.undrain
			}
		}

		// Wait for notification.
		index, _ = s.Fetch(true)
	}
}

// execute executes the TCP 3-way handshake.
//
// 不管是客户端还是服务器，三步握手的处理方式都是在同一个函数中。
//
func (h *handshake) execute() *tcpip.Error {

	//
	if h.ep.route.IsResolutionRequired() {
		if err := h.resolveRoute(); err != nil {
			return err
		}
	}

	// Initialize the resend timer.
	// 设置重传的 Waker ，并将 RTO 初始值设置为 1s 。
	resendWaker := sleep.Waker{}
	timeOut := time.Duration(time.Second) 	// 设置初始 RTO 为 1s
	rt := time.AfterFunc(timeOut, func() {
		resendWaker.Assert() 				// RTO 后触发超时重传
	})
	defer rt.Stop()

	// Set up the wakers.
	//
	// 把 Waker 注册进 Sleeper
	s := sleep.Sleeper{}
	s.AddWaker(&resendWaker, wakerForResend)
	s.AddWaker(&h.ep.notificationWaker, wakerForNotification)
	s.AddWaker(&h.ep.newSegmentWaker, wakerForNewSegment)
	defer s.Done()

	// 是否需要协商 SACK
	var sackEnabled SACKEnabled
	if err := h.ep.stack.TransportProtocolOption(ProtocolNumber, &sackEnabled); err != nil {
		// If stack returned an error when checking for SACKEnabled
		// status then just default to switching off SACK negotiation.
		//
		// 如果协议栈在检查 SACKEnabled 状态时返回错误，就默认关闭 SACK 协商。
		sackEnabled = false
	}

	// Send the initial SYN segment and loop until the handshake is completed.
	// 发送初始 SYN 段并循环直到完成握手
	h.ep.amss = calculateAdvertisedMSS(h.ep.userMSS, h.ep.route)

	// 设置 Syn 握手选项
	synOpts := header.TCPSynOptions{
		WS:            h.rcvWndScale,		// 设置自己这一端的 wndScale
		TS:            true, 				//
		TSVal:         h.ep.timestamp(),
		TSEcr:         h.ep.recentTS,
		SACKPermitted: bool(sackEnabled),
		MSS:           h.ep.amss,
	}

	// Execute is also called in a listen context so we want to make sure we
	// only send the TS/SACK option when we received the TS/SACK in the initial SYN.
	//
	// Execute 也是在监听上下文中调用的，要确保在 init SYN 中存在 TS/SACK 时才发送 TS/SACK 选项。

	// SynRcvd 这个状态是 Server 才有的，说明当前是由 Listen 调用的被动连接，而非由 Connect 发起的主动连接，
	// 此时，由对方决定是否使用 TS、SACK、sndWndScale 选项 。
	if h.state == handshakeSynRcvd {
		synOpts.TS = h.ep.sendTSOk
		synOpts.SACKPermitted = h.ep.sackPermitted && bool(sackEnabled)
		if h.sndWndScale < 0 {
			// Disable window scaling if the peer did not send us the window scaling option.
			// 如果对端没有向我们发送窗口缩放选项，则禁用窗口缩放。
			synOpts.WS = -1
		}
	}

	h.ep.sendSynTCP(
		&h.ep.route,
		h.ep.ID,
		h.ep.ttl,			// ttl
		h.ep.sendTOS,		//
		h.flags,			// 标识位
		h.iss, 				// seq 初始序号
		h.ackNum,			// ack 序号，如果是主动发起连接，该值为 0，相反，则值为 irs + 1
		h.rcvWnd,			// 接收窗口
		synOpts,            // 附加选项
	)

	// 检查状态
	for h.state != handshakeCompleted {

		switch index, _ := s.Fetch(true); index {

		// 超时重传
		case wakerForResend:
			// 超时后，等待时间会翻倍（指数退避），最大为 60s
			timeOut *= 2
			if timeOut > 60*time.Second {
				return tcpip.ErrTimeout
			}
			rt.Reset(timeOut)
			// 重传
			h.ep.sendSynTCP(&h.ep.route, h.ep.ID, h.ep.ttl, h.ep.sendTOS, h.flags, h.iss, h.ackNum, h.rcvWnd, synOpts)

		// Notification 分两种：
		//	第一种是 Close，也就是直接关闭；
		//	另一种是 Drain，这是什么呢？
		//
		// 当收到这个 Drain 通知的时候，该节点会逐渐的清空自己的 segmentQueue（也就是半连接队列），直至将等待队列清空。
		//
		// 到这里有没有想到什么？
		// 其实这里就是在做拥塞控制，而且这只是在握手的时候。
		//
		// 但是为什么要这里做一个拥塞控制呢？
		// 我认为这里主要是为了 Server 的安全，因为这里可能存在 Client 疯狂发送 Syn，但是不回应的情况，所以在这里就要来这么一手。
		case wakerForNotification:
			n := h.ep.fetchNotifications()
			// 如果收到关闭信号
			if n&notifyClose != 0 {
				return tcpip.ErrAborted
			}
			// 如果需要 BBR 缓解拥塞
			if n&notifyDrain != 0 {
				for !h.ep.segmentQueue.empty() {
					s := h.ep.segmentQueue.dequeue()
					err := h.handleSegment(s)
					s.decRef()
					if err != nil {
						return err
					}
					if h.state == handshakeCompleted {
						return nil
					}
				}
				close(h.ep.drainDone)
				<-h.ep.undrain
			}

		// 等待并处理新的 SYN 数据包或握手第三步的 ACK
		case wakerForNewSegment:

			if err := h.processSegments(); err != nil {
				return err
			}
		}

	}

	return nil
}

func parseSynSegmentOptions(s *segment) header.TCPSynOptions {
	synOpts := header.ParseSynOptions(s.options, s.flagIsSet(header.TCPFlagAck))
	if synOpts.TS {
		s.parsedOptions.TSVal = synOpts.TSVal
		s.parsedOptions.TSEcr = synOpts.TSEcr
	}
	return synOpts
}

var optionPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, maxOptionSize)
	},
}

func getOptions() []byte {
	return optionPool.Get().([]byte)
}

func putOptions(options []byte) {
	// Reslice to full capacity.
	optionPool.Put(options[0:cap(options)])
}

func makeSynOptions(opts header.TCPSynOptions) []byte {
	// Emulate linux option order. This is as follows:
	//
	// if md5: NOP NOP MD5SIG 18 md5sig(16)
	// if mss: MSS 4 mss(2)
	// if ts and sack_advertise:
	//	SACK 2 TIMESTAMP 2 timestamp(8)
	// elif ts: NOP NOP TIMESTAMP 10 timestamp(8)
	// elif sack: NOP NOP SACK 2
	// if wscale: NOP WINDOW 3 ws(1)
	// if sack_blocks: NOP NOP SACK ((2 + (#blocks * 8))
	//	[for each block] start_seq(4) end_seq(4)
	// if fastopen_cookie:
	//	if exp: EXP (4 + len(cookie)) FASTOPEN_MAGIC(2)
	// 	else: FASTOPEN (2 + len(cookie))
	//	cookie(variable) [padding to four bytes]
	//
	options := getOptions()

	// Always encode the mss.
	offset := header.EncodeMSSOption(uint32(opts.MSS), options)

	// Special ordering is required here. If both TS and SACK are enabled,
	// then the SACK option precedes TS, with no padding. If they are
	// enabled individually, then we see padding before the option.
	if opts.TS && opts.SACKPermitted {
		offset += header.EncodeSACKPermittedOption(options[offset:])
		offset += header.EncodeTSOption(opts.TSVal, opts.TSEcr, options[offset:])
	} else if opts.TS {
		offset += header.EncodeNOP(options[offset:])
		offset += header.EncodeNOP(options[offset:])
		offset += header.EncodeTSOption(opts.TSVal, opts.TSEcr, options[offset:])
	} else if opts.SACKPermitted {
		offset += header.EncodeNOP(options[offset:])
		offset += header.EncodeNOP(options[offset:])
		offset += header.EncodeSACKPermittedOption(options[offset:])
	}

	// Initialize the WS option.
	if opts.WS >= 0 {
		offset += header.EncodeNOP(options[offset:])
		offset += header.EncodeWSOption(opts.WS, options[offset:])
	}

	// Padding to the end; note that this never apply unless we add a
	// fastopen option, we always expect the offset to remain the same.
	if delta := header.AddTCPOptionPadding(options, offset); delta != 0 {
		panic("unexpected option encoding")
	}

	return options[:offset]
}

func (e *endpoint) sendSynTCP(r *stack.Route, id stack.TransportEndpointID, ttl, tos uint8, flags byte, seq, ack seqnum.Value, rcvWnd seqnum.Size, opts header.TCPSynOptions) *tcpip.Error {
	options := makeSynOptions(opts)
	// We ignore SYN send errors and let the callers re-attempt send.
	if err := e.sendTCP(r, id, buffer.VectorisedView{}, ttl, tos, flags, seq, ack, rcvWnd, options, nil); err != nil {
		e.stats.SendErrors.SynSendToNetworkFailed.Increment()
	}
	putOptions(options)
	return nil
}

func (e *endpoint) sendTCP(r *stack.Route, id stack.TransportEndpointID, data buffer.VectorisedView, ttl, tos uint8, flags byte, seq, ack seqnum.Value, rcvWnd seqnum.Size, opts []byte, gso *stack.GSO) *tcpip.Error {
	if err := sendTCP(r, id, data, ttl, tos, flags, seq, ack, rcvWnd, opts, gso); err != nil {
		e.stats.SendErrors.SegmentSendToNetworkFailed.Increment()
		return err
	}
	e.stats.SegmentsSent.Increment()
	return nil
}

func buildTCPHdr(r *stack.Route, id stack.TransportEndpointID, d *stack.PacketDescriptor, data buffer.VectorisedView, flags byte, seq, ack seqnum.Value, rcvWnd seqnum.Size, opts []byte, gso *stack.GSO) {
	optLen := len(opts)
	hdr := &d.Hdr
	packetSize := d.Size
	off := d.Off
	// Initialize the header.
	tcp := header.TCP(hdr.Prepend(header.TCPMinimumSize + optLen))
	tcp.Encode(&header.TCPFields{
		SrcPort:    id.LocalPort,
		DstPort:    id.RemotePort,
		SeqNum:     uint32(seq),
		AckNum:     uint32(ack),
		DataOffset: uint8(header.TCPMinimumSize + optLen),
		Flags:      flags,
		WindowSize: uint16(rcvWnd),
	})
	copy(tcp[header.TCPMinimumSize:], opts)

	length := uint16(hdr.UsedLength() + packetSize)
	xsum := r.PseudoHeaderChecksum(ProtocolNumber, length)
	// Only calculate the checksum if offloading isn't supported.
	if gso != nil && gso.NeedsCsum {
		// This is called CHECKSUM_PARTIAL in the Linux kernel. We
		// calculate a checksum of the pseudo-header and save it in the
		// TCP header, then the kernel calculate a checksum of the
		// header and data and get the right sum of the TCP packet.
		tcp.SetChecksum(xsum)
	} else if r.Capabilities()&stack.CapabilityTXChecksumOffload == 0 {
		xsum = header.ChecksumVVWithOffset(data, xsum, off, packetSize)
		tcp.SetChecksum(^tcp.CalculateChecksum(xsum))
	}

}

func sendTCPBatch(r *stack.Route, id stack.TransportEndpointID, data buffer.VectorisedView, ttl, tos uint8, flags byte, seq, ack seqnum.Value, rcvWnd seqnum.Size, opts []byte, gso *stack.GSO) *tcpip.Error {
	optLen := len(opts)
	if rcvWnd > 0xffff {
		rcvWnd = 0xffff
	}

	mss := int(gso.MSS)
	n := (data.Size() + mss - 1) / mss

	hdrs := stack.NewPacketDescriptors(n, header.TCPMinimumSize+int(r.MaxHeaderLength())+optLen)

	size := data.Size()
	off := 0
	for i := 0; i < n; i++ {
		packetSize := mss
		if packetSize > size {
			packetSize = size
		}
		size -= packetSize
		hdrs[i].Off = off
		hdrs[i].Size = packetSize
		buildTCPHdr(r, id, &hdrs[i], data, flags, seq, ack, rcvWnd, opts, gso)
		off += packetSize
		seq = seq.Add(seqnum.Size(packetSize))
	}
	if ttl == 0 {
		ttl = r.DefaultTTL()
	}
	sent, err := r.WritePackets(gso, hdrs, data, stack.NetworkHeaderParams{Protocol: ProtocolNumber, TTL: ttl, TOS: tos})
	if err != nil {
		r.Stats().TCP.SegmentSendErrors.IncrementBy(uint64(n - sent))
	}
	r.Stats().TCP.SegmentsSent.IncrementBy(uint64(sent))
	return err
}

// sendTCP sends a TCP segment with the provided options via the provided
// network endpoint and under the provided identity.
func sendTCP(r *stack.Route, id stack.TransportEndpointID, data buffer.VectorisedView, ttl, tos uint8, flags byte, seq, ack seqnum.Value, rcvWnd seqnum.Size, opts []byte, gso *stack.GSO) *tcpip.Error {
	optLen := len(opts)
	if rcvWnd > 0xffff {
		rcvWnd = 0xffff
	}

	if r.Loop&stack.PacketLoop == 0 && gso != nil && gso.Type == stack.GSOSW && int(gso.MSS) < data.Size() {
		return sendTCPBatch(r, id, data, ttl, tos, flags, seq, ack, rcvWnd, opts, gso)
	}

	d := &stack.PacketDescriptor{
		Hdr:  buffer.NewPrependable(header.TCPMinimumSize + int(r.MaxHeaderLength()) + optLen),
		Off:  0,
		Size: data.Size(),
	}
	buildTCPHdr(r, id, d, data, flags, seq, ack, rcvWnd, opts, gso)

	if ttl == 0 {
		ttl = r.DefaultTTL()
	}
	if err := r.WritePacket(gso, stack.NetworkHeaderParams{Protocol: ProtocolNumber, TTL: ttl, TOS: tos}, tcpip.PacketBuffer{
		Header: d.Hdr,
		Data:   data,
	}); err != nil {
		r.Stats().TCP.SegmentSendErrors.Increment()
		return err
	}
	r.Stats().TCP.SegmentsSent.Increment()
	if (flags & header.TCPFlagRst) != 0 {
		r.Stats().TCP.ResetsSent.Increment()
	}
	return nil
}

// makeOptions makes an options slice.
func (e *endpoint) makeOptions(sackBlocks []header.SACKBlock) []byte {
	options := getOptions()
	offset := 0

	// N.B. the ordering here matches the ordering used by Linux internally
	// and described in the raw makeOptions function. We don't include
	// unnecessary cases here (post connection.)
	if e.sendTSOk {
		// Embed the timestamp if timestamp has been enabled.
		//
		// We only use the lower 32 bits of the unix time in
		// milliseconds. This is similar to what Linux does where it
		// uses the lower 32 bits of the jiffies value in the tsVal
		// field of the timestamp option.
		//
		// Further, RFC7323 section-5.4 recommends millisecond
		// resolution as the lowest recommended resolution for the
		// timestamp clock.
		//
		// Ref: https://tools.ietf.org/html/rfc7323#section-5.4.
		offset += header.EncodeNOP(options[offset:])
		offset += header.EncodeNOP(options[offset:])
		offset += header.EncodeTSOption(e.timestamp(), uint32(e.recentTS), options[offset:])
	}
	if e.sackPermitted && len(sackBlocks) > 0 {
		offset += header.EncodeNOP(options[offset:])
		offset += header.EncodeNOP(options[offset:])
		offset += header.EncodeSACKBlocks(sackBlocks, options[offset:])
	}

	// We expect the above to produce an aligned offset.
	if delta := header.AddTCPOptionPadding(options, offset); delta != 0 {
		panic("unexpected option encoding")
	}

	return options[:offset]
}

// sendRaw sends a TCP segment to the endpoint's peer.
func (e *endpoint) sendRaw(data buffer.VectorisedView, flags byte, seq, ack seqnum.Value, rcvWnd seqnum.Size) *tcpip.Error {
	var sackBlocks []header.SACKBlock
	if e.state == StateEstablished && e.rcv.pendingBufSize > 0 && (flags&header.TCPFlagAck != 0) {
		sackBlocks = e.sack.Blocks[:e.sack.NumBlocks]
	}
	options := e.makeOptions(sackBlocks)
	err := e.sendTCP(&e.route, e.ID, data, e.ttl, e.sendTOS, flags, seq, ack, rcvWnd, options, e.gso)
	putOptions(options)
	return err
}

func (e *endpoint) handleWrite() *tcpip.Error {

	// Move packets from send queue to send list. The queue is accessible
	// from other goroutines and protected by the send mutex, while the send
	// list is only accessible from the handler goroutine, so it needs no mutexes.
	//
	// 将数据包从发送队列 e.sendQueue 移动到发送列表 e.snd.writeList 。
	//
	// 发送队列 e.sendQueue 可以被多个 goroutine 并发访问，所以要受 e.sndBufMu 保护。
	// 发送列表 e.snd.writeList 只能从 handleWrite() 中访问，调用 handleWrite() 时已经加了锁，
	// 所以 e.snd.writeList 只能被一个 goroutine 操作，不需要再加锁。
	//
	e.sndBufMu.Lock()
	first := e.sndQueue.Front()
	if first != nil {
		e.snd.writeList.PushBackList(&e.sndQueue)		// 把 e.sendQueue 整个链表追加到了 e.snd.writeList 尾部，由 e.sender 接管
		e.snd.sndNxtList.UpdateForward(e.sndBufInQueue) //
		e.sndBufInQueue = 0 							//
	}
	e.sndBufMu.Unlock()

	// Initialize the next segment to write if it's currently nil.
	// 如果当前 e.snd.writeNext  为 nil ，则初始化为下一个将要写的段，即 first 。
	if e.snd.writeNext == nil {
		e.snd.writeNext = first
	}

	// Push out any new packets.
	// 推送出任何新的数据包。
	e.snd.sendData()

	return nil
}

func (e *endpoint) handleClose() *tcpip.Error {
	// Drain the send queue.
	e.handleWrite()

	// Mark send side as closed.
	e.snd.closed = true

	return nil
}

// resetConnectionLocked puts the endpoint in an error state with the given
// error code and sends a RST if and only if the error is not ErrConnectionReset
// indicating that the connection is being reset due to receiving a RST. This
// method must only be called from the protocol goroutine.
func (e *endpoint) resetConnectionLocked(err *tcpip.Error) {
	// Only send a reset if the connection is being aborted for a reason
	// other than receiving a reset.
	if e.state == StateEstablished || e.state == StateCloseWait {
		e.stack.Stats().TCP.EstablishedResets.Increment()
		e.stack.Stats().TCP.CurrentEstablished.Decrement()
	}
	e.state = StateError
	e.HardError = err
	if err != tcpip.ErrConnectionReset {
		// The exact sequence number to be used for the RST is the same as the
		// one used by Linux. We need to handle the case of window being shrunk
		// which can cause sndNxt to be outside the acceptable window on the
		// receiver.
		//
		// See: https://www.snellman.net/blog/archive/2016-02-01-tcp-rst/ for more
		// information.
		sndWndEnd := e.snd.sndUna.Add(e.snd.sndWnd)
		resetSeqNum := sndWndEnd
		if !sndWndEnd.LessThan(e.snd.sndNxt) || e.snd.sndNxt.Size(sndWndEnd) < (1<<e.snd.sndWndScale) {
			resetSeqNum = e.snd.sndNxt
		}
		e.sendRaw(buffer.VectorisedView{}, header.TCPFlagAck|header.TCPFlagRst, resetSeqNum, e.rcv.rcvNxt, 0)
	}
}

// completeWorkerLocked is called by the worker goroutine when it's about to exit.
// It marks the worker as completed and performs cleanup work if requested by Close().
func (e *endpoint) completeWorkerLocked() {
	e.workerRunning = false
	if e.workerCleanup {
		e.cleanupLocked()
	}
}

// transitionToStateCloseLocked ensures that the endpoint is
// cleaned up from the transport demuxer, "before" moving to
// StateClose. This will ensure that no packet will be
// delivered to this endpoint from the demuxer when the endpoint
// is transitioned to StateClose.
func (e *endpoint) transitionToStateCloseLocked() {
	if e.state == StateClose {
		return
	}
	e.cleanupLocked()
	e.state = StateClose
}

// tryDeliverSegmentFromClosedEndpoint attempts to deliver the parsed
// segment to any other endpoint other than the current one. This is called
// only when the endpoint is in StateClose and we want to deliver the segment
// to any other listening endpoint. We reply with RST if we cannot find one.
func (e *endpoint) tryDeliverSegmentFromClosedEndpoint(s *segment) {
	ep := e.stack.FindTransportEndpoint(e.NetProto, e.TransProto, e.ID, &s.route)
	if ep == nil {
		replyWithReset(s)
		s.decRef()
		return
	}
	ep.(*endpoint).enqueueSegment(s)
}

func (e *endpoint) handleReset(s *segment) (ok bool, err *tcpip.Error) {
	if e.rcv.acceptable(s.sequenceNumber, 0) {
		// RFC 793, page 37 states that "in all states
		// except SYN-SENT, all reset (RST) segments are
		// validated by checking their SEQ-fields." So
		// we only process it if it's acceptable.
		s.decRef()
		e.mu.Lock()
		switch e.state {
		// In case of a RST in CLOSE-WAIT linux moves
		// the socket to closed state with an error set
		// to indicate EPIPE.
		//
		// Technically this seems to be at odds w/ RFC.
		// As per https://tools.ietf.org/html/rfc793#section-2.7
		// page 69 the behavior for a segment arriving
		// w/ RST bit set in CLOSE-WAIT is inlined below.
		//
		//  ESTABLISHED
		//  FIN-WAIT-1
		//  FIN-WAIT-2
		//  CLOSE-WAIT

		//  If the RST bit is set then, any outstanding RECEIVEs and
		//  SEND should receive "reset" responses. All segment queues
		//  should be flushed.  Users should also receive an unsolicited
		//  general "connection reset" signal. Enter the CLOSED state,
		//  delete the TCB, and return.
		case StateCloseWait:
			e.transitionToStateCloseLocked()
			e.HardError = tcpip.ErrAborted
			e.mu.Unlock()
			return false, nil
		default:
			e.mu.Unlock()
			return false, tcpip.ErrConnectionReset
		}
	}
	return true, nil
}

// handleSegments pulls segments from the queue and processes them.
// It returns no error if the protocol loop should continue, an error otherwise.
func (e *endpoint) handleSegments() *tcpip.Error {

	checkRequeue := true

	// maxSegmentsPerWake 是一个常量，值为 100，其实是随意设置的一个值，因为每次 newSegmentWaker 被触发时可能有很多包要被处理。
	for i := 0; i < maxSegmentsPerWake; i++ {

		e.mu.RLock()
		state := e.state
		e.mu.RUnlock()

		if state == StateClose {
			// When we get into StateClose while processing from the queue,
			// return immediately and let the protocolMainloop handle it.
			//
			// We can reach StateClose only while processing a previous segment
			// or a notification from the protocolMainLoop (caller goroutine).
			// This means that with this return, the segment dequeue below can
			// never occur on a closed endpoint.
			return nil
		}

		// 从队列拿到无序的数据包
		s := e.segmentQueue.dequeue()
		if s == nil {
			checkRequeue = false
			break
		}

		// Invoke the tcp probe if installed.
		// 如果安装了 tcp 探针，则调用该探针。
		if e.probe != nil {
			e.probe(e.completeState())
		}

		// 处理 RST 报文
		if s.flagIsSet(header.TCPFlagRst) {
			if ok, err := e.handleReset(s); !ok {
				return err
			}

		// 处理 SYN 报文
		} else if s.flagIsSet(header.TCPFlagSyn) {

			// See: https://tools.ietf.org/html/rfc5961#section-4.1
			//   1) If the SYN bit is set, irrespective of the sequence number, TCP
			//    MUST send an ACK (also referred to as challenge ACK) to the remote
			//    peer:
			//
			//    <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>
			//
			//    After sending the acknowledgment, TCP MUST drop the unacceptable
			//    segment and stop processing further.


			// By sending an ACK, the remote peer is challenged to confirm the loss
			// of the previous connection and the request to start a new connection.
			// A legitimate peer, after restart, would not have a TCB in the
			// synchronized state.  Thus, when the ACK arrives, the peer should send
			// a RST segment back with the sequence number derived from the ACK
			// field that caused the RST.
			//
			// 通过发送 ACK ，远程 peer 受到挑战，以确认前一个连接的丢失和启动新连接的请求。
			// 合法的 peer 在重新启动后，不会有一个处于同步状态的 TCP 连接。
			// 因此，当 ACK 到达时，远程 peer 应该发送一个 RST 段回来，序列号来自引起 RST 的 ACK 字段。


			// This RST will confirm that the remote peer has indeed closed the
			// previous connection.  Upon receipt of a valid RST, the local TCP
			// endpoint MUST terminate its connection.  The local TCP endpoint
			// should then rely on SYN retransmission from the remote end to
			// re-establish the connection.
			//
			// 该 RST 将确认远程 peer 确实已经关闭了之前的连接。
			// 收到有效的 RST 后，本地 TCP 端点必须终止其连接。
			// 然后，本地 TCP 端点应该依靠远端的 SYN 重传来重新建立连接。

			e.snd.sendAck()

		// 处理 ACK 报文
		} else if s.flagIsSet(header.TCPFlagAck) {

			// Patch the window size in the segment according to the send window scale.
			// 根据发送窗口的比例，在该段中修补窗口大小。
			s.window <<= e.snd.sndWndScale

			// RFC 793, page 41 states that
			// "once in the ESTABLISHED state all segments must carry current acknowledgment information."
			//
			// 一旦进入 ESTABLISHED 状态，所有的段必须携带当前的确认信息。
			drop, err := e.rcv.handleRcvdSegment(s)

			if err != nil {
				s.decRef()
				return err
			}

			if drop {
				s.decRef()
				continue
			}

			e.snd.handleRcvdSegment(s)
		}
		s.decRef()
	}


	// If the queue is not empty, make sure we'll wake up in the next iteration.
	// 当 100 次过后还有未处理的包，再次触发 newSegmentWaker，继续处理。
	if checkRequeue && !e.segmentQueue.empty() {
		e.newSegmentWaker.Assert()
	}

	// Send an ACK for all processed packets if needed.
	// 如果需要，为所有处理过的数据包发送ACK。
	if e.rcv.rcvNxt != e.snd.maxSentAck {
		e.snd.sendAck()
	}

	// 重置 keepalive 定时器
	e.resetKeepaliveTimer(true)

	return nil
}

// keepaliveTimerExpired is called when the keepaliveTimer fires.
// We send TCP keepalive packets periodically when the connection is idle.
// If we don't hear from the other side after a number of tries, we terminate the connection.
//
// keepaliveTimerExpired() 在 keepaliveTimer 触发时被调用。
// 当连接空闲时，我们会定期发送 TCP keepalive 数据包，如果多次发送后都没有收到对方的回应，就终止连接。
func (e *endpoint) keepaliveTimerExpired() *tcpip.Error {

	e.keepalive.Lock()
	if !e.keepalive.enabled || !e.keepalive.timer.checkExpiration() {
		e.keepalive.Unlock()
		return nil
	}


	// 若 unacked 的 keepalive 数据包超过阈值，则中断连接。
	if e.keepalive.unacked >= e.keepalive.count {
		e.keepalive.Unlock()
		return tcpip.ErrTimeout
	}

	// RFC1122 4.2.3.6: TCP keepalive is a dataless ACK with seg.seq = snd.nxt-1.
	// RFC1122 4.2.3.6: TCP keepalive 是一个无数据 ACK ，seg.seq = snd.nxt-1 。

	// 当 keepaliveTimerExpired() 被调用，意味着 keepalive 数据包发送超时，没有得到对方响应，需要增加 unacked 计数。
	e.keepalive.unacked++
	e.keepalive.Unlock()

	//
	e.snd.sendSegmentFromView(buffer.VectorisedView{}, header.TCPFlagAck, e.snd.sndNxt-1)

	// 重置 keepalive 超时定时器。
	e.resetKeepaliveTimer(false)
	return nil
}

// resetKeepaliveTimer restarts or stops the keepalive timer, depending on
// whether it is enabled for this endpoint.
func (e *endpoint) resetKeepaliveTimer(receivedData bool) {
	e.keepalive.Lock()
	defer e.keepalive.Unlock()
	if receivedData {
		e.keepalive.unacked = 0
	}
	// Start the keepalive timer IFF it's enabled and there is no pending data to send.
	if !e.keepalive.enabled || e.snd == nil || e.snd.sndUna != e.snd.sndNxt {
		e.keepalive.timer.disable()
		return
	}
	if e.keepalive.unacked > 0 {
		e.keepalive.timer.enable(e.keepalive.interval)
	} else {
		e.keepalive.timer.enable(e.keepalive.idle)
	}
}

// disableKeepaliveTimer stops the keepalive timer.
func (e *endpoint) disableKeepaliveTimer() {
	e.keepalive.Lock()
	e.keepalive.timer.disable()
	e.keepalive.Unlock()
}

// protocolMainLoop is the main loop of the TCP protocol. It runs in its own
// goroutine and is responsible for sending segments and handling received segments.
//
//
// 主要是注册一些回调，添加到 sleeper 的 waker 里，然后进入循环，Fetch 拿到触发了的事件，然后执行这些事件对应的回调。

func (e *endpoint) protocolMainLoop(handshake bool) *tcpip.Error {

	var closeTimer *time.Timer
	var closeWaker sleep.Waker

	// 尾声
	epilogue := func() {

		// e.mu is expected to be hold upon entering this section.
		if e.snd != nil {
			e.snd.resendTimer.cleanup()
		}

		if closeTimer != nil {
			closeTimer.Stop()
		}

		e.completeWorkerLocked()

		if e.drainDone != nil {
			close(e.drainDone)
		}

		e.mu.Unlock()
		// When the protocol loop exits we should wake up our waiters.
		e.waiterQueue.Notify(waiter.EventHUp | waiter.EventErr | waiter.EventIn | waiter.EventOut)
	}


	if handshake {
		// This is an active connection, so we must initiate the 3-way handshake,
		// and then inform potential waiters about its completion.
		//
		// 这是主动连接，我们必须发起 3 路握手，然后在完成后通知潜在的 waiters 。
		initialRcvWnd := e.initialReceiveWindow()
		h := newHandshake(e, seqnum.Size(initialRcvWnd))
		e.mu.Lock()
		h.ep.state = StateSynSent // 处于 "SynSent" 状态
		e.mu.Unlock()

		// 执行三次握手
		if err := h.execute(); err != nil {
			e.lastErrorMu.Lock()
			e.lastError = err
			e.lastErrorMu.Unlock()

			e.mu.Lock()
			e.stack.Stats().TCP.EstablishedResets.Increment()
			e.stack.Stats().TCP.CurrentEstablished.Decrement()
			e.state = StateError
			e.HardError = err

			// Lock released below.
			epilogue()
			return err
		}

		// Transfer handshake state to TCP connection.
		// We disable receive window scaling if the peer doesn't
		// support it (indicated by a negative send window scale).
		e.snd = newSender(e, h.iss, h.ackNum-1, h.sndWnd, h.mss, h.sndWndScale)

		rcvBufSize := seqnum.Size(e.receiveBufferSize())
		e.rcvListMu.Lock()
		e.rcv = newReceiver(e, h.ackNum-1, h.rcvWnd, h.effectiveRcvWndScale(), rcvBufSize)
		// boot strap the auto tuning algorithm. Starting at zero will
		// result in a large step function on the first proper causing
		// the window to just go to a really large value after the first
		// RTT itself.
		e.rcvAutoParams.prevCopied = initialRcvWnd
		e.rcvListMu.Unlock()
		e.stack.Stats().TCP.CurrentEstablished.Increment()
		e.mu.Lock()
		e.state = StateEstablished
		e.mu.Unlock()
	}

	e.keepalive.timer.init(&e.keepalive.waker)
	defer e.keepalive.timer.cleanup()

	// Tell waiters that the endpoint is connected and writable.
	e.mu.Lock()
	drained := e.drainDone != nil
	e.mu.Unlock()
	if drained {
		close(e.drainDone)
		<-e.undrain
	}

	e.waiterQueue.Notify(waiter.EventOut)

	// Set up the functions that will be called when the main protocol loop wakes up.
	// 设置主协议循环唤醒时调用的函数。
	funcs := [] struct {
		w *sleep.Waker
		f func() *tcpip.Error
	}{
		{
			w: &e.sndWaker,
			f: e.handleWrite,
		},
		{
			w: &e.sndCloseWaker,
			f: e.handleClose,
		},
		{
			w: &e.newSegmentWaker,
			f: e.handleSegments,
		},
		{
			w: &closeWaker,
			f: func() *tcpip.Error {
				// This means the socket is being closed due to the TCP_FIN_WAIT2 timeout was hit.
				// Just mark the socket as closed.
				//
				// 这意味着由于 TCP_FIN_WAIT2 超时，套接字正在被关闭，将该套接字标记为 'StateClose' 即可。
				e.mu.Lock()
				e.transitionToStateCloseLocked()
				e.mu.Unlock()
				return nil
			},
		},
		{
			w: &e.snd.resendWaker,
			f: func() *tcpip.Error {
				if !e.snd.retransmitTimerExpired() {
					return tcpip.ErrTimeout
				}
				return nil
			},
		},
		{
			w: &e.keepalive.waker,
			f: e.keepaliveTimerExpired,
		},
		{
			w: &e.notificationWaker,
			f: func() *tcpip.Error {

				n := e.fetchNotifications()
				if n&notifyNonZeroReceiveWindow != 0 {
					e.rcv.nonZeroWindow()
				}

				if n&notifyReceiveWindowChanged != 0 {
					e.rcv.pendingBufSize = seqnum.Size(e.receiveBufferSize())
				}

				if n&notifyMTUChanged != 0 {
					e.sndBufMu.Lock()
					count := e.packetTooBigCount
					e.packetTooBigCount = 0
					mtu := e.sndMTU
					e.sndBufMu.Unlock()

					e.snd.updateMaxPayloadSize(mtu, count)
				}

				if n&notifyReset != 0 {
					e.mu.Lock()
					e.resetConnectionLocked(tcpip.ErrConnectionAborted)
					e.mu.Unlock()
				}

				if n&notifyClose != 0 && closeTimer == nil {
					e.mu.Lock()
					if e.state == StateFinWait2 && e.closed {
						// The socket has been closed and we are in FIN_WAIT2
						// so start the FIN_WAIT2 timer.
						closeTimer = time.AfterFunc(e.tcpLingerTimeout, func() {
							closeWaker.Assert()
						})
						e.waiterQueue.Notify(waiter.EventHUp | waiter.EventErr | waiter.EventIn | waiter.EventOut)
					}
					e.mu.Unlock()
				}

				if n&notifyKeepaliveChanged != 0 {
					// The timer could fire in background
					// when the endpoint is drained. That's
					// OK. See above.
					e.resetKeepaliveTimer(true)
				}

				if n&notifyDrain != 0 {
					for !e.segmentQueue.empty() {
						if err := e.handleSegments(); err != nil {
							return err
						}
					}
					if e.state != StateClose && e.state != StateError {
						// Only block the worker if the endpoint
						// is not in closed state or error state.
						close(e.drainDone)
						<-e.undrain
					}
				}

				if n&notifyTickleWorker != 0 {
					// Just a tickle notification. No need to do
					// anything.
					return nil
				}

				return nil
			},
		},
	}

	// Initialize the sleeper based on the wakers in funcs.
	s := sleep.Sleeper{}
	for i := range funcs {
		s.AddWaker(funcs[i].w, i)
	}

	// The following assertions and notifications are needed for restored
	// endpoints. Fresh newly created endpoints have empty states and should
	// not invoke any.
	e.segmentQueue.mu.Lock()
	if !e.segmentQueue.list.Empty() {
		e.newSegmentWaker.Assert()
	}
	e.segmentQueue.mu.Unlock()

	e.rcvListMu.Lock()
	if !e.rcvList.Empty() {
		e.waiterQueue.Notify(waiter.EventIn)
	}
	e.rcvListMu.Unlock()

	e.mu.Lock()
	if e.workerCleanup {
		e.notifyProtocolGoroutine(notifyClose)
	}

	// Main loop. Handle segments until both send and receive ends of the
	// connection have completed.

	for e.state != StateTimeWait && e.state != StateClose && e.state != StateError {
		e.mu.Unlock()
		e.workMu.Unlock()
		v, _ := s.Fetch(true)
		e.workMu.Lock()
		if err := funcs[v].f(); err != nil {
			e.mu.Lock()
			// Ensure we release all endpoint registration and route
			// references as the connection is now in an error state.
			e.workerCleanup = true
			e.resetConnectionLocked(err)
			// Lock released below.
			epilogue()

			return nil
		}
		e.mu.Lock()
	}

	state := e.state
	e.mu.Unlock()
	var reuseTW func()
	if state == StateTimeWait {

		// Disable close timer as we now entering real TIME_WAIT.
		if closeTimer != nil {
			closeTimer.Stop()
		}

		// Mark the current sleeper done so as to free all associated wakers.
		s.Done()
		// Wake up any waiters before we enter TIME_WAIT.
		e.waiterQueue.Notify(waiter.EventHUp | waiter.EventErr | waiter.EventIn | waiter.EventOut)
		reuseTW = e.doTimeWait()
	}

	// Mark endpoint as closed.
	e.mu.Lock()
	if e.state != StateError {
		e.stack.Stats().TCP.EstablishedResets.Increment()
		e.stack.Stats().TCP.CurrentEstablished.Decrement()
		e.transitionToStateCloseLocked()
	}

	// Lock released below.
	epilogue()

	// epilogue removes the endpoint from the transport-demuxer and
	// unlocks e.mu. Now that no new segments can get enqueued to this
	// endpoint, try to re-match the segment to a different endpoint
	// as the current endpoint is closed.
	for !e.segmentQueue.empty() {
		s := e.segmentQueue.dequeue()
		e.tryDeliverSegmentFromClosedEndpoint(s)
	}

	// A new SYN was received during TIME_WAIT and we need to abort
	// the timewait and redirect the segment to the listener queue
	if reuseTW != nil {
		reuseTW()
	}

	return nil
}



// handleTimeWaitSegments processes segments received during TIME_WAIT state.
func (e *endpoint) handleTimeWaitSegments() (extendTimeWait bool, reuseTW func()) {
	checkRequeue := true
	for i := 0; i < maxSegmentsPerWake; i++ {
		s := e.segmentQueue.dequeue()
		if s == nil {
			checkRequeue = false
			break
		}
		extTW, newSyn := e.rcv.handleTimeWaitSegment(s)
		if newSyn {
			info := e.EndpointInfo.TransportEndpointInfo
			newID := info.ID
			newID.RemoteAddress = ""
			newID.RemotePort = 0
			netProtos := []tcpip.NetworkProtocolNumber{info.NetProto}
			// If the local address is an IPv4 address then also
			// look for IPv6 dual stack endpoints that might be
			// listening on the local address.
			if newID.LocalAddress.To4() != "" {
				netProtos = []tcpip.NetworkProtocolNumber{header.IPv4ProtocolNumber, header.IPv6ProtocolNumber}
			}
			for _, netProto := range netProtos {
				if listenEP := e.stack.FindTransportEndpoint(netProto, info.TransProto, newID, &s.route); listenEP != nil {
					tcpEP := listenEP.(*endpoint)
					if EndpointState(tcpEP.State()) == StateListen {
						reuseTW = func() {
							tcpEP.enqueueSegment(s)
						}
						// We explicitly do not decRef
						// the segment as it's still
						// valid and being reflected to
						// a listening endpoint.
						return false, reuseTW
					}
				}
			}
		}
		if extTW {
			extendTimeWait = true
		}
		s.decRef()
	}
	if checkRequeue && !e.segmentQueue.empty() {
		e.newSegmentWaker.Assert()
	}
	return extendTimeWait, nil
}

// doTimeWait is responsible for handling the TCP behaviour once a socket
// enters the TIME_WAIT state. Optionally it can return a closure that
// should be executed after releasing the endpoint registrations. This is
// done in cases where a new SYN is received during TIME_WAIT that carries
// a sequence number larger than one see on the connection.
func (e *endpoint) doTimeWait() (twReuse func()) {

	// Trigger a 2 * MSL time wait state.
	// During this period we will drop all incoming segments.
	// NOTE: On Linux this is not configurable and is fixed at 60 seconds.
	timeWaitDuration := DefaultTCPTimeWaitTimeout

	// Get the stack wide configuration.
	var tcpTW tcpip.TCPTimeWaitTimeoutOption
	if err := e.stack.TransportProtocolOption(ProtocolNumber, &tcpTW); err == nil {
		timeWaitDuration = time.Duration(tcpTW)
	}

	const newSegment = 1
	const notification = 2
	const timeWaitDone = 3

	s := sleep.Sleeper{}
	s.AddWaker(&e.newSegmentWaker, newSegment)
	s.AddWaker(&e.notificationWaker, notification)

	var timeWaitWaker sleep.Waker
	s.AddWaker(&timeWaitWaker, timeWaitDone)
	timeWaitTimer := time.AfterFunc(timeWaitDuration, timeWaitWaker.Assert)
	defer timeWaitTimer.Stop()

	for {
		e.workMu.Unlock()
		v, _ := s.Fetch(true)
		e.workMu.Lock()
		switch v {
		case newSegment:
			extendTimeWait, reuseTW := e.handleTimeWaitSegments()
			if reuseTW != nil {
				return reuseTW
			}
			if extendTimeWait {
				timeWaitTimer.Reset(timeWaitDuration)
			}
		case notification:

			n := e.fetchNotifications()
			if n&notifyClose != 0 {
				return nil
			}

			if n&notifyDrain != 0 {
				for !e.segmentQueue.empty() {
					// Ignore extending TIME_WAIT during a save.
					// For sockets in TIME_WAIT we just terminate the TIME_WAIT early.
					e.handleTimeWaitSegments()
				}
				close(e.drainDone)
				<-e.undrain
				return nil
			}

		case timeWaitDone:
			return nil
		}
	}
}
