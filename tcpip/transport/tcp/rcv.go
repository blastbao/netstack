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
	"container/heap"
	"time"

	"github.com/blastbao/netstack/tcpip"
	"github.com/blastbao/netstack/tcpip/header"
	"github.com/blastbao/netstack/tcpip/seqnum"
)

// receiver holds the state necessary to receive TCP segments and turn them into a stream of bytes.
//
// +stateify savable
type receiver struct {

	ep *endpoint

	//
	//						 +-------> rcvWnd <-------+
	//						 |                        |
	//	---------------------+------------------------+--------------------
	//	|      rcved         | * * * * * * * * * *  * |   unrcved
	//	---------------------+------------------------+--------------------
	//						 ^                        ^
	//						 |                        |
	// 					   rcvNxt                  rcvNxt + rcvWnd
	//
	//
	// Receive Sequence Space
	//	rcved 	- old sequence numbers which have been acknowledged
	//  rcvWnd 	- sequence numbers allowed for new reception
	//  unrcved - future sequence numbers which are not yet allowed


	// 接下来要接收的序号
	rcvNxt seqnum.Value

	// rcvAcc is one beyond the last acceptable sequence number.
	// That is, the "largest" sequence value that the receiver has announced to the
	// its peer that it's willing to accept.
	//
	// This may be different than rcvNxt + rcvWnd if the receive window is reduced;
	// in that case we have to reduce the window as we receive more data instead of shrinking it.
	//
	// rcvAcc 是最后一个可接受的序列号 +1 ，也就是接收者向其 peer 宣布的它愿意接受的 "最大 "序列值。
	//
	// ////// 如果当前窗口大小为 [rcvNxt, rcvNxt+rcvWnd)
	//
	rcvAcc seqnum.Value


	// rcvWnd is the non-scaled receive window last advertised to the peer.
	// 当前接收窗口的大小，
	rcvWnd seqnum.Size

	// 本端接收窗口扩大因子，大小是 8 bit，所以其值最大为 255 。
	rcvWndScale uint8

	closed bool

	pendingRcvdSegments segmentHeap
	pendingBufUsed      seqnum.Size
	pendingBufSize      seqnum.Size

}

func newReceiver(ep *endpoint, irs seqnum.Value, rcvWnd seqnum.Size, rcvWndScale uint8, pendingBufSize seqnum.Size) *receiver {
	return &receiver{
		ep:             ep,
		rcvNxt:         irs + 1,				// 希望接收的下个序号
		rcvAcc:         irs.Add(rcvWnd + 1), 	// 所能接受的最大序号
		rcvWnd:         rcvWnd, 				// 接收窗口
		rcvWndScale:    rcvWndScale,			// 接收窗口扩大倍数
		pendingBufSize: pendingBufSize,			//
	}
}


// acceptable checks if the segment sequence number range is acceptable
// according to the table on page 26 of RFC 793.
//
// tcp流量控制：判断 segSeq 在窗口內
func (r *receiver) acceptable(segSeq seqnum.Value, segLen seqnum.Size) bool {

	// 计算接收窗口： rcvWnd := rcvAcc - rcvNxt
	rcvWnd := r.rcvNxt.Size(r.rcvAcc)
	if rcvWnd == 0 {
		return segLen == 0 && segSeq == r.rcvNxt
	}

	return segSeq.InWindow(r.rcvNxt, rcvWnd) || seqnum.Overlap(r.rcvNxt, rcvWnd, segSeq, segLen)
}


// getSendParams returns the parameters needed by the sender when building segments to send.
// getSendParams 返回 sender 在构造 segments 时需要的参数：（1）期待接收的段序号 （2）当前接收窗口大小。
func (r *receiver) getSendParams() (rcvNxt seqnum.Value, rcvWnd seqnum.Size) {

	// Calculate the window size based on the available buffer space.
	// 根据可用的缓冲空间计算接收窗口大小。

	// 1. 获取当前可用的接收缓冲区大小
	receiveBufferAvailable := r.ep.receiveBufferAvailable()

	// 2. 根据缓存区大小和 rcvNxt 计算当前能接收的最大序号 rcvAcc
	acc := r.rcvNxt.Add(seqnum.Size(receiveBufferAvailable))
	if r.rcvAcc.LessThan(acc) {
		r.rcvAcc = acc
	}

	// Stash away the non-scaled receive window as we use it for measuring receiver's estimated RTT.
	// 收起 non-scaled 的接收窗口，因为我们用它来测量接收器的估计 RTT 。

	// 3. 计算当前接收窗口大小
	r.rcvWnd = r.rcvNxt.Size(r.rcvAcc)

	// 4. 返回（1）期待接收的段序号；（2）当前接收窗口大小。
	return r.rcvNxt, r.rcvWnd >> r.rcvWndScale
}

// nonZeroWindow is called when the receive window grows from zero to nonzero;
// in such cases we may need to send an ack to indicate to our peer that it can resume sending data.
//
// tcp 流量控制：当接收窗口从零增长到非零时，调用 nonZeroWindow；在这种情况下，我们可能需要发送一个 ack，以便向对端表明它可以恢复发送数据。
func (r *receiver) nonZeroWindow() {
	if (r.rcvAcc-r.rcvNxt)>>r.rcvWndScale != 0 {
		// We never got around to announcing a zero window size,
		// so we don't need to immediately announce a nonzero one.
		return
	}
	// Immediately send an ack.
	r.ep.snd.sendAck()
}

// consumeSegment attempts to consume a segment that was received by r. The
// segment may have just been received or may have been received earlier but
// wasn't ready to be consumed then.
//
// Returns true if the segment was consumed, false if it cannot be consumed
// yet because of a missing segment.
//
// consumeSegment 判断当前收到的包是否可以造成接收窗口右移，
// 如果是，说明 pendingRcvdSegments 这个堆里的数据包是连续的，
// 然后把连续的包存到 endpoint 的 rcvList 队列里；
// 如果不是，说明收到失序报文段，返回 FALSE
func (r *receiver) consumeSegment(s *segment, segSeq seqnum.Value, segLen seqnum.Size) bool {

	if segLen > 0 {

		// If the segment doesn't include the seqnum we're expecting to consume now, we're missing a segment.
		// We cannot proceed until we receive that segment though.
		//
		if !r.rcvNxt.InWindow(segSeq, segLen) {
			return false
		}

		// Trim segment to eliminate already acknowledged data.
		if segSeq.LessThan(r.rcvNxt) {
			diff := segSeq.Size(r.rcvNxt)
			segLen -= diff
			segSeq.UpdateForward(diff)
			s.sequenceNumber.UpdateForward(diff)
			s.data.TrimFront(int(diff))
		}

		// Move segment to ready-to-deliver list. Wakeup any waiters.
		r.ep.readyToRead(s)

	} else if segSeq != r.rcvNxt {
		return false
	}

	// Update the segment that we're expecting to consume.
	r.rcvNxt = segSeq.Add(segLen)

	// In cases of a misbehaving sender which could send more than the
	// advertised window, we could end up in a situation where we get a
	// segment that exceeds the window advertised. Instead of partially
	// accepting the segment and discarding bytes beyond the advertised
	// window, we accept the whole segment and make sure r.rcvAcc is moved
	// forward to match r.rcvNxt to indicate that the window is now closed.
	//
	// In absence of this check the r.acceptable() check fails and accepts
	// segments that should be dropped because rcvWnd is calculated as
	// the size of the interval (rcvNxt, rcvAcc] which becomes extremely
	// large if rcvAcc is ever less than rcvNxt.
	if r.rcvAcc.LessThan(r.rcvNxt) {
		r.rcvAcc = r.rcvNxt
	}



	// Trim SACK Blocks to remove any SACK information that covers sequence numbers that have been consumed.
	TrimSACKBlockList(&r.ep.sack, r.rcvNxt)



	// Handle FIN or FIN-ACK.
	if s.flagIsSet(header.TCPFlagFin) {


		r.rcvNxt++

		// Send ACK immediately.
		r.ep.snd.sendAck()

		// Tell any readers that no more data will come.
		r.closed = true
		r.ep.readyToRead(nil)

		// We just received a FIN, our next state depends on whether we sent a
		// FIN already or not.
		r.ep.mu.Lock()
		switch r.ep.state {
		case StateEstablished:
			r.ep.state = StateCloseWait
		case StateFinWait1:
			if s.flagIsSet(header.TCPFlagAck) {
				// FIN-ACK, transition to TIME-WAIT.
				r.ep.state = StateTimeWait
			} else {
				// Simultaneous close, expecting a final ACK.
				r.ep.state = StateClosing
			}
		case StateFinWait2:
			r.ep.state = StateTimeWait
		}
		r.ep.mu.Unlock()

		// Flush out any pending segments, except the very first one if
		// it happens to be the one we're handling now because the
		// caller is using it.
		first := 0
		if len(r.pendingRcvdSegments) != 0 && r.pendingRcvdSegments[0] == s {
			first = 1
		}

		for i := first; i < len(r.pendingRcvdSegments); i++ {
			r.pendingRcvdSegments[i].decRef()
		}
		r.pendingRcvdSegments = r.pendingRcvdSegments[:first]

		return true
	}



	// Handle ACK (not FIN-ACK, which we handled above) during one of the shutdown states.
	if s.flagIsSet(header.TCPFlagAck) {
		r.ep.mu.Lock()
		switch r.ep.state {
		case StateFinWait1:
			r.ep.state = StateFinWait2
			// Notify protocol goroutine that we have received an
			// ACK to our FIN so that it can start the FIN_WAIT2
			// timer to abort connection if the other side does
			// not close within 2MSL.
			r.ep.notifyProtocolGoroutine(notifyClose)
		case StateClosing:
			r.ep.state = StateTimeWait
		case StateLastAck:
			r.ep.transitionToStateCloseLocked()
		}
		r.ep.mu.Unlock()
	}

	return true
}

// updateRTT updates the receiver RTT measurement based on the sequence number
// of the received segment.
func (r *receiver) updateRTT() {
	// From: https://public.lanl.gov/radiant/pubs/drs/sc2001-poster.pdf
	//
	// A system that is only transmitting acknowledgements can still
	// estimate the round-trip time by observing the time between when a byte
	// is first acknowledged and the receipt of data that is at least one
	// window beyond the sequence number that was acknowledged.
	r.ep.rcvListMu.Lock()
	if r.ep.rcvAutoParams.rttMeasureTime.IsZero() {
		// New measurement.
		r.ep.rcvAutoParams.rttMeasureTime = time.Now()
		r.ep.rcvAutoParams.rttMeasureSeqNumber = r.rcvNxt.Add(r.rcvWnd)
		r.ep.rcvListMu.Unlock()
		return
	}
	if r.rcvNxt.LessThan(r.ep.rcvAutoParams.rttMeasureSeqNumber) {
		r.ep.rcvListMu.Unlock()
		return
	}
	rtt := time.Since(r.ep.rcvAutoParams.rttMeasureTime)
	// We only store the minimum observed RTT here as this is only used in
	// absence of a SRTT available from either timestamps or a sender
	// measurement of RTT.
	if r.ep.rcvAutoParams.rtt == 0 || rtt < r.ep.rcvAutoParams.rtt {
		r.ep.rcvAutoParams.rtt = rtt
	}
	r.ep.rcvAutoParams.rttMeasureTime = time.Now()
	r.ep.rcvAutoParams.rttMeasureSeqNumber = r.rcvNxt.Add(r.rcvWnd)
	r.ep.rcvListMu.Unlock()
}

func (r *receiver) handleRcvdSegmentClosing(s *segment, state EndpointState, closed bool) (drop bool, err *tcpip.Error) {
	r.ep.rcvListMu.Lock()
	rcvClosed := r.ep.rcvClosed || r.closed
	r.ep.rcvListMu.Unlock()

	// If we are in one of the shutdown states then we need to do
	// additional checks before we try and process the segment.

	// 如果当前处于 `shutdown` 状态，在尝试处理 s 之前，需要做额外的检查。
	switch state {
	// 这些状态意味着已接收到对端的 FIN 报文，其已经结束数据发送，所以不再读取新数据。
	case StateCloseWait, StateClosing, StateLastAck:
		if !s.sequenceNumber.LessThanEq(r.rcvNxt) {
			s.decRef()
			// Just drop the segment as we have already received a FIN and
			// this segment is after the sequence number for the FIN.
			//
			// 丢弃 s ，因为已收到 FIN 报文，且 s 是在 FIN 报文序列号之后。
			return true, nil
		}
		fallthrough

	//
	case StateFinWait1:
		fallthrough

	//
	case StateFinWait2:

		// If we are closed for reads (either due to an incoming FIN or the user calling shutdown(..,
		// SHUT_RD) then any data past the rcvNxt should trigger a RST.
		//
		//
		//
		endDataSeq := s.sequenceNumber.Add(seqnum.Size(s.data.Size()))
		if rcvClosed && r.rcvNxt.LessThan(endDataSeq) {
			s.decRef()
			return true, tcpip.ErrConnectionAborted
		}
		if state == StateFinWait1 {
			break
		}

		// If it's a retransmission of an old data segment
		// or a pure ACK then allow it.
		if s.sequenceNumber.Add(s.logicalLen()).LessThanEq(r.rcvNxt) ||
			s.logicalLen() == 0 {
			break
		}

		// In FIN-WAIT2 if the socket is fully
		// closed(not owned by application on our end
		// then the only acceptable segment is a
		// FIN. Since FIN can technically also carry
		// data we verify that the segment carrying a
		// FIN ends at exactly e.rcvNxt+1.
		//
		// From RFC793 page 25.
		//
		// For sequence number purposes, the SYN is
		// considered to occur before the first actual
		// data octet of the segment in which it occurs,
		// while the FIN is considered to occur after
		// the last actual data octet in a segment in
		// which it occurs.
		if closed && (!s.flagIsSet(header.TCPFlagFin) || s.sequenceNumber.Add(s.logicalLen()) != r.rcvNxt+1) {
			s.decRef()
			return true, tcpip.ErrConnectionAborted
		}
	}


	// We don't care about receive processing anymore if the receive side is closed.
	//
	// NOTE: We still want to permit a FIN as it's possible only our
	// end has closed and the peer is yet to send a FIN.
	// Hence we compare only the payload.

	segEnd := s.sequenceNumber.Add(seqnum.Size(s.data.Size()))
	if rcvClosed && !segEnd.LessThanEq(r.rcvNxt) {
		return true, nil
	}

	return false, nil
}


// handleRcvdSegment handles TCP segments directed at the connection managed by r as they arrive.
// It is called by the protocol main loop.
//
// 本函数主要作用是接收乱序的包，放到 receiver 的 pendingRcvdSegments 这个最小堆里，
// 在合适的时候把连续、完整的几个包放到 endpoint 的 rcvList，应用层读取连接的数据就是通过这个 rcvList 。
//
func (r *receiver) handleRcvdSegment(s *segment) (drop bool, err *tcpip.Error) {

	r.ep.mu.RLock()
	state := r.ep.state
	closed := r.ep.closed
	r.ep.mu.RUnlock()

	// 检查 e.state 是否是 "已经建立"，若非则丢弃 segment 。
	if state != StateEstablished {
		//
		drop, err := r.handleRcvdSegmentClosing(s, state, closed)
		if drop || err != nil {
			return drop, err
		}
	}

	// 序列号
	segSeq := s.sequenceNumber
	// 段大小
	segLen := seqnum.Size(s.data.Size())


	// If the sequence number range is outside the acceptable range,
	// just send an ACK and stop further processing of the segment.
	// This is according to RFC 793, page 68.
	//
	// 如果序列号范围超出了可接受的范围，只需发送一个 ACK ，并丢弃 segment 。
	if !r.acceptable(segSeq, segLen) {
		r.ep.snd.sendAck() // 发送冗余 ACK
		return true, nil
	}

	// Defer segment processing if it can't be consumed now.
	// 如果现在不能消费，则推迟处理 segment 。
	if !r.consumeSegment(s, segSeq, segLen) {

		//
		if segLen > 0 || s.flagIsSet(header.TCPFlagFin) {

			// We only store the segment if it's within our buffer size limit.
			// 如果缓冲区空间足以容纳 s ，就存入 r.pendingRcvdSegments 中。
			if r.pendingBufUsed < r.pendingBufSize {
				r.pendingBufUsed += s.logicalLen()
				s.incRef()
				heap.Push(&r.pendingRcvdSegments, s)
				UpdateSACKBlocks(&r.ep.sack, segSeq, segSeq.Add(segLen), r.rcvNxt)
			}

			// Immediately send an ack so that the peer knows it may have to retransmit.
			// 立即发送 ACK ，让对端知道它可能要重传。
			r.ep.snd.sendAck()

		}
		return false, nil
	}

	// Since we consumed a segment update the receiver's RTT estimate if required.
	// 由于我们消耗了一个 segment ，如果需要的话，更新接收器的 RTT 估计。
	if segLen > 0 {
		r.updateRTT()
	}

	// By consuming the current segment, we may have filled a gap in the
	// sequence number domain that allows pending segments to be consumed
	// now. So try to do it.
	//
	//
	// 继续检查 pendingRcvdSegments 里是否有更多连续的数据，如果有，取出来放到 rcvList 里
	for !r.closed && r.pendingRcvdSegments.Len() > 0 {

		s := r.pendingRcvdSegments[0]
		segLen := seqnum.Size(s.data.Size())
		segSeq := s.sequenceNumber

		// Skip segment altogether if it has already been acknowledged.
		if !segSeq.Add(segLen-1).LessThan(r.rcvNxt) &&
			!r.consumeSegment(s, segSeq, segLen) {
			break
		}

		heap.Pop(&r.pendingRcvdSegments)
		r.pendingBufUsed -= s.logicalLen()
		s.decRef()
	}

	return false, nil
}

// handleTimeWaitSegment handles inbound segments received when the endpoint
// has entered the TIME_WAIT state.
func (r *receiver) handleTimeWaitSegment(s *segment) (resetTimeWait bool, newSyn bool) {
	segSeq := s.sequenceNumber
	segLen := seqnum.Size(s.data.Size())

	// Just silently drop any RST packets in TIME_WAIT. We do not support
	// TIME_WAIT assasination as a result we confirm w/ fix 1 as described
	// in https://tools.ietf.org/html/rfc1337#section-3.
	if s.flagIsSet(header.TCPFlagRst) {
		return false, false
	}

	// If it's a SYN and the sequence number is higher than any seen before
	// for this connection then try and redirect it to a listening endpoint
	// if available.
	//
	// RFC 1122:
	//   "When a connection is [...] on TIME-WAIT state [...]
	//   [a TCP] MAY accept a new SYN from the remote TCP to
	//   reopen the connection directly, if it:

	//    (1) assigns its initial sequence number for the new
	//     connection to be larger than the largest sequence
	//     number it used on the previous connection incarnation,
	//     and

	//    (2) returns to TIME-WAIT state if the SYN turns out
	//      to be an old duplicate".
	if s.flagIsSet(header.TCPFlagSyn) && r.rcvNxt.LessThan(segSeq) {
		return false, true
	}

	// Drop the segment if it does not contain an ACK.
	if !s.flagIsSet(header.TCPFlagAck) {
		return false, false
	}

	// Update Timestamp if required. See RFC7323, section-4.3.
	if r.ep.sendTSOk && s.parsedOptions.TS {
		r.ep.updateRecentTimestamp(s.parsedOptions.TSVal, r.ep.snd.maxSentAck, segSeq)
	}

	if segSeq.Add(1) == r.rcvNxt && s.flagIsSet(header.TCPFlagFin) {
		// If it's a FIN-ACK then resetTimeWait and send an ACK, as it
		// indicates our final ACK could have been lost.
		r.ep.snd.sendAck()
		return true, false
	}

	// If the sequence number range is outside the acceptable range or
	// carries data then just send an ACK. This is according to RFC 793,
	// page 37.
	//
	// NOTE: In TIME_WAIT the only acceptable sequence number is rcvNxt.
	if segSeq != r.rcvNxt || segLen != 0 {
		r.ep.snd.sendAck()
	}
	return false, false
}
