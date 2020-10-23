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

// renoState stores the variables related to TCP New Reno congestion
// control algorithm.
//
// +stateify savable
type renoState struct {
	s *sender
}

// newRenoCC initializes the state for the NewReno congestion control algorithm.
func newRenoCC(s *sender) *renoState {
	return &renoState{s: s}
}

// updateSlowStart will update the congestion window as per the slow-start
// algorithm used by NewReno. If after adjusting the congestion window
// we cross the SSthreshold then it will return the number of packets that
// must be consumed in congestion avoidance mode.
//
// updateSlowStart 将根据 NewReno 使用的慢启动算法更新拥塞窗口。
func (r *renoState) updateSlowStart(packetsAcked int) int {

	// Don't let the congestion window cross into the congestion avoidance range.

	// 在慢启动阶段，每收到一个新的 ACK ，cwnd 增长 1 ，直到增长到 ssthresh 。
	newcwnd := r.s.sndCwnd + packetsAcked
	if newcwnd >= r.s.sndSsthresh {
		newcwnd = r.s.sndSsthresh	// 将拥塞窗口设置为 sndSsthresh
		r.s.sndCAAckCount = 0
	}

	// 如果 cwnd + packetsAcked 超过了 ssthresh ，那么将从 `慢启动` 阶段进入 `拥塞避免` 阶段，
	// 此时需要在 `拥塞避免` 阶段消费 cwnd + packetsAcked - ssthresh 个数据包，返回这个值。
	packetsAcked -= newcwnd - r.s.sndCwnd
	r.s.sndCwnd = newcwnd
	return packetsAcked
}

// updateCongestionAvoidance will update congestion window in congestion
// avoidance mode as described in RFC5681 section 3.1
func (r *renoState) updateCongestionAvoidance(packetsAcked int) {
	// Consume the packets in congestion avoidance mode.


	// 在拥塞避免期间，cwnd 在每个 ACK 以 1/cwnd 的速度递增。

	r.s.sndCAAckCount += packetsAcked
	if r.s.sndCAAckCount >= r.s.sndCwnd {
		r.s.sndCwnd += r.s.sndCAAckCount / r.s.sndCwnd
		r.s.sndCAAckCount = r.s.sndCAAckCount % r.s.sndCwnd
	}
}

// reduceSlowStartThreshold reduces the slow-start threshold per RFC 5681,
// page 6, eq. 4. It is called when we detect congestion in the network.
func (r *renoState) reduceSlowStartThreshold() {
	r.s.sndSsthresh = r.s.outstanding / 2
	if r.s.sndSsthresh < 2 {
		r.s.sndSsthresh = 2
	}
}

// Update updates the congestion state based on the number of packets that were acknowledged.
// Update implements congestionControl.Update.
func (r *renoState) Update(packetsAcked int) {

	// 慢启动
	if r.s.sndCwnd < r.s.sndSsthresh {
		// 在慢启动阶段，每收到一个新的 ACK ，sndCwnd 增长 1 直到 ssthresh 。
		packetsAcked = r.updateSlowStart(packetsAcked)
		// 如果 packetsAcked == 0 ，则仍处于 `满启动` 阶段。
		// 如果 packetsAcked != 0 ，意味着已经进入 `拥塞避免` 阶段，且在 `拥塞避免` 阶段仍需消费 packetsAcked 个包。
		if packetsAcked == 0 {
			return
		}
	}

	// 拥塞避免，在此阶段需消费 packetsAcked 个包。
	r.updateCongestionAvoidance(packetsAcked)
}

// HandleNDupAcks implements congestionControl.HandleNDupAcks.
func (r *renoState) HandleNDupAcks() {

	// A retransmit was triggered due to nDupAckThreshold being hit.
	// Reduce our slow start threshold.
	//
	// 如果重复的 ACK 超过了 nDupAckThreshold 阈值，意味着丢包，会触发重传，此时需降低慢启动阈值 ssthresh 。
	r.reduceSlowStartThreshold()
}

// HandleRTOExpired implements congestionControl.HandleRTOExpired.
func (r *renoState) HandleRTOExpired() {

	// We lost a packet, so reduce ssthresh.
	// 出现丢包，减少 ssthresh 。
	r.reduceSlowStartThreshold()

	// Reduce the congestion window to 1, i.e., enter slow-start. Per
	// RFC 5681, page 7, we must use 1 regardless of the value of the
	// initial congestion window.

	// 出现丢包，进入慢启动。
	r.s.sndCwnd = 1
}

// PostRecovery implements congestionControl.PostRecovery.
func (r *renoState) PostRecovery() {
	// noop.
}
