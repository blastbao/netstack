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
	"sync/atomic"
	"time"

	"github.com/blastbao/netstack/tcpip"
	"github.com/blastbao/netstack/tcpip/buffer"
	"github.com/blastbao/netstack/tcpip/header"
	"github.com/blastbao/netstack/tcpip/seqnum"
	"github.com/blastbao/netstack/tcpip/stack"
)

// segment represents a TCP segment. It holds the payload and parsed TCP segment
// information, and can be added to intrusive lists.
// segment is mostly immutable, the only field allowed to change is viewToDeliver.
//
// +stateify savable
type segment struct {
	segmentEntry

	// 引用计数
	refCnt int32

	// 传输层协议端点的标识符，四元组 <源地址，源端口，目的地址，目的端口> 。
	id stack.TransportEndpointID

	// 通过网络到达目的地的路由信息
	route stack.Route

	// 数据载荷
	data buffer.VectorisedView

	// views is used as buffer for data when its length is large enough to store a VectorisedView.
	// views 可作为数据的缓冲区，当它的长度足够大，可以存储一个 VectorisedView 。
	views [8]buffer.View

	// viewToDeliver keeps track of the next View that should be delivered by the Read endpoint.
	// viewToDeliver 跟踪下一个应该由 Read 端点交付的 View 。
	viewToDeliver int

	// 序列号
	sequenceNumber seqnum.Value

	// 应答序列号
	ackNumber seqnum.Value

	// 标识
	flags uint8

	// 窗口大小
	window seqnum.Size

	// csum is only populated for received segments.
	// 校验和
	csum uint16

	// csumValid is true if the csum in the received segment is valid.
	// 校验和：如果接收到的 segment 的 csum 有效，则 csumValid 为 true 。
	csumValid bool

	// parsedOptions stores the parsed values from the options in the segment.
	// 选项
	parsedOptions header.TCPOptions

	// 选项
	options []byte

	// 是否包含新的 sack 信息
	hasNewSACKInfo bool

	// 接收时间
	rcvdTime time.Time

	// xmitTime is the last transmit time of this segment. A zero value
	// indicates that the segment has yet to be transmitted.
	//
	// xmitTime 是该 segment 的最后一次发送时间。零值表示该 segment 尚未传输。
	xmitTime time.Time
}

func newSegment(r *stack.Route, id stack.TransportEndpointID, pkt tcpip.PacketBuffer) *segment {
	s := &segment{
		refCnt: 1,
		id:     id,
		route:  r.Clone(),
	}
	s.data = pkt.Data.Clone(s.views[:]) // 从 packet 中拷贝数据到 s.data 里
	s.rcvdTime = time.Now()				// 更新 s 的接收时间
	return s
}

func newSegmentFromView(r *stack.Route, id stack.TransportEndpointID, v buffer.View) *segment {
	s := &segment{
		refCnt: 1,
		id:     id,
		route:  r.Clone(),
	}
	s.views[0] = v
	s.data = buffer.NewVectorisedView(len(v), s.views[:1]) // 从 v 中拷贝数据到 s.data 里
	s.rcvdTime = time.Now()
	return s
}

func (s *segment) clone() *segment {
	t := &segment{
		refCnt:         1,
		id:             s.id,
		sequenceNumber: s.sequenceNumber,
		ackNumber:      s.ackNumber,
		flags:          s.flags,
		window:         s.window,
		route:          s.route.Clone(),
		viewToDeliver:  s.viewToDeliver,
		rcvdTime:       s.rcvdTime,
	}
	t.data = s.data.Clone(t.views[:])
	return t
}

// flagIsSet checks if at least one flag in flags is set in s.flags.
func (s *segment) flagIsSet(flags uint8) bool {
	return s.flags&flags != 0
}

// flagsAreSet checks if all flags in flags are set in s.flags.
func (s *segment) flagsAreSet(flags uint8) bool {
	return s.flags&flags == flags
}

func (s *segment) decRef() {
	if atomic.AddInt32(&s.refCnt, -1) == 0 {
		s.route.Release()
	}
}

func (s *segment) incRef() {
	atomic.AddInt32(&s.refCnt, 1)
}

// logicalLen is the segment length in the sequence number space.
// It's defined as the data length plus one for each of the SYN and FIN bits set.
//
func (s *segment) logicalLen() seqnum.Size {
	l := seqnum.Size(s.data.Size())
	if s.flagIsSet(header.TCPFlagSyn) {
		l++
	}
	if s.flagIsSet(header.TCPFlagFin) {
		l++
	}
	return l
}

// parse populates the sequence & ack numbers, flags, and window fields of the
// segment from the TCP header stored in the data. It then updates the view to
// skip the header.
//
// parse 解析 data 中存储的 TCP 头部，填充 segment 的 seq、ack、flags 和窗口字段。
// 然后它更新 view 来跳过 tcp 头部。
//
// Returns boolean indicating if the parsing was successful.
// 如果解析成功，则返回 true 。
//
// If checksum verification is not offloaded then parse also verifies the
// TCP checksum and stores the checksum and result of checksum verification in
// the csum and csumValid fields of the segment.
//
// 如果校验和验证模块没有被卸载，那么 parse 中需要验证 TCP 校验和并将校验和和校验结果保存
// 到 segment 的 csum 和 csumValid 字段中。
//
func (s *segment) parse() bool {

	// 从 data 中取出 header
	h := header.TCP(s.data.First())

	// h is the header followed by the payload. We check that the offset to
	// the data respects the following constraints:
	// 1. That it's at least the minimum header size; if we don't do this
	//    then part of the header would be delivered to user.
	// 2. That the header fits within the buffer; if we don't do this, we
	//    would panic when we tried to access data beyond the buffer.
	//
	// N.B. The segment has already been validated as having at least the
	//      minimum TCP size before reaching here, so it's safe to read the
	//      fields.
	//
	// N.B. 到达这里时，该 segment 已经被验证为至少有最小的 TCP 大小，所以读取这些字段是安全的。

	// 检查数据偏移的合法性
	offset := int(h.DataOffset())
	if offset < header.TCPMinimumSize || offset > len(h) {
		return false
	}

	// 解析 options
	s.options = []byte(h[header.TCPMinimumSize:offset])
	s.parsedOptions = header.ParseTCPOptions(s.options)

	// Query the link capabilities to decide if checksum validation is required.
	verifyChecksum := true

	if s.route.Capabilities()&stack.CapabilityRXChecksumOffload != 0 {
		s.csumValid = true
		verifyChecksum = false
		s.data.TrimFront(offset)
	}

	// 校验和
	if verifyChecksum {
		s.csum = h.Checksum()
		xsum := s.route.PseudoHeaderChecksum(ProtocolNumber, uint16(s.data.Size()))
		xsum = h.CalculateChecksum(xsum)
		s.data.TrimFront(offset)
		xsum = header.ChecksumVV(s.data, xsum)
		s.csumValid = xsum == 0xffff
	}

	s.sequenceNumber = seqnum.Value(h.SequenceNumber())
	s.ackNumber = seqnum.Value(h.AckNumber())
	s.flags = h.Flags()
	s.window = seqnum.Size(h.WindowSize())
	return true
}

// sackBlock returns a header.SACKBlock that represents this segment.
func (s *segment) sackBlock() header.SACKBlock {
	return header.SACKBlock{
		s.sequenceNumber,
		s.sequenceNumber.Add(s.logicalLen()),
	}
}
