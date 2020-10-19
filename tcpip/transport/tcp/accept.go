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
	"crypto/sha1"
	"encoding/binary"
	"hash"
	"io"
	"sync"
	"time"

	"github.com/blastbao/netstack/rand"
	"github.com/blastbao/netstack/sleep"
	"github.com/blastbao/netstack/tcpip"
	"github.com/blastbao/netstack/tcpip/buffer"
	"github.com/blastbao/netstack/tcpip/header"
	"github.com/blastbao/netstack/tcpip/seqnum"
	"github.com/blastbao/netstack/tcpip/stack"
	"github.com/blastbao/netstack/waiter"
)

const (

	// tsLen is the length, in bits, of the timestamp in the SYN cookie.
	// tsLen 是 SYN cookie 中时间戳的长度，单位为 bit 。
	tsLen = 8

	// tsMask is a mask for timestamp values (i.e., tsLen bits).
	tsMask = (1 << tsLen) - 1

	// tsOffset is the offset, in bits, of the timestamp in the SYN cookie.
	tsOffset = 24

	// hashMask is the mask for hash values (i.e., tsOffset bits).
	hashMask = (1 << tsOffset) - 1

	// maxTSDiff is the maximum allowed difference between a received cookie
	// timestamp and the current timestamp. If the difference is greater
	// than maxTSDiff, the cookie is expired.
	maxTSDiff = 2
)

var (

	// SynRcvdCountThreshold is the global maximum number of connections
	// that are allowed to be in SYN-RCVD state before TCP starts using SYN
	// cookies to accept connections.
	//
	// It is an exported variable only for testing, and should not otherwise
	// be used by importers of this package.
	//
	// SynRcvdCountThreshold 是指在 TCP 开始使用 SYN cookies 接受连接之前，
	// 允许处于 SYN-RCVD 状态的全局最大连接数。这个导出变量只用于测试，正常情况下不应该被包的引入者使用。
	SynRcvdCountThreshold uint64 = 1000

	// mssTable is a slice containing the possible MSS values that we
	// encode in the SYN cookie with two bits.
	//
	// mssTable 是一个包含可能的 MSS 值的 slice ，我们在 SYN cookie 中可能会使用它。
	mssTable = []uint16{536, 1300, 1440, 1460}


)

func encodeMSS(mss uint16) uint32 {

	for i := len(mssTable) - 1; i > 0; i-- {
		if mss >= mssTable[i] {
			return uint32(i)
		}
	}

	return 0
}

// syncRcvdCount is the number of endpoints in the SYN-RCVD state. The value is
// protected by a mutex so that we can increment only when it's guaranteed not
// to go above a threshold.
var synRcvdCount struct {
	sync.Mutex
	value   uint64
	pending sync.WaitGroup
}

// listenContext is used by a listening endpoint to store state used while
// listening for connections. This struct is allocated by the listen goroutine
// and must not be accessed or have its methods called concurrently as they
// may mutate the stored objects.
//
// listenContext 被 listen endpoint 用来存储监听连接时使用的状态。
// 这个结构是由 listen goroutine 创建的，它的方法不能被并发调用，方式数据竞争。
//
type listenContext struct {
	stack    *stack.Stack
	rcvWnd   seqnum.Size
	nonce    [2][sha1.BlockSize]byte
	listenEP *endpoint

	hasherMu sync.Mutex
	hasher   hash.Hash
	v6only   bool
	netProto tcpip.NetworkProtocolNumber

	// pendingMu protects pendingEndpoints. This should only be accessed
	// by the listening endpoint's worker goroutine.
	//
	// Lock Ordering: listenEP.workerMu -> pendingMu
	//
	// pendingMu 保护 pendingEndpoints ，保证只有 listen endpoint 端点的 worker goroutine 才能访问。
	pendingMu sync.Mutex

	// pending is used to wait for all pendingEndpoints to finish when a socket is closed.
	// pending 用于当一个套接字被关闭时，等待所有的 pendingEndpoints 结束。
	pending sync.WaitGroup

	// pendingEndpoints is a map of all endpoints for which a handshake is in progress.
	// pendingEndpoints 是保存所有正在进行握手的 endpoints 的 map 。
	pendingEndpoints map[stack.TransportEndpointID]*endpoint
}

// timeStamp returns an 8-bit timestamp with a granularity of 64 seconds.
// timeStamp 返回一个单位为 64 秒的 8 位时间戳。
func timeStamp() uint32 {
	return uint32(time.Now().Unix()>>6) & tsMask
}

// incSynRcvdCount tries to increment the global number of endpoints in SYN-RCVD state.
// It succeeds if the increment doesn't make the count go beyond the threshold,
// and fails otherwise.
//
// incSynRcvdCount 试图递增全局处于 SYN-RCVD 状态的端点数量，如果总数超过阈值，则报 false ，此时不接受新的 syn 请求。
//
func incSynRcvdCount() bool {

	synRcvdCount.Lock()
	if synRcvdCount.value >= SynRcvdCountThreshold {
		synRcvdCount.Unlock()
		return false
	}

	synRcvdCount.pending.Add(1)
	synRcvdCount.value++

	synRcvdCount.Unlock()
	return true
}

// decSynRcvdCount atomically decrements the global number of endpoints in SYN-RCVD state.
// It must only be called if a previous call to incSynRcvdCount succeeded.
//
//
//
func decSynRcvdCount() {
	synRcvdCount.Lock()

	synRcvdCount.value--
	synRcvdCount.pending.Done()
	synRcvdCount.Unlock()
}

// synCookiesInUse() returns true if the synRcvdCount is greater than SynRcvdCountThreshold.
func synCookiesInUse() bool {
	synRcvdCount.Lock()
	v := synRcvdCount.value
	synRcvdCount.Unlock()
	return v >= SynRcvdCountThreshold
}

// newListenContext creates a new listen context.
func newListenContext(
	stk *stack.Stack,
	listenEP *endpoint,
	rcvWnd seqnum.Size,
	v6only bool,
	netProto tcpip.NetworkProtocolNumber,
) *listenContext {

	// 构造 listen 上下文
	l := &listenContext{
		stack:            stk,
		rcvWnd:           rcvWnd,
		hasher:           sha1.New(),
		v6only:           v6only,
		netProto:         netProto,
		listenEP:         listenEP,
		pendingEndpoints: make(map[stack.TransportEndpointID]*endpoint),
	}

	// 生成 2 个随机数
	rand.Read(l.nonce[0][:])
	rand.Read(l.nonce[1][:])

	return l
}

// cookieHash calculates the cookieHash for the given id, timestamp and nonce
// index. The hash is used to create and validate cookies.
func (l *listenContext) cookieHash(id stack.TransportEndpointID, ts uint32, nonceIndex int) uint32 {

	// Initialize block with fixed-size data: local ports and v.
	var payload [8]byte
	binary.BigEndian.PutUint16(payload[0:], id.LocalPort)
	binary.BigEndian.PutUint16(payload[2:], id.RemotePort)
	binary.BigEndian.PutUint32(payload[4:], ts)

	// Feed everything to the hasher.
	l.hasherMu.Lock()
	l.hasher.Reset()
	l.hasher.Write(payload[:])
	l.hasher.Write(l.nonce[nonceIndex][:])
	io.WriteString(l.hasher, string(id.LocalAddress))
	io.WriteString(l.hasher, string(id.RemoteAddress))

	// Finalize the calculation of the hash and return the first 4 bytes.
	h := make([]byte, 0, sha1.Size)
	h = l.hasher.Sum(h)
	l.hasherMu.Unlock()

	return binary.BigEndian.Uint32(h[:])
}

// createCookie creates a SYN cookie for the given id and incoming sequence number.
// createCookie 为给定的 id 和传入的序列号创建一个 SYN cookie 。
func (l *listenContext) createCookie(id stack.TransportEndpointID, seq seqnum.Value, data uint32) seqnum.Value {
	// 获取当前时间戳
	ts := timeStamp()
	//
	v := l.cookieHash(id, 0, 0) + uint32(seq) + (ts << tsOffset)
	v += (l.cookieHash(id, ts, 1) + data) & hashMask
	return seqnum.Value(v)
}

// isCookieValid checks if the supplied cookie is valid for the given id and
// sequence number. If it is, it also returns the data originally encoded in the
// cookie when createCookie was called.
func (l *listenContext) isCookieValid(id stack.TransportEndpointID, cookie seqnum.Value, seq seqnum.Value) (uint32, bool) {
	ts := timeStamp()
	v := uint32(cookie) - l.cookieHash(id, 0, 0) - uint32(seq)
	cookieTS := v >> tsOffset
	if ((ts - cookieTS) & tsMask) > maxTSDiff {
		return 0, false
	}

	return (v - l.cookieHash(id, cookieTS, 1)) & hashMask, true
}

// createConnectingEndpoint creates a new endpoint in a connecting state, with
// the connection parameters given by the arguments.
//
// createConnectingEndpoint 创建一个处于 "正在连接" 状态的新端点，连接参数由参数给出。
func (l *listenContext) createConnectingEndpoint(
	s *segment,							//
	iss seqnum.Value,					//
	irs seqnum.Value,					//
	rcvdSynOpts *header.TCPSynOptions, 	// 连接参数
) (*endpoint, *tcpip.Error) {

	// Create a new endpoint.

	// 网络协议
	netProto := l.netProto
	if netProto == 0 {
		netProto = s.route.NetProto
	}

	n := newEndpoint(l.stack, netProto, nil)
	n.v6only = l.v6only
	n.ID = s.id
	n.boundNICID = s.route.NICID()
	n.route = s.route.Clone()
	n.effectiveNetProtos = []tcpip.NetworkProtocolNumber{s.route.NetProto}
	n.rcvBufSize = int(l.rcvWnd)
	n.amss = mssForRoute(&n.route)

	n.maybeEnableTimestamp(rcvdSynOpts)
	n.maybeEnableSACKPermitted(rcvdSynOpts)

	n.initGSO()

	// Register new endpoint so that packets are routed to it.
	if err := n.stack.RegisterTransportEndpoint(n.boundNICID, n.effectiveNetProtos, ProtocolNumber, n.ID, n, n.reusePort, n.bindToDevice); err != nil {
		n.Close()
		return nil, err
	}

	n.isRegistered = true

	// Create sender and receiver.
	//
	// The receiver at least temporarily has a zero receive window scale,
	// but the caller may change it (before starting the protocol loop).
	n.snd = newSender(n, iss, irs, s.window, rcvdSynOpts.MSS, rcvdSynOpts.WS)
	n.rcv = newReceiver(n, irs, seqnum.Size(n.initialReceiveWindow()), 0, seqnum.Size(n.receiveBufferSize()))


	// Bootstrap the auto tuning algorithm. Starting at zero will result in
	// a large step function on the first window adjustment causing the
	// window to grow to a really large value.
	n.rcvAutoParams.prevCopied = n.initialReceiveWindow()

	return n, nil
}

// createEndpoint creates a new endpoint in connected state and then performs the TCP 3-way handshake.
// createEndpoint 在连接状态下创建一个新的 Endpoint ，然后执行 TCP 三次握手 Handshake 。
//
// 也就是说，等待请求的是一个 Endpoint ，处理请求的又是另一个 Endpoint ，这里涉及到 Endpoint 状态的更改，
// 并且没有什么强关系，所以完全可以交给两个 Endpoint 分别去负责，这个处理方式值得借鉴。
// 创建完 Endpoint 之后，就是要去创建 Handshake 了，并且这个 resetToSynRcvd() 函数算是直接告诉我们这里的 Handshake 状态
// 为 handshakeSynRcvd。也就是说，Sever 初始的 Handshake 就是这个，这个弄清楚之后，我们来看一下执行发生了什么。

func (l *listenContext) createEndpointAndPerformHandshake(s *segment, opts *header.TCPSynOptions) (*endpoint, *tcpip.Error) {

	// Create new endpoint.
	// 从 Listen Endpoint 创建一个 Handshake Endpoint ，让其负责连接建立。

	//
	irs := s.sequenceNumber
	isn := generateSecureISN(s.id, l.stack.Seed())
	ep, err := l.createConnectingEndpoint(s, isn, irs, opts)
	if err != nil {
		return nil, err
	}

	// listenEP is nil when listenContext is used by tcp.Forwarder.
	//
	// 当 listenContext 被 tcp.Forwarder 使用时，listenEP 为 nil 。
	if l.listenEP != nil {
		l.listenEP.mu.Lock()
		if l.listenEP.state != StateListen {
			l.listenEP.mu.Unlock()
			return nil, tcpip.ErrConnectionAborted
		}
		l.addPendingEndpoint(ep)
		l.listenEP.mu.Unlock()
	}


	// Perform the 3-way handshake.
	h := newHandshake(ep, seqnum.Size(ep.initialReceiveWindow()))
	h.resetToSynRcvd(isn, irs, opts)
	if err := h.execute(); err != nil {
		ep.Close()
		if l.listenEP != nil {
			l.removePendingEndpoint(ep)
		}
		return nil, err
	}

	ep.mu.Lock()
	ep.stack.Stats().TCP.CurrentEstablished.Increment()		// 已建立连接数 ++
	ep.state = StateEstablished 							// 将 ep 状态修改为 "Established"
	ep.isConnectNotified = true 							//
	ep.mu.Unlock()

	// Update the receive window scaling. We can't do it before the handshake
	// because it's possible that the peer doesn't support window scaling.
	//
	// 更新接收窗口的比例。我们不能在握手前进行设置，因为有可能对端不支持窗口缩放。
	ep.rcv.rcvWndScale = h.effectiveRcvWndScale()

	return ep, nil
}

func (l *listenContext) addPendingEndpoint(n *endpoint) {
	l.pendingMu.Lock()
	l.pendingEndpoints[n.ID] = n
	l.pending.Add(1)
	l.pendingMu.Unlock()
}

func (l *listenContext) removePendingEndpoint(n *endpoint) {
	l.pendingMu.Lock()
	delete(l.pendingEndpoints, n.ID)
	l.pending.Done()
	l.pendingMu.Unlock()
}

func (l *listenContext) closeAllPendingEndpoints() {
	l.pendingMu.Lock()
	for _, n := range l.pendingEndpoints {
		n.notifyProtocolGoroutine(notifyClose)
	}
	l.pendingMu.Unlock()
	l.pending.Wait()
}

// deliverAccepted delivers the newly-accepted endpoint to the listener.
// If the endpoint has transitioned out of the listen state, the new endpoint is closed instead.
//
// deliverAccepted 将新接受的 endpoint 传送给 listener ，如果 listener 已经脱离了 listen 状态，新 endpoint 将被关闭。
func (e *endpoint) deliverAccepted(n *endpoint) {

	e.mu.Lock()
	state := e.state
	e.pendingAccepted.Add(1)
	defer e.pendingAccepted.Done()
	acceptedChan := e.acceptedChan
	e.mu.Unlock()

	// 如果 e.state 为 listening 状态，则将 n 传送给 e.acceptedChan 并通知它，否则关闭 n 。
	if state == StateListen {
		acceptedChan <- n
		e.waiterQueue.Notify(waiter.EventIn)
	} else {
		n.Close()
	}

}

// handleSynSegment is called in its own goroutine once the listening endpoint
// receives a SYN segment. It is responsible for completing the handshake and
// queueing the new endpoint for acceptance.
//
// A limited number of these goroutines are allowed before TCP starts using SYN
// cookies to accept connections.
//
// 一旦 listening 端点接收到 SYN segment，就会在自己的 goroutine 中调用 handleSynSegment ，
// 它负责完成握手和排队接受新的 Connected EndPoint 。
//
// 在 TCP 使用 SYN cookies 接受连接之前，允许使用有限数量的 goroutine 。
func (e *endpoint) handleSynSegment(ctx *listenContext, s *segment, opts *header.TCPSynOptions) {

	// 不论最后有没有成功建立连接，把半连接数量 -1
	defer decSynRcvdCount()
	defer e.decSynRcvdCount()
	defer s.decRef()

	// 创建的一个新的 Endpoint 并执行 Handshake 操作
	n, err := ctx.createEndpointAndPerformHandshake(s, opts)
	if err != nil {
		e.stack.Stats().TCP.FailedConnectionAttempts.Increment()	// connect 失败计数
		e.stats.FailedConnectionAttempts.Increment()				// connect 失败计数
		return
	}

	// 执行 handshake 成功，从 ctx.pendingEndpoints 中移除 n
	ctx.removePendingEndpoint(n)

	// Start the protocol goroutine.
	// 启动协议协程，负责发送和接收 segments 。
	wq := &waiter.Queue{}
	n.startAcceptedLoop(wq)
	e.stack.Stats().TCP.PassiveConnectionOpenings.Increment()

	// e 为 listening endpoint ，把当前 n 传递给 e.acceptedChan 并通知 e 处理它。
	e.deliverAccepted(n)
}

func (e *endpoint) incSynRcvdCount() bool {
	e.mu.Lock()
	// 如果处于 Sync Rcvd 状态的 Endpoint 总数超过 accChan 容量，则返回 False，否则 e.synRcvdCount++
	if e.synRcvdCount >= cap(e.acceptedChan) {
		e.mu.Unlock()
		return false
	}
	e.synRcvdCount++
	e.mu.Unlock()
	return true
}

func (e *endpoint) decSynRcvdCount() {
	e.mu.Lock()
	e.synRcvdCount--
	e.mu.Unlock()
}

func (e *endpoint) acceptQueueIsFull() bool {
	e.mu.Lock()
	if l, c := len(e.acceptedChan)+e.synRcvdCount, cap(e.acceptedChan); l >= c {
		e.mu.Unlock()
		return true
	}
	e.mu.Unlock()
	return false
}

// handleListenSegment is called when a listening endpoint receives a segment and needs to handle it.
//
// 当 Listen Endpoint 收到一个 segment 时，会调用 handleListenSegment 处理它。
func (e *endpoint) handleListenSegment(ctx *listenContext, s *segment) {

	// 如果 s 为 SYN-ACK 报文，直接回复 RST ，否则若回复 ACK ，会完成旧的握手，建立错误连接。
	if s.flagsAreSet(header.TCPFlagSyn | header.TCPFlagAck) {

		// RFC 793 section 3.4 page 35 (figure 12) outlines that a RST
		// must be sent in response to a SYN-ACK while in the listen
		// state to prevent completing a handshake from an old SYN.
		//
		// RFC 793 第 3.4 节第 35 页（图12）概述了在 listen 状态下必须发送 RST 来响应 SYN-ACK ，
		// 以防止从一个旧的 SYN 完成握手。
		e.sendTCP(
			&s.route,
			s.id,
			buffer.VectorisedView{},
			e.ttl,
			e.sendTOS,
			header.TCPFlagRst,	// RST 报文
			s.ackNumber,
			0,
			0,
			nil,
			nil,
		)
		return
	}


	// TODO(b/143300739): Use the userMSS of the listening socket for accepted sockets.

	// 至此，只有可能是 Syn 或者 Ack 报文。

	switch {

	// 如果是 SYN 报文，说明该连接处于三步握手的第一步。
	//
	// 为什么不是第二步？因为这是 Listen 函数，当前处于连接的被动方。
	//
	// 这里会有一个队列，称为 SYN_RCVD 队列或半连接队列，长度为 max(64,/proc/sys/net/ipv4/tcp_max_syn_backlog) 。
	// 当 SYN_RCVD 队列满了，在不开启 syncookies 的时候，Server 会丢弃新来的 SYN 包，而 Client 端在多次重发 SYN 包
	// 得不到响应而返回（connection time out）错误。
	//
	// 但是，当 Server 端开启了 syncookies=1，那么 SYN 半连接队列就没有逻辑上的最大值了，
	// 并且 /proc/sys/net/ipv4/tcp_max_syn_backlog 设置的值也会被忽略。
	//
	// 注意，在 netstack 中，默认开启了 syncookies。
	case s.flags == header.TCPFlagSyn:

		// 解析 tcp 选项
		opts := parseSynSegmentOptions(s)

		// SYN_RCVD 半连接队列长度 +1，成功返回 true，队列已满返回 false，走 else 分支。
		if incSynRcvdCount() {

			// Only handle the syn if the following conditions hold
			//   - accept queue is not full.
			//   - number of connections in synRcvd state is less than the
			//     backlog.
			//
			// 如果 acceptChan 未满，则处理 syn 报文 s 。
			if !e.acceptQueueIsFull() && e.incSynRcvdCount() {
				s.incRef()
				// 处理 Syn 报文
				go e.handleSynSegment(ctx, s, &opts)
				return
			}

			// 至此，意味着 acceptChan 已满，无法接受新 Syn 请求。
			decSynRcvdCount()
			e.stack.Stats().TCP.ListenOverflowSynDrop.Increment()		// syn 队列满
			e.stats.ReceiveErrors.ListenOverflowSynDrop.Increment()		// syn 队列满
			e.stack.Stats().DroppedPackets.Increment() 					// 丢包
			return


		} else {

			// If cookies are in use but the endpoint accept queue is full then drop the syn.
			// 如果已经启用了 SYNCookies 策略，SYN 半连接队列就没有逻辑上的最大值，但若接受队列已满，也只能放弃 syn 报文。
			if e.acceptQueueIsFull() {
				e.stack.Stats().TCP.ListenOverflowSynDrop.Increment()
				e.stats.ReceiveErrors.ListenOverflowSynDrop.Increment()
				e.stack.Stats().DroppedPackets.Increment()
				return
			}

			//
			cookie := ctx.createCookie(s.id, s.sequenceNumber, encodeMSS(opts.MSS))

			// Send SYN without window scaling because we currently dont't encode this information in the cookie.
			// Enable Timestamp option if the original syn did have the timestamp option specified.
			//
			// 发送 SYN 时不需指定窗口缩放选项，因为目前没有在 cookie 中编码这些信息。
			// 如果原始 SYN 报文中有指定时间戳选项，则启用时间戳选项。
			synOpts := header.TCPSynOptions{
				WS:    -1,
				TS:    opts.TS,
				TSVal: tcpTimeStamp(timeStampOffset()),
				TSEcr: opts.TSVal,
				MSS:   mssForRoute(&s.route),
			}

			//
			e.sendSynTCP(
				&s.route,
				s.id,
				e.ttl,
				e.sendTOS,
				header.TCPFlagSyn|header.TCPFlagAck,
				cookie,
				s.sequenceNumber+1,
				ctx.rcvWnd,
				synOpts,
			)

			e.stack.Stats().TCP.ListenOverflowSynCookieSent.Increment()
		}

	// 如果数据包没有 SYN 而有 ACK 标识的话，那么根据三次握手，它属于第三步。
	// 验证其合法后，该数据包对应的连接已经建立，那么为该连接创建一个新的 endpoint，将其发给 Accept 队列。
	case (s.flags & header.TCPFlagAck) != 0:

		// 若接受队列已满，只能放弃 syn 报文。
		if e.acceptQueueIsFull() {
			// Silently drop the ack as the application can't accept
			// the connection at this point. The ack will be
			// retransmitted by the sender anyway and we can
			// complete the connection at the time of retransmit if
			// the backlog has space.
			e.stack.Stats().TCP.ListenOverflowAckDrop.Increment()
			e.stats.ReceiveErrors.ListenOverflowAckDrop.Increment()
			e.stack.Stats().DroppedPackets.Increment()
			return
		}

		// 若未开启 SYNCookies 策略，
		if !synCookiesInUse() {

			// When not using SYN cookies, as per RFC 793, section 3.9, page 64:
			// Any acknowledgment is bad if it arrives on a connection still in
			// the LISTEN state.  An acceptable reset segment should be formed
			// for any arriving ACK-bearing segment.  The RST should be
			// formatted as follows:
			//
			//  <SEQ=SEG.ACK><CTL=RST>
			//
			// Send a reset as this is an ACK for which there is no
			// half open connections and we are not using cookies
			// yet.
			//
			// The only time we should reach here when a connection
			// was opened and closed really quickly and a delayed
			// ACK was received from the sender.

			replyWithReset(s)
			return
		}

		// Since SYN cookies are in use this is potentially an ACK to a
		// SYN-ACK we sent but don't have a half open connection state
		// as cookies are being used to protect against a potential SYN
		// flood. In such cases validate the cookie and if valid create
		// a fully connected endpoint and deliver to the accept queue.
		//
		// If not, silently drop the ACK to avoid leaking information
		// when under a potential syn flood attack.
		//
		// Validate the cookie.
		data, ok := ctx.isCookieValid(s.id, s.ackNumber-1, s.sequenceNumber-1)
		if !ok || int(data) >= len(mssTable) {
			e.stack.Stats().TCP.ListenOverflowInvalidSynCookieRcvd.Increment()
			e.stack.Stats().DroppedPackets.Increment()
			return
		}
		e.stack.Stats().TCP.ListenOverflowSynCookieRcvd.Increment()
		// Create newly accepted endpoint and deliver it.
		rcvdSynOptions := &header.TCPSynOptions{
			MSS: mssTable[data],
			// Disable Window scaling as original SYN is
			// lost.
			WS: -1,
		}

		// When syn cookies are in use we enable timestamp only
		// if the ack specifies the timestamp option assuming
		// that the other end did in fact negotiate the
		// timestamp option in the original SYN.
		if s.parsedOptions.TS {
			rcvdSynOptions.TS = true
			rcvdSynOptions.TSVal = s.parsedOptions.TSVal
			rcvdSynOptions.TSEcr = s.parsedOptions.TSEcr
		}

		n, err := ctx.createConnectingEndpoint(s, s.ackNumber-1, s.sequenceNumber-1, rcvdSynOptions)
		if err != nil {
			e.stack.Stats().TCP.FailedConnectionAttempts.Increment()
			e.stats.FailedConnectionAttempts.Increment()
			return
		}

		// clear the tsOffset for the newly created
		// endpoint as the Timestamp was already
		// randomly offset when the original SYN-ACK was
		// sent above.
		n.tsOffset = 0

		// Switch state to connected.
		n.stack.Stats().TCP.CurrentEstablished.Increment()
		n.state = StateEstablished
		n.isConnectNotified = true

		// Do the delivery in a separate goroutine so
		// that we don't block the listen loop in case
		// the application is slow to accept or stops
		// accepting.
		//
		// NOTE: This won't result in an unbounded
		// number of goroutines as we do check before
		// entering here that there was at least some
		// space available in the backlog.

		// Start the protocol goroutine.
		wq := &waiter.Queue{}
		n.startAcceptedLoop(wq)
		e.stack.Stats().TCP.PassiveConnectionOpenings.Increment()
		go e.deliverAccepted(n)
	}
}

// protocolListenLoop is the main loop of a listening TCP endpoint.
// It runs in its own goroutine and is responsible for handling connection requests.
//
// protocolListenLoop 是 listening endpoint 的主循环，它在独立的 goroutine 中运行，负责处理建立连接请求。
//
//
//
func (e *endpoint) protocolListenLoop(rcvWnd seqnum.Size) *tcpip.Error {

	e.mu.Lock()
	v6only := e.v6only
	e.mu.Unlock()

	// 构造 listen 上下文
	ctx := newListenContext(e.stack, e, rcvWnd, v6only, e.NetProto)

	// 退出时，执行清理逻辑
	defer func() {

		// Mark endpoint as closed.
		// This will prevent goroutines running handleSynSegment() from attempting to
		// queue new connections to the endpoint.
		//
		// 将状态置为 close ，这将防止运行 handleSynSegment() 的 goroutines 试图将新的连接请求入队。
		e.mu.Lock()
		e.state = StateClose

		// close any endpoints in SYN-RCVD state.
		// 关闭处于 SYN-RCVD 状态的 endpoints 。
		ctx.closeAllPendingEndpoints()

		// Do cleanup if needed.
		// 必要时做清理工作。
		e.completeWorkerLocked()

		// ?
		if e.drainDone != nil {
			close(e.drainDone)
		}
		e.mu.Unlock()

		// Notify waiters that the endpoint is shutdown.
		// 通知 waiters 监听端点已关闭。
		e.waiterQueue.Notify(waiter.EventIn | waiter.EventOut)

	}()

	// 监听定时事件，执行回调逻辑
	s := sleep.Sleeper{}
	s.AddWaker(&e.notificationWaker, wakerForNotification)
	s.AddWaker(&e.newSegmentWaker, wakerForNewSegment)

	for {

		switch index, _ := s.Fetch(true); index {

		case wakerForNotification:
			n := e.fetchNotifications()
			// 收到退出通知
			if n&notifyClose != 0 {
				return nil
			}
			// 收到排空通知
			if n&notifyDrain != 0 {
				// 如果 segment 队列不空，就逐个出队并处理
				for !e.segmentQueue.empty() {
					s := e.segmentQueue.dequeue()
					e.handleListenSegment(ctx, s)
					s.decRef()
				}
				close(e.drainDone)
				<-e.undrain
			}

		case wakerForNewSegment:
			// Process at most maxSegmentsPerWake segments.
			mayRequeue := true
			// maxSegmentsPerWake == 100，因为收到一个通知可能对应收到多个数据包，所以每次 wake 都处理多次。
			for i := 0; i < maxSegmentsPerWake; i++ {
				s := e.segmentQueue.dequeue()
				if s == nil {
					mayRequeue = false
					break
				}

				e.handleListenSegment(ctx, s)
				s.decRef()
			}

			// If the queue is not empty, make sure we'll wake up in the next iteration.
			// 经过 maxSegmentsPerWake 次循环仍然没有处理完所有的包，再次唤醒 waker ，继续处理。
			if mayRequeue && !e.segmentQueue.empty() {
				e.newSegmentWaker.Assert()
			}
		}
	}
}
