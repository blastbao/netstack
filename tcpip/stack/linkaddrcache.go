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
	"fmt"
	"sync"
	"time"

	"github.com/blastbao/netstack/sleep"
	"github.com/blastbao/netstack/tcpip"
)


const linkAddrCacheSize = 512 // max cache entries



// 背景介绍
//
// ARP 实现中，最需要关注的是其具有缓存功能，它缓存了一个 IP/MAC 的映射表，
// 当本地主机需要向某一主机发送数据时，就会先查询 ARP 缓存表，看目标主机的 IP 地址是否在其中，
// 	(1) 如果存在，那么就可以取出对应的 MAC 地址，然后直接放到数据帧中，
//  (2) 如果不存在，就会发一个 ARP 广播，询问同一网段中的所有主机，
// 		当然，非目标主机并不响应，只有目标主机会回应自己的 IP & MAC 地址，
// 		然后本地主机会将这条数据放到自己的缓存表中，以保证下次再与目标主机通信时可以直接去缓存表里查询即可。




// linkAddrCache is a fixed-sized cache mapping IP addresses to link addresses.
// The entries are stored in a ring buffer, oldest entry replaced first.
// This struct is safe for concurrent use.
//
// linkAddrCache 是一个固定大小的缓存，将 IP 地址映射到 MAC 地址。
// 条目存储在环形缓冲区中，最老的条目先被替换。
// 这个结构可以安全地并发使用。
type linkAddrCache struct {

	// ageLimit is how long a cache entry is valid for.
	// ageLimit 指一个缓存条目的过期时间。
	ageLimit time.Duration

	// resolutionTimeout is the amount of time to wait for a link request to resolve an address.
	// resolutionTimeout 是解析 MAC 地址的超时时间。
	resolutionTimeout time.Duration

	// resolutionAttempts is the number of times an address is attempted to be resolved before failing.
	// resolutionTimeout 是解析 MAC 地址的尝试次数。
	resolutionAttempts int

	// 环形缓存，长度为 512
	cache struct {
		sync.Mutex									// 锁 - 确保并发安全
		table map[tcpip.FullAddress]*linkAddrEntry	// 缓存表项
		lru   linkAddrEntryList						// LRU 链表，控制先进先出
	}
}


// entryState controls the state of a single entry in the cache.
// entryState 控制缓存中单个条目的状态。
type entryState int

const (
	// incomplete means that there is an outstanding request to resolve the address.
	// This is the initial state.
	//
	// incomplete 表示有一个正在进行 resolved 的请求。这是初始状态。
	incomplete entryState = iota

	// ready means that the address has been resolved and can be used.
	//
	// ready 表示地址已经 resolved ，可以使用。
	ready

	// failed means that address resolution timed out and the address
	// could not be resolved.
	//
	// failed 表示地址解析超时，无法解析。
	failed
)

// String implements Stringer.
func (s entryState) String() string {
	switch s {
	case incomplete:
		return "incomplete"
	case ready:
		return "ready"
	case failed:
		return "failed"
	default:
		return fmt.Sprintf("unknown(%d)", s)
	}
}

// A linkAddrEntry is an entry in the linkAddrCache.
// This struct is thread-compatible.
type linkAddrEntry struct {

	linkAddrEntryEntry				// 链表结构

	addr       tcpip.FullAddress	// IP 地址
	linkAddr   tcpip.LinkAddress	// MAC 地址
	expiration time.Time			// 缓存条目过期时间
	s          entryState			// 缓存条目状态

	// wakers is a set of waiters for address resolution result.
	// Anytime state transitions out of incomplete these waiters are notified.
	//
	// wakers 保存了地址解析结果的等待者。
	// 当 Entry 状态从 incomplete 状态转为其它时，这些等待者都会被通知。
	wakers map[*sleep.Waker]struct{}

	// done is used to allow callers to wait on address resolution.
	// It is nil iff s is incomplete and resolution is not yet in progress.
	//
	// done 用于调用者阻塞式的等待地址解析完成。
	// 如果 s 是 incomplete 状态，且解析还没有进行，则 done 为 nil 。
	done chan struct{}
}

// changeState sets the entry's state to ns, notifying any waiters.
//
// The entry's expiration is bumped up to the greater of itself and the passed
// expiration; the zero value indicates immediate expiration, and is set
// unconditionally - this is an implementation detail that allows for entries
// to be reused.
func (e *linkAddrEntry) changeState(ns entryState, expiration time.Time) {

	// Notify whoever is waiting on address resolution when transitioning out of incomplete.
	if e.s == incomplete && ns != incomplete {

		for w := range e.wakers {
			w.Assert()
		}

		e.wakers = nil
		if ch := e.done; ch != nil {
			close(ch)
		}

		e.done = nil
	}

	if expiration.IsZero() || expiration.After(e.expiration) {
		e.expiration = expiration
	}
	e.s = ns
}

func (e *linkAddrEntry) removeWaker(w *sleep.Waker) {
	delete(e.wakers, w)
}


// 将 MAC 地址更新到 K 关联的 ARP 缓存上。
//
// add adds a k -> v mapping to the cache.
func (c *linkAddrCache) add(k tcpip.FullAddress, v tcpip.LinkAddress) {

	// Calculate expiration time before acquiring the lock,
	// since expiration is relative to the time when information was learned,
	// rather than when it happened to be inserted into the cache.
	//
	// 在获取锁之前计算过期时间，因为过期时间是相对于信息被学习的时间，而不是恰好插入缓存的时间。
	expiration := time.Now().Add(c.ageLimit)

	c.cache.Lock()
	// 检索与 k 相关联的 ARP 缓存条目
	entry := c.getOrCreateEntryLocked(k)
	// 将 Mac 地址更新到该条目上
	entry.linkAddr = v
	// 将缓存条目状态更新为 ready ，可被直接使用
	entry.changeState(ready, expiration)
	c.cache.Unlock()
}


// getOrCreateEntryLocked retrieves a cache entry associated with k.
// The returned entry is always refreshed in the cache (it is reachable via the map,
// and its place is bumped in LRU).
//
// If a matching entry exists in the cache, it is returned. If no matching
// entry exists and the cache is full, an existing entry is evicted via LRU,
// reset to state incomplete, and returned. If no matching entry exists and the
// cache is not full, a new entry with state incomplete is allocated and
// returned.
//
// getOrCreateEntryLocked 检索与 k 相关联的缓存条目，被检索条目会被 refreshed 。
//
// 如果缓存中存在匹配的条目，则直接返回。
// 如果缓存中没有匹配的条目，并且缓存已满，则通过 LRU 驱逐一条现有的条目，并重置为 "incomplete" 状态，然后返回。
// 如果缓存中不存在匹配条目，并且缓存未满，则分配一个 "incomplete" 状态的新条目并返回。
//
//
func (c *linkAddrCache) getOrCreateEntryLocked(k tcpip.FullAddress) *linkAddrEntry {

	// 检索 k 关联条目，若存在，则刷新 lru 队列（插入队头）。
	if entry, ok := c.cache.table[k]; ok {
		c.cache.lru.Remove(entry)
		c.cache.lru.PushFront(entry)
		return entry
	}

	// 若缓存条目不存在，且缓存已满，则根据 LRU 算法淘汰一个条目，后面会重用该条目（避免分配对象?）
	var entry *linkAddrEntry
	if len(c.cache.table) == linkAddrCacheSize {
		// 取 lru 队尾元素，从 table 和 lru 队列中移除它
		entry = c.cache.lru.Back()
		delete(c.cache.table, entry.addr)
		c.cache.lru.Remove(entry)

		// Wake waiters and mark the soon-to-be-reused entry as expired.
		// Note that the state passed doesn't matter when the zero time is passed.
		entry.changeState(failed, time.Time{})
	} else {
		entry = new(linkAddrEntry)
	}

	// 构造一个新条目（或复用刚刚淘汰的条目）
	*entry = linkAddrEntry{
		addr: k,			// IP 地址
		s:    incomplete,	// 缓存状态
	}

	// 保存到缓存中
	c.cache.table[k] = entry
	c.cache.lru.PushFront(entry)
	return entry
}

// get reports any known link address for k.
func (c *linkAddrCache) get(

	k tcpip.FullAddress,			// 远端地址
	linkRes LinkAddressResolver,	// MAC 地址解析器
	localAddr tcpip.Address,		// 本地地址
	linkEP LinkEndpoint, 			//
	waker *sleep.Waker,				//

) (

 	tcpip.LinkAddress,				//
  	<-chan struct{},				//
  	*tcpip.Error,					//

) {


	//
	if linkRes != nil {
		if addr, ok := linkRes.ResolveStaticAddress(k.Addr); ok {
			return addr, nil, nil
		}
	}

	c.cache.Lock()
	defer c.cache.Unlock()

	// 检索与 k 相关联的缓存条目 entry 。
	entry := c.getOrCreateEntryLocked(k)
	// 检查 entry 的缓存状态。
	switch s := entry.s; s {
	case ready, failed:
		// 条目尚未过期
		if !time.Now().After(entry.expiration) {
			// Not expired.
			switch s {
			case ready:
				return entry.linkAddr, nil, nil
			case failed:
				return entry.linkAddr, nil, tcpip.ErrNoLinkAddress
			default:
				panic(fmt.Sprintf("invalid cache entry state: %s", s))
			}
		}
		// 条目已过期，更正缓存状态
		entry.changeState(incomplete, time.Time{})
		fallthrough
	case incomplete:

		if waker != nil {
			if entry.wakers == nil {
				entry.wakers = make(map[*sleep.Waker]struct{})
			}
			entry.wakers[waker] = struct{}{}
		}

		if entry.done == nil {
			// Address resolution needs to be initiated.
			if linkRes == nil {
				return entry.linkAddr, nil, tcpip.ErrNoLinkAddress
			}

			entry.done = make(chan struct{})
			go c.startAddressResolution(k, linkRes, localAddr, linkEP, entry.done)
		}

		return entry.linkAddr, entry.done, tcpip.ErrWouldBlock
	default:
		panic(fmt.Sprintf("invalid cache entry state: %s", s))
	}
}

// removeWaker removes a waker previously added through get().
func (c *linkAddrCache) removeWaker(k tcpip.FullAddress, waker *sleep.Waker) {
	c.cache.Lock()
	defer c.cache.Unlock()

	if entry, ok := c.cache.table[k]; ok {
		entry.removeWaker(waker)
	}
}

func (c *linkAddrCache) startAddressResolution(k tcpip.FullAddress, linkRes LinkAddressResolver, localAddr tcpip.Address, linkEP LinkEndpoint, done <-chan struct{}) {

	//
	for i := 0; ; i++ {

		// Send link request, then wait for the timeout limit and check
		// whether the request succeeded.
		//
		// 发送 ARP 地址解析请求，然后等待超时。
		linkRes.LinkAddressRequest(k.Addr, localAddr, linkEP)

		select {
		// 解析超时
		case now := <-time.After(c.resolutionTimeout):
			// 如果 stop 为 true，意味着没有收到 ARP 回复包，且重试次数未达到阈值，需要进行一次 ARP 解析请求。
			if stop := c.checkLinkRequest(now, k, i); stop {
				return
			}
		case <-done:
			return
		}
	}
}

// checkLinkRequest checks whether previous attempt to resolve address has succeeded
// and mark the entry accordingly, e.g. ready, failed, etc.
//
// Return true if request can stop, false if another request should be sent.
//
// checkLinkRequest 检查之前的地址解析尝试是否成功，并相应地标记条目状态，如 ready ，failed 等。
//
// 如果请求可以停止，则返回 true ，如果应该发送另一个请求，则返回 false 。
func (c *linkAddrCache) checkLinkRequest(now time.Time, k tcpip.FullAddress, attempt int) bool {

	c.cache.Lock()
	defer c.cache.Unlock()

	// 从缓存中获取地址 k 的解析结果，若缓存中不存在，则返回 true 。
	entry, ok := c.cache.table[k]
	if !ok {
		// Entry was evicted from the cache.
		return true
	}

	// 检查缓存条目的状态：
	//	如果为 ready 或者 failed ，则返回 true；
	//	如果为 incomplete ，且重试次数未达到限制，则返回 false ，否则，更新状态为 failed 。
	switch s := entry.s; s {
	case ready, failed:
		// Entry was made ready by resolver or failed. Either way we're done.
	case incomplete:
		if attempt+1 < c.resolutionAttempts {
			// No response yet, need to send another ARP request.
			// 没有回复，需要再发一次 ARP 请求。
			return false
		}
		// Max number of retries reached, mark entry as failed.
		entry.changeState(failed, now.Add(c.ageLimit))
	default:
		panic(fmt.Sprintf("invalid cache entry state: %s", s))
	}


	return true
}

func newLinkAddrCache(ageLimit, resolutionTimeout time.Duration, resolutionAttempts int) *linkAddrCache {
	c := &linkAddrCache{
		ageLimit:           ageLimit,
		resolutionTimeout:  resolutionTimeout,
		resolutionAttempts: resolutionAttempts,
	}
	// 最大缓存表项为 512
	c.cache.table = make(map[tcpip.FullAddress]*linkAddrEntry, linkAddrCacheSize)
	return c
}
