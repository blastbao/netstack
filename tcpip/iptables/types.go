// Copyright 2019 The gVisor authors.
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

package iptables

import (
	"github.com/blastbao/netstack/tcpip/buffer"
)


// A Hook specifies one of the hooks built into the network stack.
//
//                      Userspace app          Userspace app
//                            ^                      |
//                            |                      v
//                         [Input]               [Output]
//                            ^                      |
//                            |                      v
//                            |                   routing
//                            |                      |
//                            |                      v
// ----->[Prerouting]----->routing----->[Forward]---------[Postrouting]----->
//
// Hook 指定了网络协议栈中内置的钩子。
type Hook uint

// These values correspond to values in include/uapi/linux/netfilter.h.
const (
	// Prerouting happens before a packet is routed to applications or to be forwarded.
	// Prerouting 发生在数据包被路由到应用程序或被 forward 转发前。
	Prerouting Hook = iota

	// Input happens before a packet reaches an application.
	// Input 发生在数据包到达应用程序之前。
	Input

	// Forward happens once it's decided that a packet should be forwarded to another host.
	// Forward 发生在将一个数据包转发到另一台主机时。
	Forward

	// Output happens after a packet is written by an application to be sent out.
	// Output 发生在应用程序写入一个数据包并将其发送出去之后。
	Output

	// Postrouting happens just before a packet goes out on the wire.
	// Postrouting 发生在数据包在线路上发出之前。
	Postrouting

	// The total number of hooks.
	// 钩子的总数。
	NumHooks
)

// A Verdict is returned by a rule's target to indicate how traversal of rules
// should (or should not) continue.
//
// Verdict 由规则的目标返回，用于指示规则的遍历应该（或不应该）如何继续。
type Verdict int

const (
	// Accept indicates the packet should continue traversing netstack as normal.
	// Accept 表示数据包应该正常地继续遍历 netstack 。
	Accept Verdict = iota

	// Drop inicates the packet should be dropped, stopping traversing netstack.
	// Drop 指示数据包应该被丢弃，停止遍历 netstack 。
	Drop

	// Stolen indicates the packet was co-opted by the target and should stop traversing netstack.
	// Stolen 表示数据包被目标方获取，应停止遍历 netstack 。(?)
	Stolen

	// Queue indicates the packet should be queued for userspace processing.
	// Queue 表示数据包应该排队等待用户空间处理。
	Queue

	// Repeat indicates the packet should re-traverse the chains for the current hook.
	// Repeat 表示数据包应该为当前的钩子重新遍历链。(?)
	Repeat

	// None indicates no verdict was reached.
	// None 表示没有作出判决。
	None

	// Jump indicates a jump to another chain.
	// Jump 表示跳到另一个链上。
	Jump

	// Continue indicates that traversal should continue at the next rule.
	// Continue 表示应在下一条规则处继续遍历。
	Continue

	// Return indicates that traversal should return to the calling chain.
	// Return 表示遍历应该返回到调用链。
	Return
)

// IPTables holds all the tables for a netstack.
type IPTables struct {

	// Tables maps table names to tables. User tables have arbitrary names.
	Tables map[string]Table

	// Priorities maps each hook to a list of table names. The order of the
	// list is the order in which each table should be visited for that hook.
	Priorities map[Hook][]string
}

// A Table defines a set of chains and hooks into the network stack.
// The currently supported tables are:
//   * nat
//   * mangle
type Table struct {

	// BuiltinChains holds the un-deletable chains built into netstack.
	// If a hook isn't present in the map, this table doesn't utilize that hook.
	BuiltinChains map[Hook]Chain

	// DefaultTargets holds a target for each hook that will be executed if
	// chain traversal doesn't yield a verdict.
	DefaultTargets map[Hook]Target

	// UserChains holds user-defined chains for the keyed by name. Users
	// can give their chains arbitrary names.
	UserChains map[string]Chain

	// Chains maps names to chains for both builtin and user-defined chains.
	// Its entries point to Chains already either in BuiltinChains or
	// UserChains, and its purpose is to make looking up tables by name
	// fast.
	Chains map[string]*Chain

	// Metadata holds information about the Table that is useful to users
	// of IPTables, but not to the netstack IPTables code itself.
	metadata interface{}
}

// ValidHooks returns a bitmap of the builtin hooks for the given table.
func (table *Table) ValidHooks() uint32 {
	hooks := uint32(0)
	for hook, _ := range table.BuiltinChains {
		hooks |= 1 << hook
	}
	return hooks
}

// Metadata returns the metadata object stored in table.
func (table *Table) Metadata() interface{} {
	return table.metadata
}

// SetMetadata sets the metadata object stored in table.
func (table *Table) SetMetadata(metadata interface{}) {
	table.metadata = metadata
}

// A Chain defines a list of rules for packet processing. When a packet
// traverses a chain, it is checked against each rule until either a rule
// returns a verdict or the chain ends.
//
// By convention, builtin chains end with a rule that matches everything and
// returns either Accept or Drop. User-defined chains end with Return. These
// aren't strictly necessary here, but the iptables tool writes tables this way.
type Chain struct {
	// Name is the chain name.
	Name string

	// Rules is the list of rules to traverse.
	Rules []Rule
}



// A Rule is a packet processing rule. It consists of two pieces. First it
// contains zero or more matchers, each of which is a specification of which
// packets this rule applies to. If there are no matchers in the rule, it
// applies to any packet.
type Rule struct {
	// Matchers is the list of matchers for this rule.
	Matchers []Matcher

	// Target is the action to invoke if all the matchers match the packet.
	Target Target
}

// A Matcher is the interface for matching packets.
type Matcher interface {
	// Match returns whether the packet matches and whether the packet
	// should be "hotdropped", i.e. dropped immediately. This is usually
	// used for suspicious packets.
	Match(hook Hook, packet buffer.VectorisedView, interfaceName string) (matches bool, hotdrop bool)
}

// A Target is the interface for taking an action for a packet.
type Target interface {
	// Action takes an action on the packet and returns a verdict on how
	// traversal should (or should not) continue. If the return value is
	// Jump, it also returns the name of the chain to jump to.
	Action(packet buffer.VectorisedView) (Verdict, string)
}
