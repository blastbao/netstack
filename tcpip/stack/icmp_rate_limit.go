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
	"golang.org/x/time/rate"
)

const (
	// icmpLimit is the default maximum number of ICMP messages permitted by this rate limiter.
	// icmpLimit 是限频器允许产生 ICMP 消息的最大速率。
	icmpLimit = 1000

	// icmpBurst is the default number of ICMP messages that can be sent in a single burst.
	// icmpBurst 是单次突发事件中可以发送的 ICMP 消息的数量。
	icmpBurst = 50
)

// ICMPRateLimiter is a global rate limiter that controls the generation of ICMP messages generated by the stack.
// ICMPRateLimiter 是一个全局速率限制器，用于控制协议栈产生 ICMP 消息的速率。
type ICMPRateLimiter struct {
	*rate.Limiter
}

// NewICMPRateLimiter returns a global rate limiter for controlling the rate at which ICMP messages are generated by the stack.
// NewICMPRateLimiter 返回一个全局速率限制器，用于控制协议栈产生 ICMP 消息的速率。
func NewICMPRateLimiter() *ICMPRateLimiter {
	return &ICMPRateLimiter{
		Limiter: rate.NewLimiter(icmpLimit, icmpBurst),
	}
}
