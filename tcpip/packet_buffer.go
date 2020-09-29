// Copyright 2019 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at //
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tcpip

import "github.com/blastbao/netstack/tcpip/buffer"




// A PacketBuffer contains all the data of a network packet.
//
// As a PacketBuffer traverses up the stack, it may be necessary to pass it to
// multiple endpoints. Clone() should be called in such cases so that
// modifications to the Data field do not affect other copies.
//
// PacketBuffer 中包含了一个网络包的所有数据。当一个 PacketBuffer 在协议栈中遍历时，
// 可能需要将它传递给多个端点，在这种情况下，应该调用 Clone() ，这样对 Data 字段的修改不
// 会影响其他副本。
//
// +stateify savable
type PacketBuffer struct {


	// Data holds the payload of the packet. For inbound packets, it also
	// holds the headers, which are consumed as the packet moves up the
	// stack. Headers are guaranteed not to be split across views.
	//
	// The bytes backing Data are immutable, but Data itself may be trimmed
	// or otherwise modified.
	//
	// Data 存储着网络包的有效载荷。
	// 对于入栈数据包，它还保存着报头，报头在数据包向上移动时被逐层剔除。
	//
	Data buffer.VectorisedView



	// Header holds the headers of outbound packets.
	// As a packet is passed down the stack, each layer adds to Header.
	//
	// Header 保存出栈数据包的头。
	// 当一个数据包向下传递时，每一层都会向 Header 添加新头部。
	Header buffer.Prependable



	// These fields are used by both inbound and outbound packets. They
	// typically overlap with the Data and Header fields.
	//
	// 这些字段被入栈和出栈数据包使用，它们通常与 Data 和 Header 字段重叠。
	//
	// The bytes backing these views are immutable. Each field may be nil
	// if either it has not been set yet or no such header exists (e.g.
	// packets sent via loopback may not have a link header).
	//
	// 存储着这些 views 的底层字节是不可改变的。
	// 如果尚未设置或不存在这样的头，则对应字段为 nil（例如，通过环回发送的数据包可能没有数据链路层头部）。
	//
	// These fields may be Views into other slices (either Data or Header).
	// SR dosen't support this, so deep copies are necessary in some cases.
	//
	// 这些字段可能是其他切片（Data 或 Header）的视图。
	// SR 不支持这样做，所以在某些情况下需要进行深度复制。

	// 链路层头
	LinkHeader      buffer.View
	// 网络层头
	NetworkHeader   buffer.View
	// 传输层头
	TransportHeader buffer.View
}

// Clone makes a copy of pk. It clones the Data field, which creates a new
// VectorisedView but does not deep copy the underlying bytes.
//
// Clone also does not deep copy any of its other fields.
func (pk PacketBuffer) Clone() PacketBuffer {
	pk.Data = pk.Data.Clone(nil)
	return pk
}
