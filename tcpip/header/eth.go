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

package header

import (
	"encoding/binary"

	"github.com/blastbao/netstack/tcpip"
)

const (
	dstMAC  = 0
	srcMAC  = 6
	ethType = 12
)

//
//
// 网络设备如何确定以太网数据帧的上层协议？
//   以太网帧中包含一个 Type 字段，表示帧中的数据应该发送到上层哪个协议处理。
//   比如，IP 协议对应的 Type 值为 0x0800 ，ARP 协议对应的 Type 值为 0x0806 。
//
// 终端设备接收到以太网数据帧时，会如何处理？
//
//   主机检查帧头中的目的 MAC 地址，如果目的 MAC 地址不是本机 MAC 地址，
//   也不是本机侦听的组播或广播 MAC 地址，则主机会丢弃收到的帧。
//
//   如果目的 MAC 地址是本机 MAC 地址，则接收该帧，检查帧校验序列（FCS）字段，
//   并与本机计算的值对比来确定帧在传输过程中是否保持了完整性。
//
//   如果检查通过，就会剥离帧头和帧尾，然后根据帧头中的 Type 字段来决定把数据
//   发送到哪个上层协议进行后续处理。
//
//
//  http://en.wikipedia.org/wiki/Ethernet_frame#Structure
//  - no preamble / SFD / FCS (handle by hardware)
//
//  +-----------+-----------+----------+------------------------------------
//  | dest(6B)  | src(6B)   | type(2B) | payload                           |
//  +-----------+-----------+----------+------------------------------------
//


// EthernetFields contains the fields of an ethernet frame header.
// It is used to describe the fields of a frame that needs to be encoded.
//
// EthernetFields 包含以太网帧头的字段，它用于描述需要编码的帧的字段。
type EthernetFields struct {
	// SrcAddr is the "MAC source" field of an ethernet frame header.
	// 源 Mac 地址
	SrcAddr tcpip.LinkAddress

	// DstAddr is the "MAC destination" field of an ethernet frame header.
	// 目的 Mac 地址
	DstAddr tcpip.LinkAddress

	// Type is the "ethertype" field of an ethernet frame header.
	// Type 是以太网帧头的 "ethertype" 字段，标识网络层的协议号。
	Type tcpip.NetworkProtocolNumber
}

// Ethernet represents an ethernet frame header stored in a byte array.
//
// Ethernet 表示以太网帧头。
type Ethernet []byte

const (
	// EthernetMinimumSize is the minimum size of a valid ethernet frame.
	// 以太网有效帧的最小尺寸，6+6+2=14
	EthernetMinimumSize = 14

	// EthernetAddressSize is the size, in bytes, of an ethernet address.
	// 以太网地址的大小，以字节为单位。
	EthernetAddressSize = 6

	// unspecifiedEthernetAddress is the unspecified ethernet address (all bits set to 0).
	// 未指定的以太网地址（6个字节都设置为0）。
	unspecifiedEthernetAddress = tcpip.LinkAddress("\x00\x00\x00\x00\x00\x00")

	// unicastMulticastFlagMask is the mask of the least significant bit in
	// the first octet (in network byte order) of an ethernet address that
	// determines whether the ethernet address is a unicast or multicast.
	// If the masked bit is a 1, then the address is a multicast, unicast otherwise.
	//
	// See the IEEE Std 802-2001 document for more details. Specifically,
	// section 9.2.1 of http://ieee802.org/secmail/pdfocSP2xXA6d.pdf:
	// "A 48-bit universal address consists of two parts. The first 24 bits
	// correspond to the OUI as assigned by the IEEE, expect that the
	// assignee may set the LSB of the first octet to 1 for group addresses
	// or set it to 0 for individual addresses."
	//
	//
	// unicastMulticastFlagMask 是以太网地址的第一个八位组（以网络字节顺序）中最低有效位的掩码，
	// 用于确定以太网地址是单播还是多播。如果掩码位为1，则该地址为多播，否则为单播。
	//
	// 有关更多详细信息，请参见 IEEE Std 802-2001 文档。
	// 具体来说，http://ieee802.org/secmail/pdfocSP2xXA6d.pdf 的9.2.1节：
	// “一个 48 位通用地址由两部分组成。前 24 位对应于 IEEE 分配的 OUI ，
	// 希望受让人可以将组播地址的第一个八位字节的 LSB 设置为1，而对于单播地址，则将其设置为0。”
	unicastMulticastFlagMask = 1

	// unicastMulticastFlagByteIdx is the byte that holds the unicast/multicast flag.
	// See unicastMulticastFlagMask.
	//
	// unicastMulticastFlagByteIdx 是持有单播/多播标志的字节。参见 unicastMulticastFlagMask 。
	unicastMulticastFlagByteIdx = 0
)

const (

	// EthernetProtocolAll is a catch-all for all protocols carried inside
	// an ethernet frame. It is mainly used to create packet sockets that
	// capture all traffic.
	//
	// EthernetProtocolAll 是以太网框架内承载的所有协议的总称。
	// 它主要用于创建捕获所有流量的数据包套接字。
	EthernetProtocolAll tcpip.NetworkProtocolNumber = 0x0003

	// EthernetProtocolPUP is the PARC Universial Packet protocol ethertype.
	//
	// EthernetProtocolPUP 是 PARC 通用数据包协议类型。
	EthernetProtocolPUP tcpip.NetworkProtocolNumber = 0x0200
)

// Ethertypes holds the protocol numbers describing the payload of an ethernet frame.
// These types aren't necessarily supported by netstack, but can be used to catch all
// traffic of a type via packet endpoints.
//
// Ethertypes 保存了描述以太网帧有效载荷的协议号。
// 这些类型不一定被 netstack 支持，但可以通过数据包端点来捕获该类型的所有流量。
var Ethertypes = []tcpip.NetworkProtocolNumber{
	EthernetProtocolAll,
	EthernetProtocolPUP,
}

// SourceAddress returns the "MAC source" field of the ethernet frame header.
//
// SourceAddress 返回以太网帧头的 "MAC source"字段。
func (b Ethernet) SourceAddress() tcpip.LinkAddress {
	return tcpip.LinkAddress(b[srcMAC:][:EthernetAddressSize])
}

// DestinationAddress returns the "MAC destination" field of the ethernet frame header.
//
// DestinationAddress 返回以太网帧头的 "MAC destination" 字段。
func (b Ethernet) DestinationAddress() tcpip.LinkAddress {
	return tcpip.LinkAddress(b[dstMAC:][:EthernetAddressSize])
}

// Type returns the "ethertype" field of the ethernet frame header.
//
// Type 返回以太网帧头的 "ethertype" 字段。
func (b Ethernet) Type() tcpip.NetworkProtocolNumber {
	return tcpip.NetworkProtocolNumber(binary.BigEndian.Uint16(b[ethType:]))
}

// Encode encodes all the fields of the ethernet frame header.
//
// Encode 对以太网帧头的所有字段进行编码。
func (b Ethernet) Encode(e *EthernetFields) {
	//  +-----------+-----------+----------+-------------+
	//  | dest(6B)  | src(6B)   | type(2B) | payload     |
	//  +-----------+-----------+----------+-------------+
	binary.BigEndian.PutUint16(b[ethType:], uint16(e.Type))		// 网络层协议类型
	copy(b[srcMAC:][:EthernetAddressSize], e.SrcAddr)			// 源地址
	copy(b[dstMAC:][:EthernetAddressSize], e.DstAddr)			// 目的地址
}

// IsValidUnicastEthernetAddress returns true if addr is a valid unicast ethernet address.
//
// 如果 addr 是有效的单播以太网地址，则 IsValidUnicastEthernetAddress 返回true。
func IsValidUnicastEthernetAddress(addr tcpip.LinkAddress) bool {

	// Must be of the right length.
	// 地址长度必须正确。
	if len(addr) != EthernetAddressSize {
		return false
	}

	// Must not be unspecified.
	// 不能是未定义的空地址。
	if addr == unspecifiedEthernetAddress {
		return false
	}

	// Must not be a multicast.
	// 不能是多播地址
	if addr[unicastMulticastFlagByteIdx]&unicastMulticastFlagMask != 0 {
		return false
	}

	// addr is a valid unicast ethernet address.
	// addr 是有效的单播以太网地址。
	return true
}
