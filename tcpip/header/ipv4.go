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
	versIHL = 0
	tos     = 1

	// IPv4TotalLenOffset is the offset of the total length field in the IPv4 header.
	IPv4TotalLenOffset = 2
	id                 = 4
	flagsFO            = 6
	ttl                = 8
	protocol           = 9
	checksum           = 10
	srcAddr            = 12
	dstAddr            = 16
)

// IPv4Fields contains the fields of an IPv4 packet.
// It is used to describe the fields of a packet that needs to be encoded.
type IPv4Fields struct {

	// IHL is the "internet header length" field of an IPv4 packet.
	// IHL 是 IPv4 数据包的 “互联网报头长度” 字段。
	IHL uint8

	// TOS is the "type of service" field of an IPv4 packet.
	// TOS 是 IPv4 数据包的 “服务类型” 字段。
	TOS uint8

	// TotalLength is the "total length" field of an IPv4 packet.
	TotalLength uint16

	// ID is the "identification" field of an IPv4 packet.
	// ID 是 IPv4 数据包的 “标识” 字段。
	ID uint16

	// Flags is the "flags" field of an IPv4 packet.
	Flags uint8

	// FragmentOffset is the "fragment offset" field of an IPv4 packet.
	FragmentOffset uint16

	// TTL is the "time to live" field of an IPv4 packet.
	TTL uint8

	// Protocol is the "protocol" field of an IPv4 packet.
	Protocol uint8

	// Checksum is the "checksum" field of an IPv4 packet.
	Checksum uint16

	// SrcAddr is the "source ip address" of an IPv4 packet.
	SrcAddr tcpip.Address

	// DstAddr is the "destination ip address" of an IPv4 packet.
	DstAddr tcpip.Address
}

// IPv4 represents an ipv4 header stored in a byte array.
// Most of the methods of IPv4 access to the underlying slice without
// checking the boundaries and could panic because of 'index out of range'.
// Always call IsValid() to validate an instance of IPv4 before using other methods.
//
// IPv4 表示存储在字节数组中的 ipv4 标头。
//
// IPv4 提供的方法多数都是在不检查边界的情况下访问底层切片的，可能由于 “索引超出范围” 而出现 Panic 。
//
// 所以在使用 IPv4 提供的方法之前，请调用 IsValid() 来验证 IPv4 是否合法。
type IPv4 []byte

const (
	// IPv4MinimumSize is the minimum size of a valid IPv4 packet.
	//
	// IPv4MinimumSize 是一个有效 IPv4 数据包的最小尺寸。
	IPv4MinimumSize = 20

	// IPv4MaximumHeaderSize is the maximum size of an IPv4 header. Given
	// that there are only 4 bits to represents the header length in 32-bit
	// units, the header cannot exceed 15*4 = 60 bytes.
	//
	// IPv4MaximumHeaderSize 是一个 IPv4 报头的最大尺寸。
	// 由于只有 4 位代表 32 位单位的报头长度，所以报头不能超过 15*4=60 字节。
	IPv4MaximumHeaderSize = 60

	// MinIPFragmentPayloadSize is the minimum number of payload bytes that
	// the first fragment must carry when an IPv4 packet is fragmented.
	//
	// MinIPFragmentPayloadSize 是指当一个 IPv4 数据包被分片时，
	// 首个分片必须携带的最小有效载荷字节数。
	MinIPFragmentPayloadSize = 8

	// IPv4AddressSize is the size, in bytes, of an IPv4 address.
	// IPv4AddressSize 是 IPv4 地址的大小，以字节为单位。
	IPv4AddressSize = 4

	// IPv4ProtocolNumber is IPv4's network protocol number.
	IPv4ProtocolNumber tcpip.NetworkProtocolNumber = 0x0800

	// IPv4Version is the version of the ipv4 protocol.
	// IPv4 版本号
	IPv4Version = 4

	// IPv4Broadcast is the broadcast address of the IPv4 procotol.
	// IPv4Broadcast 是 IPv4 procotol 的广播地址。
	IPv4Broadcast tcpip.Address = "\xff\xff\xff\xff"

	// IPv4Any is the non-routable IPv4 "any" meta address.
	//
	// Anycast 最初是在 RFC1546 中提出并定义的，
	// 根据 RFC1546 的说明 IPv4 的任播地址不同于 IPv4 的单播地址，
	// 它建议从 IPv4 的地址空间分配出一块独立的地址空间作为任播地址空间。
	//
	// 例如：在 IP 网络上通过一个 Anycast 地址标识一组提供特定服务的主机，
	// 同时服务访问方并不关心提供服务的具体是哪一台主机（比如：DNS 或者镜像服务），
	// 访问该地址的报文可以被 IP 网络路由到这一组目标中的任何一台主机上。
	//
	IPv4Any tcpip.Address = "\x00\x00\x00\x00"

	// IPv4MinimumProcessableDatagramSize is the minimum size of an IP
	// packet that every IPv4 capable host must be able to
	// process/reassemble.
	//
	// IPv4MinimumProcessableDatagramSize 是每个 IPv4 主机必须能够 处理/重组 的 IP 数据包的最小尺寸。
	IPv4MinimumProcessableDatagramSize = 576
)

// Flags that may be set in an IPv4 packet.
const (
	IPv4FlagMoreFragments = 1 << iota
	IPv4FlagDontFragment
)

// IPv4EmptySubnet is the empty IPv4 subnet.
var IPv4EmptySubnet = func() tcpip.Subnet {
	subnet, err := tcpip.NewSubnet(IPv4Any, tcpip.AddressMask(IPv4Any))
	if err != nil {
		panic(err)
	}
	return subnet
}()

// IPVersion returns the version of IP used in the given packet. It returns -1
// if the packet is not large enough to contain the version field.
func IPVersion(b []byte) int {
	// Length must be at least offset+length of version field.
	if len(b) < versIHL+1 {
		return -1
	}
	return int(b[versIHL] >> 4)
}

// HeaderLength returns the value of the "header length" field of the ipv4
// header.
func (b IPv4) HeaderLength() uint8 {
	return (b[versIHL] & 0xf) * 4
}

// ID returns the value of the identifier field of the ipv4 header.
func (b IPv4) ID() uint16 {
	return binary.BigEndian.Uint16(b[id:])
}

// Protocol returns the value of the protocol field of the ipv4 header.
func (b IPv4) Protocol() uint8 {
	return b[protocol]
}

// Flags returns the "flags" field of the ipv4 header.
func (b IPv4) Flags() uint8 {
	return uint8(binary.BigEndian.Uint16(b[flagsFO:]) >> 13)
}

// TTL returns the "TTL" field of the ipv4 header.
func (b IPv4) TTL() uint8 {
	return b[ttl]
}

// FragmentOffset returns the "fragment offset" field of the ipv4 header.
func (b IPv4) FragmentOffset() uint16 {
	return binary.BigEndian.Uint16(b[flagsFO:]) << 3
}

// TotalLength returns the "total length" field of the ipv4 header.
func (b IPv4) TotalLength() uint16 {
	return binary.BigEndian.Uint16(b[IPv4TotalLenOffset:])
}

// Checksum returns the checksum field of the ipv4 header.
func (b IPv4) Checksum() uint16 {
	return binary.BigEndian.Uint16(b[checksum:])
}

// SourceAddress returns the "source address" field of the ipv4 header.
func (b IPv4) SourceAddress() tcpip.Address {
	return tcpip.Address(b[srcAddr : srcAddr+IPv4AddressSize])
}

// DestinationAddress returns the "destination address" field of the ipv4
// header.
func (b IPv4) DestinationAddress() tcpip.Address {
	return tcpip.Address(b[dstAddr : dstAddr+IPv4AddressSize])
}

// TransportProtocol implements Network.TransportProtocol.
func (b IPv4) TransportProtocol() tcpip.TransportProtocolNumber {
	return tcpip.TransportProtocolNumber(b.Protocol())
}

// Payload implements Network.Payload.
func (b IPv4) Payload() []byte {
	return b[b.HeaderLength():][:b.PayloadLength()]
}

// PayloadLength returns the length of the payload portion of the ipv4 packet.
func (b IPv4) PayloadLength() uint16 {
	return b.TotalLength() - uint16(b.HeaderLength())
}

// TOS returns the "type of service" field of the ipv4 header.
func (b IPv4) TOS() (uint8, uint32) {
	return b[tos], 0
}

// SetTOS sets the "type of service" field of the ipv4 header.
func (b IPv4) SetTOS(v uint8, _ uint32) {
	b[tos] = v
}

// SetTotalLength sets the "total length" field of the ipv4 header.
func (b IPv4) SetTotalLength(totalLength uint16) {
	binary.BigEndian.PutUint16(b[IPv4TotalLenOffset:], totalLength)
}

// SetChecksum sets the checksum field of the ipv4 header.
func (b IPv4) SetChecksum(v uint16) {
	binary.BigEndian.PutUint16(b[checksum:], v)
}

// SetFlagsFragmentOffset sets the "flags" and "fragment offset" fields of the
// ipv4 header.
func (b IPv4) SetFlagsFragmentOffset(flags uint8, offset uint16) {
	v := (uint16(flags) << 13) | (offset >> 3)
	binary.BigEndian.PutUint16(b[flagsFO:], v)
}

// SetID sets the identification field.
func (b IPv4) SetID(v uint16) {
	binary.BigEndian.PutUint16(b[id:], v)
}

// SetSourceAddress sets the "source address" field of the ipv4 header.
func (b IPv4) SetSourceAddress(addr tcpip.Address) {
	copy(b[srcAddr:srcAddr+IPv4AddressSize], addr)
}

// SetDestinationAddress sets the "destination address" field of the ipv4
// header.
func (b IPv4) SetDestinationAddress(addr tcpip.Address) {
	copy(b[dstAddr:dstAddr+IPv4AddressSize], addr)
}

// CalculateChecksum calculates the checksum of the ipv4 header.
func (b IPv4) CalculateChecksum() uint16 {
	return Checksum(b[:b.HeaderLength()], 0)
}

// Encode encodes all the fields of the ipv4 header.
func (b IPv4) Encode(i *IPv4Fields) {
	b[versIHL] = (4 << 4) | ((i.IHL / 4) & 0xf)
	b[tos] = i.TOS
	b.SetTotalLength(i.TotalLength)
	binary.BigEndian.PutUint16(b[id:], i.ID)
	b.SetFlagsFragmentOffset(i.Flags, i.FragmentOffset)
	b[ttl] = i.TTL
	b[protocol] = i.Protocol
	b.SetChecksum(i.Checksum)
	copy(b[srcAddr:srcAddr+IPv4AddressSize], i.SrcAddr)
	copy(b[dstAddr:dstAddr+IPv4AddressSize], i.DstAddr)
}

// EncodePartial updates the total length and checksum fields of ipv4 header,
// taking in the partial checksum, which is the checksum of the header without
// the total length and checksum fields. It is useful in cases when similar
// packets are produced.
func (b IPv4) EncodePartial(partialChecksum, totalLength uint16) {
	b.SetTotalLength(totalLength)
	checksum := Checksum(b[IPv4TotalLenOffset:IPv4TotalLenOffset+2], partialChecksum)
	b.SetChecksum(^checksum)
}

// IsValid performs basic validation on the packet.
func (b IPv4) IsValid(pktSize int) bool {
	if len(b) < IPv4MinimumSize {
		return false
	}

	hlen := int(b.HeaderLength())
	tlen := int(b.TotalLength())
	if hlen < IPv4MinimumSize || hlen > tlen || tlen > pktSize {
		return false
	}

	if IPVersion(b) != IPv4Version {
		return false
	}

	return true
}

// IsV4MulticastAddress determines if the provided address is an IPv4 multicast
// address (range 224.0.0.0 to 239.255.255.255). The four most significant bits
// will be 1110 = 0xe0.
//
// 判断是否为 IPv4 多播地址。
func IsV4MulticastAddress(addr tcpip.Address) bool {
	// 检查是否为四个字节
	if len(addr) != IPv4AddressSize {
		return false
	}
	// 检查标记位
	return (addr[0] & 0xf0) == 0xe0
}
