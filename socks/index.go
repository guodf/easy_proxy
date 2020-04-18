//							socks v4
//  http://ftp.icm.edu.pl/packages/socks/socks4/SOCKS4.protocol
//	握手数据
//			+----+----+----+----+----+----+----+----+----+----+....+----+
//			| VN | CD | DSTPORT |      DSTIP        | USERID       |NULL|
//			+----+----+----+----+----+----+----+----+----+----+....+----+
// 长度		   1    1      2              4            可变           1
// VN: 4
// CD:
//		1:CONNECT
//		2:BIND
// DSTPORT: 端口
// DSTIP:	ipv4
// USERID:	用户信息
// NULL:	结束位为0

//  握手响应响应
//			+----+----+----+----+----+----+----+----+
//			| VN | CD | DSTPORT |      DSTIP        |
//			+----+----+----+----+----+----+----+----+
// 长度        1    1      2              4
// VN: 固定不变值0
// CD:
//		0x5A为允许；
//		0x5B为拒绝或失败；
//		0x5C为请求被拒绝，因为SOCKS服务器无法连接到客户端;
// 		0x5D为请求被拒绝，因为USERID不匹配；
// DSTPORT: 端口
// DSTIP:	ipv4

//								socks v5
//  https://tools.ietf.org/html/rfc1928
// socket握手分两个阶段: 1. 客户端列举自己的密码模式供服务端选择，2. 客户端发起握手连接
//	1. 客户端列举自己的密码模式供服务端选择
//			+----+----------+----------+
//			|VER | NMETHODS | METHODS  |
//			+----+----------+----------+
//			| 1  |    1     | 1 to 255 |
//			+----+----------+----------+
// VER: 5
// NMETHODS: METHODS字节数
// METHODS: 密码模式
//		  0x00 NO AUTHENTICATION REQUIRED
//		  0x01 GSSAPI
//		  0x02 USERNAME/PASSWORD
//		  0x03 to 0x7F' IANA ASSIGNED
//		  0x80 to 0xFE' RESERVED FOR PRIVATE METHODS
//		  0xFF NO ACCEPTABLE METHODS
//	1. 服务端选择一个支持的加密模式响应客户端
//			 +----+--------+
//			|VER | METHOD |
//			+----+--------+
//			| 1  |   1    |
//			+----+--------+
// VER: 0x05
// METHOD: 选择一种密码模式
//   2. 客户端发起握手连接
//			+----+-----+-------+------+----------+----------+
//			|VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
//			+----+-----+-------+------+----------+----------+
//			| 1  |  1  | X'00' |  1   | Variable |    2     |
//			+----+-----+-------+------+----------+----------+
// VER: 0x05
// CMD:
//		CONNECT 0x01
//		BIND 	0x02
//		UDP 	0x03
// RSV: 0x00 保留
// ATYP: 用来指定DST.ADDR的类型及长度
//		IPV4:		  	0x01  4个字节
//		DOMAINNAME:		0x03  第一个字节指定DOMAINNAME的长度
//		IPV6 address: 	0x04  16个字节
// DST.ADDR:	可变长度
// DST.PORT:	端口
//	  2. 恢复客户端发起的握手连接
//			+----+-----+-------+------+----------+----------+
//			|VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
//			+----+-----+-------+------+----------+----------+
//			| 1  |  1  | X'00' |  1   | Variable |    2     |
//			+----+-----+-------+------+----------+----------+
// VER: 0x05
// REP
//		0x00' succeeded
//		0x01' socket服务器故障
//		0x02' 不允许连接
//		0x03' 网络不可达
//		0x04' 主机无法访问
//		0x05' 连接拒绝
//		0x06' TTL过期
//		0x07' 命令不支持
//		0x08' 地址类型不支持
//		0x09' 之后的都未使用
// RSV   保留值 必须为0x00
// ATYP: 用来指定DST.ADDR的类型及长度
//		IPV4:		  	0x01  4个字节
//		DOMAINNAME:		0x03  第一个字节指定DOMAINNAME的长度
//		IPV6 address: 	0x04  16个字节

// BND.ADDR  服务器绑定的地址
// BND.PORT  服务器绑定的端口

// UDP请求
//			+----+------+------+----------+----------+----------+
//			|RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
//			+----+------+------+----------+----------+----------+
//			| 2  |  1   |  1   | Variable |    2     | Variable |
//			+----+------+------+----------+----------+----------+
// RSV 保留值 Ox0000
// FRAG udp分段序号
// ATYP
//		IPV4:		  	0x01  4个字节
//		DOMAINNAME:		0x03  第一个字节指定DOMAINNAME的长度
//		IPV6 address: 	0x04  16个字节
// DST.ADDR  目标地址
// DST.PORT  目标端口
// DATA		 用户数据

package socks

import (
	"bufio"
	"errors"
	"io"
)

const (
	VN4 = 0x04
	VN5 = 0x05
)

// CMD 命令
const (
	CONNECT = 0x01
	BIND    = 0x02
)

type SocksV4 struct {
	VER      byte
	CMD      byte
	Port     [2]byte
	IP       [4]byte
	UserData []byte
	End      byte
}

var NoSockaV4 = errors.New("not socks v4")

func NewSocksV4(bfr *bufio.Reader) (*SocksV4, error) {

	socksV4 := &SocksV4{
		VER:      4,
		CMD:      0,
		Port:     [2]byte{},
		IP:       [4]byte{},
		UserData: nil,
		End:      0,
	}
	cmd, e := bfr.ReadByte()
	socksV4.CMD = cmd
	if e != nil {
		return nil, e
	}
	b := make([]byte, 2)
	length, e := bfr.Read(b)
	if e != nil || length != 2 {
		return nil, e
	}
	for i, bi := range b {
		socksV4.Port[i] = bi
	}
	b = make([]byte, 4)
	length, e = bfr.Read(b)
	if e != nil || length != 4 {
		return nil, e
	}
	for i, bi := range b {
		socksV4.IP[i] = bi
	}
	bs, e := bfr.ReadBytes(0)
	if e == io.EOF {
		socksV4.End = 0
		return socksV4, nil
	}
	if e != nil {
		return nil, e
	}
	socksV4.UserData = bs
	socksV4.End = 0
	return socksV4, nil
}

func (socksV4 *SocksV4) Accept() []byte {

	var resp []byte
	resp = append(resp, 0x00)
	resp = append(resp, 0x5A)
	for _, b := range socksV4.Port {
		resp = append(resp, b)
	}
	for _, b := range socksV4.IP {
		resp = append(resp, b)
	}
	return resp
}

func (socksV4 *SocksV4) Failed() []byte {
	var resp []byte
	resp = append(resp, 0x00)
	resp = append(resp, 0x5B)
	for _, b := range socksV4.Port {
		resp = append(resp, b)
	}
	for _, b := range socksV4.IP {
		resp = append(resp, b)
	}
	return resp
}