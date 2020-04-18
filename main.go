package main

import (
	"bufio"
	"bytes"
	"easy_proxy/socks"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"strings"
	"sync/atomic"
	"time"
)

var count int64

func main() {
	l, e := net.Listen("tcp", ":8088")
	if e != nil {
		log.Println("failed!")
		log.Panic(e)
	}
	defer l.Close()

	for {
		conn, e := l.Accept()
		if e != nil {
			log.Println("发现新连接，连接失败!")
			log.Println(e)
			continue
		}
		atomic.AddInt64(&count, 1)
		log.Println("当前连接数:", count)
		go conner(conn)
	}
	//fresh
}

func conner(conn net.Conn) {
	defer func() {
		conn.Close()
		atomic.AddInt64(&count, -1)
		log.Println("当前连接数:", count)
		if e := recover(); e != nil {
			log.Println("连接异常退出")
		}
	}()
	bfr := bufio.NewReader(conn)
	var addr string
	firstByte, _ := bfr.ReadByte()
	if firstByte == socks.VN4 {
		socksV4, e := socks.NewSocksV4(bfr)
		if e == nil {
			ip := net.IP(socksV4.IP[0:4])
			port := binary.BigEndian.Uint16(socksV4.Port[0:2])
			addr = fmt.Sprintf("%s:%d", ip, port)
			conn.Write(socksV4.Accept())
		} else {
			conn.Write(socksV4.Failed())
			return
		}
	} else {
		endlineBytes, e := bfr.ReadBytes('\n')
		if len(endlineBytes) == 0 {
			return
		}
		if e != nil {
			log.Println("reader first line failed")
			log.Println(e)
			return
		}
		firstLine := []byte{firstByte}
		firstLine = append(firstLine, endlineBytes...)
		bs := bytes.TrimSuffix(firstLine, []byte{'\r', '\n'})
		firstLineArr := bytes.Split(bs, []byte{' '})

		u := string(firstLineArr[1])
		var uri *url.URL
		if strings.Index(u, "http://") == 0 || strings.Index(u, "https://") == 0 {
			uri, _ = url.Parse(u)
		} else {
			uri, _ = url.Parse("http://" + u)
		}
		var port string
		if uri.Port() == "" {
			port = ":80"
		}
		addr = uri.Host + port
		if string(firstLineArr[0]) == "CONNECT" {
			conn.Write(firstLineArr[2])
			fmt.Fprint(conn, " 200 Connection established\r\n\r\n")
		} else {
			conn.Write(firstLine)
		}
	}
	tagConn, e := net.Dial("tcp", addr)
	tagConn.SetDeadline(time.Now().Add(time.Second * 60))
	if e != nil {
		log.Println("create tarConn failed")
		log.Println(e)
		return
	}
	//进行转发
	go io.Copy(tagConn, conn)
	io.Copy(conn, tagConn)
}
