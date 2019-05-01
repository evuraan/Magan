/*
 * ----------------------------------------------------------------------------
    magan : a DoH server
    Copyright (C) 2019  Evuraan, <evuraan@gmail.com>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
 * ----------------------------------------------------------------------------
*/
package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/net/dns/dnsmessage"
)

const (
	binary_name = "Magan"
	Version     = "Magan/1.3.0g"
)

type Response struct {
	Status   int        `json:"Status"`
	TC       bool       `json:"TC"`
	RD       bool       `json:"RD"`
	RA       bool       `json:"RA"`
	AD       bool       `json:"AD"`
	CD       bool       `json:"CD"`
	Question []Question `json:"Question"`
	Answer   []Answer   `json:"Answer"`
	Comment  string     `json:"Comment"`
}
type Question struct {
	Name string `json:"name"`
	Type int    `json:"type"`
}
type Answer struct {
	Name string `json:"name"`
	Type int    `json:"type"`
	TTL  int    `json:"TTL"`
	Data string `json:"data"`
}

type dns_rr struct {
	TYPE  uint16
	CLASS uint16
	TTL   uint32
	RDLEN uint16
}

type waist_down struct {
	qdcount uint16
	ancount uint16
	nscount uint16
	arcount uint16
}

var (
	a   int = 31
	tag string
)

func main() {

	argc := len(os.Args)
	port := "53"

	if argc == 1 {
		port = "53"
	} else if argc > 1 {
		for i, arg := range os.Args {
			if arg == "help" || arg == "--help" || arg == "h" || arg == "--h" || arg == "-h" || arg == "-help" || arg == "?" {
				showhelp()
				os.Exit(0)
			}

			if arg == "version" || arg == "--version" || arg == "v" || arg == "--v" || arg == "-v" || arg == "-version" {
				fmt.Println("Version:", Version)
				os.Exit(0)
			}

			if arg == "port" || arg == "--port" || arg == "p" || arg == "--p" || arg == "-p" || arg == "-port" {
				next := i + 1
				if argc > next {
					port = os.Args[i+1]
					_, err := strconv.Atoi(port)
					checkerr(err)
				} else {
					fmt.Println("Invalid usage")
					showhelp()
					os.Exit(1)
				}
			}

		}
	}

	tag = fmt.Sprintf("%s[%d]", binary_name, os.Getpid())
	Port := ":" + port
	print("%s Copyright (C) 2019 Evuraan <evuraan@gmail.com>", Version)
	print("This program comes with ABSOLUTELY NO WARRANTY.")
	setup_udp_stuff(Port)

}

func showhelp() {
	fmt.Printf("Usage: %s <port>\n", os.Args[0])
	fmt.Println("  -h  --help         print this usage and exit")
	fmt.Println("  -p  --port         alternate port to listen")
	fmt.Println("  -v  --version      print version information and exit")
}

func checkerr(err error) {
	if err != nil {
		fmt.Println("Error:", err)
		log.Fatal(err)
	}
}

func setup_udp_stuff(Port string) {
	// this is the best spot to start our tcp listener  as well.
	go setup_tcp_stuff(Port)
	Proto := "udp"
	// setup *net.UDPAddr first:
	udpaddr, err := net.ResolveUDPAddr(Proto, Port)
	checkerr(err)

	//setup *net.UDPConn next
	conn, err := net.ListenUDP(Proto, udpaddr)
	checkerr(err)

	print("Port %s", Port)
	print("Ready!")

	// lets loop over
	for {
		buffer := make([]byte, 8192) // udp, won't > 512
		n, addr, err := conn.ReadFromUDP(buffer)

		checkerr(err)
		//fmt.Printf("UDP Recvd %d bytes from %s\n", n, addr)
		print("UDP Recvd %d bytes from %s", n, addr)
		go send_udp_reply(buffer, conn, addr, syscall.SOCK_DGRAM)
	}

}

func setup_tcp_stuff(Port string) {
	Proto := "tcp"
	tcp_Listener, err := net.Listen(Proto, Port)
	checkerr(err)
	defer tcp_Listener.Close()
	for {
		conn, err := tcp_Listener.Accept()
		checkerr(err)
		go do_tcp_thingy(conn)
	}
}

func do_tcp_thingy(conn net.Conn) {
	buffer := make([]byte, 8192)
	n, err := conn.Read(buffer)
	//fmt.Printf("TCP Recvd %d bytes from %s\n", n, conn.RemoteAddr())
	print("TCP Recvd %d bytes from %s", n, conn.RemoteAddr())
	checkerr(err)
	buf := gather_reply(buffer[2:])
	if buf == nil {
		return
	}

	tcp_length_thingy := uint16(buf.Len())

	tcp_reply := &bytes.Buffer{}
	binary.Write(tcp_reply, binary.BigEndian, tcp_length_thingy)
	tcp_reply.Write(buf.Bytes())
	SenT, err := conn.Write(tcp_reply.Bytes())
	print("TCP - Replied with %d bytes", SenT)
	conn.Close()
}

func gather_reply(query_buffer []uint8) *bytes.Buffer {

	var m dnsmessage.Message
	err := m.Unpack(query_buffer)
	if err != nil {
		fmt.Println("Error, outta here", err)
		return nil
	}
	question := m.Questions[0]
	they_asked_for := question.Name.String()
	qlen := len(they_asked_for) + 5
	_type := strings.Replace(question.Type.String(), "Type", "", -1)
	// https://dns.google.com/resolve?name=www.nbc.com.&type=A
	//url := "https://dns.google.com/resolve?name=" + they_asked_for + "&type=" + _type
	url := fmt.Sprintf("https://dns.google.com/resolve?name=%s&type=%s", they_asked_for, _type)

	m.RecursionAvailable = true
	m.Response = true

	var waist_down waist_down
	waist_down.qdcount = 1
	buf := &bytes.Buffer{}
	timeout := time.Duration(15 * time.Second)
	client := http.Client{
		Timeout: timeout,
	}

	req, err := http.NewRequest("GET", url, nil)
	checkerr(err)
	req.Header.Set("User-Agent", Version)
	t1 := time.Now()
	resp, err := client.Do(req)
	checkerr(err)
	defer resp.Body.Close()
	contents := make([]byte, 8192)
	if resp.StatusCode == 200 {
		contents, err = ioutil.ReadAll(resp.Body)
		checkerr(err)
		var response Response
		json.Unmarshal(contents, &response)

		var ancount_int int = len(response.Answer)
		Rcode := response.Status

		if Rcode == 3 {
			m.RCode = 3
		} else if Rcode == 2 {
			m.RCode = 2
		} else if Rcode == 4 {
			m.RCode = 4
		} else if Rcode == 1 {
			m.RCode = 1
		} else if Rcode == 5 {
			m.RCode = 5
		}

		temp_reply, _ := m.Pack()

		waist_down.ancount = uint16(ancount_int)
		binary.Write(buf, binary.BigEndian, temp_reply[:4])
		binary.Write(buf, binary.BigEndian, waist_down)
		binary.Write(buf, binary.BigEndian, temp_reply[12:qlen+12])

		for i := 0; i < ancount_int; i++ {

			converted := convert(response.Answer[i].Name)
			buf.Write([]byte(converted))

			var dns_rr dns_rr
			dns_rr.TYPE = uint16(response.Answer[i].Type)
			dns_rr.CLASS = 1
			dns_rr.TTL = uint32(response.Answer[i].TTL)

			switch response.Answer[i].Type {
			case 1:
				dns_rr.RDLEN = 4
				binary.Write(buf, binary.BigEndian, dns_rr)
				taba := net.ParseIP(response.Answer[i].Data)
				a := [4]byte{}
				copy(a[:], taba.To4())
				binary.Write(buf, binary.BigEndian, a)
			case 2, 5, 12:
				mehu := convert(response.Answer[i].Data)
				dns_rr.RDLEN = uint16(len(mehu))
				binary.Write(buf, binary.BigEndian, dns_rr)
				buf.Write([]byte(mehu))
			case 16, 99:
				all_raw := response.Answer[i].Data
				var mehu string
				this_len := len(all_raw)
				if this_len < 255 {
					var b strings.Builder
					b.Grow(this_len + 5)
					fmt.Fprintf(&b, "%c%s", this_len, all_raw)
					mehu = b.String()
				} else {
					//fmt.Println("Call in the big guns for", all_raw)
					mehu = try_this(all_raw)
				}
				//fmt.Println("mehu", mehu)
				dns_rr.RDLEN = uint16(len(mehu))
				binary.Write(buf, binary.BigEndian, dns_rr)
				buf.Write([]byte(mehu))

			case 28:
				dns_rr.RDLEN = 16
				binary.Write(buf, binary.BigEndian, dns_rr)
				taba := net.ParseIP(response.Answer[i].Data)
				a := [16]byte{}
				copy(a[:], taba.To16())
				binary.Write(buf, binary.BigEndian, a)

			case 15:
				MX := strings.Split(response.Answer[i].Data, " ")
				mehu := convert(MX[1])
				var prio uint16
				dies, _ := strconv.Atoi(MX[0])
				prio = uint16(dies)
				ye_long := uint16(unsafe.Sizeof(prio)) + uint16(len(mehu))
				dns_rr.RDLEN = ye_long
				binary.Write(buf, binary.BigEndian, dns_rr)
				binary.Write(buf, binary.BigEndian, prio)
				buf.Write([]byte(mehu))

			case 6:
				NS := strings.Split(response.Answer[i].Data, " ")
				mname := convert(NS[0])
				rname := convert(NS[1])
				serial_atoi, _ := strconv.Atoi(NS[2])
				serial := uint32(serial_atoi)
				refresh_atoi, _ := strconv.Atoi(NS[3])
				refresh := uint32(refresh_atoi)
				retry_atoi, _ := strconv.Atoi(NS[4])
				retry := uint32(retry_atoi)
				expire_atoi, _ := strconv.Atoi(NS[5])
				expire := uint32(expire_atoi)
				min_atoi, _ := strconv.Atoi(NS[6])
				min := uint32(min_atoi)
				ye_long := uint16(len(mname)) + uint16(len(rname)) + uint16(unsafe.Sizeof(serial)*5)
				dns_rr.RDLEN = ye_long
				binary.Write(buf, binary.BigEndian, dns_rr)

				buf.Write([]byte(mname))
				buf.Write([]byte(rname))
				binary.Write(buf, binary.BigEndian, serial)
				binary.Write(buf, binary.BigEndian, refresh)
				binary.Write(buf, binary.BigEndian, retry)
				binary.Write(buf, binary.BigEndian, expire)
				binary.Write(buf, binary.BigEndian, min)

			}
		}

	} else {
		fmt.Println("404!")
	}
	t2 := time.Now()
	diff := t2.Sub(t1)
	meh := "2006-01-02 15:04:05.000"
	t2.Format(meh)
	//fmt.Println(t2.Format(meh),url, diff)
	//fmt.Printf("Url: %s, took: %s\n", url, diff)
	print("Url: %s, took: %s", url, diff)

	return buf
}

func send_udp_reply(query_buffer []uint8, conn *net.UDPConn, addr *net.UDPAddr, Protocol int) {

	buf := gather_reply(query_buffer)

	if buf == nil {
		return
	}

	if Protocol == syscall.SOCK_DGRAM {
		size_est := buf.Len()
		if size_est >= 512 {

			print("Too big, %d bytes, sending TC flag", size_est)

			var m dnsmessage.Message
			err := m.Unpack(query_buffer)
			if err != nil {
				fmt.Println("Error, outta here", err)
				return
			}

			m.Response = true
			m.Truncated = true
			tc_reply, _ := m.Pack()
			SenT, err := conn.WriteToUDP(tc_reply, addr)
			checkerr(err)
			print("UDP - Replied with %d bytes", SenT)
			return
		}

		SenT, err := conn.WriteToUDP(buf.Bytes(), addr)
		checkerr(err)
		print("UDP - Replied with %d bytes", SenT)
	}

}

func convert(_input string) string {

	input := fmt.Sprintf("%s.", _input)
	var b strings.Builder
	var temp strings.Builder
	b.Grow(len(input) + 3)
	temp.Grow(len(input) + 3)
	j := 0

	for _, v := range input {
		if v == '.' {
			temp_s := temp.String()
			fmt.Fprintf(&b, "%c%s", j, temp_s)
			j = 0
			temp.Reset()
		} else {
			fmt.Fprintf(&temp, "%c", v)
			j++
		}
	}

	out := b.String()
	return out
}

func print(strings string, args ...interface{}) {
	a := time.Now()
	layout := "Mon Jan 02 15:04:05 2006"
	msg := fmt.Sprintf(strings, args...)
	fmt.Println(a.Format(layout), tag, msg)
}

func try_this(input string) string {

	watermark := 110 // Go throws a fit if this is larger than 127
	input_len := len(input)
	var b strings.Builder
	b.Grow(input_len + 5)
	loop_count := input_len/watermark + 1

	start := 0
	end := 0
	for i := 0; i < loop_count; i++ {
		chunk := input[start:]
		if len(chunk) > watermark {
			// too large
			end = start + watermark
			chunk = input[start:end]
		}

		fmt.Fprintf(&b, "%c", len(chunk))

		for _, v := range chunk {
			fmt.Fprintf(&b, "%c", v)
		}

		start = end

	}

	out := b.String()
	//fmt.Println("out len", len(out) )
	return out

}
