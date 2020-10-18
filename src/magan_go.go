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
	"context"
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
	binaryName = "Magan"
	version    = "Magan/1.3.3b"
)

//Response exported
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

//Question exported
type Question struct {
	Name string `json:"name"`
	Type int    `json:"type"`
}

//Answer exported
type Answer struct {
	Name string `json:"name"`
	Type int    `json:"type"`
	TTL  int    `json:"TTL"`
	Data string `json:"data"`
}

type dnsRRStruct struct {
	TYPE  uint16
	CLASS uint16
	TTL   uint32
	RDLEN uint16
}

type waistDownStruct struct {
	qdcount uint16
	ancount uint16
	nscount uint16
	arcount uint16
}

var (
	a           int = 31
	tag         string
	nameservers = []string{"1.1.1.1", "8.8.8.8", "8.8.4.4", "9.9.9.9"}
	resolver    *net.Resolver
	dialer      *net.Dialer
	useAddress  = ""
	routeTo     = ""
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
				fmt.Println("version:", version)
				os.Exit(0)
			}

			if arg == "routeTo" || arg == "--routeTo" || arg == "r" || arg == "--r" || arg == "-r" || arg == "-routeTo" {
				next := i + 1
				if argc > next {
					useAddress = os.Args[i+1]
					routeTo = fmt.Sprintf("[%s]:443", useAddress)
				} else {
					fmt.Println("Invalid usage")
					showhelp()
					os.Exit(1)
				}
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

	tag = fmt.Sprintf("%s[%d]", binaryName, os.Getpid())
	Port := ":" + port
	print("%s Copyright (C) 2019 Evuraan <evuraan@gmail.com>", version)
	print("This program comes with ABSOLUTELY NO WARRANTY.")
	go do_lookup()
	setupUDPStuff(Port)

}

func showhelp() {
	fmt.Printf("Usage: %s <port>\n", os.Args[0])
	fmt.Println("  -h  --help         print this usage and exit")
	fmt.Println("  -p  --port         alternate port to listen")
	fmt.Println("  -r  --routeTo      ipaddr for dns.google.com")
	fmt.Println("  -v  --version      print version information and exit")
}

func checkerr(err error) {
	if err != nil {
		fmt.Println("Error:", err)
		log.Fatal(err)
	}
}

func setupUDPStuff(Port string) {
	// this is the best spot to start our tcp listener  as well.
	go setupTCPStuff(Port)
	Proto := "udp"
	// setup *net.UDPAddr first:
	udpaddr, err := net.ResolveUDPAddr(Proto, Port)
	checkerr(err)

	//setup *net.UDPConn next
	conn, err := net.ListenUDP(Proto, udpaddr)
	checkerr(err)

	print("Listening on Port %s", Port)
	print("Ready!")

	// lets loop over
	for {
		buffer := make([]byte, 8192) // udp, won't > 512
		n, addr, err := conn.ReadFromUDP(buffer)

		checkerr(err)
		//fmt.Printf("UDP Recvd %d bytes from %s\n", n, addr)
		print("UDP Recvd %d bytes from %s", n, addr)
		if n < 5 || n == 0 {
			print("Low watermark, ignoring this likely spurious UDP request")
		} else {
			go sendUDPReply(buffer, conn, addr, syscall.SOCK_DGRAM)
		}
	}

}

func setupTCPStuff(Port string) {
	Proto := "tcp"
	tcpListener, err := net.Listen(Proto, Port)
	checkerr(err)
	defer tcpListener.Close()
	for {
		conn, err := tcpListener.Accept()
		checkerr(err)
		go doTCPThingy(conn)
	}
}

func doTCPThingy(conn net.Conn) {
	buffer := make([]byte, 8192)
	n, err := conn.Read(buffer)
	//fmt.Printf("TCP Recvd %d bytes from %s\n", n, conn.RemoteAddr())
	print("TCP Recvd %d bytes from %s", n, conn.RemoteAddr())
	checkerr(err)
	if n < 5 || n == 0 {
		print("Low watermark, ignoring this likely spurious TCP request")
		return
	}

	buf := gatherReply(buffer[2:])
	if buf == nil {
		return
	}

	tcpLengthThingy := uint16(buf.Len())

	tcpReply := &bytes.Buffer{}
	binary.Write(tcpReply, binary.BigEndian, tcpLengthThingy)
	tcpReply.Write(buf.Bytes())
	SenT, err := conn.Write(tcpReply.Bytes())
	print("TCP - Replied with %d bytes", SenT)
	conn.Close()
}

func gatherReply(queryBuffer []uint8) *bytes.Buffer {

	var m dnsmessage.Message
	err := m.Unpack(queryBuffer)
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

	var waistDownStruct waistDownStruct
	waistDownStruct.qdcount = 1
	buf := &bytes.Buffer{}

	dialer = &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		DualStack: true,
	}

	if useAddress != "" {
		http.DefaultTransport.(*http.Transport).DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			if addr == "dns.google.com:443" {
				addr = routeTo
				print("Routing to %s\n", addr)
			}
			return dialer.DialContext(ctx, network, addr)
		}
	}

	client := http.Client{}

	req, err := http.NewRequest("GET", url, nil)
	checkerr(err)
	req.Header.Set("User-Agent", version)
	t1 := time.Now()
	resp, err := client.Do(req)
	checkerr(err)
	defer resp.Body.Close()
	if resp.StatusCode == 200 {
		contents, err := ioutil.ReadAll(resp.Body)
		checkerr(err)
		var response Response
		json.Unmarshal(contents, &response)

		var anCountInt int = len(response.Answer)
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

		tempReply, _ := m.Pack()

		waistDownStruct.ancount = uint16(anCountInt)
		binary.Write(buf, binary.BigEndian, tempReply[:4])
		binary.Write(buf, binary.BigEndian, waistDownStruct)
		binary.Write(buf, binary.BigEndian, tempReply[12:qlen+12])

		for i := 0; i < anCountInt; i++ {

			converted := convert(response.Answer[i].Name)
			buf.Write([]byte(converted))

			var dnsRRStruct dnsRRStruct
			dnsRRStruct.TYPE = uint16(response.Answer[i].Type)
			dnsRRStruct.CLASS = 1
			dnsRRStruct.TTL = uint32(response.Answer[i].TTL)

			switch response.Answer[i].Type {
			case 1:
				dnsRRStruct.RDLEN = 4
				binary.Write(buf, binary.BigEndian, dnsRRStruct)
				taba := net.ParseIP(response.Answer[i].Data)
				a := [4]byte{}
				copy(a[:], taba.To4())
				binary.Write(buf, binary.BigEndian, a)
			case 2, 5, 12:
				mehu := convert(response.Answer[i].Data)
				dnsRRStruct.RDLEN = uint16(len(mehu))
				binary.Write(buf, binary.BigEndian, dnsRRStruct)
				buf.Write([]byte(mehu))
			case 16, 99:
				allRaw := response.Answer[i].Data
				var mehu string
				thisLen := len(allRaw)
				if thisLen < 255 {
					var b strings.Builder
					b.Grow(thisLen + 5)
					fmt.Fprintf(&b, "%c%s", thisLen, allRaw)
					mehu = b.String()
				} else {
					//fmt.Println("Call in the big guns for", allRaw)
					mehu = tryThis(allRaw)
				}
				//fmt.Println("mehu", mehu)
				dnsRRStruct.RDLEN = uint16(len(mehu))
				binary.Write(buf, binary.BigEndian, dnsRRStruct)
				buf.Write([]byte(mehu))

			case 28:
				dnsRRStruct.RDLEN = 16
				binary.Write(buf, binary.BigEndian, dnsRRStruct)
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
				yeLong := uint16(unsafe.Sizeof(prio)) + uint16(len(mehu))
				dnsRRStruct.RDLEN = yeLong
				binary.Write(buf, binary.BigEndian, dnsRRStruct)
				binary.Write(buf, binary.BigEndian, prio)
				buf.Write([]byte(mehu))

			case 6:
				NS := strings.Split(response.Answer[i].Data, " ")
				mname := convert(NS[0])
				rname := convert(NS[1])
				serialAtoi, _ := strconv.Atoi(NS[2])
				serial := uint32(serialAtoi)
				refreshAtoi, _ := strconv.Atoi(NS[3])
				refresh := uint32(refreshAtoi)
				retryAtoi, _ := strconv.Atoi(NS[4])
				retry := uint32(retryAtoi)
				expireAtoi, _ := strconv.Atoi(NS[5])
				expire := uint32(expireAtoi)
				minAtoi, _ := strconv.Atoi(NS[6])
				min := uint32(minAtoi)
				yeLong := uint16(len(mname)) + uint16(len(rname)) + uint16(unsafe.Sizeof(serial)*5)
				dnsRRStruct.RDLEN = yeLong
				binary.Write(buf, binary.BigEndian, dnsRRStruct)

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

func sendUDPReply(queryBuffer []uint8, conn *net.UDPConn, addr *net.UDPAddr, Protocol int) {

	buf := gatherReply(queryBuffer)

	if buf == nil {
		return
	}

	if Protocol == syscall.SOCK_DGRAM {
		sizeEst := buf.Len()
		if sizeEst >= 512 {

			print("Too big, %d bytes, sending TC flag", sizeEst)

			var m dnsmessage.Message
			err := m.Unpack(queryBuffer)
			if err != nil {
				fmt.Println("Error, outta here", err)
				return
			}

			m.Response = true
			m.Truncated = true
			tcReply, _ := m.Pack()
			SenT, err := conn.WriteToUDP(tcReply, addr)
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
			tempS := temp.String()
			fmt.Fprintf(&b, "%c%s", j, tempS)
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

func tryThis(input string) string {

	watermark := 110 // Go throws a fit if this is larger than 127
	inputLen := len(input)
	var b strings.Builder
	b.Grow(inputLen + 5)
	loopCount := inputLen/watermark + 1

	start := 0
	end := 0
	for i := 0; i < loopCount; i++ {
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

func do_lookup() {

	// Scope: See if we can figure out an address to send https requests to..

	if useAddress != "" {
		print("We will send HTTPS queries to %s", useAddress)
		return
	}

	lookFor := "dns.Google.Com"

	// try against []nameservers 1st
	for _, nameserver := range nameservers {
		print("Initial lookup: Trying %s", nameserver)
		if nameserver != "" {
			resolver = &net.Resolver{
				PreferGo: true,
				Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
					d := net.Dialer{}
					return d.DialContext(ctx, "udp", net.JoinHostPort(nameserver, "53"))
				},
			}
		} else {
			resolver = net.DefaultResolver
		}

		c1 := make(chan string, 1)
		go func() {
			ips, err := resolver.LookupIPAddr(context.Background(), lookFor)
			if err != nil {
				fmt.Println("err", err)
			} else {
				// for now pick an ipv4 address
				for i := range ips {
					ipString := ips[i].String()
					if strings.Contains(ipString, ":") {
						continue
					} else {
						useAddress = ipString
						break
					}
				}
				c1 <- "Done!"
			}
		}()

		select {
		case <-c1:
			print("Yay! %s %s source: %s", lookFor, useAddress, nameserver)
		case <-time.After(2 * time.Second):
			print("%s", "Timed out!")
		}

		if useAddress == "" {
			print("Falling back to 8.8.8.8, this may or may not work for you!")
			useAddress = "8.8.8.8"
		}

		if useAddress != "" {
			print("We will send HTTPS queries to %s", useAddress)
			routeTo = fmt.Sprintf("[%s]:443", useAddress)
			return
		}
	}

	if useAddress == "" {
		// one last try, against whatever default resolver we have set on this system
		c2 := make(chan string, 1)
		go func() {
			print("Tryng system default name resolver")
			ips, err := net.LookupIP(lookFor)
			if err != nil {
				fmt.Println("Err", err)
			} else {
				useAddress = ips[0].String()
				c2 <- "Done!"
			}
		}()
		select {
		case <-c2:
			print("Yay! %s %s", lookFor, useAddress)
		case <-time.After(2 * time.Second):
			print("%s", "Timed out!")
		}

		if useAddress == "" {
			print("Unable to resolve %s. This may become fatal!", lookFor)
		} else {
			return
		}
	}

}
