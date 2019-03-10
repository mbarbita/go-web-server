package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

var lock sync.Mutex
var gSensorVal map[int]string

func readSensors() {
	// Listen on TCP port 2000 on all available unicast and
	// anycast IP addresses of the local system.
	l, err := net.Listen("tcp", ":5000")
	if err != nil {
		log.Fatal("listen :5000 err:", err)
	}
	defer l.Close()
	log.Println("listening on :5000 for sensors...")
	for {
		// Wait for a connection.
		conn, err := l.Accept()
		if err != nil {
			log.Println("conn accept err:", err)
			break
		}
		// Handle the connection in a new goroutine.
		// The loop then returns to accepting, so that
		// multiple connections may be served concurrently.
		go func(c net.Conn) {
			// Echo all incoming data.
			r := bufio.NewReader(c)
			// for {
			line, err := r.ReadBytes(byte('\n'))
			switch err {
			case nil:
				break
			case io.EOF:
			default:
				fmt.Println("readbytes err:", err)
			}
			lineStr := string(line)
			fields1 := strings.Split(strings.TrimSpace(lineStr), ";")
			log.Println("reading from sensor:", lineStr)
			if fields1[0] == "A01" {
				lock.Lock()
				gSensorVal[1] = lineStr
				lock.Unlock()
			}

			if fields1[0] == "A02" {
				lock.Lock()
				gSensorVal[2] = lineStr
				lock.Unlock()
			}

			// 	conn.Write(line)
			// }

			fmt.Println("local:", c.LocalAddr(), "remote:", c.RemoteAddr())
			// io.Copy(c, c)
			c.Write([]byte("its aliveee!\n"))
			// Shut down the connection.
			c.Close()
		}(conn)
	}
}

func simpleDial() {

	// connect to this socket
	conn, _ := net.Dial("tcp", "127.0.0.1:5000")
	for {
		// read in input from stdin
		reader := bufio.NewReader(os.Stdin)
		fmt.Print("Text to send: ")
		text, _ := reader.ReadString('\n')
		// send to socket
		fmt.Fprintf(conn, text+"\n")
		// listen for reply
		message, _ := bufio.NewReader(conn).ReadString('\n')
		fmt.Print("Message from server: " + message)
	}
}

func simpleDial2(msg string) {

	for {
		// connect to this socket
		conn, _ := net.Dial("tcp", "127.0.0.1:5000")
		// send to socket
		// conn.Write(b)
		n, err := fmt.Fprintf(conn, msg+"\n")
		if err != nil {
			log.Println("conn write err:", err)
		}
		log.Println("bytes sent to server:", n)
		// listen for reply
		message, _ := bufio.NewReader(conn).ReadString('\n')
		fmt.Print("Message from server: " + message)
		time.Sleep(5 * time.Second)
	}
}
