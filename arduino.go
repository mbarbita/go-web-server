package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// Arduino global map for sensors data and global lock
type Arduino struct {
	ID            string
	message       string
	messageFields []string
	lastSeen      time.Time
	seen          bool
}

var lock sync.Mutex
var gSensor map[int]*Arduino

// wsArduino handles browser requests to /msgard/
func wsArduino(w http.ResponseWriter, r *http.Request) {

	// Get session
	// sok, vok := checkLogin(r, cfgMap["session name"], "user")
	// if !sok || !vok {
	// 	http.Error(w, http.StatusText(http.StatusInternalServerError),
	// 		http.StatusInternalServerError)
	// 	return
	// }

	cc := make(chan bool)

	// upgrade to websocket
	c, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("upgrade:", err)
		return
	}
	defer c.Close()

	// handle websocket incoming browser messages
	go func(c *websocket.Conn) {
		for {
			_, message, err := c.ReadMessage()
			if err != nil {
				log.Println("read:", err)
				cc <- true
				return
			}
			log.Printf("recv: %s", message)
		}
	}(c)

	// send websocket message to browser
	for {
		select {
		case <-cc:
			return
		default:
			var wsMessage []byte
			var sortedKeys []int

			// sort map keys and store into oarray
			for k := range gSensor {
				sortedKeys = append(sortedKeys, k)
			}
			sort.Ints(sortedKeys)

			// build message to browser
			// response = append(response, (" Sensor: " + gSensorVal[1] +
			// 	" | " + gSensorVal[2])...)
			for _, v := range sortedKeys {
				if gSensor[v].seen {
					wsMessage = append(wsMessage, (gSensor[v].ID +
						" " + gSensor[v].messageFields[1] + " " +
						gSensor[v].messageFields[2] + ";")...)

					now := time.Now()
					diff := now.Sub(gSensor[v].lastSeen)
					if diff > time.Duration(time.Second*10) {
						wsMessage = append(wsMessage, (gSensor[v].ID +
							" -2 " +
							fmt.Sprint(gSensor[v].lastSeen.Format("02-01-2006-15:04:05")) +
							";")...)
					}
				} else {
					wsMessage = append(wsMessage, (gSensor[v].ID +
						" -2 never ;")...)
					// wsMessage = append(wsMessage, (gSensor[v].ID +
					// 	" -2 " +
					// 	fmt.Sprint(gSensor[v].lastSeen.Format("02-01-2006-15:04:05")) +
					// 	";")...)
				}
			}

			// send message to browser
			// mesage type = 1
			err = c.WriteMessage(1, wsMessage)
			if err != nil {
				log.Println("ws write err:", err)
				break
			}
			time.Sleep(time.Second)
		}
	}
}

// readSensors listen for arduinos and store received data into global data map
func readSensors() {
	smax, err := strconv.Atoi(cfgMap["max sensors"])
	if err != nil {
		log.Println(err)
	}

	// populate global map gsensor map[int]Arduino
	for i := 1; i <= smax; i++ {
		lock.Lock()
		gSensor[i] = &Arduino{
			ID:            "A" + strconv.Itoa(i),
			message:       "",
			messageFields: make([]string, 3),
			lastSeen:      time.Time{},
			// lastSeen: time.Now(),
			seen: false,
		}
		lock.Unlock()
	}
	// for k, v := range gSensor {
	// 	fmt.Printf("gSensor: k: %+v v: %+v\n", k, v)
	// }

	// Listen on TCP port 5000 for arduinos
	l, err := net.Listen("tcp", ":5000")
	if err != nil {
		log.Fatal("listen :5000 err:", err)
	}
	defer l.Close()
	log.Println("listening on :5000 for sensors...")

	// handles connections from arduinos
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

			// Shut down the connection.
			defer c.Close()

			// log incomming adruinos connections
			log.Println("arduino new connection:", "remote:", c.RemoteAddr())

			// read \n terminated line from connection
			r := bufio.NewReader(c)
			line, err := r.ReadBytes(byte('\n'))
			switch err {
			case nil:
				break
			case io.EOF:
			default:
				fmt.Println("readbytes err:", err)
			}

			// convert to string and split on ; separator into an string slice
			lineStr := string(line)
			fields1 := strings.Split(strings.TrimSpace(lineStr), ";")
			log.Println("reading from sensor:", lineStr)

			// loop for configured max sensors
			// check for a recognisable field in the message
			// use map key from 1 up not 0 up
			for i := 1; i <= smax; i++ {
				if fields1[0] == "A"+strconv.Itoa(i) {
					intField, _ := strconv.Atoi(fields1[1])

					// build the final map entry, lock and update the map
					lock.Lock()
					gSensor[i].message = lineStr
					gSensor[i].messageFields[0] = fields1[0]
					gSensor[i].messageFields[1] = fields1[1]
					gSensor[i].messageFields[2] = fmt.Sprintf("%08b", intField)
					gSensor[i].lastSeen = time.Now()
					gSensor[i].seen = true
					lock.Unlock()
				}
			}
			for k, v := range gSensor {
				fmt.Printf("gSensor populated: k: %+v v: %+v\n", k, v)
			}

			// write some reply to arduinos
			c.Write([]byte("its aliveee!\n"))
		}(conn)
	}
}

// simpleDial2 simulate arduino
func simpleDial2(msg string, cerr int) {
	time.Sleep(time.Second * 3)
	rand.Seed(42)
	for {
		// connect to this socket
		conn, _ := net.Dial("tcp", "127.0.0.1:5000")
		// conn.Close()

		// add some random data
		mess := msg + ";" + strconv.Itoa(rand.Intn(254)) + ";"

		// add status errors
		if cerr == -1 {
			mess = msg + ";-1;"
		}
		// if err == -2 {
		// 	mess = msg + ";-2;"
		// }

		// send message to server
		n, err := fmt.Fprintf(conn, mess+"\n")
		if err != nil {
			log.Println("conn write err:", err)
		}
		log.Println("bytes sent to server:", n, "port:", conn.LocalAddr())
		// listen for reply
		message, _ := bufio.NewReader(conn).ReadString('\n')
		log.Print("Message from server: " + message)

		// sleep between sends
		if cerr == -2 {
			// mess = msg + ";-2;"
			conn.Close()
			return
		}
		conn.Close()
		time.Sleep(5 * time.Second)
	}
}
