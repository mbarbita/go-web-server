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

	// upgrade to websocket
	c, err := upgrader.Upgrade(w, r, nil)
	defer c.Close()
	if err != nil {
		log.Println("upgrade:", err)
		return
	}

	// send websocket message to browser
	for {
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
					" " +
					gSensor[v].messageFields[1] +
					" " +
					gSensor[v].messageFields[2] +
					" " +
					gSensor[v].messageFields[3] +
					";")...)

				// calculate timeout
				diff := time.Now().Sub(gSensor[v].lastSeen)
				if diff > time.Duration(time.Second*20) {
					wsMessage = []byte(gSensor[v].ID +
						" -2 0 " +
						fmt.Sprint(gSensor[v].lastSeen.Format("02-01-2006-15:04:05")) +
						";")
				}
			} else {
				wsMessage = append(wsMessage, (gSensor[v].ID +
					" -2 0 never;")...)
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
	} // for
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
			messageFields: make([]string, 4),
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
					intField, _ := strconv.Atoi(fields1[2])

					// build the final map entry, lock and update the map
					lock.Lock()
					gSensor[i].message = lineStr
					gSensor[i].messageFields[0] = fields1[0]
					gSensor[i].messageFields[1] = fields1[1]
					gSensor[i].messageFields[2] = fields1[2]
					gSensor[i].messageFields[3] = fmt.Sprintf("%08b", intField)
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
func simpleDial2(inmsg string, status int) {
	time.Sleep(time.Second * 3)
	rand.Seed(42)
	for {
		// connect to this socket
		conn, _ := net.Dial("tcp", "127.0.0.1:5000")
		// conn.Close()

		//build message
		msg := inmsg

		// add some random data
		if status == 0 || status == -2 {
			msg = inmsg + ";0;" + strconv.Itoa(rand.Intn(254)) + ";"
		}

		// add status errors
		if status == -1 {
			msg = inmsg + ";-1;" + strconv.Itoa(rand.Intn(254)) + ";"
		}
		// if status == -2 {
		// 	mess = inmsg + ";-2;"
		// }

		// send message to server
		n, err := fmt.Fprintf(conn, msg+"\n")
		if err != nil {
			log.Println("conn write err:", err)
		}
		log.Println("bytes sent to server:", n, "port:", conn.LocalAddr())
		// listen for reply
		message, _ := bufio.NewReader(conn).ReadString('\n')
		log.Print("Message from server: " + message)

		// sleep between sends
		if status == -2 {
			// mess = inmsg + ";-2;"
			conn.Close()
			return
		}
		conn.Close()
		time.Sleep(5 * time.Second)
	}
}
