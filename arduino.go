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
	id      string
	name    string
	message string
	// messageFields []string
	status   string
	value    string
	binval   string
	lastSeen time.Time
	seen     bool
}

var lock sync.Mutex
var gSensor map[int]*Arduino

// var sepAtoS = ";"
// var sepStoB = "|"

// var signature = "A"
var ardSig = cfgMap["arduino signature"]

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
	if err != nil {
		log.Println("upgrade:", err)
		return
	}
	defer c.Close()

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
			ls := fmt.Sprint(gSensor[v].lastSeen.Format("02-01-2006 15:04:05"))
			if gSensor[v].seen {
				wsMessage = append(wsMessage,
					(gSensor[v].id +
						";" +
						gSensor[v].name +
						";" +
						gSensor[v].status +
						";" +
						gSensor[v].value +
						";" +
						ls +
						"|")...)

				// calculate timeout and build response
				diff := time.Now().Sub(gSensor[v].lastSeen)
				if diff > time.Duration(time.Second*20) {
					wsMessage = []byte(
						gSensor[v].id +
							";" +
							gSensor[v].name +
							";-2;0;" +
							ls +
							"|")
				}
			} else { // not seen
				wsMessage = append(wsMessage,
					(gSensor[v].id +
						";" +
						"no name" +
						";-2;0;never|")...)
				// wsMessage = append(wsMessage, (gSensor[v].ID +
				// 	" -2 " +
				// 	fmt.Sprint(gSensor[v].lastSeen.Format("02-01-2006-15:04:05")) +
				// 	";")...)
			}
		} // for

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
			id:      ardSig + strconv.Itoa(i),
			name:    "",
			message: "",
			// messageFields: make([]string, 4),
			status:   "-2",
			value:    "0",
			binval:   "0",
			lastSeen: time.Time{},
			// lastSeen: time.Now(),
			seen: false,
		}
		lock.Unlock()
	}
	// for k, v := range gSensor {
	// 	fmt.Printf("gSensor: k: %+v v: %+v\n", k, v)
	// }

	// Listen on TCP port 5000 for arduinos
	// TODO: read port from cfg.ini
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
			fields := strings.Split(strings.TrimSpace(lineStr), ";")
			log.Print("reading from sensor:", lineStr)
			log.Println("reading fromsensor total fields:", len(fields))

			// loop for configured max sensors
			// check for a recognisable field in the message
			// use map key from 1 up
			for i := 1; i <= smax; i++ {

				if len(fields) == 5 {
					// TODO: read signature from cfg.ini
					if fields[0] == ardSig+strconv.Itoa(i) {

						// build the final map entry, lock and update the map
						lock.Lock()
						gSensor[i].message = lineStr
						gSensor[i].name = fields[1]
						gSensor[i].status = fields[2]
						gSensor[i].value = fields[3]
						intField, _ := strconv.Atoi(fields[2])
						gSensor[i].binval = fmt.Sprintf("%08b", intField)
						gSensor[i].lastSeen = time.Now()
						gSensor[i].seen = true
						lock.Unlock()
					}
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

// simpleDial simulate arduino
func simpleDial(id string, simstatus int) {
	time.Sleep(time.Second * 3)
	rand.Seed(42)

	// var id string = inmsg
	var name string
	var status string
	var msg string

	for {
		var value string = strconv.Itoa(rand.Intn(254))
		// connect to this socket
		conn, _ := net.Dial("tcp", "127.0.0.1:5000")
		// conn.Close()

		//build message
		// add some random data
		if simstatus == 0 || simstatus == -2 {
			status = "0"
			name = id + "-name"
			msg = id + ";" + name + ";" + status + ";" + value + ";"
		}

		// add status errors
		if simstatus == -1 {
			status = "-1"
			name = id + "-name"
			msg = id + ";" + name + ";" + status + ";" + value + ";"
		}

		// send message to server
		n, err := fmt.Fprintf(conn, msg+"\n")
		if err != nil {
			log.Println("conn write err:", err)
		}
		log.Println("bytes sent to server:", n, "port:", conn.LocalAddr())
		// listen for reply
		message, _ := bufio.NewReader(conn).ReadString('\n')
		log.Print("Message from server: " + message)

		if simstatus == -2 {
			// mess = inmsg + ";-2;"
			conn.Close()
			return
		}

		conn.Close()
		// sleep between sends
		time.Sleep(5 * time.Second)
	}
}
