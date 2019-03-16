package main

import (
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/websocket"
)

// wsMessage handles browser requests to /msg/
func wsMessage(w http.ResponseWriter, r *http.Request) {

	// Get session, continue only if authenticated
	sok, vok := checkLogin(r, cfgMap["session name"], "user")
	if !sok || !vok {
		http.Error(w, http.StatusText(http.StatusInternalServerError),
			http.StatusInternalServerError)
		return
	}

	cc := make(chan bool)
	// upgrade to websocket
	c, err := upgrader.Upgrade(w, r, nil)
	defer c.Close()
	if err != nil {
		log.Println("upgrade:", err)
		return
	}

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
			response := []byte(<-wsChan)
			// mesage type = 1
			err = c.WriteMessage(1, response)
			if err != nil {
				log.Println("ws write err:", err)
				break
			}
			time.Sleep(time.Second)
		}
	}
}

// wsChanSend build and send messages to connected browsers, the channel
// is shared between connections
func wsChanSend() {
	log.Println("wschan running...")
	i := 1
	for {
		// send stuff to clients
		// TODO: solve multiple clients connecting
		wsChan <- "test: " + strconv.Itoa(i)
		i++
	}
}

// func wsEcho(w http.ResponseWriter, r *http.Request) {
// 	c, err := upgrader.Upgrade(w, r, nil)
// 	if err != nil {
// 		log.Print("upgrade:", err)
// 		return
// 	}
// 	defer c.Close()
//
// 	for {
// 		mt, message, err := c.ReadMessage()
// 		if err != nil {
// 			log.Println("read:", err)
// 			break
// 		}
// 		log.Printf("recv: %s", message)
// 		var response []byte
// 		// extra := []byte{'e', 'x', 't', 'r', 'a', ' '}
// 		// extra := []byte("extra text ")
// 		ex := <-wsChan
// 		extra := []byte(ex)
// 		// fmt.Println("read chan", ex, extra)
// 		for _, e := range extra {
// 			response = append(response, e)
// 		}
// 		for _, e := range message {
// 			response = append(response, e)
// 		}
// 		err = c.WriteMessage(mt, response)
// 		if err != nil {
// 			log.Println("write:", err)
// 			break
// 		}
// 	}
// }
