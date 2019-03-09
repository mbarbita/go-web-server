package main

import (
	"bufio"
	"crypto/md5"
	"crypto/sha256"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/gorilla/context"
	"github.com/gorilla/sessions"
	"github.com/gorilla/websocket"

	cfgutils "github.com/mbarbita/golib-cfgutils"
)

func home(w http.ResponseWriter, r *http.Request) {

	// Define a struct for sending data to templates
	type TData struct {
		// NavAll []string
		Host   string
		WSHost string
		Visits int
		User   string
	}

	// init struct
	tData := new(TData)
	// tData.NavAll = navAll
	tData.Host = r.Host
	tData.WSHost = "ws://" + r.Host + "/msg/"

	// Get session
	// session, err := store.Get(r, "session")
	session, err := store.Get(r, cfgMap["session name"])
	if err != nil {
		log.Println("home get session:", err)

		// authenticatedMap[cookieuser] = false
		// delete(authenticatedMap, cookieuser)
		// TODO: clear maps ?
		session.Options.MaxAge = -1
		session.Save(r, w)
		http.Redirect(w, r, "/home.html", http.StatusSeeOther)
		return
	}

	// key := "visits"
	// val, ok := session.Values[key].(int)
	// if !ok {
	// 	session.Values[key] = 1
	// 	tData.Visits = 1
	// }
	// if ok {
	// 	val++
	// 	session.Values[key] = val
	// 	tData.Visits = val
	// }

	// check logins
	sok, vok := checkLogin(r, cfgMap["session name"], "user")
	if !sok {
		// log.Println("home get session:", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError),
			http.StatusInternalServerError)
		return
	}

	tData.User = ""
	if vok {
		// http.Redirect(w, r, "/login.html", http.StatusSeeOther)
		tData.User, _ = session.Values["user"].(string)
		// return
	}

	// Save it before we write to the response/return from the handler.
	err = session.Save(r, w)
	if err != nil {
		log.Println("Session save error:", err)
	}
	// var path = strings.Trim(r.URL.Path, "/")
	if logL1 {
		log.Println("=== home ===")
		log.Println("path:", r.URL.Path)
		log.Println("host:", tData.Host)

		log.Println("session:", session)
		val, _ := session.Values["visits"].(int)
		log.Printf("visits: %v: %T\n", val, val)
	}

	// Execute template
	err = htmlTmpl.ExecuteTemplate(w, "home-page.html", tData)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError),
			http.StatusInternalServerError)
	}
}

func download(w http.ResponseWriter, r *http.Request) {

	// Define a struct for sending data to templates
	type FileElem struct {
		Index int
		Name  string
		Dir   string
	}

	type TData struct {
		// NavAll  []string
		FList   []FileElem
		DirList []FileElem
		T       map[string]bool
		Host    string
		User    string
		// WSHost  string
	}

	// init struct
	tData := new(TData)
	// tData.NavAll = navAll
	// tData.T = make(map[string]bool)
	tData.Host = r.Host
	// tData.WSHost = "ws://" + r.Host + "/echo"
	if logL1 {
		log.Println("=== download ===")
		log.Println(r.URL.Path)
	}

	// Get session
	session, err := store.Get(r, cfgMap["session name"])
	if err != nil {
		log.Println("download get session:", err)

		// authenticatedMap[cookieuser] = false
		// delete(authenticatedMap, cookieuser)
		// TODO: clear maps ?
		session.Options.MaxAge = -1
		session.Save(r, w)
		http.Redirect(w, r, "/home.html", http.StatusSeeOther)
		return
	}

	sok, vok := checkLogin(r, cfgMap["session name"], "user")
	if !sok {
		http.Error(w, http.StatusText(http.StatusInternalServerError),
			http.StatusInternalServerError)
		return
	}

	tData.User = ""
	if !vok {
		http.Redirect(w, r, "/login.html", http.StatusSeeOther)
		return
	}

	tData.User, _ = session.Values["user"].(string)

	//Read files
	reqURL := r.URL.Path[len("/downloads.html/"):]
	folderPath := "download"
	folderURL := "/download"

	if reqURL != "" {
		// folderPath += folderPath+"/"+ reqURL
		folderPath = folderPath + "/" + reqURL
		folderURL = folderURL + "/" + reqURL
		// folderURL += r.URL.Path
	}

	if logL1 {
		log.Println("url:", r.URL.Path)
		log.Println("req url:", reqURL)
		log.Println("folder path:", folderPath)
		log.Println("folder url:", folderURL)
	}

	// Read folder structure
	files, err := ioutil.ReadDir(folderPath)

	if err != nil {
		http.Redirect(w, r, "/downloads.html", http.StatusNotFound)
		return
		// log.Fatal(err)
	}

	// Add files and folders to separae slices of [index, name, folderURL]
	// tData.FList = make([]FileElem, len(files))
	i, j := 0, 0
	var felem, direlem FileElem
	for _, file := range files {
		// Folders
		if file.IsDir() {
			direlem.Index = j + 1
			direlem.Name = file.Name()
			direlem.Dir = folderURL
			tData.DirList = append(tData.DirList, direlem)
			j++
			// Files
		} else {
			felem.Index = i + 1
			felem.Name = file.Name()
			felem.Dir = folderURL
			tData.FList = append(tData.FList, felem)
			i++
		}
	}
	// Process template and write to response to client
	err = htmlTmpl.ExecuteTemplate(w, "download-page.html", tData)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError),
			http.StatusInternalServerError)
	}
}

func upload(w http.ResponseWriter, r *http.Request) {

	// Define a struct for sending data to templates
	type TData struct {
		// NavAll []string
		Token string
		Host  string
		User  string
		// WSHost string
	}

	// init struct
	tData := new(TData)
	// tData.NavAll = navAll
	tData.Host = r.Host
	// loggedin := false

	if logL1 {
		log.Println("=== upload ===")
	}

	// Get session
	session, err := store.Get(r, cfgMap["session name"])
	if err != nil {
		log.Println("upload get session:", err)

		// authenticatedMap[cookieuser] = false
		// delete(authenticatedMap, cookieuser)
		// TODO: clear maps ?
		session.Options.MaxAge = -1
		session.Save(r, w)
		http.Redirect(w, r, "/home.html", http.StatusSeeOther)
		return
	}

	sok, vok := checkLogin(r, cfgMap["session name"], "user")
	if !sok {
		http.Error(w, http.StatusText(http.StatusInternalServerError),
			http.StatusInternalServerError)
		return
	}

	tData.User = ""
	if !vok {
		http.Redirect(w, r, "/login.html", http.StatusSeeOther)
		return
	}

	tData.User, _ = session.Values["user"].(string)

	if logL1 {
		log.Println("method:", r.Method)
	}

	if r.Method == "GET" {
		crutime := time.Now().Unix()
		h := md5.New()
		io.WriteString(h, strconv.FormatInt(crutime, 10))
		tData.Token = fmt.Sprintf("%x", h.Sum(nil))

		err := htmlTmpl.ExecuteTemplate(w, "upload-page.html", tData)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError),
				http.StatusInternalServerError)
		}

		// not GET method
	} else {
		// Get File from POST
		r.ParseMultipartForm(32 << 20)
		file, handler, err := r.FormFile("uploadfile")
		if err != nil {
			fmt.Println(err)
			return
		}
		defer file.Close()
		// fmt.Fprintf(w, "Done: %v", handler.Filename)

		// Save File
		// fmt.Fprintf(w, "%v", handler.Header)
		f, err := os.OpenFile("download/"+handler.Filename,
			os.O_WRONLY|os.O_CREATE, 0666)
		if err != nil {
			fmt.Println(err)
			return
		}
		defer f.Close()
		io.Copy(f, file)
		fmt.Fprintf(w, "Done: %v", handler.Filename)
		// http.Redirect(w, r, "/upload.html", http.StatusSeeOther)
	}
}

func login(w http.ResponseWriter, r *http.Request) {

	// Define a struct for sending data to templates
	type TData struct {
		// NavAll []string
		Token string
		Host  string
		// WSHost string
	}

	// init struct
	tData := new(TData)
	// tData.NavAll = navAll
	tData.Host = r.Host

	if logL1 {
		log.Println("=== login ===")
	}

	// Get session
	sok, vok := checkLogin(r, cfgMap["session name"], "user")
	if !sok {
		http.Error(w, http.StatusText(http.StatusInternalServerError),
			http.StatusInternalServerError)
		return
	}

	if vok {
		http.Redirect(w, r, "/home.html", http.StatusSeeOther)
		return
	}

	if logL1 {
		log.Println("method:", r.Method)
	}

	if r.Method == "GET" {

		err := htmlTmpl.ExecuteTemplate(w, "login-page.html", tData)
		if err != nil {
			log.Println("template parse error")
			http.Error(w, http.StatusText(http.StatusInternalServerError),
				http.StatusInternalServerError)
		}

		// not GET method
	} else {

		session, err := store.Get(r, cfgMap["session name"])
		if err != nil {
			log.Println("login get session:", err)
			http.Error(w, http.StatusText(http.StatusInternalServerError),
				http.StatusInternalServerError)
			return
		}

		// Get credentials from POST
		r.ParseForm()

		if logL1 {
			log.Println("form username:", r.Form["username"])
			log.Println("form password:", r.Form["password"])
		}

		formuser := r.Form["username"][0]
		formpassword := r.Form["password"][0]

		if logL1 {
			log.Println("form username:", formuser, "form password:", formpassword)
		}

		//check if logins match saved logins
		v, ok := usersMap[formuser]

		if ok {
			if v == formpassword {
				log.Println("form authentication ok")

				session.Values["user"] = formuser
				session.Values["authlvl"] = "1"

				// Save it before we write to the response/return from the handler.
				err = session.Save(r, w)
				if err != nil {
					log.Println("Session save error:", err)
				}
				// mutex ?
				authenticatedMap[formuser] = true
				if logL1 {
					log.Println("auth map:", authenticatedMap)
				}
				http.Redirect(w, r, "/home.html", http.StatusSeeOther)
			} else {
				log.Println("form authentication failed")
				http.Redirect(w, r, "/home.html", http.StatusSeeOther)
				return
			}
		} else {
			log.Println("form assert authentication failed")
			http.Redirect(w, r, "/home.html", http.StatusSeeOther)
			return
		}
	}
}

func logout(w http.ResponseWriter, r *http.Request) {
	if logL1 {
		log.Println("=== logout ===")
	}

	// Get session
	session, err := store.Get(r, cfgMap["session name"])
	if err != nil {
		log.Println("logout get session:", err)
		// Session logic broken, return
		http.Error(w, http.StatusText(http.StatusInternalServerError),
			http.StatusInternalServerError)
		return
	}

	cookieuser, ok := session.Values["user"].(string)
	if !ok {
		log.Println("user assert failed")
		http.Redirect(w, r, "/login.html", http.StatusSeeOther)
		return
	}

	// logoutUser := session.Values["user"]
	authenticatedMap[cookieuser] = false
	// delete(authenticatedMap, cookieuser)
	session.Options.MaxAge = -1
	session.Save(r, w)
	http.Redirect(w, r, "/home.html", http.StatusSeeOther)
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

func wsMessage(w http.ResponseWriter, r *http.Request) {

	// Get session
	sok, vok := checkLogin(r, cfgMap["session name"], "user")
	if !sok || !vok {
		http.Error(w, http.StatusText(http.StatusInternalServerError),
			http.StatusInternalServerError)
		return
	}

	cc := make(chan bool)
	c, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Print("upgrade:", err)
		return
	}
	defer c.Close()

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

	for {
		select {
		case <-cc:
			return
		default:
			response := []byte(<-wsChan)
			// response = append(response, ", Sensor: "...)
			response = append(response, (" Sensor: " + gSensorVal[1] +
				" | " + gSensorVal[2])...)
			mestype := 1
			err = c.WriteMessage(mestype, response)
			if err != nil {
				log.Println("ws write err:", err)
				break
			}
			time.Sleep(time.Second)
		}
	}
}

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

func status(w http.ResponseWriter, r *http.Request) {
	io.WriteString(w, "Hello, world!\n")
}

func checkLogin(r *http.Request, sessionName string,
	sessionValue interface{}) (sessionOk, authOk bool) {
	sessionOk, authOk = true, true
	// Get session
	session, err := store.Get(r, sessionName)
	if err != nil {
		log.Println("login get session:", err)
		// http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		sessionOk, authOk = false, false
		return
	}

	cookieVal, ok := session.Values[sessionValue].(string)
	if !ok {
		// no user
		log.Println("user assert failed:", cookieVal)
		authOk = false
		return
	}

	//mutex ?
	v, ok := authenticatedMap[cookieVal]

	if !ok || !v {
		log.Println("not logged in or auth map err:", !v, !ok)
		authOk = false
	}
	return
}

// Watch templates folder and reload templates on change
func dirWatcher(folders ...string) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatal(err)
	}
	defer watcher.Close()

	done := make(chan bool)
	go func() {
		for {
			select {
			case event := <-watcher.Events:
				if logL1 {
					log.Println("=== dir Watcher ===")
					log.Println("event:", event)
				}
				if event.Op&fsnotify.Write == fsnotify.Write {
					// if logL1 {
					log.Println("modified file:", event.Name)
					// }
				}

				// Parse templates
				htmlTmpl = template.Must(template.ParseGlob("templates/*.html"))
			case err := <-watcher.Errors:
				log.Println("error:", err)
			}
		}
	}()

	for _, folder := range folders {
		err = watcher.Add(folder)
		if err != nil {
			log.Fatal(err)
		}
		log.Println("Watching folder:", folder)
	}
	//loop forever
	<-done
}

func setSessionInt(session *sessions.Session, key string, val int) {
	// if session.Values[key] == nil {
	// session.Values[key] = val
	// return 0
	// } else {
	// val, _ := session.Values[key].(int)
	// val++
	// session.Values[key] = val
	// return val
	// }
}

func readLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}

// writeLines writes the lines to the given file.
func writeLines(lines []string, path string) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	w := bufio.NewWriter(file)
	for _, line := range lines {
		fmt.Fprintln(w, line)
	}
	return w.Flush()
}

func compSum() {
	sum := sha256.Sum256([]byte("hello world"))
	fmt.Printf("%x", sum)
}

var (
	cfgMap   = cfgutils.ReadCfgFile("cfg.ini", true)
	usersMap = cfgutils.ReadCfgFile("users.txt", true)

	htmlTmpl = template.Must(template.ParseGlob("templates/*.html"))

	//navAll = []string{"home", "downloads", "upload", "login"}
	store *sessions.CookieStore

	logL0, logL1 bool
	logL2, logL3 bool

	// loginsMap        = make(map[string]string)
	authenticatedMap = make(map[string]bool)

	upgrader = websocket.Upgrader{} // use default options
	wsChan   = make(chan string)
	// loggerBuf bytes.Buffer
	// logger    = log.New(&loggerBuf, "logger: ", log.Lshortfile)
)

func init() {

	switch cfgMap["log level"] {
	case "0":
		logL0 = true
		log.Println("Log level: 0")
	case "1":
		logL1 = true
		log.Println("Log level: 1")
	case "2":
		logL2 = true
		log.Println("Log level: 2")
	case "3":
		logL3 = true
		log.Println("Log level: 3")
	}

	// if cfgMap["logl0"] == "1" {
	// 	logL0 = true
	// 	log.Println("Log level 0")
	// }
	//
	// if cfgMap["logl1"] == "1" {
	// 	logL1 = true
	// 	log.Println("Log level 1")
	// }

	// gorilla cookie store
	var SHA1 = sha256.Sum256([]byte("sha 1-1"))
	var SHA2 = sha256.Sum256([]byte("sha 2-1"))
	store = sessions.NewCookieStore(SHA1[:], SHA2[:])

	store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   86400 * 3600,
		HttpOnly: true,
		// Secure cookie works only over secure connection (no cookie on insecure).
		// cookie encription work over insecure connection
		// Secure:   true,
	}

	// logins = getLogins()
	// getLogins()

	if logL1 {
		log.Println("logins map (init func):", usersMap)
	}

	// authenticated = make(map[string]bool)
	for k := range usersMap {
		authenticatedMap[k] = false
	}
	if logL1 {
		log.Println("authenticated map (init func):", authenticatedMap)
	}

	lock.Lock()
	gSensorVal = make(map[int]string)
	lock.Unlock()
}

func main() {

	// logger.Print(fmt.Sprint("lg test ", loginsMap))
	// fmt.Print(&loggerBuf)

	//Watch template foldr
	go dirWatcher("templates")

	go wsChanSend()
	go readSensors()
	go simpleDial2("A01; Val1: 123; Val2: 234.5; Val3: dada;")
	go simpleDial2("A02; Val1: 678; Val2: 666.2; Val3: nunu;")
	// go func() {
	// time.Sleep(2 * time.Second)
	// }()

	http.HandleFunc("/home.html/", home)
	http.HandleFunc("/downloads.html/", download)
	http.HandleFunc("/upload.html/", upload)
	http.HandleFunc("/login.html/", login)
	http.HandleFunc("/logout.html/", logout)

	// http.HandleFunc("/echo", wsEcho)
	http.HandleFunc("/msg/", wsMessage)

	// http.HandleFunc("/ws", wSocket)

	http.HandleFunc("/status.txt", status)

	http.Handle("/download/", http.StripPrefix("/download/",
		http.FileServer(http.Dir("download"))))
	http.Handle("/img/", http.StripPrefix("/img/",
		http.FileServer(http.Dir("img"))))
	http.Handle("/", http.StripPrefix("/",
		http.FileServer(http.Dir("root"))))

	log.Println("Running...")

	// Gorilla mux
	// go func() {
	// 	err := http.ListenAndServeTLS(":443", "pki/server.crt", "pki/server.key",
	// 		context.ClearHandler(http.DefaultServeMux))
	// 	// err := http.ListenAndServe(":80", nil)
	// 	if err != nil {
	// 		panic("ListenAndServeTLS: " + err.Error())
	// 	}
	// }()

	err := http.ListenAndServe(":80", context.ClearHandler(http.DefaultServeMux))
	if err != nil {
		panic("ListenAndServe: " + err.Error())
	}
}
