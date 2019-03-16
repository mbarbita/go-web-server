package main

import (
	"crypto/md5"
	"crypto/sha256"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strconv"
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
		WSConn []string
		Visits int
		User   string
	}

	// init struct
	tData := new(TData)
	// tData.NavAll = navAll
	tData.Host = r.Host
	// tData.WSConn = append(tData.WSConn, "ws://"+r.Host+"/msg/")
	tData.WSConn = append(tData.WSConn, r.Host)

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
	if logLevel >= 6 {
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
	if logLevel >= 6 {
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

	if logLevel >= 6 {
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

	if logLevel >= 6 {
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

	if logLevel >= 6 {
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

	if logLevel >= 6 {
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

	if logLevel >= 6 {
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

		if logLevel >= 6 {
			log.Println("form username:", r.Form["username"])
			log.Println("form password:", r.Form["password"])
		}

		formuser := r.Form["username"][0]
		formpassword := r.Form["password"][0]

		if logLevel >= 6 {
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
				if logLevel >= 6 {
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
	if logLevel >= 6 {
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
				if logLevel >= 6 {
					log.Println("=== dir Watcher ===")
					log.Println("event:", event)
				}
				if event.Op&fsnotify.Write == fsnotify.Write {
					// if logL1 {
					log.Println("modified file:", event.Name)
					// }
				}

				// Parse templates
				htmlTmpl = template.Must(template.ParseGlob("templates/*.*"))
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

var (
	cfgMap   = cfgutils.ReadCfgFile("cfg.ini", true)
	usersMap = cfgutils.ReadCfgFile("users.txt", true)

	htmlTmpl = template.Must(template.ParseGlob("templates/*.*"))

	store *sessions.CookieStore

	logLevel int8

	// loginsMap        = make(map[string]string)
	authenticatedMap = make(map[string]bool)

	upgrader = websocket.Upgrader{} // use default options
	wsChan   = make(chan string)
)

func init() {

	logLevel, err := strconv.Atoi(cfgMap["log level"])
	if err != nil {
		log.Println("logLevel conv error:", err)
	}
	log.Println("log level:", logLevel)

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

	if logLevel >= 6 {
		log.Println("logins map (init func):", usersMap)
	}

	// authenticated = make(map[string]bool)
	for k := range usersMap {
		authenticatedMap[k] = false
	}
	if logLevel >= 6 {
		log.Println("authenticated map (init func):", authenticatedMap)
	}

	lock.Lock()
	gSensor = make(map[int]*Arduino)
	lock.Unlock()
}

func main() {

	cmd := exec.Command("cmd", "/c", "cls")
	cmd.Stdout = os.Stdout
	cmd.Run()

	//Watch template foldr
	go dirWatcher("templates")

	go wsChanSend()
	go readSensors()
	go simpleDial("A1", -2)
	go simpleDial("A2", -1)
	go simpleDial("A3", 0)

	http.HandleFunc("/home.html/", home)
	http.HandleFunc("/downloads.html/", download)
	http.HandleFunc("/upload.html/", upload)
	http.HandleFunc("/login.html/", login)
	http.HandleFunc("/logout.html/", logout)

	// http.HandleFunc("/echo", wsEcho)
	http.HandleFunc("/msg/", wsMessage)
	http.HandleFunc("/msgard/", wsArduino)

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
