package main

import (
	"bufio"
	"bytes"
	"crypto/md5"
	"crypto/sha256"
	"flag"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/gorilla/context"
	"github.com/gorilla/sessions"
)

func home(w http.ResponseWriter, r *http.Request) {

	// Define a struct for sending data to templates
	type TData struct {
		NavAll []string
		Host   string
		Visits int
		User   string
	}

	// Parse templates
	// moved to goroutine fsnotify
	// var htmlTpl = template.Must(template.ParseGlob("templates/*.html"))

	// init struct
	tData := new(TData)
	tData.NavAll = navAll
	tData.Host = r.Host

	// Get session
	session, err := store.Get(r, "session")
	if err != nil {
		log.Println("home get session:", err)

		// authenticatedMap[cookieuser] = false
		// delete(authenticatedMap, cookieuser)
		// TODO: clear maps ?
		session.Options.MaxAge = -1
		session.Save(r, w)
		http.Redirect(w, r, "/home.html", http.StatusSeeOther)

		// http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	// Set some session values.
	key := "visits"
	if session.Values[key] == nil {
		session.Values[key] = 1
		tData.Visits = 1
	} else {
		val, _ := session.Values[key].(int)
		val++
		session.Values[key] = val
		tData.Visits = val
	}

	tData.User, _ = session.Values["user"].(string)
	// if tData.User == "" {
	// 	tData.User = "Not logged in"
	// }

	// session.Values["user"] = "user2"
	// session.Values["password"] = "pass2"

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
		val, _ := session.Values[key].(int)
		log.Printf("visits: %v: %T\n", val, val)
	}

	// Execute template
	err = htmlTmpl.ExecuteTemplate(w, "home-page.html", tData)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
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
		NavAll  []string
		FList   []FileElem
		DirList []FileElem
		T       map[string]bool
		host    string
	}
	// Parse templates
	// var htmlTpl = template.Must(template.ParseGlob("templates/*.html"))

	// init struct
	tData := new(TData)
	tData.NavAll = navAll
	// tData.T = make(map[string]bool)
	tData.host = r.Host
	if logL1 {
		log.Println("=== download ===")
		log.Println(r.URL.Path)
	}

	// Add some data
	// tData.T["txt1"] = false

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
		log.Fatal(err)
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
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}

}

func upload(w http.ResponseWriter, r *http.Request) {

	// Define a struct for sending data to templates
	type TData struct {
		NavAll []string
		token  string
		host   string
	}

	// init struct
	tData := new(TData)
	tData.NavAll = navAll
	tData.host = r.Host
	// loggedin := false

	if logL1 {
		log.Println("=== upload ===")
	}

	// Get session
	// session, err := store.Get(r, "session")
	// if err != nil {
	// 	log.Println("upload get session:", err)
	// 	// TODO redirect
	// 	http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	// 	return
	// }
	//
	// cookieuser, ok := session.Values["user"].(string)
	// if !ok {
	// 	log.Println("user assert failed")
	// 	http.Redirect(w, r, "/login.html", http.StatusSeeOther)
	// 	return
	// }
	//
	// v, ok := authenticatedMap[cookieuser]
	//
	// if !ok {
	// 	log.Println("auth map failed")
	// 	http.Redirect(w, r, "/login.html", http.StatusSeeOther)
	// }
	//
	// if ok {
	// 	if v {
	// 		log.Println("authenticated")
	// 		// loggedin = true
	// 	} else {
	// 		log.Println("not authenticated")
	// 		// not authenticated, redirect to login
	// 		http.Redirect(w, r, "/login.html", http.StatusSeeOther)
	// 		return
	// 	}
	// }

	sok, vok := checkLogin(r, "session", "user")
	if !sok {
		// log.Println("upload get session:", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	if !vok {
		http.Redirect(w, r, "/login.html", http.StatusSeeOther)
		return
	}

	if logL1 {
		log.Println("method:", r.Method)
	}

	if r.Method == "GET" {
		crutime := time.Now().Unix()
		h := md5.New()
		io.WriteString(h, strconv.FormatInt(crutime, 10))
		tData.token = fmt.Sprintf("%x", h.Sum(nil))

		// Parse templates
		// var htmlTpl = template.Must(template.ParseGlob("templates/*.html"))

		err := htmlTmpl.ExecuteTemplate(w, "upload-page.html", tData)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
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
		f, err := os.OpenFile("download/"+handler.Filename, os.O_WRONLY|os.O_CREATE, 0666)
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
		NavAll []string
		token  string
		host   string
	}

	// init struct
	tData := new(TData)
	tData.NavAll = navAll
	tData.host = r.Host
	// loggedin := false

	if logL1 {
		log.Println("=== login ===")
	}

	// Get session
	// session, err := store.Get(r, "session")
	// if err != nil {
	// 	log.Println("login get session:", err)
	// 	http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	// 	return
	// }
	//
	// cookieuser, ok := session.Values["user"].(string)
	// // not needed
	// // if !ok {
	// // 	// no user, continue for now
	// // 	log.Println("user assert failed")
	// // 	// return
	// // }
	//
	// v, ok := authenticatedMap[cookieuser]
	//
	// if ok {
	// 	if v {
	// 		log.Println("cookie authentication ok")
	// 		// already authenticated, redirect home
	// 		http.Redirect(w, r, "/home.html", http.StatusSeeOther)
	// 	}
	//
	// 	//not needed
	// 	// } else {
	// 	// login required, continue
	// 	// log.Println("cookie authentication failed")
	// 	// return
	// 	// }
	// }
	//
	// // log.Println("loggedin (should be always true):", loggedin)

	sok, vok := checkLogin(r, "session", "user")
	if !sok {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
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

		// Parse templates
		// var htmlTpl = template.Must(template.ParseGlob("templates/*.html"))

		err := htmlTmpl.ExecuteTemplate(w, "login-page.html", tData)
		if err != nil {
			log.Println("template parse error")
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		}

		// not GET method
	} else {

		session, err := store.Get(r, "session")
		if err != nil {
			log.Println("login get session:", err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
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
		v, ok := loginsMap[formuser]

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
				log.Println("auth map:", authenticatedMap)
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
	session, err := store.Get(r, "session")
	if err != nil {
		log.Println("logout get session:", err)
		// Session logic broken, return
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
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

func checkLogin(r *http.Request, sessionName string, sessionValue interface{}) (sessionOk, authOk bool) {
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
		// no user, continue for now
		log.Println("user assert failed:", cookieVal)
		authOk = false
		return
	}

	//mutex ?
	v, ok := authenticatedMap[cookieVal]

	// if ok {
	// 	if v {
	// 		log.Println("cookie authentication ok")
	// 		// already authenticated, redirect home
	// 		// http.Redirect(w, r, "/home.html", http.StatusSeeOther)
	// 	}
	// }

	if !ok || !v {
		log.Println("not logged in or auth map err:", v, ok)
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
					if logL1 {
						log.Println("modified file:", event.Name)
					}
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

func getSessionInt(session *sessions.Session, key string) int {
	val := 0
	// key := "visits"
	// if session.Values[key] == nil {
	// session.Values[key] = 0
	// return 0
	// } else {
	// val, _ := session.Values[key].(int)
	// val++
	// session.Values[key] = val
	// return val
	// }
	// 	val, _ := session.Values[key].(int)
	return val
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

// func getLogins() map[string]string {
func getLogins() {

	// var logins = make(map[string]string)

	lines, err := readLines("users.txt")
	if err != nil {
		log.Fatalf("read lines: %s", err)
	}

	for i, line := range lines {
		if logL1 {
			log.Println("readed line:", i, line)
		}
		if strings.HasPrefix(line, "#") {
			continue
		}
		fld := strings.Fields(line)
		if logL1 {
			log.Printf("fields: %q\n", fld)
		}
		loginsMap[fld[0]] = fld[1]
	}

	if logL1 {
		log.Println("logins map:", loginsMap)
	}
	// return logins
	// if err := writeLines(lines, "test.out.txt"); err != nil {
	// 	log.Fatalf("writeLines: %s", err)
	// }
}

func lg(msgs ...interface{}) {
	m := ""
	for _, msg := range msgs {
		m += fmt.Sprintf("%v, ", msg)
	}
	log.Println(m)
}

func lg1(msgs ...interface{}) {

	// m := fmt.Sprint(msgs)

	logger.Print(fmt.Sprint(msgs))
	fmt.Print(&loggerBuf)

	// log.Println(m[1 : len(m)-1])
}

var (
	htmlTmpl = template.Must(template.ParseGlob("templates/*.html"))
	navAll   = []string{"home", "downloads", "upload", "login"}
	store    *sessions.CookieStore
	// logMore          = flag.Bool("logmore", true, "false: disabled, true: enabled")
	logLevel         = flag.Int("loglevel", 0, "loglevel 0...3")
	logL0, logL1     bool
	logL2, logL3     bool
	loginsMap        = make(map[string]string)
	authenticatedMap = make(map[string]bool)

	logger    = log.New(&loggerBuf, "logger: ", log.Lshortfile)
	loggerBuf bytes.Buffer
)

func init() {

	flag.Parse()
	switch *logLevel {
	case 0:
		logL0 = true
	case 1:
		logL1 = true
	case 2:
		logL2 = true
	case 3:
		logL3 = true
	}

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
	getLogins()
	if logL1 {
		log.Println("logins map (init func):", loginsMap)
	}

	// authenticated = make(map[string]bool)
	for k, _ := range loginsMap {
		authenticatedMap[k] = false
	}
	if logL1 {
		log.Println("authenticated map (init func):", authenticatedMap)
		// authenticated["user2"] = true
		log.Println("auth user: authenticated map (init func):", authenticatedMap)
	}
}

func main() {

	lg1("lg test", "f1", "f2", loginsMap)

	//Watch template foldr
	go dirWatcher("templates")

	http.HandleFunc("/home.html/", home)
	http.HandleFunc("/downloads.html/", download)
	http.HandleFunc("/upload.html/", upload)
	http.HandleFunc("/login.html/", login)
	http.HandleFunc("/logout.html/", logout)
	http.Handle("/download/", http.StripPrefix("/download/", http.FileServer(http.Dir("download"))))
	http.Handle("/", http.StripPrefix("/", http.FileServer(http.Dir("root"))))

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
