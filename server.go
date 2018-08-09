package main

import (
	"bufio"
	"crypto/md5"
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
	}

	// Parse templates
	// var htmlTpl = template.Must(template.ParseGlob("templates/*.html"))

	// init struct
	tData := new(TData)
	tData.NavAll = navAll
	tData.Host = r.Host

	// Get session
	session, err := store.Get(r, "test-session")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
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

	// val := getSessionInt(session, "visits")

	// session.Values[42] = 43
	// Save it before we write to the response/return from the handler.
	err = session.Save(r, w)
	if err != nil {
		log.Println("Session save error:", err)
	}
	// var path = strings.Trim(r.URL.Path, "/")
	if *logmore {
		log.Println("=== home ===")
		log.Println("path:", r.URL.Path)
		log.Println("host:", tData.Host)

		log.Println("session:", session)
		val, _ := session.Values[key].(int)
		log.Printf("val: %v: %T\n", val, val)
	}

	// Execute template
	err = htmlTpl.ExecuteTemplate(w, "home-page.html", tData)
	if err != nil {
		//in prod replace err.error() with something else
		http.Error(w, err.Error(), http.StatusInternalServerError)
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
	if *logmore {
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

	if *logmore {
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
	err = htmlTpl.ExecuteTemplate(w, "download-page.html", tData)
	if err != nil {
		//in prod replace err.error() with something else
		http.Error(w, err.Error(), http.StatusInternalServerError)
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

	if *logmore {
		log.Println("=== upload ===")
		log.Println("method:", r.Method)
	}

	if r.Method == "GET" {
		crutime := time.Now().Unix()
		h := md5.New()
		io.WriteString(h, strconv.FormatInt(crutime, 10))
		tData.token = fmt.Sprintf("%x", h.Sum(nil))

		// Parse templates
		// var htmlTpl = template.Must(template.ParseGlob("templates/*.html"))

		err := htmlTpl.ExecuteTemplate(w, "upload-page.html", tData)
		if err != nil {
			//in prod replace err.error() with something else
			http.Error(w, err.Error(), http.StatusInternalServerError)
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
		fmt.Fprintf(w, "Done: %v", handler.Filename)

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
				if *logmore {
					log.Println("=== dir Watcher ===")
					log.Println("event:", event)
				}
				if event.Op&fsnotify.Write == fsnotify.Write {
					if *logmore {
						log.Println("modified file:", event.Name)
					}
				}

				// Parse templates
				htmlTpl = template.Must(template.ParseGlob("templates/*.html"))
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
	}
	//loop forever
	<-done
}

func getSessionInt(session *sessions.Session, key string) int {
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
	val, _ := session.Values[key].(int)
	return val
}

func setSessionInt(session *sessions.Session, key string, val int) {
	// if session.Values[key] == nil {
	session.Values[key] = val
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

func getLogins() map[string]string {

	var logins = make(map[string]string)

	lines, err := readLines("users.txt")
	if err != nil {
		log.Fatalf("readLines: %s", err)
	}

	for i, line := range lines {
		if *logmore {
			fmt.Println("Readed line:", i, line)
		}
		if strings.HasPrefix(line, "#") {
			continue
		}
		fld := strings.Fields(line)
		if *logmore {
			fmt.Printf("Fields are: %q\n", fld)
		}
		logins[fld[0]] = fld[1]
	}

	if *logmore {
		fmt.Println("map:", logins)
	}
	return logins
	// if err := writeLines(lines, "test.out.txt"); err != nil {
	// 	log.Fatalf("writeLines: %s", err)
	// }
}

var htmlTpl = template.Must(template.ParseGlob("templates/*.html"))
var navAll = []string{"home", "downloads", "upload"}
var store *sessions.CookieStore
var logmore = flag.Bool("logmore", true, "false: disabled, true: enabled")
var logins = make(map[string]string)

func init() {

	// gorilla cookie store
	store = sessions.NewCookieStore([]byte("something-very-secret"))
	// loglvl := flag.Bool("loglvl", false, "false: disabled, true: enabled")

	store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   86400 * 3600,
		HttpOnly: true,
	}

	logins := getLogins()
	if *logmore {
		fmt.Println(logins)
	}
}

func main() {

	// loglvl := flag.Bool("loglvl", "0", "false: disabled, true: enabled")
	flag.Parse()

	//Watch template foldr
	go dirWatcher("templates")

	http.HandleFunc("/home.html", home)
	http.HandleFunc("/downloads.html/", download)
	http.HandleFunc("/upload.html/", upload)
	http.Handle("/download/", http.StripPrefix("/download/", http.FileServer(http.Dir("download"))))
	http.Handle("/", http.StripPrefix("/", http.FileServer(http.Dir("root"))))

	log.Println("Running...")

	// Gorilla mux
	err := http.ListenAndServe(":80", context.ClearHandler(http.DefaultServeMux))
	// err := http.ListenAndServe(":80", nil)
	if err != nil {
		panic("ListenAndServe: " + err.Error())
	}
}
