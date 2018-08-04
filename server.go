package main

import (
	"crypto/md5"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/fsnotify/fsnotify"
)

func home(w http.ResponseWriter, r *http.Request) {

	// Define a struct for sending data to templates
	type TData struct {
		NavA []string
	}

	// Parse templates
	// var htmlTpl = template.Must(template.ParseGlob("templates/*.html"))

	// init struct
	tData := new(TData)
	tData.NavA = navA

	// var path = strings.Trim(r.URL.Path, "/")
	log.Println("=== home ===")
	log.Println(r.URL.Path)

	// Execute template
	err := htmlTpl.ExecuteTemplate(w, "home-page.html", tData)
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
		NavA    []string
		FList   []FileElem
		DirList []FileElem
		// DlFolder string
		T map[string]bool
	}
	// Parse templates
	// var htmlTpl = template.Must(template.ParseGlob("templates/*.html"))

	// init struct
	tData := new(TData)
	tData.NavA = navA
	tData.T = make(map[string]bool)

	// var path = "download"
	// var path = strings.Trim(r.URL.Path, "/")
	log.Println("=== download ===")
	log.Println(r.URL.Path)

	// Add some data
	tData.T["txt1"] = false

	//Read files
	reqURL := r.URL.Path[len("/downloads.html/"):]
	folderPath := "./download"
	folderURL := "/download"
	if reqURL != "" {

		// folderPath += folderPath+"/"+ reqURL
		folderPath = folderPath + "/" + reqURL
		folderURL = folderURL + "/" + reqURL
		// folderURL += r.URL.Path
	}

	log.Println("url:", r.URL.Path)
	log.Println("req url:", reqURL)
	log.Println("folder path:", folderPath)
	log.Println("folder url:", folderURL)

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
		NavA  []string
		token string
	}
	log.Println("=== upload ===")

	// init struct
	tData := new(TData)
	tData.NavA = navA

	log.Println("method:", r.Method)
	if r.Method == "GET" {
		crutime := time.Now().Unix()
		h := md5.New()
		io.WriteString(h, strconv.FormatInt(crutime, 10))
		tData.token = fmt.Sprintf("%x", h.Sum(nil))

		// var htmlTpl = template.Must(template.ParseGlob("templates/*.html"))
		// t, _ := template.ParseFiles("upload.html")
		// t.Execute(w, token)
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
		f, err := os.OpenFile("./download/"+handler.Filename, os.O_WRONLY|os.O_CREATE, 0666)
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
				log.Println("=== dir Watcher ===")
				log.Println("event:", event)
				if event.Op&fsnotify.Write == fsnotify.Write {
					log.Println("modified file:", event.Name)
				}
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
	// err = watcher.Add("./test")
	// err = watcher.Add("./test2")
	// if err != nil {
	// 	log.Fatal(err)
	// }

	//loop forever
	<-done
}

var htmlTpl = template.Must(template.ParseGlob("templates/*.html"))
var navA = []string{"home", "downloads", "upload"}

func main() {

	http.HandleFunc("/home.html", home)
	http.HandleFunc("/downloads.html/", download)
	http.HandleFunc("/upload.html/", upload)
	http.Handle("/download/", http.StripPrefix("/download/", http.FileServer(http.Dir("download"))))
	http.Handle("/", http.StripPrefix("/", http.FileServer(http.Dir("root"))))

	log.Println("Running...")

	//Watch template foldr
	go dirWatcher("./templates")

	err := http.ListenAndServe(":80", nil)
	if err != nil {
		panic("ListenAndServe: " + err.Error())
	}
}
