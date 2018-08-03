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
)

func home(w http.ResponseWriter, r *http.Request) {

	// Define a struct for sending data to templates
	type TData struct {
		NavA []string
	}

	var htmlTpl = template.Must(template.ParseGlob("templates/*.html"))

	// init struct
	tData := new(TData)
	tData.NavA = navA

	// var path = strings.Trim(r.URL.Path, "/")
	log.Println("=== home ===")
	log.Println(r.URL.Path)

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

	var htmlTpl = template.Must(template.ParseGlob("templates/*.html"))

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
	files, err := ioutil.ReadDir(folderPath)

	if err != nil {
		http.Redirect(w, r, "/downloads.html", http.StatusNotFound)
		return
		log.Fatal(err)
	}

	// tData.FList = make([]FileElem, len(files))
	i, j := 0, 0
	var felem, direlem FileElem
	for _, file := range files {
		if file.IsDir() {
			direlem.Index = j + 1
			direlem.Name = file.Name()
			direlem.Dir = folderURL
			tData.DirList = append(tData.DirList, direlem)
			// tData.FList[i].Index = i + 1
			// tData.FList[i].Name = file.Name()
			j++
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

		var htmlTpl = template.Must(template.ParseGlob("templates/*.html"))
		// t, _ := template.ParseFiles("upload.html")
		// t.Execute(w, token)
		err := htmlTpl.ExecuteTemplate(w, "upload-page.html", tData)
		if err != nil {
			//in prod replace err.error() with something else
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		// not ET method
	} else {
		r.ParseMultipartForm(32 << 20)
		file, handler, err := r.FormFile("uploadfile")
		if err != nil {
			fmt.Println(err)
			return
		}
		defer file.Close()
		fmt.Fprintf(w, "Done: %v", handler.Filename)
		// fmt.Fprintf(w, "%v", handler.Header)
		f, err := os.OpenFile("./download/"+handler.Filename, os.O_WRONLY|os.O_CREATE, 0666)
		if err != nil {
			fmt.Println(err)
			return
		}
		defer f.Close()
		io.Copy(f, file)
		// http.Redirect(w, r, "/upload.html", http.StatusSeeOther)
	}
}

// var htmlTpl = template.Must(template.ParseGlob("templates/*.html"))
var navA = []string{"home", "downloads", "upload"}

func main() {

	http.HandleFunc("/home.html", home)
	http.HandleFunc("/downloads.html/", download)
	http.HandleFunc("/upload.html/", upload)
	http.Handle("/download/", http.StripPrefix("/download/", http.FileServer(http.Dir("download"))))
	http.Handle("/", http.StripPrefix("/", http.FileServer(http.Dir("root"))))

	log.Println("Running")
	err := http.ListenAndServe(":80", nil)
	if err != nil {
		panic("ListenAndServe: " + err.Error())
	}
}
