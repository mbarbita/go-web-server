package main

import (
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
)

func home(w http.ResponseWriter, r *http.Request) {

	// Define a struct for sending data to templates
	type TData struct {
		NavA []string
	}

	// init struct
	tData := new(TData)
	tData.NavA = navA

	// var path = strings.Trim(r.URL.Path, "/")
	log.Println("home-----------------------------------------------------")
	log.Println(r.URL.Path)

	// if r.URL.Path != "/index.html" {
	// 	log.Println("restu")
	// }

	var htmlTpl = template.Must(template.ParseGlob("templates/*.html"))
	// var htmlTpl = template.Must(template.ParseFiles("templates/page.html"))
	// log.Println(htmlTpl)

	// Process template and write to response to client
	err := htmlTpl.ExecuteTemplate(w, "home-page.html", tData)
	if err != nil {
		//in prod replace err.error() with something else
		// http.Error(w, err.Error(), http.StatusInternalServerError)
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

	// init struct
	tData := new(TData)
	tData.NavA = navA
	tData.T = make(map[string]bool)

	// var path = "download"
	// var path = strings.Trim(r.URL.Path, "/")
	log.Println("download-------------------------------------------------")
	log.Println(r.URL.Path)

	var htmlTpl = template.Must(template.ParseGlob("templates/*.html"))
	// var htmlTpl = template.Must(template.ParseFiles("templates/page.html"))
	//log.Println(htmlTpl)

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

	// tData.FList = files
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
		// fmt.Println(tData.FList[i].Name)
		// fmt.Println(i)
	}
	// tData.DlFolder = folderURL + "/"
	// log.Println(tData.DlFolder)
	// Process template and write to response to client
	err = htmlTpl.ExecuteTemplate(w, "download-page.html", tData)
	if err != nil {
		//in prod replace err.error() with something else
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

}

var navA = []string{"home", "downloads"}

func main() {
	http.HandleFunc("/home.html", home)
	// http.HandleFunc("/", index)
	// http.HandleFunc("/download.html", download)
	http.HandleFunc("/downloads.html/", download)
	http.Handle("/download/", http.StripPrefix("/download/", http.FileServer(http.Dir("download"))))
	http.Handle("/", http.StripPrefix("/", http.FileServer(http.Dir("root"))))

	// http.Handle("/css/", http.StripPrefix("/css/", http.FileServer(http.Dir("bootstrap/css"))))
	// http.Handle("/js/", http.StripPrefix("/js/", http.FileServer(http.Dir("bootstrap/js"))))
	log.Println("Starting...")
	err := http.ListenAndServe(":80", nil)
	if err != nil {
		panic("ListenAndServe: " + err.Error())
	}
}
