package main

import (
	// "fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	// "strings"
	// "os"
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
	// log.Println(path)

	// if r.URL.Path != "/index.html" {
	// 	log.Println("restu")
	// }

	var htmlTpl = template.Must(template.ParseGlob("templates/*.html"))
	// var htmlTpl = template.Must(template.ParseFiles("templates/page.html"))
	// log.Println(htmlTpl)

	// Add some data

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
	}

	type TData struct {
		NavA  []string
		FList []FileElem
		T     map[string]bool
	}

	// init struct
	tData := new(TData)
	tData.NavA = navA
	tData.T = make(map[string]bool)

	// var path = "download"
	// var path = strings.Trim(r.URL.Path, "/")
	log.Println("download-------------------------------------------------")
	log.Println(r.URL.Path)
	// log.Println(path)

	var htmlTpl = template.Must(template.ParseGlob("templates/*.html"))
	// var htmlTpl = template.Must(template.ParseFiles("templates/page.html"))
	//log.Println(htmlTpl)

	// Add some data

	tData.T["txt1"] = false

	//Read files
	files, err := ioutil.ReadDir("./download")

	if err != nil {
		log.Fatal(err)
	}

	// tData.FList = files
	tData.FList = make([]FileElem, len(files))

	for i, file := range files {

		tData.FList[i].Index = i + 1
		tData.FList[i].Name = file.Name()
		// fmt.Println(tData.FList[i].Name)
		// fmt.Println(i)
	}

	// Process template and write to response to client
	err = htmlTpl.ExecuteTemplate(w, "download-page.html", tData)
	if err != nil {
		//in prod replace err.error() with something else
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

}

var navA = []string{"home", "download"}

func main() {
	http.HandleFunc("/home.html", home)
	// http.HandleFunc("/", index)
	http.HandleFunc("/download.html", download)

	http.Handle("/download/", http.StripPrefix("/download/", http.FileServer(http.Dir("download"))))
	http.Handle("/", http.StripPrefix("/", http.FileServer(http.Dir("root"))))

	// http.Handle("/css/", http.StripPrefix("/css/", http.FileServer(http.Dir("bootstrap/css"))))
	// http.Handle("/js/", http.StripPrefix("/js/", http.FileServer(http.Dir("bootstrap/js"))))

	err := http.ListenAndServe(":80", nil)
	if err != nil {
		panic("ListenAndServe: " + err.Error())
	}
}
