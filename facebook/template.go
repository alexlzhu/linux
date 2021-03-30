package main

import (
	"encoding/json"
	"flag"
	"log"
	"os"
	"text/template"
)

var file = flag.String("template", "", "template file to render")
var varsJSON = flag.String("vars", "", "json string of variables")

func main() {
	flag.Parse()
	tmpl := template.Must(template.ParseFiles(*file))
	vars := make(map[string]interface{})
	err := json.Unmarshal([]byte(*varsJSON), &vars)
	if err != nil {
		log.Fatal(err)
	}
	err = tmpl.Execute(os.Stdout, vars)
	if err != nil {
		log.Fatal(err)
	}
}
