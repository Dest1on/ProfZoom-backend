package main

import (
	"log"
	"net/http"

	apphttp "github.com/Dest1on/ProfZoom-backend/internal/http"
)

func main() {
	router := apphttp.NewRouter()

	log.Println("API started on :8080")
	if err := http.ListenAndServe(":8080", router); err != nil {
		log.Fatal(err)
	}
}
