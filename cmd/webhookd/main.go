package main

import (
    "log"
    "net/http"

    "github.com/huangjie666777-ux/webhook-gateway-012/internal/httpapi"
    "github.com/huangjie666777-ux/webhook-gateway-012/internal/webhook"
)

func main() {
    store := webhook.NewMemoryStore()
    log.Println("webhookd listening on :8080")
    if err := http.ListenAndServe(":8080", httpapi.NewRouter(store)); err != nil {
        log.Fatal(err)
    }
}
