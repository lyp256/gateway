package controller

import (
	"io/fs"
	"net/http"

	"github.com/lyp256/gateway/web"
)

func (ctl *controller) registerWebUI() {
	assets, err := fs.Sub(web.Assets, "dist")
	if err != nil {
		panic(err)
	}

	ctl.http.Get("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-cache")
		http.ServeFileFS(w, r, assets, "index.html")
	})
	ctl.http.Handle("/assets/*", http.StripPrefix("/", http.FileServerFS(assets)))
}
