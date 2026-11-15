package henbane_test

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"

	"github.com/datadir-lab/henbane"
)

// This example wraps an application handler with Henbane and shows that ordinary
// traffic passes straight through to the app.
func Example() {
	hb, err := henbane.New(henbane.Config{})
	if err != nil {
		panic(err)
	}

	app := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "hello from my app")
	})

	// hb.Handler is a func(http.Handler) http.Handler — it drops into net/http,
	// chi's r.Use, alice, or any router that consumes that shape.
	srv := httptest.NewServer(hb.Handler(app))
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		panic(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	fmt.Println(string(body))
	// Output: hello from my app
}
