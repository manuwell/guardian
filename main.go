package main

import (
	"github.com/manuwell/guardian/Godeps/_workspace/src/github.com/joho/godotenv"
	"github.com/manuwell/guardian/Godeps/_workspace/src/github.com/julienschmidt/httprouter"
	"github.com/manuwell/guardian/Godeps/_workspace/src/github.com/pquerna/otp"
	"github.com/manuwell/guardian/Godeps/_workspace/src/github.com/pquerna/otp/totp"

	"bytes"
	"encoding/base64"
	"encoding/json"
	"html/template"
	"image/png"
	"log"
	"net/http"
	"os"
)

type TokenValidationStruct struct {
	Valid bool
}

func checkAuth(w http.ResponseWriter, r *http.Request, ps httprouter.Params, handler func(http.ResponseWriter, *http.Request, httprouter.Params)) {
	user, pass, _ := r.BasicAuth()

	if (user == os.Getenv("GUARDIAN_HTTP_USER")) && (pass == os.Getenv("GUARDIAN_HTTP_PASS")) {
		handler(w, r, ps)
	} else {
		renderForbidden(w, r)
	}
}

func tokenValidation(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	token := ps.ByName("token")
	secret := os.Getenv("GUARDIAN_SECRET")
	valid := totp.Validate(token, secret)

	validator := TokenValidationStruct{valid}

	response, err := json.MarshalIndent(validator, "", "\t")
	if err != nil {
		log.Fatal(err)
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(response)
}

func qrcode(key *otp.Key) string {
	// Convert TOTP key into a PNG
	var buf bytes.Buffer
	img, err := key.Image(400, 400)
	if err != nil {
		panic(err)
	}
	png.Encode(&buf, img)
	return base64.StdEncoding.EncodeToString(buf.Bytes())
}

func render(key *otp.Key) []byte {
	const tpl = `
  <!DOCTYPE html>
  <html>
  <head>
  <meta charset="UTF-8">
  <title>{{.Title}}</title>
  </head>
  <body style="text-align: center">
    <img src="data:image/png;base64,{{ .Qrcode }}" />

    <p>{{ .Issuer }}</p>
    <p>{{ .Account }}</p>
    <p>{{ .Secret }}</p>
  </body>
  </html>`

	t, err := template.New("webpage").Parse(tpl)
	data := struct {
		Title   string
		Qrcode  string
		Issuer  string
		Account string
		Secret  string
	}{
		Title:   "Guardian Token Generator",
		Qrcode:  qrcode(key),
		Issuer:  key.Issuer(),
		Account: key.AccountName(),
		Secret:  key.Secret(),
	}

	var buf bytes.Buffer
	err = t.Execute(&buf, data)
	if err != nil {
		log.Fatal(err)
	}

	return buf.Bytes()
}

func tokenGenereation(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {

	secret := os.Getenv("GUARDIAN_SECRET")
	if secret != "" {
		w.Write(bytes.NewBufferString("You already set an OTP secret").Bytes())
		w.WriteHeader(http.StatusNotAcceptable)
		return
	}

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      r.FormValue("issuer"),
		AccountName: r.FormValue("account"),
	})

	if err != nil {
		panic(err)
	}

	os.Setenv("GUARDIAN_SECRET", key.Secret())

	response := render(key)

	w.Write(response)
	w.Header().Set("Content-Disposition", "attachment; filename='guardian.html'")
	w.WriteHeader(http.StatusCreated)
}

func renderInternalServerError(w http.ResponseWriter, r *http.Request, message string) {
	w.Write(bytes.NewBufferString(message).Bytes())
	w.WriteHeader(http.StatusInternalServerError)
}

func renderForbidden(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusForbidden)
}

func loadEnv() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}
}

func main() {
	if os.Getenv("GUARDIAN_ENV") != "production" {
		loadEnv()
	}

	router := httprouter.New()
	router.POST("/token", func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		checkAuth(w, r, ps, tokenGenereation)
	})
	router.GET("/token/check/:token", func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		checkAuth(w, r, ps, tokenValidation)
	})

	http.ListenAndServe(":"+os.Getenv("GUARDIAN_HTTP_PORT"), router)
}
