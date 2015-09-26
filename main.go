package main

import (
	"github.com/manuwell/guardian/Godeps/_workspace/src/github.com/joho/godotenv"
	"github.com/manuwell/guardian/Godeps/_workspace/src/github.com/julienschmidt/httprouter"
	"github.com/manuwell/guardian/Godeps/_workspace/src/github.com/pquerna/otp/totp"

	"bytes"
	"encoding/base64"
	"encoding/json"
	"image/png"
	"log"
	"net/http"
	"os"
)

type TokenStruct struct {
	Issuer  string
	Account string
	Secret  string
	QRCode  string
}

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

func tokenImgGenereation(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      r.FormValue("issuer"),
		AccountName: r.FormValue("account"),
	})

	if err != nil {
		panic(err)
	}

	// Convert TOTP key into a PNG
	var buf bytes.Buffer
	img, err := key.Image(400, 400)
	if err != nil {
		panic(err)
	}
	png.Encode(&buf, img)

	w.Header().Set("Content-Type", "image/png")
	w.Write(buf.Bytes())
}

func tokenGenereation(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      r.FormValue("issuer"),
		AccountName: r.FormValue("account"),
	})

	if err != nil {
		panic(err)
	}

	// Convert TOTP key into a PNG
	var buf bytes.Buffer
	img, err := key.Image(200, 200)
	if err != nil {
		panic(err)
	}
	png.Encode(&buf, img)
	imgBase64Str := base64.StdEncoding.EncodeToString(buf.Bytes())

	token := TokenStruct{
		key.Issuer(),
		key.AccountName(),
		key.Secret(),
		imgBase64Str,
	}

	response, err := json.MarshalIndent(token, "", "\t")
	if err != nil {
		log.Fatal(err)
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(response)
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
	router.GET("/token/:token", func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		checkAuth(w, r, ps, tokenValidation)
	})

	http.ListenAndServe(":"+os.Getenv("GUARDIAN_HTTP_PORT"), router)
}
