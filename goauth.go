package main

import (
	"fmt"
	//"io"
	"net/http"
	"time"
	"math/rand"
	"crypto/sha1"
	"encoding/base64"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"text/template"
	"crypto/md5"
    "encoding/hex"
	"github.com/gocql/gocql"
)

var cluster *gocql.ClusterConfig;
var db_session *gocql.Session;
var templatesPath = "templates"


//Ported from Python Beaker library
func session_id() string {
	id_str := strconv.FormatInt(time.Now().Unix(), 10) + strconv.Itoa(rand.Int()) + strconv.Itoa(os.Getpid())
	id_byte := sha1.Sum([]byte(id_str))
	raw_id := base64.StdEncoding.EncodeToString(id_byte[:])
	raw_id = strings.Replace(raw_id, "+", "-", -1)
	raw_id = strings.Replace(raw_id, "/", "_", -1)
	raw_id = strings.TrimRight(raw_id, "=")
	return raw_id
}

type Auth struct {
	UserId string
	IsAuth bool
	Login string
}

func index_handler(w http.ResponseWriter, r *http.Request) {
	user_id, is_auth := auth(r)
	var login string;
	
	if is_auth {
		login = get_user(user_id)
	}
	auth_state := Auth{UserId: user_id, IsAuth: is_auth, Login: login}
	if t, err := template.ParseFiles(filepath.Join(templatesPath, "index.html")); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	} else {
		t.Execute(w, auth_state)
	}
}

func auth(r *http.Request) (string,  bool) {
	auth_token, ok := r.Cookie("goauth")
	var user_id string;
	if ok == http.ErrNoCookie {
		return user_id, false
	}
	
	db_session, _ = cluster.CreateSession()
	defer db_session.Close()

	if err := db_session.Query("SELECT user_id FROM sessions WHERE key=?",
		auth_token.Value).Scan(&user_id); err != nil {
		fmt.Println(err)
		return user_id, false;
	}
	return user_id, true
}

func get_user(user_id string) string {
	var login string
	db_session, _ = cluster.CreateSession()
	defer db_session.Close()
	if err := db_session.Query(`SELECT login FROM users WHERE user_id = ? LIMIT 1`,
		user_id).Consistency(gocql.One).Scan(&login); err != nil {
		fmt.Println(err)
		return login
	}

	return login
}



func auth_handler(w http.ResponseWriter, r *http.Request) {
	//w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if r.Method == "GET" {
		if t, err := template.ParseFiles(filepath.Join(templatesPath, "auth.html")); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		} else {
			t.Execute(w, nil)
		}
	} else if r.Method == "POST" {
		r.ParseForm()
		fmt.Println(r.Form)
		db_session, _ = cluster.CreateSession()
		defer db_session.Close()
		var password string;
		var user_id string;
		if err := db_session.Query(`SELECT user_id, password FROM users WHERE login = ? LIMIT 1`,
			r.Form["login"][0]).Consistency(gocql.One).Scan(&user_id, &password); err != nil {
			w.WriteHeader(http.StatusForbidden)
			fmt.Println(err)
			return
		}
		//need bcrypt or PBKDF2 but md5 for simple now
		hasher := md5.New()
		hasher.Write([]byte(r.Form["password"][0]))
		if hex.EncodeToString(hasher.Sum(nil)) != password {
			w.WriteHeader(http.StatusForbidden)
			return
		}

		key := session_id()
		if err := db_session.Query(`INSERT INTO sessions (key, user_id) VALUES (?, ?)`,
			key,
			user_id).Exec(); err != nil {
			w.WriteHeader(http.StatusForbidden)
			fmt.Println(err)
			return
		}
		cookie := http.Cookie{
			Name: "goauth",
			Value: key,
			Path: "/",
			Domain: "127.0.0.1",
			MaxAge: 50000,
		}
		http.SetCookie(w, &cookie)
	}

	
}

func logout_handler(w http.ResponseWriter, r *http.Request) {
	db_session, _ = cluster.CreateSession()
	defer db_session.Close()
	auth_token, ok := r.Cookie("goauth")
	if ok != http.ErrNoCookie {
		if err := db_session.Query(`DELETE FROM sessions WHERE key = ?`,
			auth_token.Value).Exec(); err != nil {
			fmt.Println(err)
		}
	}
	cookie := http.Cookie{
		Name: "goauth",
		Value: "delete",
		Path: "/",
		Domain: "127.0.0.1",
		MaxAge: -1,
	}
	//r.AddCookie(&cookie)
	http.SetCookie(w, &cookie)
	http.Redirect(w, r, "/", 301)
}

var mux map[string]func(http.ResponseWriter, *http.Request)

func main() {
	dir, _ := os.Getwd()
	templatesPath = filepath.Join(dir, templatesPath)

	cluster = gocql.NewCluster("127.0.0.1")
	cluster.Keyspace = "goauth"
	

	server := http.Server{
		Addr:    ":8000",
		Handler: &myHandler{},
	}

	mux = make(map[string]func(http.ResponseWriter, *http.Request))
	mux["/"] = index_handler
	mux["/auth"] = auth_handler
	mux["/logout"] = logout_handler

	server.ListenAndServe()
}

type myHandler struct{}

func (*myHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h, ok := mux[r.URL.String()]; ok {
		h(w, r)
		return
	}
	http.ServeFile(w, r, r.URL.Path[1:])
	//w.WriteHeader(http.StatusNotFound)
	//io.WriteString(w, "Not found "+r.URL.String())
}
