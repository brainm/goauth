package main

import (
	"encoding/json"
	"fmt"
	"github.com/brainm/httpauth"
	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
	"html/template"
	"net/http"
	"os"
	"path/filepath"
)

const (
	AUTH_FILE        = "auth.json"
	DEFAULT_USER     = "admin"
	DEFAULT_PASSWORD = "adminpass"
)

var (
	backend httpauth.FileAuthBackend
	aaa     httpauth.Authorizer
	roles   map[string]httpauth.Role
	port    = 8009
	//
	root string
	//
	funcMap = template.FuncMap{
		"noescape": func(s string) template.HTML {
			return template.HTML(s)
		},
	}
)

func main() {
	root, _ = filepath.Abs(filepath.Dir(os.Args[0]))
	//
	initialization()
	// //
	r := mux.NewRouter()
	r.HandleFunc("/", handlePage).Methods("GET") // authorized page
	r.HandleFunc("/change", postChange).Methods("POST")
	r.HandleFunc("/login", getLogin).Methods("GET")
	r.HandleFunc("/login", postLogin).Methods("POST")
	r.HandleFunc("/admin", handleAdmin).Methods("GET")
	r.HandleFunc("/add_user", postAddUser).Methods("POST")
	r.HandleFunc("/logout", handleLogout)
	//
	http.Handle("/", r)
	fmt.Printf("Server running on port %d\n", port)
	http.ListenAndServe(fmt.Sprintf(":%d", port), nil)
}

func handlePage(rw http.ResponseWriter, req *http.Request) {
	if err := aaa.Authorize(rw, req, true); err != nil {
		fmt.Println(err)
		http.Redirect(rw, req, "/login", http.StatusSeeOther)
		return
	}
	if user, err := aaa.CurrentUser(rw, req); err == nil {
		type data struct {
			User httpauth.UserData
		}
		d := data{User: user}
		t, err := template.New("index.html").Funcs(funcMap).ParseFiles(root + string(filepath.Separator) + "template" + string(filepath.Separator) + "index.html")
		if err != nil {
			panic(err)
		}
		t.Execute(rw, d)
	}
}

func postChange(rw http.ResponseWriter, req *http.Request) {
	email := req.PostFormValue("email")
	password := req.PostFormValue("password")
	password2 := req.PostFormValue("password2")
	if password != "" && password == password2 {
		aaa.Update(rw, req, password, email)
		http.Redirect(rw, req, "/logout", http.StatusSeeOther)
	}
	http.Redirect(rw, req, "/", http.StatusSeeOther)
}

func getLogin(rw http.ResponseWriter, req *http.Request) {
	messages := aaa.Messages(rw, req)
	var d struct{
		Messages interface{}
	}
	d.Messages = messages
	t, err := template.New("login.html").Funcs(funcMap).ParseFiles(root + string(filepath.Separator) + "template" + string(filepath.Separator) + "login.html")
	if err != nil {
		panic(err)
	}
	t.Execute(rw, d)
}

func postLogin(rw http.ResponseWriter, req *http.Request) {
	username := req.PostFormValue("username")
	password := req.PostFormValue("password")
	if err := aaa.Login(rw, req, username, password, "/"); err != nil && err.Error() == "already authenticated" {
		http.Redirect(rw, req, "/", http.StatusSeeOther)
	} else if err != nil {
		fmt.Println(err)
		http.Redirect(rw, req, "/login", http.StatusSeeOther)
	}
}

func handleAdmin(rw http.ResponseWriter, req *http.Request) {
	if err := aaa.AuthorizeRole(rw, req, "admin", true); err != nil {
		fmt.Println(err)
		http.Redirect(rw, req, "/login", http.StatusSeeOther)
		return
	}
	if user, err := aaa.CurrentUser(rw, req); err == nil {
		type data struct {
			User  httpauth.UserData
			Roles map[string]httpauth.Role
			Users []httpauth.UserData
			Msg   []string
		}
		messages := aaa.Messages(rw, req)
		users, err := backend.Users()
		if err != nil {
			panic(err)
		}
		d := data{User: user, Roles: roles, Users: users, Msg: messages}
		t, err := template.New("admin").Parse(`
            <html>
            <head><title>Admin page</title></head>
            <body>
                <h1>Httpauth example<h1>
                <h2>Admin Page</h2>
                <p>{{.Msg}}</p>
                {{ with .User }}<p>Hello {{ .Username }}, your role is '{{ .Role }}'. Your email is {{ .Email }}.</p>{{ end }}
                <p><a href="/">Back</a> <a href="/logout">Logout</a></p>
                <h3>Users</h3>
                <ul>{{ range .Users }}<li>{{.Username}}</li>{{ end }}</ul>
                <form action="/add_user" method="post" id="add_user">
                    <h3>Add user</h3>
                    <p><input type="text" name="username" placeholder="username"><br>
                    <input type="password" name="password" placeholder="password"><br>
                    <input type="email" name="email" placeholder="email"><br>
                    <select name="role">
                        <option value="">role<option>
                        {{ range $key, $val := .Roles }}<option value="{{$key}}">{{$key}} - {{$val}}</option>{{ end }}
                    </select></p>
                    <button type="submit">Submit</button>
                </form>
            </body>
            `)
		if err != nil {
			panic(err)
		}
		t.Execute(rw, d)
	}
}

func postAddUser(rw http.ResponseWriter, req *http.Request) {
	if err := aaa.AuthorizeRole(rw, req, "admin", true); err != nil {
		fmt.Println(err)
		http.Redirect(rw, req, "/login", http.StatusSeeOther)
		return
	}
	var user httpauth.UserData
	user.Username = req.PostFormValue("username")
	user.Email = req.PostFormValue("email")
	password := req.PostFormValue("password")
	user.Role = req.PostFormValue("role")
	if err := aaa.Register(rw, req, user, password); err != nil {
		// maybe something
	}

	http.Redirect(rw, req, "/admin", http.StatusSeeOther)
}

func handleLogout(rw http.ResponseWriter, req *http.Request) {
	if err := aaa.Logout(rw, req); err != nil {
		fmt.Println(err)
		// this shouldn't happen
		return
	}
	http.Redirect(rw, req, "/", http.StatusSeeOther)
}

func initialization() {
	// Prepare httpauth
	if _, err := os.Stat(AUTH_FILE); err != nil {
		// if file does not exists, create empty
		file, err := os.OpenFile(AUTH_FILE, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0666)
		data, err := json.Marshal(make(map[string]interface{}))
		if err != nil {
			fmt.Println(err)
		}
		file.Write(data)
		file.Close()
	}
	// create the backend
	var err error
	backend, err = httpauth.NewFileAuthBackend(AUTH_FILE)
	if err != nil {
		panic(err)
	}
	// create some default roles
	roles = make(map[string]httpauth.Role)
	roles["user"] = 30
	roles["admin"] = 80
	aaa, err = httpauth.NewAuthorizer(backend, []byte("cookie-encryption-key"), "user", roles)
	//
	if _, err := backend.User(DEFAULT_USER); err != nil {
		// if admin user does not exists
		// create a default user
		hash, err := bcrypt.GenerateFromPassword([]byte(DEFAULT_PASSWORD), bcrypt.DefaultCost)
		if err != nil {
			panic(err)
		}
		defaultUser := httpauth.UserData{Username: DEFAULT_USER, Email: "admin@localhost", Hash: hash, Role: "admin"}
		err = backend.SaveUser(defaultUser)
		if err != nil {
			panic(err)
		}
	}
}

func htmlSafe(text string) template.HTML {
	return template.HTML(text)
}
