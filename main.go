package main

import (
    "context"
    "fmt"
    "html/template"
    "log"
    "net/http"

    "github.com/gorilla/sessions"
    "github.com/jackc/pgx/v5"
    "golang.org/x/crypto/bcrypt"
)

var (
    tmpl        = template.Must(template.ParseGlob("templates/*.html"))
    store       = sessions.NewCookieStore([]byte("super-secret-key")) // session key
    conn        *pgx.Conn
)

func main() {
    var err error
    conn, err = pgx.Connect(context.Background(), "postgres://postgres:Tedan254!@localhost:5432/myapp")
    if err != nil {
        log.Fatal("❌ Could not connect to DB:", err)
    }
    defer conn.Close(context.Background())

    http.HandleFunc("/register", registerHandler)
    http.HandleFunc("/login", loginHandler)
    http.HandleFunc("/dashboard", dashboardHandler)
    http.HandleFunc("/logout", logoutHandler)

    fmt.Println("🌐 Server running at http://localhost:8080")
    http.ListenAndServe(":8080", nil)
}

// Register handler (already working)
func registerHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method == http.MethodGet {
        tmpl.ExecuteTemplate(w, "register.html", nil)
        return
    }

    username := r.FormValue("username")
    email := r.FormValue("email")
    password := r.FormValue("password")

    hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

    _, err := conn.Exec(context.Background(), `
        INSERT INTO users (username, email, password)
        VALUES ($1, $2, $3)
    `, username, email, string(hashedPassword))
    if err != nil {
        http.Error(w, "Error saving user", http.StatusInternalServerError)
        return
    }

    fmt.Fprintln(w, "🎉 User registered successfully! <a href='/login'>Login here</a>")
}

// Login handler
func loginHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method == http.MethodGet {
        tmpl.ExecuteTemplate(w, "login.html", nil)
        return
    }

    email := r.FormValue("email")
    password := r.FormValue("password")

    var username string
    var hashedPassword string

    err := conn.QueryRow(context.Background(), `
        SELECT username, password FROM users WHERE email = $1
    `, email).Scan(&username, &hashedPassword)

    if err != nil {
        http.Error(w, "Invalid email", http.StatusUnauthorized)
        return
    }

    err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
    if err != nil {
        http.Error(w, "Invalid password", http.StatusUnauthorized)
        return
    }

    // Save username in session
    session, _ := store.Get(r, "session")
    session.Values["username"] = username
    session.Save(r, w)

    http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

// Dashboard (only if logged in)
func dashboardHandler(w http.ResponseWriter, r *http.Request) {
    session, _ := store.Get(r, "session")
    username, ok := session.Values["username"].(string)
    if !ok {
        http.Redirect(w, r, "/login", http.StatusSeeOther)
        return
    }

    tmpl.ExecuteTemplate(w, "dashboard.html", struct {
        Username string
    }{
        Username: username,
    })
}

// Logout
func logoutHandler(w http.ResponseWriter, r *http.Request) {
    session, _ := store.Get(r, "session")
    session.Options.MaxAge = -1
    session.Save(r, w)
    http.Redirect(w, r, "/login", http.StatusSeeOther)
}
