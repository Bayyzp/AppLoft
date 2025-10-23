package main

import (
    "archive/zip"
    "crypto/rand"
    "database/sql"
    "encoding/hex"
    "fmt"
    "html/template"
    "io"
    "log"
    "mime/multipart"
    "net/http"
    "net/http/httputil"
    "net/url"
    "os"
    "os/exec"
    "path/filepath"
    "strconv"
    "strings"
    "sync"
    "time"

    _ "github.com/mattn/go-sqlite3"
    "golang.org/x/crypto/bcrypt"
)

var templates = template.Must(template.ParseGlob("templates/*.html"))

type Server struct {
    db *sql.DB
    mu sync.Mutex
    nextPort int
    procs map[int]*os.Process
}

func main() {
    db, err := sql.Open("sqlite3", "data.db")
    if err != nil {
        log.Fatal(err)
    }
    if err := initDB(db); err != nil {
        log.Fatal(err)
    }

    srv := &Server{
        db: db,
        nextPort: 30000,
        procs: make(map[int]*os.Process),
    }

    mux := http.NewServeMux()
    mux.HandleFunc("/", srv.handleIndex)
    mux.HandleFunc("/register", srv.handleRegister)
    mux.HandleFunc("/login", srv.handleLogin)
    mux.HandleFunc("/logout", srv.handleLogout)
    mux.HandleFunc("/dashboard", srv.requireAuth(srv.handleDashboard))
    mux.HandleFunc("/upload", srv.requireAuth(srv.handleUpload))
    mux.HandleFunc("/apps/", srv.requireAuth(srv.handleApps))
    mux.HandleFunc("/proxy/", srv.handleProxy) // internal health check proxy route

    // Reverse proxy by Host header
    mux.HandleFunc("/r/", srv.handleReverseProxy) // alternate: for Host header proxying

    addr := ":8080"
    log.Printf("Server starting on %s", addr)
    log.Fatal(http.ListenAndServe(addr, mux))
}

// --- Database ---
func initDB(db *sql.DB) error {
    queries := []string{
        `CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password TEXT);`,
        `CREATE TABLE IF NOT EXISTS apps (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, name TEXT, domain TEXT, port INTEGER, dir TEXT);`,
    }
    for _, q := range queries {
        if _, err := db.Exec(q); err != nil {
            return err
        }
    }
    return nil
}

// --- Templates / Helpers ---
func render(w http.ResponseWriter, name string, data interface{}) {
    if err := templates.ExecuteTemplate(w, name, data); err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
    }
}

func randToken(n int) string {
    b := make([]byte, n)
    _, _ = rand.Read(b)
    return hex.EncodeToString(b)
}

// --- Auth ---
func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        sid, err := r.Cookie("session")
        if err != nil || sid.Value == "" {
            http.Redirect(w, r, "/login", http.StatusSeeOther)
            return
        }
        var uid int
        err = s.db.QueryRow("SELECT user_id FROM sessions WHERE token = ?", sid.Value).Scan(&uid)
        if err != nil {
            http.Redirect(w, r, "/login", http.StatusSeeOther)
            return
        }
        ctx := r.Context()
        ctx = contextWithUserID(ctx, uid)
        next(w, r.WithContext(ctx))
    }
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
    render(w, "index.html", nil)
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
    if r.Method == http.MethodGet {
        render(w, "register.html", nil)
        return
    }
    username := r.FormValue("username")
    password := r.FormValue("password")
    if username == "" || password == "" {
        http.Error(w, "missing", http.StatusBadRequest)
        return
    }
    hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
    _, err := s.db.Exec("INSERT INTO users (username, password) VALUES (?, ?)", username, string(hash))
    if err != nil {
        http.Error(w, "username taken", http.StatusBadRequest)
        return
    }
    http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
    if r.Method == http.MethodGet {
        render(w, "login.html", nil)
        return
    }
    username := r.FormValue("username")
    password := r.FormValue("password")
    var id int
    var hash string
    err := s.db.QueryRow("SELECT id, password FROM users WHERE username = ?", username).Scan(&id, &hash)
    if err != nil {
        http.Error(w, "invalid credentials", http.StatusUnauthorized)
        return
    }
    if bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) != nil {
        http.Error(w, "invalid credentials", http.StatusUnauthorized)
        return
    }
    token := randToken(16)
    // create sessions table if not exists
    s.db.Exec(`CREATE TABLE IF NOT EXISTS sessions (token TEXT PRIMARY KEY, user_id INTEGER, created_at DATETIME)`)
    _, err = s.db.Exec("INSERT INTO sessions (token, user_id, created_at) VALUES (?, ?, datetime('now'))", token, id)
    if err != nil {
        http.Error(w, "internal", http.StatusInternalServerError)
        return
    }
    http.SetCookie(w, &http.Cookie{Name: "session", Value: token, Path: "/", HttpOnly: true})
    http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
    c := &http.Cookie{Name: "session", Value: "", Path: "/", MaxAge: -1}
    http.SetCookie(w, c)
    http.Redirect(w, r, "/", http.StatusSeeOther)
}

// --- Dashboard & Upload ---
func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
    uid := userIDFromContext(r.Context())
    rows, _ := s.db.Query("SELECT id, name, domain, port FROM apps WHERE user_id = ?", uid)
    type App struct {ID int; Name, Domain string; Port int}
    apps := []App{}
    for rows.Next() {
        var a App
        rows.Scan(&a.ID, &a.Name, &a.Domain, &a.Port)
        apps = append(apps, a)
    }
    render(w, "dashboard.html", map[string]interface{}{"Apps": apps})
}

func (s *Server) handleUpload(w http.ResponseWriter, r *http.Request) {
    if r.Method == http.MethodGet {
        render(w, "upload.html", nil)
        return
    }
    uid := userIDFromContext(r.Context())
    r.ParseMultipartForm(32 << 20)
    file, hdr, err := r.FormFile("project")
    if err != nil {
        http.Error(w, "missing file", http.StatusBadRequest)
        return
    }
    defer file.Close()
    appName := r.FormValue("name")
    domain := r.FormValue("domain")
    if appName == "" {
        http.Error(w, "missing app name", http.StatusBadRequest)
        return
    }
    // allocate dir
    base := filepath.Join("apps", strconv.Itoa(uid), appName)
    os.MkdirAll(base, 0755)
    // save uploaded zip
    zipPath := filepath.Join(base, hdr.Filename)
    out, _ := os.Create(zipPath)
    io.Copy(out, file)
    out.Close()
    // extract
    if err := unzip(zipPath, base); err != nil {
        http.Error(w, "extract failed: "+err.Error(), http.StatusInternalServerError)
        return
    }
    // allocate port and start app
    s.mu.Lock()
    port := s.nextPort
    s.nextPort++
    s.mu.Unlock()
// Start app inside a Docker container via helper script (safer than running on host)
go func() {
    // best-effort: run the helper script which starts a Docker container for the app
    helper := "./scripts/run_app_container.sh"
    // ensure helper is executable
    _ = os.Chmod(helper, 0755)
    cmd := exec.Command("/bin/sh", "-c", helper+" "+strconv.Itoa(uid)+" "+appName+" "+strconv.Itoa(port)+" 3000 256m 0.5")
    cmd.Dir = "."
    out, err := cmd.CombinedOutput()
    if err != nil {
        log.Printf("failed to start container for %s: %v output=%s", base, err, string(out))
        return
    }
    cname := strings.TrimSpace(string(out))
    log.Printf("started container %s for app %s on port %d", cname, appName, port)
}()
    // record in DB
    _, _ = s.db.Exec("INSERT INTO apps (user_id, name, domain, port, dir) VALUES (?, ?, ?, ?, ?)", uid, appName, domain, port, base)
    http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

// helper to run command in dir, returns process pointer if started
func runCmd(dir string, cmd []string) *os.Process {
    if len(cmd) == 0 { return nil }
    c := exec.Command(cmd[0], cmd[1:]...)
    c.Dir = dir
    // redirect output to logs file
    logfile := filepath.Join(dir, "run.log")
    f, _ := os.OpenFile(logfile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
    c.Stdout = f
    c.Stderr = f
    if err := c.Start(); err != nil {
        return nil
    }
    return c.Process
}

func unzip(src, dest string) error {
    r, err := zip.OpenReader(src)
    if err != nil { return err }
    defer r.Close()
    for _, f := range r.File {
        fpath := filepath.Join(dest, f.Name)
        if !strings.HasPrefix(fpath, filepath.Clean(dest)+string(os.PathSeparator)) {
            return fmt.Errorf("illegal file path: %s", fpath)
        }
        if f.FileInfo().IsDir() {
            os.MkdirAll(fpath, f.Mode())
            continue
        }
        if err := os.MkdirAll(filepath.Dir(fpath), 0755); err != nil {
            return err
        }
        outFile, err := os.OpenFile(fpath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
        if err != nil { return err }
        rc, err := f.Open()
        if err != nil { outFile.Close(); return err }
        _, err = io.Copy(outFile, rc)
        outFile.Close()
        rc.Close()
        if err != nil { return err }
    }
    return nil
}

// --- App listing/management ---
func (s *Server) handleApps(w http.ResponseWriter, r *http.Request) {
    // simple static file serving for app logs or files could be added
    http.NotFound(w, r)
}

// --- Reverse proxy based on Host header ---
func (s *Server) handleReverseProxy(w http.ResponseWriter, r *http.Request) {
    host := r.Host
    // strip port if present
    if strings.Contains(host, ":") {
        host = strings.Split(host, ":")[0]
    }
    var port int
    err := s.db.QueryRow("SELECT port FROM apps WHERE domain = ?", host).Scan(&port)
    if err != nil {
        http.Error(w, "No app for host", http.StatusBadGateway)
        return
    }
    target := fmt.Sprintf("http://127.0.0.1:%d", port)
    u, _ := url.Parse(target)
    proxy := httputil.NewSingleHostReverseProxy(u)
    proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, e error) {
        http.Error(w, "upstream error: "+e.Error(), http.StatusBadGateway)
    }
    proxy.ServeHTTP(w, r)
}

// --- minimal context user id (avoid importing context package globally) ---
type key int
const userIDKey key = 0

func contextWithUserID(ctx interface{}, uid int) interface{} {
    // This is a tiny hack: we will actually store the user ID in the request via a cookie lookup each time
    // to avoid pulling in context package complex usage in this template.
    return ctx
}
func userIDFromContext(ctx interface{}) int {
    // not used; requireAuth sets nothing; instead we'll re-check session cookie (simple approach)
    return 0
}
