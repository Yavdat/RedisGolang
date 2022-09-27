package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"time"
	"encoding/json"
	"math/rand"

	"github.com/garyburd/redigo/redis"
)

var (
	redisAddr = flag.String("addr", "redis://user:@localhost:6379/0", "redis addr")

	sessManager *SessionManager

	users = map[string]string{
		"yakkuzhin":        "test",
		"rb02": "100500",
	}
)

type Session struct {
	Login     string
	Useragent string
}

type SessionID struct {
	ID string
}

const sessKeyLen = 10

type SessionManager struct {
	redisConn redis.Conn
}

func NewSessionManager(conn redis.Conn) *SessionManager {
	return &SessionManager{
		redisConn: conn,
	}
}

func (sm *SessionManager) Create(in *Session) (*SessionID, error) {
	id := SessionID{RandStringRunes(sessKeyLen)}
	dataSerialized, _ := json.Marshal(in)
	mkey := "sessions:" + id.ID
	data, err := sm.redisConn.Do("SET", mkey, dataSerialized, "EX", 86400)
	result, err := redis.String(data, err)
	if err != nil {
		return nil, err
	}
	if result != "OK" {
		return nil, fmt.Errorf("result not OK")
	}
	return &id, nil
}

func (sm *SessionManager) Check(in *SessionID) *Session {
	mkey := "sessions:" + in.ID
	log.Println("mkey", mkey)
	data, err := redis.Bytes(sm.redisConn.Do("GET", mkey))
	if err != nil {
		log.Println("cant get data:", err)
		return nil
	}
	sess := &Session{}
	err = json.Unmarshal(data, sess)
	if err != nil {
		log.Println("cant unpack session data:", err)
		return nil
	}
	return sess
}

func (sm *SessionManager) Delete(in *SessionID) {
	mkey := "sessions:" + in.ID
	_, err := redis.Int(sm.redisConn.Do("DEL", mkey))
	if err != nil {
		log.Println("redis error:", err)
	}
}

var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

func RandStringRunes(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}


func checkSession(r *http.Request) (*Session, error) {
	cookieSessionID, err := r.Cookie("session_id")
	if err == http.ErrNoCookie {
		return nil, nil
	} else if err != nil {
		return nil, err
	}

	sess := sessManager.Check(&SessionID{
		ID: cookieSessionID.Value,
	})
	return sess, nil
}

func innerPage(w http.ResponseWriter, r *http.Request) {
	sess, err := checkSession(r)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if sess == nil {
		w.Write(loginFormTmpl)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintln(w, "Welcome, "+sess.Login+" <br />")
	fmt.Fprintln(w, "Session ua: "+sess.Useragent+" <br />")
	fmt.Fprintln(w, `<a href="/logout">logout</a>`)
}

func loginPage(w http.ResponseWriter, r *http.Request) {
	inputLogin := r.FormValue("login")
	inputPass := r.FormValue("password")
	expiration := time.Now().Add(24 * time.Hour)

	pass, exist := users[inputLogin]
	if !exist || pass != inputPass {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	sess, err := sessManager.Create(&Session{
		Login:     inputLogin,
		Useragent: r.UserAgent(),
	})
	if err != nil {
		log.Println("cant create session:", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	cookie := http.Cookie{
		Name:    "session_id",
		Value:   sess.ID,
		Expires: expiration,
	}
	http.SetCookie(w, &cookie)
	http.Redirect(w, r, "/", http.StatusFound)
}

func main() {
	flag.Parse()

	var err error

	// установим соединение
	redisConn, err := redis.DialURL(*redisAddr)
	if err != nil {
		log.Fatalf("cant connect to redis")
	}
	// тут просто возвращаем соединения
	/*
		return &SessionManager{
			redisConn: conn,
		}
	*/
	sessManager = NewSessionManager(redisConn)

	http.HandleFunc("/", innerPage)
	http.HandleFunc("/login", loginPage)
	http.HandleFunc("/logout", logoutPage)

	fmt.Println("starting server at :8086")
	http.ListenAndServe(":8086", nil)
}

func logoutPage(w http.ResponseWriter, r *http.Request) {
	session, err := r.Cookie("session_id")
	if err == http.ErrNoCookie {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	} else if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	sessManager.Delete(&SessionID{
		ID: session.Value,
	})

	session.Expires = time.Now().AddDate(0, 0, -1)
	http.SetCookie(w, session)

	http.Redirect(w, r, "/", http.StatusFound)
}

var loginFormTmpl = []byte(`
	<html>
		<body>
		<form action="/login" method="post">
			Login: <input type="text" name="login">
			Password: <input type="password" name="password">
			<input type="submit" value="Login">
		</form>
		</body>
	</html>
	`)
