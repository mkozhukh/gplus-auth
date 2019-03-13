Authentication for Go
---------------------

Based on https://github.com/markbates/goth

- doesn't use gorilla.mux and gorilla.session
- uses github.com/alexedwards/scs for cookies

### How to use

```go
import (
	"github.com/mkozhukh/login"
	"github.com/markbates/goth/providers/google"
)

...
login.SetSession(sessionManager)
login.SetProvider(
	google.New(Key, Secret, Callback),
	router,
	"/login", "/logout", "/callback",
	handler
)
```

Where router and handler are

```go
type Router interface {
	Get(pattern string, handlerFn http.HandlerFunc)
}
type Handler interface {
	Login(req *http.Request, res http.ResponseWriter, email string) string
	Logout(req *http.Request, res http.ResponseWriter) string
}
```

