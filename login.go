package login

import (
	"log"
	"net/http"

	"github.com/alexedwards/scs"
	"github.com/markbates/goth"
)

// SetSession defines session store
func SetSession(session *scs.Manager) {
	store = session
}

type Router interface {
	Get(pattern string, handlerFn http.HandlerFunc)
}
type Handler interface {
	Login(req *http.Request, res http.ResponseWriter, email string) string
	Logout(req *http.Request, res http.ResponseWriter) string
}

// SetProvider defines auth provider
func SetProvider(provider goth.Provider, r Router, loginURL, logoutURL, callbackURL string, handler Handler) {
	goth.UseProviders(provider)
	name := provider.Name()

	//add routes
	r.Get(callbackURL, func(res http.ResponseWriter, req *http.Request) {
		user, err := completeUserAuth(res, req, name)
		if err != nil {
			log.Printf("Can't complete user's authentication, %s", err.Error())
			return
		}

		redirect(res, handler.Login(req, res, user.Email))
	})

	r.Get(loginURL, func(res http.ResponseWriter, req *http.Request) {
		// try to get the user without re-authenticating
		if user, err := completeUserAuth(res, req, name); err == nil {
			redirect(res, handler.Login(req, res, user.Email))
		} else {
			beginAuthHandler(res, req, name)
		}
	})

	r.Get(logoutURL, func(res http.ResponseWriter, req *http.Request) {
		_ = logout(res, req, name)
		redirect(res, handler.Logout(req, res))
	})
}

func redirect(res http.ResponseWriter, url string) {
	res.Header().Set("Location", url)
	res.WriteHeader(http.StatusTemporaryRedirect)
}
