package auth

import (
	"net/http"

	"github.com/alexedwards/scs"
	"github.com/go-chi/chi"
	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/gplus"

	log "github.com/sirupsen/logrus"
)

// Config stores external auth service credentials
type Config struct {
	Key      string
	Secret   string
	Callback string
}

// UserInfo stores info about user access
type UserInfo struct {
	Access AccessType
	Email  string
}

// UnmarshalYAML converts yaml to UserInfo structure
func (u *UserInfo) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var temp struct {
		Email  string `yaml:"email"`
		Access string `yaml:"access"`
	}

	err := unmarshal(&temp)
	if err != nil {
		return err
	}

	var ok bool
	u.Email = temp.Email
	u.Access, ok = codes[temp.Access]

	if !ok {
		u.Access = NoneAccess
	}

	return nil
}

// NewProvider creates new Auth Provider
func NewProvider(cfg *Config, session *scs.Manager, users []UserInfo) *Provider {
	t := Provider{}
	t.DeniedPage = "/auth-denied"
	t.SuccessPage = "/"
	t.DefaultProvider = "gplus"
	t.UserList = users
	t.Session = session

	store = session

	goth.UseProviders(
		gplus.New(cfg.Key, cfg.Secret, cfg.Callback+"/gplus/callback"),
	)

	return &t
}

// Provider is a host for the auth process
type Provider struct {
	DeniedPage      string
	SuccessPage     string
	DefaultProvider string

	Session  *scs.Manager
	UserList []UserInfo
}

//AccessType is an enumeration of possible access levels
type AccessType int

const (
	//NoneAccess means access denied
	NoneAccess AccessType = iota
	//AdminAccess gives full access
	AdminAccess
)

var codes = map[string]AccessType{
	"admin": AdminAccess,
}

//GetRouter returns auth router
func (t *Provider) GetRouter() http.Handler {
	r := chi.NewRouter()

	//add routes
	r.Get("/{provider}/callback", func(res http.ResponseWriter, req *http.Request) {
		user, err := completeUserAuth(res, req)
		if err != nil {
			log.Printf("Can't complete user's authentication, %s", err.Error())
			return
		}

		t.gateway(res, req, user.Email)
	})

	r.Get("/{provider}/login", func(res http.ResponseWriter, req *http.Request) {
		// try to get the user without re-authenticating
		if user, err := completeUserAuth(res, req); err == nil {
			t.gateway(res, req, user.Email)
		} else {
			beginAuthHandler(res, req)
		}
	})

	r.Get("/{provider}/logout", func(res http.ResponseWriter, req *http.Request) {
		logout(res, req)
		redirect(res, t.SuccessPage)
	})

	return r
}

//GetAccess returns acess type for the current user
func (t *Provider) GetAccess(req *http.Request) AccessType {
	email, err := t.Session.Load(req).GetString("email")
	if err != nil || email == "" {
		return NoneAccess
	}

	return t.getAccessByEmail(email)
}

func (t *Provider) getAccessByEmail(email string) AccessType {
	for _, el := range t.UserList {
		if el.Email == email {
			return el.Access
		}
	}

	return NoneAccess
}

// CheckAccess confirms that user has one of provided user levels
func (t *Provider) CheckAccess(req *http.Request, types ...AccessType) bool {
	access := t.GetAccess(req)
	for _, el := range types {
		if el == access {
			return true
		}
	}
	return false
}

// GuardAccess middleware, checks user access and redirects user to "denied" page if they have not a required access
func (t *Provider) GuardAccess(types ...AccessType) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !t.CheckAccess(r, types...) {
				http.Redirect(w, r, t.DeniedPage, http.StatusTemporaryRedirect)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func (t *Provider) gateway(res http.ResponseWriter, req *http.Request, email string) {
	access := t.getAccessByEmail(email)
	if access == NoneAccess {
		redirect(res, t.DeniedPage)
		return
	}

	if t.Session.Load(req).PutString(res, "email", email) != nil {
		log.Error("Can't save auth info into session")
		redirect(res, t.DeniedPage)
		return
	}

	redirect(res, t.SuccessPage)
}

func redirect(res http.ResponseWriter, url string) {
	res.Header().Set("Location", url)
	res.WriteHeader(http.StatusTemporaryRedirect)
}
