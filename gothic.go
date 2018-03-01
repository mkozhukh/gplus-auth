package auth

/*
https://github.com/markbates/goth/tree/master/gothic

- gorilla.mux replaced with chi.URLParam
- gorilla.session replaced with scs
*/

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/alexedwards/scs"
	"github.com/go-chi/chi"
	"github.com/markbates/goth"
)

// Store can/should be set by applications using gothic. The default is a cookie store.
var store *scs.Manager
var gothicRand *rand.Rand

func init() {
	gothicRand = rand.New(rand.NewSource(time.Now().UnixNano()))
}

/*
BeginAuthHandler is a convenience handler for starting the authentication process.
It expects to be able to get the name of the provider from the query parameters
as either "provider" or ":provider".

BeginAuthHandler will redirect the user to the appropriate authentication end-point
for the requested provider.

See https://github.com/markbates/goth/examples/main.go to see this in action.
*/
func beginAuthHandler(res http.ResponseWriter, req *http.Request) {
	url, err := getAuthURL(res, req)
	if err != nil {
		res.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(res, err)
		return
	}

	http.Redirect(res, req, url, http.StatusTemporaryRedirect)
}

// setState sets the state string associated with the given request.
// If no state string is associated with the request, one will be generated.
// This state is sent to the provider and can be retrieved during the
// callback.
var setState = func(req *http.Request) string {
	state := req.URL.Query().Get("state")
	if len(state) > 0 {
		return state
	}

	// If a state query param is not passed in, generate a random
	// base64-encoded nonce so that the state on the auth URL
	// is unguessable, preventing CSRF attacks, as described in
	//
	// https://auth0.com/docs/protocols/oauth2/oauth-state#keep-reading
	nonceBytes := make([]byte, 64)
	for i := 0; i < 64; i++ {
		nonceBytes[i] = byte(gothicRand.Int63() % 256)
	}
	return base64.URLEncoding.EncodeToString(nonceBytes)
}

// getState gets the state returned by the provider during the callback.
// This is used to prevent CSRF attacks, see
// http://tools.ietf.org/html/rfc6749#section-10.12
var getState = func(req *http.Request) string {
	return req.URL.Query().Get("state")
}

/*
GetAuthURL starts the authentication process with the requested provided.
It will return a URL that should be used to send users to.

It expects to be able to get the name of the provider from the query parameters
as either "provider" or ":provider".

I would recommend using the BeginAuthHandler instead of doing all of these steps
yourself, but that's entirely up to you.
*/
func getAuthURL(res http.ResponseWriter, req *http.Request) (string, error) {
	providerName, err := getProviderName(req)
	if err != nil {
		return "", err
	}

	provider, err := goth.GetProvider(providerName)
	if err != nil {
		return "", err
	}
	sess, err := provider.BeginAuth(setState(req))
	if err != nil {
		return "", err
	}

	url, err := sess.GetAuthURL()
	if err != nil {
		return "", err
	}

	err = storeInSession(providerName, sess.Marshal(), req, res)

	if err != nil {
		return "", err
	}

	return url, err
}

/*
CompleteUserAuth does what it says on the tin. It completes the authentication
process and fetches all of the basic information about the user from the provider.

It expects to be able to get the name of the provider from the query parameters
as either "provider" or ":provider".

See https://github.com/markbates/goth/examples/main.go to see this in action.
*/
var completeUserAuth = func(res http.ResponseWriter, req *http.Request) (goth.User, error) {
	defer logout(res, req)

	providerName, err := getProviderName(req)
	if err != nil {
		return goth.User{}, err
	}

	provider, err := goth.GetProvider(providerName)
	if err != nil {
		return goth.User{}, err
	}

	value, err := getFromSession(providerName, req)
	if err != nil {
		return goth.User{}, err
	}

	sess, err := provider.UnmarshalSession(value)
	if err != nil {
		return goth.User{}, err
	}

	err = validateState(req, sess)
	if err != nil {
		return goth.User{}, err
	}

	user, err := provider.FetchUser(sess)
	if err == nil {
		// user can be found with existing session data
		return user, err
	}

	// get new token and retry fetch
	_, err = sess.Authorize(provider, req.URL.Query())
	if err != nil {
		return goth.User{}, err
	}

	err = storeInSession(providerName, sess.Marshal(), req, res)

	if err != nil {
		return goth.User{}, err
	}

	gu, err := provider.FetchUser(sess)
	return gu, err
}

// validateState ensures that the state token param from the original
// AuthURL matches the one included in the current (callback) request.
func validateState(req *http.Request, sess goth.Session) error {
	rawAuthURL, err := sess.GetAuthURL()
	if err != nil {
		return err
	}

	authURL, err := url.Parse(rawAuthURL)
	if err != nil {
		return err
	}

	originalState := authURL.Query().Get("state")
	if originalState != "" && (originalState != req.URL.Query().Get("state")) {
		return errors.New("state token mismatch")
	}
	return nil
}

// Logout invalidates a user session.
func logout(res http.ResponseWriter, req *http.Request) error {
	session := store.Load(req)

	name, err := getProviderName(req)
	if err != nil {
		return errors.New("Can't detect provider")
	}

	err = session.Remove(res, name)
	if err != nil {
		return errors.New("Could not delete user session ")
	}
	return nil
}

func getProviderName(req *http.Request) (string, error) {
	// try to get it from the context's value of "provider" key
	if p := chi.URLParam(req, "provider"); p != "" {
		return p, nil
	}

	// if not found then return an empty string with the corresponding error
	return "", errors.New("you must select a provider")
}

func storeInSession(key string, value string, req *http.Request, res http.ResponseWriter) error {
	session := store.Load(req)
	return updateSessionValue(res, session, key, value)
}

func getFromSession(key string, req *http.Request) (string, error) {
	session := store.Load(req)
	value, err := getSessionValue(session, key)
	if err != nil {
		log.Print(err.Error())
		return "", errors.New("could not find a matching session for this request")
	}

	return value, nil
}

func getSessionValue(session *scs.Session, key string) (string, error) {
	value, err := session.GetBytes(key)
	if err != nil {
		return "", fmt.Errorf("could not find a matching session for this request")
	}
	rdata := strings.NewReader(string(value))
	r, err := gzip.NewReader(rdata)
	if err != nil {
		return "", err
	}
	s, err := ioutil.ReadAll(r)
	if err != nil {
		return "", err
	}

	return string(s), nil
}

func updateSessionValue(w http.ResponseWriter, session *scs.Session, key, value string) error {
	var b bytes.Buffer
	gz := gzip.NewWriter(&b)
	if _, err := gz.Write([]byte(value)); err != nil {
		return err
	}
	if err := gz.Flush(); err != nil {
		return err
	}
	if err := gz.Close(); err != nil {
		return err
	}

	return session.PutBytes(w, key, b.Bytes())
}
