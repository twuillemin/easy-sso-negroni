package ssomiddleware

import (
	"context"
	"crypto/rsa"
	"errors"
	"github.com/dgrijalva/jwt-go"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/twuillemin/easy-sso-common/pkg/common"
)

// Middleware is a struct that has a ServeHTTP method
type easySSONegroniMiddleware struct {
	publicKey    *rsa.PublicKey
	detailedLogs bool
}

// ssoContextKey is the specific type for storing the authentication information in the context of a request. As by
// official documentation, the use of context implies to use a specific type for keys
type ssoContextKey string

// authenticationKey is the key used to find and retrieve the authentication information from the context
const authenticationKey = ssoContextKey("authentication")

// NewWithDetailedLogs creates a new EasySSO Middleware with detailed logs. As the logs can be quite verbose,
// it is recommended to only use this function for debugging/development purpose. The public key
// is given as the file name having the key stored in a PEM format.
func New(publicKeyFileName string) (*easySSONegroniMiddleware, error) {
	return newMiddleware(publicKeyFileName, false)
}

// NewWithDetailedLogs creates a new EasySSO Middleware with detailed logs. As the logs can be quite verbose,
// it is recommended to only use this function for debugging/development purpose
func NewWithDetailedLogs(publicKeyFileName string) (*easySSONegroniMiddleware, error) {
	return newMiddleware(publicKeyFileName, true)
}

// newMiddleware creates a new EasySSO Middleware
func newMiddleware(publicKeyFileName string, detailedLogs bool) (*easySSONegroniMiddleware, error) {

	// Read the private key for signing token
	publicKeyData, err := ioutil.ReadFile(publicKeyFileName)
	if err != nil {
		log.Printf("easySSONegroniMiddleware::New: The given publicKeyFileName parameter is referencing an unreadable file")
		return nil, err
	}

	publicKey, err := jwt.ParseRSAPublicKeyFromPEM(publicKeyData)
	if err != nil {
		log.Printf("easySSONegroniMiddleware::New: The given publicKeyFileName parameter is referencing a file with unreadble data")
		return nil, err
	}

	return &easySSONegroniMiddleware{
		publicKey:    publicKey,
		detailedLogs: detailedLogs,
	}, nil
}

// The middleware handler
func (middleware *easySSONegroniMiddleware) ServeHTTP(writer http.ResponseWriter, request *http.Request, next http.HandlerFunc) {

	// Use the common package to retrieve authentication
	authenticationInformation, err := common.GetAuthenticationFromRequest(request, middleware.publicKey, middleware.detailedLogs)

	if err != nil {
		switch err {
		case common.ErrMalformedAuthorization:
		case common.ErrTokenMalformed:
			{
				// Write an error and stop the handler chain
				http.Error(writer, "Bad Request", http.StatusBadRequest)
			}
		case common.ErrSignatureInvalid:
		case common.ErrNoAuthorization:
			{
				http.Error(writer, "Unauthorized", http.StatusUnauthorized)
			}
		default:
			{
				http.Error(writer, "Internal Server Error", http.StatusInternalServerError)
			}
		}

		return
	}

	if middleware.detailedLogs {
		log.Printf("easySSONegroniMiddleware::ServeHTTP: authorized user: %v with roles %v", authenticationInformation.User, authenticationInformation.Roles)
	}
	// Build a new request with an updated context
	newRequest := request.WithContext(
		context.WithValue(
			request.Context(),
			authenticationKey,
			authenticationInformation))

	// Update the given request
	*request = *newRequest

	// Pass down the request to the next middleware (or final handler)
	next(writer, request)
}

// GetSsoAuthentication retrieves the authentication information from a request
func GetSsoAuthentication(request *http.Request) (*common.AuthenticationInformation, error) {

	if request == nil {
		return nil, errors.New("no request given")
	}

	// Context is always non nil
	rawValue := request.Context().Value(authenticationKey)
	if rawValue == nil {
		return nil, errors.New("no request does not have authentication information")
	}

	original, ok := rawValue.(*common.AuthenticationInformation)
	if !ok {
		return nil, errors.New("the authentication information is not readable")
	}

	return original, nil
}
