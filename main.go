package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/golang-jwt/jwt"
)

type User struct {
	Hash string `json:"hash"` // Base64 encoded password hash
	Salt string `json:"salt"` // Base64 encoded password salt
}

// "Database" for registered users
var users = map[string]User{}

// Private key for signing JWT tokens
// It should be passed as ENV variable in real prod.
var privkey = []byte("XhQ03bPZpblI0rzJFZYUqv/13DNPGqSWGzIS+bAzO3c=")

// Write HTTP response with JSON encoded body
func respondWithJson(w http.ResponseWriter, status int, body interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.Encode(body)
}

// Write HTTP response with JSON encoded error
// In real app this would be API-wise standard
// error object like:
// {
// 	error: "bad_token"	// Generic error code
//  description: "Token signed with wrong method"	// Short description of what happened
// }
func respondWithError(w http.ResponseWriter, status int, err string) {
	respondWithJson(w, status, map[string]string{
		"error": err,
	})
}

// Test for JWT token, only accepts signed-in users
func getCoffeeHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("token")
	if err != nil {
		respondWithError(w, http.StatusTeapot, "Coffeepot functionality is available only for logged in users")
		return
	}

	jwtToken, err := jwt.Parse(cookie.Value, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("bad signing method: %v", token.Header["alg"])
		}

		// All good, return private key
		return privkey, nil
	})

	// Failed to parse token or token is forged
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	if claims, ok := jwtToken.Claims.(jwt.MapClaims); ok {
		if uid, ok := claims["uid"]; ok {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(fmt.Sprintf("Brewing coffee for %v", uid)))
			return
		}

		// Something is really bad with token
		// as it doesn't include "uid" claim
		respondWithError(w, http.StatusBadRequest, "Invalid token")
		return
	}

	w.WriteHeader(http.StatusInternalServerError)
}

// Writes all users data in response; used to check hashes and salts
// obviously this shouldn't be in any app at any time
func getUsersHandler(w http.ResponseWriter, r *http.Request) {
	respondWithJson(w, http.StatusOK, users)
}

// Accept login form and write cookie with JWT if login was successful
func postLoginHandler(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Retrieve form data
	userLogin := r.FormValue("username")
	userPassword := r.FormValue("password")

	// Check if user exists
	if user, found := users[userLogin]; found {
		// Generate password hash
		userSalt, err := base64.StdEncoding.DecodeString(user.Salt) // Decoded user's salt
		if err != nil {
			respondWithError(w, http.StatusInternalServerError, err.Error())
			return
		}

		userPassHash := sha512.Sum512(append([]byte(userPassword), userSalt...))
		userHashDecoded, err := base64.StdEncoding.DecodeString(user.Hash)
		if err != nil {
			respondWithError(w, http.StatusInternalServerError, err.Error())
			return
		}

		// Check if password was correct
		if bytes.Equal(userPassHash[:], userHashDecoded) {
			// Send cookie with JWT token
			token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
				"uid": userLogin,
			})
			tokenstr, err := token.SignedString(privkey)
			if err != nil {
				respondWithError(w, http.StatusInternalServerError, err.Error())
				return
			}

			cookie := http.Cookie{
				Name:     "token",
				Value:    tokenstr,
				HttpOnly: true,
				// Secure:   true,	// Disabled for learning purpose, in real app this will be true
			}
			http.SetCookie(w, &cookie)
			w.WriteHeader(http.StatusNoContent)
		}
	}

	respondWithError(w, http.StatusUnauthorized, "Wrong user or password")
}

// Register new user (does not log-in automatically)
func postRegisterHandler(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	userLogin := r.FormValue("username")
	userPassword := r.FormValue("password")

	// Check prerequests for login and password
	if len(userLogin) == 0 || len(userPassword) < 8 {
		respondWithError(w, http.StatusBadRequest, "No username or password is too short")
		return
	}

	// Check if user already exists
	if _, ok := users[userLogin]; ok {
		respondWithError(w, http.StatusConflict, "User with that name already exists")
		return
	}

	// Generate random prime number as seed
	prime, _ := rand.Prime(rand.Reader, 128)
	// Create salt for new user
	salt := sha256.Sum256(prime.Bytes())
	// Get hash sum for salted password
	hash := sha512.Sum512(append([]byte(userPassword), salt[:]...))

	// Create DB safe (base64 encoded) salt and hash
	saltb64 := base64.StdEncoding.EncodeToString(salt[:])
	hashb64 := base64.StdEncoding.EncodeToString(hash[:])

	// Add new user to "Database"
	users[userLogin] = User{
		Hash: hashb64,
		Salt: saltb64,
	}

	w.WriteHeader(http.StatusCreated)
}

func main() {
	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Get("/coffee", getCoffeeHandler)
	r.Get("/users", getUsersHandler)
	r.Post("/login", postLoginHandler)
	r.Post("/register", postRegisterHandler)

	http.ListenAndServe(":8080", r)
}
