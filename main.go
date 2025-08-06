package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
	"github.com/mf-stuart/chirpy/internal/auth"
	"github.com/mf-stuart/chirpy/internal/database"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync/atomic"
	"time"
)

const filepathRoot = "."
const port = "8080"
const maxChar = 140
const polkaWebhookUpgrade = "user.upgraded"

type defaultJson map[string]interface{}

type apiConfig struct {
	fileserverHits atomic.Int32
	db             *database.Queries
	tokenSecret    string
	polkaKey       string
}

type User struct {
	ID             uuid.UUID `json:"id"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
	Email          string    `json:"email"`
	HashedPassword string    `json:"password,omitempty"`
	Token          string    `json:"token,omitempty"`
	RefreshToken   string    `json:"refresh_token,omitempty"`
	IsChirpyRed    bool      `json:"is_chirpy_red"`
}

type Chirp struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Body      string    `json:"body"`
	UserID    uuid.UUID `json:"user_id"`
}

var apiCfg apiConfig

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits.Add(1)
		next.ServeHTTP(w, r)
	})
}

func helperAcceptJson(w http.ResponseWriter, r *http.Request) (defaultJson, error) {
	decoder := json.NewDecoder(r.Body)
	req := defaultJson{}
	err := decoder.Decode(&req)
	if err != nil {
		log.Println(err)
		payload, _ := json.Marshal(defaultJson{"error": err.Error()})
		w.WriteHeader(http.StatusBadRequest)
		w.Write(payload)
		return nil, err
	}
	return req, nil
}

func helperValidateLength(w http.ResponseWriter, req defaultJson) bool {
	if v, ok := req["body"]; ok && len(v.(string)) > maxChar {
		err := errors.New("Chirp is too long")
		log.Println(err)
		payload, _ := json.Marshal(map[string]interface{}{"error": err.Error()})
		w.WriteHeader(http.StatusBadRequest)
		w.Write(payload)
		return false
	} else {
		return true
	}
}

func helperValidateProfanity(jsonInput defaultJson) {
	const grawlix string = "****"
	bannedWords := map[string]struct{}{
		"kerfuffle": struct{}{},
		"sharbert":  struct{}{},
		"fornax":    struct{}{},
	}
	wordSlices := strings.Split(jsonInput["body"].(string), " ")
	for i, word := range wordSlices {
		word = strings.ToLower(word)
		if _, ok := bannedWords[word]; ok {
			wordSlices[i] = grawlix
		}
	}
	jsonInput["body"] = strings.Join(wordSlices, " ")
}

func helperValidateChirp(w http.ResponseWriter, chirp defaultJson) bool {
	if !helperValidateLength(w, chirp) {
		return false
	}

	helperValidateProfanity(chirp)
	return true
}

func handlerReadiness(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(http.StatusText(http.StatusOK)))
}

func (cfg *apiConfig) handlerMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	page, err := os.ReadFile(filepathRoot + "/admin/metrics.html")
	if err != nil {
		println(err.Error())
		return
	}
	w.Write([]byte(fmt.Sprintf(string(page), cfg.fileserverHits.Load())))
}

func (cfg *apiConfig) handlerReset(w http.ResponseWriter, r *http.Request) {
	if os.Getenv("PLATFORM") != "dev" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusForbidden)
		return
	}
	cfg.fileserverHits.Store(0)
	cfg.db.ResetUsers(r.Context())
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Reset OK"))
}

func handlerMakeChirp(w http.ResponseWriter, r *http.Request) {
	req, err := helperAcceptJson(w, r)
	if err != nil {
		return
	}

	body, _ := req["body"].(string)
	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(err.Error()))
		return
	}

	userUUID, err := auth.ValidateJWT(token, apiCfg.tokenSecret)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(err.Error()))
	}

	if !helperValidateChirp(w, req) {
		return
	}

	createChirpParams := database.CreateChirpParams{Body: body, UserID: userUUID}
	dbChirp, err := apiCfg.db.CreateChirp(r.Context(), createChirpParams)
	if err != nil {
		log.Println(err)
		payload, _ := json.Marshal(defaultJson{"error": err.Error()})
		w.WriteHeader(http.StatusBadRequest)
		w.Write(payload)
		return
	}

	chirp := Chirp{ID: dbChirp.ID, CreatedAt: dbChirp.CreatedAt, UpdatedAt: dbChirp.UpdatedAt, Body: dbChirp.Body, UserID: dbChirp.UserID}
	payload, _ := json.Marshal(chirp)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	w.Write(payload)
}

func handlerDeleteChirp(w http.ResponseWriter, r *http.Request) {
	chirpId, err := uuid.Parse(r.PathValue("chirp_id"))
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(err.Error()))
		return
	}

	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(err.Error()))
		return
	}

	userUUID, err := auth.ValidateJWT(token, apiCfg.tokenSecret)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(err.Error()))
		return
	}

	dbChirp, err := apiCfg.db.GetChirpById(r.Context(), chirpId)
	if err != nil {
		log.Println(err)
		payload, _ := json.Marshal(defaultJson{"error": err.Error()})
		w.WriteHeader(http.StatusForbidden)
		w.Write(payload)
		return
	}

	if dbChirp.UserID != userUUID {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("Unauthorized"))
		return
	}

	err = apiCfg.db.DeleteChirpById(r.Context(), dbChirp.ID)
	if err != nil {
		log.Println(err)
		payload, _ := json.Marshal(defaultJson{"error": err.Error()})
		w.WriteHeader(http.StatusNotFound)
		w.Write(payload)
		return
	}

	payload, _ := json.Marshal(defaultJson{"success": "Chirp deleted"})
	w.WriteHeader(http.StatusNoContent)
	w.Write(payload)
}

func handlerGetChirp(w http.ResponseWriter, r *http.Request) {
	keyId, err := uuid.Parse(r.PathValue("chirp_id"))
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	dbChirp, err := apiCfg.db.GetChirpById(r.Context(), keyId)
	if err != nil {
		log.Println(err)
		payload, _ := json.Marshal(defaultJson{"error": err.Error()})
		w.WriteHeader(http.StatusNotFound)
		w.Write(payload)
		return
	}

	chirp := Chirp{ID: dbChirp.ID, CreatedAt: dbChirp.CreatedAt, UpdatedAt: dbChirp.UpdatedAt, Body: dbChirp.Body, UserID: dbChirp.UserID}
	payload, _ := json.Marshal(chirp)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(payload)
}

func handlerGetChirps(w http.ResponseWriter, r *http.Request) {
	var dbChirps []database.Chirp
	var err error

	v, ok := r.URL.Query()["author_id"]
	if ok {
		authorId, err := uuid.Parse(v[0])
		if err != nil {
			log.Println(err)
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(err.Error()))
			return
		}
		dbChirps, err = apiCfg.db.GetChirpsByAuthorIdAsc(r.Context(), authorId)
		if err != nil {
			log.Println(err)
			payload, _ := json.Marshal(defaultJson{"error": err.Error()})
			w.WriteHeader(http.StatusNotFound)
			w.Write(payload)
			return
		}
	} else {
		dbChirps, err = apiCfg.db.GetChirpsAsc(r.Context())
		if err != nil {
			log.Println(err)
			payload, _ := json.Marshal(defaultJson{"error": err.Error()})
			w.WriteHeader(http.StatusBadRequest)
			w.Write(payload)
		}
	}

	chirps := make([]Chirp, len(dbChirps))
	for i, dbChirp := range dbChirps {
		chirps[i] = Chirp{ID: dbChirp.ID, CreatedAt: dbChirp.CreatedAt, UpdatedAt: dbChirp.UpdatedAt, Body: dbChirp.Body, UserID: dbChirp.UserID}
	}

	v, ok = r.URL.Query()["sort"]
	if ok {
		switch v[0] {
		case "desc":
			sort.Slice(chirps, func(i, j int) bool {
				return chirps[i].UpdatedAt.After(chirps[j].UpdatedAt)
			})
		default:
			break
		}
	}

	payload, _ := json.Marshal(chirps)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(payload)
}

func handlerAddUser(w http.ResponseWriter, r *http.Request) {
	req, err := helperAcceptJson(w, r)
	if err != nil {
		return
	}

	email := req["email"].(string)
	password := req["password"].(string)
	hashedPassword, err := auth.HashPassword(password)
	if err != nil {
		log.Println(err)
		payload, _ := json.Marshal(defaultJson{"error": err.Error()})
		w.WriteHeader(http.StatusBadRequest)
		w.Write(payload)
		return
	}

	createUserParams := database.CreateUserParams{email, hashedPassword}

	dbUser, err := apiCfg.db.CreateUser(r.Context(), createUserParams)
	user := User{
		ID:          dbUser.ID,
		Email:       dbUser.Email,
		CreatedAt:   dbUser.CreatedAt,
		UpdatedAt:   dbUser.UpdatedAt,
		IsChirpyRed: dbUser.IsChirpyRed,
	}

	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(err.Error()))
		return
	}

	data, err := json.Marshal(user)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(err.Error()))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	w.Write(data)
}

func handlerEditUser(w http.ResponseWriter, r *http.Request) {
	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(err.Error()))
		return
	}

	req, err := helperAcceptJson(w, r)
	if err != nil {
		return
	}

	newEmail := req["email"].(string)
	newPlaintextPassword := req["password"].(string)
	newHashedPassword, err := auth.HashPassword(newPlaintextPassword)
	if err != nil {
		log.Println(err)
		payload, _ := json.Marshal(defaultJson{"error": err.Error()})
		w.WriteHeader(http.StatusBadRequest)
		w.Write(payload)
		return
	}

	userUUID, err := auth.ValidateJWT(token, apiCfg.tokenSecret)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(err.Error()))
		return
	}

	setUserEmailByIdParams := database.SetUserEmailByIdParams{
		ID:    userUUID,
		Email: newEmail,
	}

	setUserHashedPasswordByIdParams := database.SetUserHashedPasswordByIdParams{
		ID:             userUUID,
		HashedPassword: newHashedPassword,
	}

	_, err = apiCfg.db.SetUserEmailById(r.Context(), setUserEmailByIdParams)
	if err != nil {
		log.Println(err)
		payload, _ := json.Marshal(defaultJson{"error": err.Error()})
		w.WriteHeader(http.StatusBadRequest)
		w.Write(payload)
		return
	}

	dbUser, err := apiCfg.db.SetUserHashedPasswordById(r.Context(), setUserHashedPasswordByIdParams)
	if err != nil {
		log.Println(err)
		payload, _ := json.Marshal(defaultJson{"error": err.Error()})
		w.WriteHeader(http.StatusBadRequest)
		w.Write(payload)
		return
	}
	payload, _ := json.Marshal(User{
		ID:          dbUser.ID,
		Email:       dbUser.Email,
		CreatedAt:   dbUser.CreatedAt,
		UpdatedAt:   dbUser.UpdatedAt,
		IsChirpyRed: dbUser.IsChirpyRed,
	})
	w.WriteHeader(http.StatusOK)
	w.Write(payload)
}

func handlerUpgradeUser(w http.ResponseWriter, r *http.Request) {
	polkaKey, err := auth.GetAPIKey(r.Header)
	if err != nil || apiCfg.polkaKey != polkaKey {
		log.Println(err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	req, err := helperAcceptJson(w, r)
	if err != nil {
		return
	}
	if req["event"].(string) != polkaWebhookUpgrade {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	userId, err := uuid.Parse(req["data"].(map[string]interface{})["user_id"].(string))
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	_, err = apiCfg.db.UpgradeUserByID(r.Context(), userId)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func handlerLogin(w http.ResponseWriter, r *http.Request) {
	req, err := helperAcceptJson(w, r)
	if err != nil {
		return
	}
	email := req["email"].(string)
	plainTextPassword := req["password"].(string)

	dbUser, err := apiCfg.db.GetUserByEmail(r.Context(), email)
	if err != nil {
		log.Println(err)
		payload, _ := json.Marshal(defaultJson{"error": err.Error()})
		w.WriteHeader(http.StatusBadRequest)
		w.Write(payload)
		return
	}
	err = auth.CheckPasswordHash(plainTextPassword, dbUser.HashedPassword)
	if err != nil {
		log.Println(err)
		payload, _ := json.Marshal(defaultJson{"error": "Incorrect email or password"})
		w.WriteHeader(http.StatusUnauthorized)
		w.Write(payload)
		return
	}

	token, err := auth.MakeJWT(dbUser.ID, apiCfg.tokenSecret, time.Hour)
	if err != nil {
		log.Println(err)
		payload, _ := json.Marshal(defaultJson{"error": err.Error()})
		w.WriteHeader(http.StatusBadRequest)
		w.Write(payload)
		return
	}

	refreshToken, err := auth.MakeRefreshToken()
	if err != nil {
		log.Println(err)
		payload, _ := json.Marshal(defaultJson{"error": err.Error()})
		w.WriteHeader(http.StatusBadRequest)
		w.Write(payload)
		return
	}

	createRefreshTokenParams := database.CreateRefreshTokenParams{refreshToken, dbUser.ID}

	_, err = apiCfg.db.CreateRefreshToken(r.Context(), createRefreshTokenParams)
	if err != nil {
		log.Println(err)
		payload, _ := json.Marshal(defaultJson{"error": err.Error()})
		w.WriteHeader(http.StatusBadRequest)
		w.Write(payload)
		return
	}

	payload, _ := json.Marshal(User{
		ID:           dbUser.ID,
		Email:        dbUser.Email,
		CreatedAt:    dbUser.CreatedAt,
		UpdatedAt:    dbUser.UpdatedAt,
		Token:        token,
		RefreshToken: refreshToken,
		IsChirpyRed:  dbUser.IsChirpyRed,
	})
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(payload)
}

func handlerRefresh(w http.ResponseWriter, r *http.Request) {
	refreshToken, err := auth.GetBearerToken(r.Header)
	if err != nil {
		log.Println(err)
		payload, _ := json.Marshal(defaultJson{"error": err.Error()})
		w.WriteHeader(http.StatusBadRequest)
		w.Write(payload)
	}

	dbRefreshToken, err := apiCfg.db.GetRefreshToken(r.Context(), refreshToken)
	if err != nil || dbRefreshToken.ExpiresAt.Before(time.Now()) || dbRefreshToken.RevokedAt.Valid {
		log.Println(err)
		payload, _ := json.Marshal(defaultJson{"error": "token denied"})
		w.WriteHeader(http.StatusUnauthorized)
		w.Write(payload)
		return
	}

	dbUser, err := apiCfg.db.GetUserByRefreshToken(r.Context(), refreshToken)
	if err != nil {
		log.Println(err)
		payload, _ := json.Marshal(defaultJson{"error": err.Error()})
		w.WriteHeader(http.StatusBadRequest)
		w.Write(payload)
		return
	}

	newAccessToken, err := auth.MakeJWT(dbUser.ID, apiCfg.tokenSecret, time.Hour)
	if err != nil {
		log.Println(err)
		payload, _ := json.Marshal(defaultJson{"error": err.Error()})
		w.WriteHeader(http.StatusBadRequest)
		w.Write(payload)
		return
	}

	payload, _ := json.Marshal(defaultJson{"token": newAccessToken})
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(payload)
}

func handlerRevoke(w http.ResponseWriter, r *http.Request) {
	refreshToken, err := auth.GetBearerToken(r.Header)
	if err != nil {
		log.Println(err)
		payload, _ := json.Marshal(defaultJson{"error": err.Error()})
		w.WriteHeader(http.StatusBadRequest)
		w.Write(payload)
		return
	}

	_, err = apiCfg.db.SetRevoked(r.Context(), refreshToken)
	if err != nil {
		log.Println(err)
		payload, _ := json.Marshal(defaultJson{"error": err.Error()})
		w.WriteHeader(http.StatusBadRequest)
		w.Write(payload)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func main() {
	godotenv.Load()
	dbUrl := os.Getenv("DATABASE_URL")
	db, _ := sql.Open("postgres", dbUrl)
	dbQueries := database.New(db)

	apiCfg.db = dbQueries
	apiCfg.tokenSecret = os.Getenv("TOKEN_SECRET")
	apiCfg.polkaKey = os.Getenv("POLKA_KEY")
	mux := http.NewServeMux()

	mux.Handle("/app/", apiCfg.middlewareMetricsInc(http.StripPrefix("/app", http.FileServer(http.Dir(filepathRoot)))))
	mux.Handle("/assets/logo.png", http.FileServer(http.Dir(".")))
	mux.HandleFunc("GET /admin/metrics", apiCfg.handlerMetrics)
	mux.HandleFunc("POST /admin/reset", apiCfg.handlerReset)
	mux.HandleFunc("GET /api/healthz", handlerReadiness)
	mux.HandleFunc("POST /api/users", handlerAddUser)
	mux.HandleFunc("POST /api/login", handlerLogin)
	mux.HandleFunc("PUT /api/users", handlerEditUser)
	mux.HandleFunc("POST /api/polka/webhooks", handlerUpgradeUser)
	mux.HandleFunc("POST /api/chirps", handlerMakeChirp)
	mux.HandleFunc("DELETE /api/chirps/{chirp_id}", handlerDeleteChirp)
	mux.HandleFunc("GET /api/chirps", handlerGetChirps)
	mux.HandleFunc("GET /api/chirps/{chirp_id}", handlerGetChirp)
	mux.HandleFunc("POST /api/refresh", handlerRefresh)
	mux.HandleFunc("POST /api/revoke", handlerRevoke)

	myHttpServer := http.Server{
		Handler: mux,
		Addr:    ":" + port,
	}

	log.Printf("Serving files from %s on port: %s\n", filepathRoot, port)
	log.Fatal(myHttpServer.ListenAndServe())
}
