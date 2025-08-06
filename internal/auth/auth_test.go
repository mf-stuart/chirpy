package auth

import (
	"github.com/google/uuid"
	"os"
	"testing"
	"time"
)

func TestPasswordHashing(t *testing.T) {
	t.Run("correct password", func(t *testing.T) {
		password := "password123"
		hash, err := HashPassword(password)
		if err != nil {
			t.Fatalf("HashPassword() error = %v", err)
		}
		if err := CheckPasswordHash(password, hash); err != nil {
			t.Fatalf("CheckPasswordHash() error = %v", err)
		}
	})

	t.Run("wrong password", func(t *testing.T) {
		password := "password123"
		hash, _ := HashPassword(password)
		if err := CheckPasswordHash("wrong123", hash); err == nil {
			t.Fatal("Expected error for incorrect password, got nil")
		}
	})
}

func TestJWT(t *testing.T) {
	var tokenSecret string = os.Getenv("TOKEN_SECRET")
	testUUID := uuid.New()
	tokenString, err := MakeJWT(testUUID, tokenSecret, time.Hour)
	if err != nil {
		t.Fatalf("MakeJWT() error = %v", err)
	}
	actualUUID, err := ValidateJWT(tokenString, tokenSecret)
	if err != nil {
		t.Fatalf("ValidateJWT() error = %v", err)
	}
	if actualUUID != testUUID {
		t.Fatalf("ValidateJWT() = %v, want %v", actualUUID, testUUID)
	}
}
