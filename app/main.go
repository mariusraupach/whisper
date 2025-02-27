package main

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"sync"

	"github.com/gin-gonic/gin"
)

type Store struct {
	secrets map[string]string
	mutex   sync.RWMutex
}

func createToken() (string, error) {
	b := make([]byte, 32)

	if _, err := rand.Read(b); err != nil {
		return "", err
	}

	return hex.EncodeToString(b), nil
}

func getScheme(c *gin.Context) string {
	if c.Request.TLS != nil {
		return "https"
	}

	if c.GetHeader("X-Forwarded-Proto") == "https" {
		return "https"
	}

	return "http"
}

func main() {
	r := gin.Default()

	store := &Store{
		secrets: make(map[string]string),
	}

	r.POST("/api/secret", func(c *gin.Context) {
		var obj struct {
			Secret string `json:"secret" binding:"required"`
		}

		if err := c.ShouldBindJSON(&obj); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		token, err := createToken()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create Token"})

			return
		}

		store.mutex.Lock()
		defer store.mutex.Unlock()

		store.secrets[token] = obj.Secret

		url := getScheme(c) + "://" + c.Request.Host + "/secret/" + token

		c.JSON(http.StatusOK, gin.H{
			"message": "Secret stored",
			"url":     url,
		})
	})

	r.GET("/secret/:token", func(c *gin.Context) {
		token := c.Param("token")

		store.mutex.Lock()
		defer store.mutex.Unlock()

		secret, exists := store.secrets[token]
		if !exists {
			c.JSON(http.StatusNotFound, gin.H{"error": "Token not found"})
			return
		}

		delete(store.secrets, token)

		c.JSON(http.StatusOK, gin.H{
			"secret": secret,
		})
	})

	r.Run()
}
