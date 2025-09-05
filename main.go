package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/gorilla/mux"
)

// ServercoreSecret представляет секрет из Servercore API
type ServercoreSecret struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Version     struct {
		VersionID int    `json:"version_id"`
		CreatedAt string `json:"created_at"`
		Value     string `json:"value"`
	} `json:"version"`
}

// WebhookResponse представляет ответ вебхука для ESO
type WebhookResponse struct {
	Namespaces map[string]NamespaceData `json:"namespaces"`
}

// NamespaceData представляет данные namespace для ESO
type NamespaceData struct {
	Secrets map[string]Secret `json:"secrets"`
}

// Secret представляет секрет для ESO
type Secret struct {
	Type     string         `json:"type"`
	Value    string         `json:"value"`
	Metadata SecretMetadata `json:"metadata"`
}

// SecretMetadata представляет метаданные секрета
type SecretMetadata struct {
	Labels            map[string]string `json:"labels"`
	Annotations       map[string]string `json:"annotations"`
	CreationTimestamp string           `json:"creationTimestamp"`
	LastUpdated       string           `json:"lastUpdated"`
}

// AuthRequest представляет запрос для получения токена
type AuthRequest struct {
	Auth struct {
		Identity struct {
			Methods []string `json:"methods"`
			Password struct {
				User struct {
					Name     string `json:"name"`
					Domain   struct {
						Name string `json:"name"`
					} `json:"domain"`
					Password string `json:"password"`
				} `json:"user"`
			} `json:"password"`
		} `json:"identity"`
		Scope struct {
			Project struct {
				Name   string `json:"name"`
				Domain struct {
					Name string `json:"name"`
				} `json:"domain"`
			} `json:"project"`
		} `json:"scope"`
	} `json:"auth"`
}

// TokenCache представляет кэш токена
type TokenCache struct {
	token     string
	expiresAt time.Time
	mutex     sync.RWMutex
	stopChan  chan struct{}
}

// Config представляет конфигурацию приложения
type Config struct {
	ServercoreAPIURL    string
	ServercoreAuthURL   string
	Username            string
	Password            string
	DomainName          string
	ProjectName         string
	LogLevel            string
	Timeout             time.Duration
	MaxRetries          int
	TokenRefreshBuffer  time.Duration
}

// Server представляет HTTP-сервер
type Server struct {
	config     *Config
	client     *http.Client
	tokenCache *TokenCache
}

func main() {
	config := &Config{
		ServercoreAPIURL:   getEnv("SERVERCORE_API_URL", "https://cloud.api.selcloud.ru/secrets-manager/v1"),
		ServercoreAuthURL:  getEnv("SERVERCORE_AUTH_URL", "https://cloud.api.servercore.com/identity/v3/auth/tokens"),
		Username:           getEnv("SERVERCORE_USERNAME", ""),
		Password:           getEnv("SERVERCORE_PASSWORD", ""),
		DomainName:         getEnv("SERVERCORE_DOMAIN_NAME", ""),
		ProjectName:        getEnv("SERVERCORE_PROJECT_NAME", ""),
		LogLevel:           getEnv("LOG_LEVEL", "info"),
		Timeout:            getDurationEnv("TIMEOUT", 30*time.Second),
		MaxRetries:         getIntEnv("MAX_RETRIES", 3),
		TokenRefreshBuffer: getDurationEnv("TOKEN_REFRESH_BUFFER", 1*time.Hour),
	}

	// Проверяем обязательные параметры
	if config.Username == "" || config.Password == "" || config.DomainName == "" || config.ProjectName == "" {
		log.Fatal("SERVERCORE_USERNAME, SERVERCORE_PASSWORD, SERVERCORE_DOMAIN_NAME, and SERVERCORE_PROJECT_NAME environment variables are required")
	}

	server := &Server{
		config: config,
		client: &http.Client{
			Timeout: config.Timeout,
		},
		tokenCache: &TokenCache{
			stopChan: make(chan struct{}),
		},
	}

	// Инициализируем токен при запуске
	log.Printf("Initializing token...")
	if err := server.initializeToken(); err != nil {
		log.Fatalf("Failed to initialize token: %v", err)
	}

	// Запускаем фоновое обновление токена
	go server.startTokenRefresh()

	router := mux.NewRouter()
	
	// Добавляем middleware для логирования всех запросов
	router.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			log.Printf("Request: %s %s", r.Method, r.URL.Path)
			next.ServeHTTP(w, r)
		})
	})
	
	// Основной эндпоинт для ESO
	router.HandleFunc("/webhook", server.webhookHandler).Methods("GET")
	
	// Эндпоинты для проверки здоровья
	router.HandleFunc("/health", server.healthHandler).Methods("GET")
	router.HandleFunc("/ready", server.readyHandler).Methods("GET")

	log.Printf("Starting server on :8081 with config: API_URL=%s, Auth_URL=%s, Username=%s, Domain=%s, Project=%s, LogLevel=%s, Timeout=%v, MaxRetries=%d", 
		config.ServercoreAPIURL, config.ServercoreAuthURL, config.Username, config.DomainName, config.ProjectName, config.LogLevel, config.Timeout, config.MaxRetries)
	log.Fatal(http.ListenAndServe(":8081", router))
}

func (s *Server) webhookHandler(w http.ResponseWriter, r *http.Request) {
	// Получаем ключ секрета из заголовка или query параметра
	secretKey := r.Header.Get("X-Request-ID")
	if secretKey == "" {
		secretKey = r.URL.Query().Get("key")
	}

	// Получаем конкретное поле из query параметра
	fieldKey := r.URL.Query().Get("field")

	if secretKey == "" {
		http.Error(w, "Missing secret key", http.StatusBadRequest)
		return
	}

	log.Printf("Received request for secret: %s, field: %s", secretKey, fieldKey)

	// Получаем токен из кэша
	token := s.getToken()

	// Получаем секрет из Servercore API
	secret, err := s.fetchSecretFromServercore(secretKey, token)
	if err != nil {
		log.Printf("Error fetching secret %s: %v", secretKey, err)
		http.Error(w, fmt.Sprintf("Failed to fetch secret: %v", err), http.StatusInternalServerError)
		return
	}

	// Декодируем и разбираем секрет
	decodedSecrets, err := s.decodeAndParseSecret(secret.Version.Value)
	if err != nil {
		log.Printf("Error decoding secret %s: %v", secretKey, err)
		// Если не удалось декодировать, возвращаем как есть
		decodedSecrets = map[string]string{
			"value": secret.Version.Value,
		}
	}

	// Если запрашивается конкретное поле, возвращаем только его значение
	if fieldKey != "" {
		fieldValue, exists := decodedSecrets[fieldKey]
		if !exists {
			log.Printf("Field %s not found in secret %s", fieldKey, secretKey)
			http.Error(w, fmt.Sprintf("Field %s not found", fieldKey), http.StatusNotFound)
			return
		}

		// Возвращаем только значение поля в формате, который ожидает External Secrets
		response := map[string]interface{}{
			"value": fieldValue,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
		return
	}

	// Формируем ответ для ESO с правильной структурой (все поля)
	secrets := make(map[string]Secret)
	for key, value := range decodedSecrets {
		secrets[key] = Secret{
			Type:  "Opaque",
			Value: value,
			Metadata: SecretMetadata{
				Labels: map[string]string{
					"managed-by": "external-secrets",
					"source":      "servercore",
				},
				Annotations: map[string]string{
					"description": secret.Description,
				},
				CreationTimestamp: secret.Version.CreatedAt,
				LastUpdated:       secret.Version.CreatedAt,
			},
		}
	}

	response := WebhookResponse{
		Namespaces: map[string]NamespaceData{
			"default": {
				Secrets: secrets,
			},
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// decodeAndParseSecret декодирует base64 и разбирает JSON секрет
func (s *Server) decodeAndParseSecret(secretValue string) (map[string]string, error) {
	// Декодируем base64
	decoded, err := base64.StdEncoding.DecodeString(secretValue)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64: %w", err)
	}

	// Парсим JSON
	var jsonData map[string]interface{}
	if err := json.Unmarshal(decoded, &jsonData); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}

	// Конвертируем в map[string]string
	result := make(map[string]string)
	for key, value := range jsonData {
		if strValue, ok := value.(string); ok {
			result[key] = strValue
		} else if numValue, ok := value.(float64); ok {
			// Конвертируем числа в строки
			result[key] = fmt.Sprintf("%.0f", numValue)
		} else if boolValue, ok := value.(bool); ok {
			// Конвертируем булевы значения в строки
			result[key] = fmt.Sprintf("%t", boolValue)
		} else if mapValue, ok := value.(map[string]interface{}); ok {
			// Для вложенных объектов создаем ключи с префиксом
			for subKey, subValue := range mapValue {
				if strSubValue, ok := subValue.(string); ok {
					result[fmt.Sprintf("%s_%s", key, subKey)] = strSubValue
				}
			}
		}
	}

	return result, nil
}

func (s *Server) fetchSecretFromServercore(secretName string, token string) (*ServercoreSecret, error) {
	url := fmt.Sprintf("%s/%s", s.config.ServercoreAPIURL, secretName)
	
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Устанавливаем заголовки аутентификации согласно Servercore API
	req.Header.Set("X-Auth-Token", token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	var secret ServercoreSecret
	var lastErr error

	// Попытки с повторениями
	for attempt := 0; attempt < s.config.MaxRetries; attempt++ {
		if attempt > 0 {
			log.Printf("Retry attempt %d for secret %s", attempt+1, secretName)
			time.Sleep(time.Duration(attempt+1) * time.Second)
		}

		resp, err := s.client.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("request failed: %w", err)
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			if err := json.NewDecoder(resp.Body).Decode(&secret); err != nil {
				lastErr = fmt.Errorf("failed to decode response: %w", err)
				continue
			}
			log.Printf("Secret fetched successfully: name=%s, version_id=%d", secret.Name, secret.Version.VersionID)
			return &secret, nil
		}

		if resp.StatusCode == http.StatusNotFound {
			return nil, fmt.Errorf("secret %s not found", secretName)
		}

		if resp.StatusCode == http.StatusUnauthorized {
			return nil, fmt.Errorf("authentication failed: invalid token")
		}

		lastErr = fmt.Errorf("unexpected status code: %d", resp.StatusCode)
		log.Printf("Unexpected response status %d for secret %s", resp.StatusCode, secretName)
	}

	return nil, fmt.Errorf("failed after %d attempts: %w", s.config.MaxRetries, lastErr)
}

func (s *Server) healthHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func (s *Server) readyHandler(w http.ResponseWriter, r *http.Request) {
	// Проверяем, есть ли токен
	token := s.getToken()
	log.Printf("Ready check - token available: %t", len(token) > 0)
	
	if token == "" {
		log.Printf("Ready check failed - no token available")
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte("Service unavailable - no token"))
		return
	}

	// Проверяем, не истек ли токен
	s.tokenCache.mutex.RLock()
	expiresAt := s.tokenCache.expiresAt
	s.tokenCache.mutex.RUnlock()
	
	// Проверяем, не истек ли токен или не истечет ли он в ближайшие 5 минут
	refreshThreshold := time.Now().Add(5 * time.Minute)
	if time.Now().After(expiresAt) {
		log.Printf("Ready check failed - token expired at %v", expiresAt)
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte("Service unavailable - token expired"))
		return
	}
	
	if refreshThreshold.After(expiresAt) {
		log.Printf("Ready check failed - token expires soon at %v (threshold: %v)", expiresAt, refreshThreshold)
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte("Service unavailable - token expires soon"))
		return
	}

	log.Printf("Ready check passed - token valid, expires at %v", expiresAt)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Ready"))
}

// getToken возвращает текущий токен из кэша
func (s *Server) getToken() string {
	s.tokenCache.mutex.RLock()
	defer s.tokenCache.mutex.RUnlock()
	return s.tokenCache.token
}

// initializeToken получает начальный токен при запуске
func (s *Server) initializeToken() error {
	token, expiresAt, err := s.requestNewToken()
	if err != nil {
		return fmt.Errorf("failed to get initial token: %w", err)
	}

	s.tokenCache.mutex.Lock()
	s.tokenCache.token = token
	s.tokenCache.expiresAt = expiresAt
	s.tokenCache.mutex.Unlock()

	log.Printf("Initial token obtained, expires at: %v", expiresAt)
	return nil
}

// startTokenRefresh запускает фоновое обновление токена
func (s *Server) startTokenRefresh() {
	ticker := time.NewTicker(10 * time.Minute) // Проверяем каждые 10 минут
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.tokenCache.mutex.RLock()
			expiresAt := s.tokenCache.expiresAt
			s.tokenCache.mutex.RUnlock()

			// Обновляем токен если он истечет в ближайшие 30 минут
			refreshThreshold := time.Now().Add(30 * time.Minute)
			needsRefresh := refreshThreshold.After(expiresAt)

			if needsRefresh {
				log.Printf("Token needs refresh (expires at %v, threshold: %v), requesting new token...", expiresAt, refreshThreshold)
				if err := s.refreshToken(); err != nil {
					log.Printf("Failed to refresh token: %v", err)
				}
			}
		case <-s.tokenCache.stopChan:
			log.Printf("Token refresh stopped")
			return
		}
	}
}

// refreshToken обновляет токен
func (s *Server) refreshToken() error {
	token, expiresAt, err := s.requestNewToken()
	if err != nil {
		return fmt.Errorf("failed to refresh token: %w", err)
	}

	s.tokenCache.mutex.Lock()
	s.tokenCache.token = token
	s.tokenCache.expiresAt = expiresAt
	s.tokenCache.mutex.Unlock()

	log.Printf("Token refreshed successfully, expires at: %v", expiresAt)
	return nil
}

// requestNewToken запрашивает новый токен у Servercore API
func (s *Server) requestNewToken() (string, time.Time, error) {
	authReq := AuthRequest{}
	authReq.Auth.Identity.Methods = []string{"password"}
	authReq.Auth.Identity.Password.User.Name = s.config.Username
	authReq.Auth.Identity.Password.User.Domain.Name = s.config.DomainName
	authReq.Auth.Identity.Password.User.Password = s.config.Password
	authReq.Auth.Scope.Project.Name = s.config.ProjectName
	authReq.Auth.Scope.Project.Domain.Name = s.config.DomainName

	jsonData, err := json.Marshal(authReq)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to marshal auth request: %w", err)
	}

	req, err := http.NewRequest("POST", s.config.ServercoreAuthURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to create auth request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("auth request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return "", time.Time{}, fmt.Errorf("auth request failed with status: %d", resp.StatusCode)
	}

	// Извлекаем токен из заголовка
	token := resp.Header.Get("X-Subject-Token")
	if token == "" {
		return "", time.Time{}, fmt.Errorf("no token in response header")
	}

	// Парсим время истечения токена из заголовка
	expiresHeader := resp.Header.Get("X-Expires-At")
	var expiresAt time.Time
	if expiresHeader != "" {
		expiresAt, err = time.Parse(time.RFC3339, expiresHeader)
		if err != nil {
			// Если не можем распарсить, устанавливаем время истечения на 24 часа
			expiresAt = time.Now().Add(24 * time.Hour)
			log.Printf("Warning: could not parse token expiration time, using 24 hours from now")
		}
	} else {
		// Если заголовок отсутствует, устанавливаем время истечения на 24 часа
		expiresAt = time.Now().Add(24 * time.Hour)
		log.Printf("Warning: no token expiration header, using 24 hours from now")
	}

	return token, expiresAt, nil
}

// maskSensitiveData маскирует чувствительные данные в строках
func maskSensitiveData(data string) string {
	if len(data) == 0 {
		return data
	}
	if len(data) <= 8 {
		return "***"
	}
	return data[:4] + "***" + data[len(data)-4:]
}

// Вспомогательные функции для работы с переменными окружения
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getDurationEnv(key string, defaultValue time.Duration) time.Duration {
	if value := os.Getenv(key); value != "" {
		if duration, err := time.ParseDuration(value); err == nil {
			return duration
		}
	}
	return defaultValue
}

func getIntEnv(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := fmt.Sscanf(value, "%d", &defaultValue); err == nil && intValue > 0 {
			return defaultValue
		}
	}
	return defaultValue
}
