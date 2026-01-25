package main

import (
	"bytes"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	_ "github.com/tursodatabase/libsql-client-go/libsql"
)

var (
	db                 *sql.DB
	googleClientID     string
	googleClientSecret string
	appURL             string
	frontendURL        string
	sessionSecret      string
	resendAPIKey       string
	fromEmail          string
)

type User struct {
	ID        string `json:"id"`
	GoogleID  string `json:"google_id"`
	Email     string `json:"email"`
	Name      string `json:"name"`
	CreatedAt string `json:"created_at"`
}

type Invoice struct {
	ID            string `json:"id"`
	UserID        string `json:"user_id"`
	ClientEmail   string `json:"client_email"`
	ClientName    string `json:"client_name"`
	Amount        string `json:"amount"`
	InvoiceNumber string `json:"invoice_number"`
	YourName      string `json:"your_name"`
	YourEmail     string `json:"your_email"`
	ChaseCount    int    `json:"chase_count"`
	Status        string `json:"status"`
	CreatedAt     string `json:"created_at"`
	NextChase     string `json:"next_chase"`
	LastChase     string `json:"last_chase"`
	PaidAt        *string `json:"paid_at"`
}

type CreateInvoiceRequest struct {
	ClientEmail   string `json:"clientEmail"`
	ClientName    string `json:"clientName"`
	Amount        string `json:"amount"`
	InvoiceNumber string `json:"invoiceNumber"`
	YourName      string `json:"yourName"`
	YourEmail     string `json:"yourEmail"`
}

type TestEmailRequest struct {
	Email   string `json:"email"`
	Website string `json:"website"`
}

type SessionData struct {
	SessionID string `json:"sessionId"`
	Secret    string `json:"secret"`
}

func main() {
	googleClientID = os.Getenv("GOOGLE_CLIENT_ID")
	googleClientSecret = os.Getenv("GOOGLE_CLIENT_SECRET")
	appURL = os.Getenv("APP_URL")
	frontendURL = os.Getenv("FRONTEND_URL")
	sessionSecret = os.Getenv("SESSION_SECRET")
	resendAPIKey = os.Getenv("RESEND_API_KEY")
	fromEmail = os.Getenv("FROM_EMAIL")

	if appURL == "" {
		appURL = "http://localhost:8080"
	}
	if frontendURL == "" {
		frontendURL = "http://localhost:3000"
	}
	if fromEmail == "" {
		fromEmail = "onboarding@resend.dev"
	}
	if sessionSecret == "" {
		sessionSecret = "change-this-secret-in-production"
	}

	tursoURL := os.Getenv("TURSO_URL")
	tursoToken := os.Getenv("TURSO_AUTH_TOKEN")
	dbURL := fmt.Sprintf("%s?authToken=%s", tursoURL, tursoToken)

	var err error
	db, err = sql.Open("libsql", dbURL)
	if err != nil {
		panic(err)
	}
	defer db.Close()

	initializeDatabase()

	http.HandleFunc("/", router)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	fmt.Printf("Server starting on port %s\n", port)
	http.ListenAndServe(":"+port, nil)
}

func initializeDatabase() {
	db.Exec(`CREATE TABLE IF NOT EXISTS users (
		id TEXT PRIMARY KEY,
		google_id TEXT UNIQUE NOT NULL,
		email TEXT NOT NULL,
		name TEXT NOT NULL,
		created_at TEXT NOT NULL
	)`)

	db.Exec(`CREATE TABLE IF NOT EXISTS invoices (
		id TEXT PRIMARY KEY,
		user_id TEXT,
		client_email TEXT NOT NULL,
		client_name TEXT NOT NULL,
		amount TEXT NOT NULL,
		invoice_number TEXT NOT NULL,
		your_name TEXT NOT NULL,
		your_email TEXT NOT NULL,
		chase_count INTEGER DEFAULT 1,
		status TEXT DEFAULT 'active',
		created_at TEXT NOT NULL,
		next_chase TEXT NOT NULL,
		last_chase TEXT NOT NULL,
		paid_at TEXT,
		FOREIGN KEY (user_id) REFERENCES users(id)
	)`)

	db.Exec(`CREATE TABLE IF NOT EXISTS rate_limits (
		id TEXT PRIMARY KEY,
		ip_address TEXT NOT NULL,
		action TEXT NOT NULL,
		created_at TEXT NOT NULL
	)`)

	db.Exec(`CREATE TABLE IF NOT EXISTS sessions (
		id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL,
		created_at TEXT NOT NULL,
		expires_at TEXT NOT NULL,
		FOREIGN KEY (user_id) REFERENCES users(id)
	)`)
}

func router(w http.ResponseWriter, r *http.Request) {
	setCORS(w, r)

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	path := r.URL.Path
	method := r.Method

	paidRegex := regexp.MustCompile(`^/api/invoices/[\w-]+/paid$`)
	stopRegex := regexp.MustCompile(`^/api/invoices/[\w-]+/stop$`)
	deleteRegex := regexp.MustCompile(`^/api/invoices/[\w-]+$`)

	switch {
	case path == "/api/auth/google" && method == "GET":
		handleGoogleAuth(w, r)
	case path == "/api/auth/google/callback" && method == "GET":
		handleGoogleCallback(w, r)
	case path == "/api/auth/logout" && method == "POST":
		handleLogout(w, r)
	case path == "/api/auth/me" && method == "GET":
		handleAuthMe(w, r)
	case path == "/api/test-email" && method == "POST":
		handleTestEmail(w, r)
	case path == "/api/invoices" && method == "GET":
		handleGetInvoices(w, r)
	case path == "/api/invoices" && method == "POST":
		handleCreateInvoice(w, r)
	case paidRegex.MatchString(path) && method == "POST":
		handleMarkPaid(w, r)
	case stopRegex.MatchString(path) && method == "POST":
		handleStopChasing(w, r)
	case deleteRegex.MatchString(path) && method == "DELETE":
		handleDeleteInvoice(w, r)
	case path == "/api/cron/chase" && (method == "GET" || method == "POST"):
		handleCronChase(w, r)
	case path == "/api/health" && method == "GET":
		handleHealth(w, r)
	default:
		// Serve static files from public directory
		fs := http.FileServer(http.Dir("public"))
		http.StripPrefix("/", fs).ServeHTTP(w, r)
	}
}

func setCORS(w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")
	if origin == "" {
		origin = frontendURL
	}
	w.Header().Set("Access-Control-Allow-Origin", origin)
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
	w.Header().Set("Access-Control-Allow-Credentials", "true")
}

func jsonResponse(w http.ResponseWriter, data interface{}, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func getClientIP(r *http.Request) string {
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		return strings.Split(forwarded, ",")[0]
	}
	if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
		return realIP
	}
	return "127.0.0.1"
}

// Session management
func createSessionToken(sessionID string) string {
	data := SessionData{SessionID: sessionID, Secret: sessionSecret}
	jsonData, _ := json.Marshal(data)
	return base64.StdEncoding.EncodeToString(jsonData)
}

func parseSessionToken(token string) string {
	decoded, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		return ""
	}
	var data SessionData
	if err := json.Unmarshal(decoded, &data); err != nil {
		return ""
	}
	if data.Secret != sessionSecret {
		return ""
	}
	return data.SessionID
}

func createSession(userID string) (string, error) {
	sessionID := uuid.New().String()
	now := time.Now()
	expiresAt := now.AddDate(0, 0, 30)

	_, err := db.Exec(`INSERT INTO sessions (id, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)`,
		sessionID, userID, now.Format(time.RFC3339), expiresAt.Format(time.RFC3339))
	if err != nil {
		return "", err
	}

	return createSessionToken(sessionID), nil
}

func getSessionUser(r *http.Request) *User {
	cookie, err := r.Cookie("session")
	if err != nil {
		return nil
	}

	sessionID := parseSessionToken(cookie.Value)
	if sessionID == "" {
		return nil
	}

	var user User
	err = db.QueryRow(`SELECT users.id, users.google_id, users.email, users.name, users.created_at 
		FROM users JOIN sessions ON users.id = sessions.user_id 
		WHERE sessions.id = ? AND sessions.expires_at > ?`,
		sessionID, time.Now().Format(time.RFC3339)).Scan(&user.ID, &user.GoogleID, &user.Email, &user.Name, &user.CreatedAt)

	if err != nil {
		return nil
	}
	return &user
}

func deleteSession(r *http.Request) {
	cookie, err := r.Cookie("session")
	if err != nil {
		return
	}
	sessionID := parseSessionToken(cookie.Value)
	if sessionID == "" {
		return
	}
	db.Exec(`DELETE FROM sessions WHERE id = ?`, sessionID)
}

// Auth handlers
func handleGoogleAuth(w http.ResponseWriter, r *http.Request) {
	params := url.Values{}
	params.Set("client_id", googleClientID)
	params.Set("redirect_uri", appURL+"/api/auth/google/callback")
	params.Set("response_type", "code")
	params.Set("scope", "openid email profile")
	params.Set("access_type", "offline")
	params.Set("prompt", "consent")

	authURL := "https://accounts.google.com/o/oauth2/v2/auth?" + params.Encode()
	http.Redirect(w, r, authURL, http.StatusFound)
}

func handleGoogleCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	errorParam := r.URL.Query().Get("error")

	if errorParam != "" || code == "" {
		http.Redirect(w, r, frontendURL+"/?error=auth_failed", http.StatusFound)
		return
	}

	tokens, err := exchangeCodeForTokens(code)
	if err != nil {
		http.Redirect(w, r, frontendURL+"/?error=auth_failed", http.StatusFound)
		return
	}

	googleUser, err := getGoogleUserInfo(tokens["access_token"].(string))
	if err != nil {
		http.Redirect(w, r, frontendURL+"/?error=auth_failed", http.StatusFound)
		return
	}

	user, err := findOrCreateUser(googleUser)
	if err != nil {
		http.Redirect(w, r, frontendURL+"/?error=auth_failed", http.StatusFound)
		return
	}

	sessionToken, err := createSession(user.ID)
	if err != nil {
		http.Redirect(w, r, frontendURL+"/?error=auth_failed", http.StatusFound)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    sessionToken,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   30 * 24 * 60 * 60,
	})

	http.Redirect(w, r, frontendURL+"/dashboard.html", http.StatusFound)
}

func exchangeCodeForTokens(code string) (map[string]interface{}, error) {
	data := url.Values{}
	data.Set("client_id", googleClientID)
	data.Set("client_secret", googleClientSecret)
	data.Set("code", code)
	data.Set("grant_type", "authorization_code")
	data.Set("redirect_uri", appURL+"/api/auth/google/callback")

	resp, err := http.Post("https://oauth2.googleapis.com/token", "application/x-www-form-urlencoded", strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var tokens map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&tokens)
	return tokens, nil
}

func getGoogleUserInfo(accessToken string) (map[string]interface{}, error) {
	req, _ := http.NewRequest("GET", "https://www.googleapis.com/oauth2/v2/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var userInfo map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&userInfo)
	return userInfo, nil
}

func findOrCreateUser(googleUser map[string]interface{}) (*User, error) {
	googleID := googleUser["id"].(string)

	var user User
	err := db.QueryRow(`SELECT id, google_id, email, name, created_at FROM users WHERE google_id = ?`, googleID).
		Scan(&user.ID, &user.GoogleID, &user.Email, &user.Name, &user.CreatedAt)

	if err == nil {
		return &user, nil
	}

	userID := uuid.New().String()
	now := time.Now().Format(time.RFC3339)
	email := googleUser["email"].(string)
	name := googleUser["name"].(string)

	_, err = db.Exec(`INSERT INTO users (id, google_id, email, name, created_at) VALUES (?, ?, ?, ?, ?)`,
		userID, googleID, email, name, now)
	if err != nil {
		return nil, err
	}

	return &User{ID: userID, GoogleID: googleID, Email: email, Name: name, CreatedAt: now}, nil
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	deleteSession(r)
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   0,
	})
	jsonResponse(w, map[string]bool{"success": true}, http.StatusOK)
}

func handleAuthMe(w http.ResponseWriter, r *http.Request) {
	user := getSessionUser(r)
	if user == nil {
		jsonResponse(w, map[string]bool{"authenticated": false}, http.StatusOK)
		return
	}
	jsonResponse(w, map[string]interface{}{
		"authenticated": true,
		"user": map[string]string{
			"id":    user.ID,
			"email": user.Email,
			"name":  user.Name,
		},
	}, http.StatusOK)
}

// Rate limiting
func checkRateLimit(ipAddress, action string) bool {
	oneDayAgo := time.Now().Add(-24 * time.Hour).Format(time.RFC3339)
	var count int
	db.QueryRow(`SELECT COUNT(*) FROM rate_limits WHERE ip_address = ? AND action = ? AND created_at > ?`,
		ipAddress, action, oneDayAgo).Scan(&count)
	return count >= 1
}

func recordRateLimit(ipAddress, action string) {
	db.Exec(`INSERT INTO rate_limits (id, ip_address, action, created_at) VALUES (?, ?, ?, ?)`,
		uuid.New().String(), ipAddress, action, time.Now().Format(time.RFC3339))
}

// Email functions
func generateHTMLEmail(clientName, invoiceNumber, amount, yourName, messageBody string) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html>
<body style="margin:0; padding:0; background:#f5f5f5; font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;">
  <div style="max-width:600px; margin:40px auto; background:#ffffff; border-radius:8px; overflow:hidden;">
    
    <!-- Main Content -->
    <div style="padding:40px;">
      <p style="margin:0 0 20px; color:#333; font-size:16px; line-height:1.6;">
        Hi <strong>%s</strong>,
      </p>
      
      <p style="margin:0 0 20px; color:#333; font-size:16px; line-height:1.6;">
        %s
      </p>
      
      <!-- Invoice Details Box -->
      <div style="background:#f9fafb; border:1px solid #e5e7eb; border-radius:8px; padding:20px; margin:24px 0;">
        <div style="color:#6b7280; font-size:12px; text-transform:uppercase; letter-spacing:0.05em; margin-bottom:12px;">
          Invoice Details
        </div>
        <div style="color:#111; font-size:16px; line-height:1.8;">
          <strong>Invoice #:</strong> %s<br>
          <strong>Amount:</strong> $%s
        </div>
      </div>
      
      <p style="margin:24px 0 0; color:#333; font-size:16px; line-height:1.6;">
        Thanks,<br>
        <strong>%s</strong>
      </p>
    </div>
    
    <!-- Viral Footer -->
    <div style="border-top:1px solid #e5e7eb; padding:24px 40px; background:#fafafa;">
      <p style="margin:0; color:#9ca3af; font-size:13px; text-align:center;">
        Need to collect invoices? Try <a href="https://hndshake.com" style="color:#22c55e; text-decoration:none; font-weight:600;">InvoiceChaser</a> at hndshake.com
      </p>
    </div>
    
  </div>
</body>
</html>`, clientName, messageBody, invoiceNumber, amount, yourName)
}

func generateEmail(invoice *Invoice) (string, string, string) {
	subjects := []string{
		fmt.Sprintf("Following up on Invoice %s", invoice.InvoiceNumber),
		fmt.Sprintf("Friendly reminder: Invoice %s", invoice.InvoiceNumber),
		fmt.Sprintf("Invoice %s - Quick follow-up", invoice.InvoiceNumber),
		fmt.Sprintf("Checking in on Invoice %s", invoice.InvoiceNumber),
		fmt.Sprintf("Invoice %s still outstanding", invoice.InvoiceNumber),
	}

	idx := invoice.ChaseCount - 1
	if idx >= len(subjects) {
		idx = len(subjects) - 1
	}
	subject := subjects[idx]

	var messageBody string
	switch invoice.ChaseCount {
	case 1:
		messageBody = "I hope you're doing well. I wanted to follow up on this invoice, which appears to still be outstanding.<br><br>I understand things get busy, so I just wanted to send a friendly reminder. Please let me know if you have any questions or if there's anything I can help with to process this payment."
	case 2:
		messageBody = "Just wanted to check in again on this invoice. I sent a note a few days ago but wanted to make sure it didn't slip through the cracks.<br><br>If there are any issues with the invoice or payment, I'm happy to help sort them out."
	case 3:
		messageBody = "I'm following up once more on this invoice. This is the third time I've reached out, so I want to make sure everything is okay on your end.<br><br>If there's a problem with the invoice or you need different payment terms, please let me know and we can work something out."
	default:
		messageBody = "I've reached out several times now about this invoice and haven't heard back. I'd really appreciate an update on when I can expect payment.<br><br>If there's an issue I'm not aware of, please let me know so we can resolve it."
	}

	htmlBody := generateHTMLEmail(invoice.ClientName, invoice.InvoiceNumber, invoice.Amount, invoice.YourName, messageBody)
	
	// Plain text fallback
	plainText := fmt.Sprintf(`Hi %s,

%s

Invoice #: %s
Amount: $%s

Thanks,
%s

---
Need to collect invoices? Try InvoiceChaser at hndshake.com`, 
		invoice.ClientName, 
		strings.ReplaceAll(messageBody, "<br>", "\n"),
		invoice.InvoiceNumber,
		invoice.Amount,
		invoice.YourName)

	return subject, htmlBody, plainText
}

func sendEmail(invoice *Invoice) error {
	subject, htmlBody, plainText := generateEmail(invoice)

	payload := map[string]interface{}{
		"from":     fmt.Sprintf("%s <%s>", invoice.YourName, fromEmail),
		"to":       invoice.ClientEmail,
		"reply_to": invoice.YourEmail,
		"subject":  subject,
		"html":     htmlBody,
		"text":     plainText,
	}

	jsonPayload, _ := json.Marshal(payload)

	req, _ := http.NewRequest("POST", "https://api.resend.com/emails", bytes.NewBuffer(jsonPayload))
	req.Header.Set("Authorization", "Bearer "+resendAPIKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("failed to send email: %d", resp.StatusCode)
	}

	return nil
}

func sendTestEmail(email string) error {
	subject := "InvoiceChaser - Sample Follow-up Email"
	
	messageBody := "This is a sample follow-up email from InvoiceChaser!<br><br>When you use InvoiceChaser, your clients will receive professionally written emails like this one, reminding them about outstanding invoices.<br><br>The email below shows what a real follow-up looks like - clean, professional, and personal."
	
	htmlBody := generateHTMLEmail("Sample Client", "INV-001", "5,000", "Your Name", messageBody)
	
	plainText := fmt.Sprintf(`Hi there,

This is a sample follow-up email from InvoiceChaser!

When you use InvoiceChaser, your clients will receive professionally written emails like this one, reminding them about outstanding invoices.

Here's what a real follow-up might look like:

---

Hi Sample Client,

I hope you're doing well. I wanted to follow up on invoice INV-001 for $5,000, which appears to still be outstanding.

I understand things get busy, so I just wanted to send a friendly reminder. Please let me know if you have any questions or if there's anything I can help with to process this payment.

Thanks so much,
Your Name

---

Ready to get paid? Sign up at %s and start chasing those invoices!

Best,
The InvoiceChaser Team`, frontendURL)

	payload := map[string]interface{}{
		"from":    fmt.Sprintf("InvoiceChaser <%s>", fromEmail),
		"to":      email,
		"subject": subject,
		"html":    htmlBody,
		"text":    plainText,
	}

	jsonPayload, _ := json.Marshal(payload)

	req, _ := http.NewRequest("POST", "https://api.resend.com/emails", bytes.NewBuffer(jsonPayload))
	req.Header.Set("Authorization", "Bearer "+resendAPIKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("failed to send test email: %d", resp.StatusCode)
	}

	return nil
}

func handleTestEmail(w http.ResponseWriter, r *http.Request) {
	var req TestEmailRequest
	json.NewDecoder(r.Body).Decode(&req)

	if req.Website != "" {
		jsonResponse(w, map[string]bool{"success": true}, http.StatusOK)
		return
	}

	if req.Email == "" {
		jsonResponse(w, map[string]string{"error": "Email is required"}, http.StatusBadRequest)
		return
	}

	emailRegex := regexp.MustCompile(`^[^\s@]+@[^\s@]+\.[^\s@]+$`)
	if !emailRegex.MatchString(req.Email) {
		jsonResponse(w, map[string]string{"error": "Invalid email address"}, http.StatusBadRequest)
		return
	}

	clientIP := getClientIP(r)
	if checkRateLimit(clientIP, "test_email") {
		jsonResponse(w, map[string]string{"error": "You've already sent a test email today. Please try again tomorrow."}, http.StatusTooManyRequests)
		return
	}

	if err := sendTestEmail(req.Email); err != nil {
		jsonResponse(w, map[string]string{"error": "Failed to send test email"}, http.StatusInternalServerError)
		return
	}

	recordRateLimit(clientIP, "test_email")
	jsonResponse(w, map[string]bool{"success": true}, http.StatusOK)
}

// Invoice handlers
func handleGetInvoices(w http.ResponseWriter, r *http.Request) {
	user := getSessionUser(r)
	if user == nil {
		jsonResponse(w, map[string]string{"error": "Unauthorized"}, http.StatusUnauthorized)
		return
	}

	rows, err := db.Query(`SELECT id, user_id, client_email, client_name, amount, invoice_number, 
		your_name, your_email, chase_count, status, created_at, next_chase, last_chase, paid_at 
		FROM invoices WHERE status = 'active' AND user_id = ?`, user.ID)
	if err != nil {
		jsonResponse(w, []Invoice{}, http.StatusOK)
		return
	}
	defer rows.Close()

	var invoices []Invoice
	for rows.Next() {
		var inv Invoice
		rows.Scan(&inv.ID, &inv.UserID, &inv.ClientEmail, &inv.ClientName, &inv.Amount, &inv.InvoiceNumber,
			&inv.YourName, &inv.YourEmail, &inv.ChaseCount, &inv.Status, &inv.CreatedAt, &inv.NextChase, &inv.LastChase, &inv.PaidAt)
		invoices = append(invoices, inv)
	}

	if invoices == nil {
		invoices = []Invoice{}
	}
	jsonResponse(w, invoices, http.StatusOK)
}

func handleCreateInvoice(w http.ResponseWriter, r *http.Request) {
	user := getSessionUser(r)
	if user == nil {
		jsonResponse(w, map[string]string{"error": "Unauthorized"}, http.StatusUnauthorized)
		return
	}

	var req CreateInvoiceRequest
	json.NewDecoder(r.Body).Decode(&req)

	if req.ClientEmail == "" || req.ClientName == "" || req.Amount == "" || req.InvoiceNumber == "" || req.YourName == "" || req.YourEmail == "" {
		jsonResponse(w, map[string]string{"error": "Missing required fields"}, http.StatusBadRequest)
		return
	}

	now := time.Now()
	nextChase := now.AddDate(0, 0, 3)

	invoice := Invoice{
		ID:            uuid.New().String(),
		UserID:        user.ID,
		ClientEmail:   req.ClientEmail,
		ClientName:    req.ClientName,
		Amount:        req.Amount,
		InvoiceNumber: req.InvoiceNumber,
		YourName:      req.YourName,
		YourEmail:     req.YourEmail,
		ChaseCount:    1,
		Status:        "active",
		CreatedAt:     now.Format(time.RFC3339),
		NextChase:     nextChase.Format(time.RFC3339),
		LastChase:     now.Format(time.RFC3339),
	}

	if err := sendEmail(&invoice); err != nil {
		jsonResponse(w, map[string]string{"error": "Failed to send email"}, http.StatusInternalServerError)
		return
	}

	_, err := db.Exec(`INSERT INTO invoices (id, user_id, client_email, client_name, amount, invoice_number, 
		your_name, your_email, chase_count, status, created_at, next_chase, last_chase) 
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		invoice.ID, invoice.UserID, invoice.ClientEmail, invoice.ClientName, invoice.Amount, invoice.InvoiceNumber,
		invoice.YourName, invoice.YourEmail, invoice.ChaseCount, invoice.Status, invoice.CreatedAt, invoice.NextChase, invoice.LastChase)

	if err != nil {
		jsonResponse(w, map[string]string{"error": "Failed to create invoice"}, http.StatusInternalServerError)
		return
	}

	jsonResponse(w, invoice, http.StatusCreated)
}

func handleMarkPaid(w http.ResponseWriter, r *http.Request) {
	user := getSessionUser(r)
	if user == nil {
		jsonResponse(w, map[string]string{"error": "Unauthorized"}, http.StatusUnauthorized)
		return
	}

	parts := strings.Split(r.URL.Path, "/")
	id := parts[3]

	paidAt := time.Now().Format(time.RFC3339)
	db.Exec(`UPDATE invoices SET status = 'paid', paid_at = ? WHERE id = ? AND user_id = ?`, paidAt, id, user.ID)
	jsonResponse(w, map[string]string{"status": "paid"}, http.StatusOK)
}

func handleStopChasing(w http.ResponseWriter, r *http.Request) {
	user := getSessionUser(r)
	if user == nil {
		jsonResponse(w, map[string]string{"error": "Unauthorized"}, http.StatusUnauthorized)
		return
	}

	parts := strings.Split(r.URL.Path, "/")
	id := parts[3]

	db.Exec(`UPDATE invoices SET status = 'stopped' WHERE id = ? AND user_id = ?`, id, user.ID)
	jsonResponse(w, map[string]string{"status": "stopped"}, http.StatusOK)
}

func handleDeleteInvoice(w http.ResponseWriter, r *http.Request) {
	user := getSessionUser(r)
	if user == nil {
		jsonResponse(w, map[string]string{"error": "Unauthorized"}, http.StatusUnauthorized)
		return
	}

	parts := strings.Split(r.URL.Path, "/")
	id := parts[3]

	db.Exec(`DELETE FROM invoices WHERE id = ? AND user_id = ?`, id, user.ID)
	jsonResponse(w, map[string]bool{"success": true}, http.StatusOK)
}

func handleCronChase(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query(`SELECT id, user_id, client_email, client_name, amount, invoice_number, 
		your_name, your_email, chase_count, status, created_at, next_chase, last_chase, paid_at 
		FROM invoices WHERE status = 'active'`)
	if err != nil {
		jsonResponse(w, map[string]int{"emailsSent": 0}, http.StatusOK)
		return
	}
	defer rows.Close()

	now := time.Now()
	emailsSent := 0

	for rows.Next() {
		var inv Invoice
		rows.Scan(&inv.ID, &inv.UserID, &inv.ClientEmail, &inv.ClientName, &inv.Amount, &inv.InvoiceNumber,
			&inv.YourName, &inv.YourEmail, &inv.ChaseCount, &inv.Status, &inv.CreatedAt, &inv.NextChase, &inv.LastChase, &inv.PaidAt)

		nextChase, _ := time.Parse(time.RFC3339, inv.NextChase)
		if now.After(nextChase) {
			inv.ChaseCount++
			if err := sendEmail(&inv); err == nil {
				newNextChase := now.AddDate(0, 0, 3).Format(time.RFC3339)
				newLastChase := now.Format(time.RFC3339)
				db.Exec(`UPDATE invoices SET chase_count = ?, next_chase = ?, last_chase = ? WHERE id = ?`,
					inv.ChaseCount, newNextChase, newLastChase, inv.ID)
				emailsSent++
			}
		}
	}

	jsonResponse(w, map[string]int{"emailsSent": emailsSent}, http.StatusOK)
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	var count int
	db.QueryRow(`SELECT COUNT(*) FROM invoices WHERE status = 'active'`).Scan(&count)
	jsonResponse(w, map[string]interface{}{"status": "ok", "invoiceCount": count}, http.StatusOK)
}
