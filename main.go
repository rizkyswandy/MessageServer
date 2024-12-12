// main.go
package main

import (
    "context"
    "encoding/json"
    "log"
    "net/http"
    "os"
    "strings"
    "sync"
    "time"
    
	"github.com/rs/cors"
    "github.com/gorilla/mux"
    "github.com/gorilla/websocket"
    "github.com/google/uuid"
    "golang.org/x/crypto/bcrypt"
    
    "messagingApp/auth"
    "messagingApp/db"
    "messagingApp/models"
)

type Message struct {
    ID        string    `json:"id"`
    Content   string    `json:"content"`
    SenderID  string    `json:"senderId"`
    Username  string    `json:"username"`  
    Timestamp time.Time `json:"timestamp"`
}

type Client struct {
    ID   string
    Conn *websocket.Conn
    Send chan *Message
    Hub  *Hub
}

type Hub struct {
    clients    map[string]*Client
    broadcast  chan *Message
    register   chan *Client
    unregister chan *Client
    mutex      sync.RWMutex
    server     *Server
}

type Server struct {
    db       *db.DB
    hub      *Hub
    upgrader websocket.Upgrader
}

func newHub() *Hub {
    return &Hub{
        clients:    make(map[string]*Client),
        broadcast:  make(chan *Message),
        register:   make(chan *Client),
        unregister: make(chan *Client),
    }
}

func (h *Hub) run() {
    for {
        select {
        case client := <-h.register:
            h.mutex.Lock()
            h.clients[client.ID] = client
            h.mutex.Unlock()
            
        case client := <-h.unregister:
            h.mutex.Lock()
            if _, ok := h.clients[client.ID]; ok {
                delete(h.clients, client.ID)
                close(client.Send)
            }
            h.mutex.Unlock()
            
        case message := <-h.broadcast:
            h.mutex.RLock()
            for _, client := range h.clients {
                select {
                case client.Send <- message:
                default:
                    close(client.Send)
                    delete(h.clients, client.ID)
                }
            }
            h.mutex.RUnlock()
        }
    }
}

func (c *Client) writePump() {
    defer func() {
        c.Conn.Close()
    }()

    for {
        message, ok := <-c.Send
        if !ok {
            c.Conn.WriteMessage(websocket.CloseMessage, []byte{})
            return
        }

        err := c.Conn.WriteJSON(message)
        if err != nil {
            return
        }
    }
}

func (c *Client) readPump() {
    defer func() {
        c.Hub.unregister <- c
        c.Conn.Close()
    }()

    for {
        var message Message
        err := c.Conn.ReadJSON(&message)
        if err != nil {
            if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
                log.Printf("error: %v", err)
            }
            break
        }
        message.Timestamp = time.Now()
        message.SenderID = c.ID
        message.ID = uuid.New().String()
        
        // Get username from database
        user, err := c.Hub.server.db.GetUserByID(c.ID)
        if err != nil {
            log.Printf("Error getting username: %v", err)
        } else {
            message.Username = user.Username
        }
        
        c.Hub.broadcast <- &message
    }
}

func NewServer(db *db.DB) *Server {
    server := &Server{
        db: db,
        upgrader: websocket.Upgrader{
            ReadBufferSize:  1024,
            WriteBufferSize: 1024,
            CheckOrigin: func(r *http.Request) bool {
                return true
            },
        },
    }
    
    // Create hub with reference to server
    hub := newHub()
    hub.server = server
    server.hub = hub
    
    return server
}

func (s *Server) authenticateMiddleware(next http.HandlerFunc) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        authHeader := r.Header.Get("Authorization")
        if authHeader == "" {
            http.Error(w, "Authorization header required", http.StatusUnauthorized)
            return
        }

        tokenParts := strings.Split(authHeader, " ")
        if len(tokenParts) != 2 || tokenParts[0] != "Bearer" {
            http.Error(w, "Invalid authorization format", http.StatusUnauthorized)
            return
        }

        userID, err := auth.ValidateToken(tokenParts[1])
        if err != nil {
            http.Error(w, "Invalid token", http.StatusUnauthorized)
            return
        }

        ctx := context.WithValue(r.Context(), "userID", userID)
        next.ServeHTTP(w, r.WithContext(ctx))
    }
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
    var req models.RegisterRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, "Invalid request format", http.StatusBadRequest)
        return
    }

    // Validate input
    if req.Username == "" || req.Password == "" {
        http.Error(w, "Username and password are required", http.StatusBadRequest)
        return
    }

    hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
    if err != nil {
        log.Printf("Error hashing password: %v", err)
        http.Error(w, "Internal server error", http.StatusInternalServerError)
        return
    }

    user := models.User{
        ID:       uuid.New().String(),
        Username: req.Username,
        Password: string(hashedPassword),
    }
    
    if err := s.db.CreateUser(&user); err != nil {
        log.Printf("Error creating user: %v", err)
        if strings.Contains(err.Error(), "username already exists") {
            http.Error(w, "Username already exists", http.StatusConflict)
            return
        }
        http.Error(w, "Error creating user", http.StatusInternalServerError)
        return
    }

    w.WriteHeader(http.StatusCreated)
    json.NewEncoder(w).Encode(map[string]string{"message": "User created successfully"})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
    var req models.LoginRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }

    user, err := s.db.GetUserByUsername(req.Username)
    if err != nil {
        http.Error(w, "Invalid credentials", http.StatusUnauthorized)
        return
    }

    if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)); err != nil {
        http.Error(w, "Invalid credentials", http.StatusUnauthorized)
        return
    }

    token, err := auth.GenerateToken(user.ID)
    if err != nil {
        http.Error(w, "Internal server error", http.StatusInternalServerError)
        return
    }

    json.NewEncoder(w).Encode(map[string]string{
        "token": token,
    })
}

func (s *Server) serveWs(w http.ResponseWriter, r *http.Request) {
    token := r.URL.Query().Get("token")
    userID, err := auth.ValidateToken(token)
    if err != nil {
        http.Error(w, "Invalid token", http.StatusUnauthorized)
        return
    }

    conn, err := s.upgrader.Upgrade(w, r, nil)
    if err != nil {
        log.Println(err)
        return
    }

    client := &Client{
        ID:   userID,
        Hub:  s.hub,
        Conn: conn,
        Send: make(chan *Message, 256),
    }

    client.Hub.register <- client
    go client.writePump()
    go client.readPump()
}

func (s *Server) handleGetMessages(w http.ResponseWriter, r *http.Request) {
    // Implement message history retrieval from database
    messages := []*Message{}
    json.NewEncoder(w).Encode(messages)
}

func main() {
    // Database connection
    dbURL := os.Getenv("DATABASE_URL")
    if dbURL == "" {
        dbURL = "postgres://rizkyswandy@localhost:5432/messagingdb?sslmode=disable"
    }
    
    database, err := db.NewDB(dbURL)
    if err != nil {
        log.Fatal("Database connection failed:", err)
    }
    defer database.Close()

    server := NewServer(database)
    go server.hub.run()

	router := mux.NewRouter()

    // Public routes
    router.HandleFunc("/register", server.handleRegister).Methods("POST")
    router.HandleFunc("/login", server.handleLogin).Methods("POST")

    // Protected routes
    router.HandleFunc("/ws", server.serveWs)
    router.HandleFunc("/messages", server.authenticateMiddleware(server.handleGetMessages)).Methods("GET")

    // Setup CORS
    c := cors.New(cors.Options{
        AllowedOrigins: []string{"*"},  // Allow all origins in development
        AllowedMethods: []string{"GET", "POST", "OPTIONS"},
        AllowedHeaders: []string{"Content-Type", "Authorization"},
        Debug:         true,
    })

    // Create a handler from the router with CORS middleware
    handler := c.Handler(router)

    port := os.Getenv("PORT")
    if port == "" {
        port = "8080"
    }

    log.Printf("Server starting on :%s", port)
    log.Fatal(http.ListenAndServe(":"+port, handler))
}