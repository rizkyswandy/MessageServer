package db

import (
    "database/sql"
    "time"
    _ "github.com/lib/pq"
    "messagingApp/models"
	"fmt"
)

type DB struct {
    *sql.DB
}

type Message struct {
    ID        string    `json:"id"`
    Content   string    `json:"content"`
    SenderID  string    `json:"senderId"`
    Username  string    `json:"username"`  // Add this
    Timestamp time.Time `json:"timestamp"`
}

func NewDB(dataSourceName string) (*DB, error) {
    db, err := sql.Open("postgres", dataSourceName)
    if err != nil {
        return nil, err
    }
    if err = db.Ping(); err != nil {
        return nil, err
    }
    return &DB{db}, nil
}

func (db *DB) CreateUser(user *models.User) error {
    // First check if username exists
    var exists bool
    err := db.QueryRow("SELECT EXISTS(SELECT 1 FROM users WHERE username = $1)", user.Username).Scan(&exists)
    if err != nil {
        return fmt.Errorf("error checking username: %v", err)
    }
    if exists {
        return fmt.Errorf("username already exists")
    }

    // If username doesn't exist, create the user
    query := `
        INSERT INTO users (id, username, password)
        VALUES ($1, $2, $3)
    `
    _, err = db.Exec(query, user.ID, user.Username, user.Password)
    if err != nil {
        return fmt.Errorf("error creating user: %v", err)
    }
    return nil
}


func (db *DB) GetUserByUsername(username string) (*models.User, error) {
    var user models.User
    query := `SELECT id, username, password FROM users WHERE username = $1`
    err := db.QueryRow(query, username).Scan(&user.ID, &user.Username, &user.Password)
    if err != nil {
        return nil, err
    }
    return &user, nil
}

func (db *DB) GetUserByID(id string) (*models.User, error) {
    var user models.User
    query := `SELECT id, username, password FROM users WHERE id = $1`
    err := db.QueryRow(query, id).Scan(&user.ID, &user.Username, &user.Password)
    if err != nil {
        return nil, err
    }
    return &user, nil
}