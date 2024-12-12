package models

type User struct {
    ID       string `json:"id"`
    Username string `json:"username"`
    Password string `json:"-"`
}

type LoginRequest struct {
    Username string `json:"username"`
    Password string `json:"password"`
}

type RegisterRequest struct {
    Username string `json:"username"`
    Password string `json:"password"`
}
