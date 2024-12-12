package auth

import (
    "time"
    "github.com/golang-jwt/jwt"
)

var jwtKey = []byte("your-secret-key") // In production, use environment variable

func GenerateToken(userID string) (string, error) {
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
        "user_id": userID,
        "exp":     time.Now().Add(time.Hour * 24).Unix(),
    })
    return token.SignedString(jwtKey)
}

func ValidateToken(tokenStr string) (string, error) {
    token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
        return jwtKey, nil
    })
    if err != nil {
        return "", err
    }
    
    if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
        return claims["user_id"].(string), nil
    }
    return "", jwt.ErrInvalidKey
}