package server

import (
	authservicev1 "auth_service/gen/go"
	"auth_service/internal/models"
	"context"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gorm.io/gorm"
	"time"
)

var secretKey = []byte("VerySecretKey2000")

type Claims struct {
	UserID string //`json:"user_id"`
	//Username string `json:"username"`
	//Role     string `json:"role"`
	jwt.RegisteredClaims
}

type AuthService struct {
	authservicev1.UnimplementedAuthServiceServer
	db *gorm.DB
}

func RegisterAuthService(gRPC *grpc.Server, db *gorm.DB) {
	authservicev1.RegisterAuthServiceServer(gRPC, &AuthService{db: db})
}

func (as *AuthService) Register(_ context.Context, req *authservicev1.User) (*authservicev1.AuthResponse, error) {
	hash, err := hashPassword(req.Pass)
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to hash password")
	}
	uid := uuid.NewString()
	user := models.User{
		UID:         uid,
		Name:        req.Name,
		Email:       req.Email,
		Pass:        hash,
		DeletedUser: false,
	}
	if err := as.db.Create(user).Error; err != nil {
		return nil, status.Error(codes.Internal, "Failed to create user")
	}
	//add JWT
	token, err := createJWT(uid)
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to create JWT")
	}
	return &authservicev1.AuthResponse{
		Token:   token,
		Message: "Success register user",
	}, nil
}

func (as *AuthService) Login(_ context.Context, userCreds *authservicev1.UserCreds) (*authservicev1.AuthResponse, error) {
	var user models.User
	if err := as.db.Where("email = ?", userCreds.Email).First(&user).Error; err != nil {
		return nil, status.Error(codes.NotFound, "User not found")
	}
	if err := checkPasswordHash(user.Pass, userCreds.Pass); err != nil {
		return nil, status.Error(codes.Unauthenticated, "Invalid password")
	}
	//add JWT
	token, err := createJWT(user.UID)
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to create JWT")
	}
	return &authservicev1.AuthResponse{
		Token:   token,
		Message: "Success login",
	}, nil
}

func hashPassword(pass string) (string, error) {
	passHash, err := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(passHash), nil
}

func checkPasswordHash(pass, hash string) error {
	return bcrypt.CompareHashAndPassword([]byte(pass), []byte(hash))
}

func createJWT(UID string) (string, error) {
	// Данные для токена
	claims := Claims{
		UserID: UID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)), // 24 часа
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Subject:   UID,
		},
	}
	// Создаем токен
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	// Подписываем секретным ключом
	return token.SignedString(secretKey)
}

//func validJWT(tokenString string) (string, error) {
//	claims := &Claims{}
//	// Парсим и проверяем токен
//	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
//		return secretKey, nil
//	})
//	if err != nil {
//		return "", err
//	}
//	// Проверяем валидность
//	if !token.Valid {
//		return "", fmt.Errorf("невалидный токен")
//	}
//	return claims.UserID, nil
//}
