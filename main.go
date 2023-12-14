package main

import (
	"fmt"
	"log"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	Name     string `json:"name"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

func hash(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	return string(bytes), err
}

func compare(hash string, password string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

func main() {
	app := fiber.New()
	app.Use(recover.New())

	const secret = "secret"
	users := make([]User, 0)

	app.Post("/sign-in", func(c *fiber.Ctx) error {
		body := struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}{}

		if err := c.BodyParser(&body); err != nil {
			panic(err)
		}

		userRes := User{}
		for _, user := range users {
			if body.Email == user.Email && compare(user.Password, body.Password) {
				userRes = user
				break
			}
		}

		expTime := time.Now().Add(time.Minute * 30).Unix()
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"email": userRes.Email,
			"exp":   expTime,
		})

		tokenString, err := token.SignedString([]byte(secret))
		if err != nil {
			panic(err)
		}

		c.Set("X-JWT-Token", tokenString)
		return c.Status(fiber.StatusOK).JSON(fiber.Map{
			"success": true,
			"user":    userRes,
		})
	})

	app.Post("/sign-up", func(c *fiber.Ctx) error {
		body := User{}

		if err := c.BodyParser(&body); err != nil {
			panic(err)
		}

		hash, err := hash(body.Password)
		if err != nil {
			panic(err)
		}

		newUser := User{
			Name:     body.Name,
			Email:    body.Email,
			Password: hash,
		}

		users = append(users, newUser)

		return c.Status(fiber.StatusOK).JSON(fiber.Map{
			"success": true,
		})
	})

	app.Post("/me", func(c *fiber.Ctx) error {
		authorization := c.Get("Authorization", "")
		if authorization == "" {
			panic("No authorization key set")
		}

		token, err := jwt.Parse(authorization, func(token *jwt.Token) (any, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("Unexpected signing method")
			}
			return []byte(secret), nil
		})
		if err != nil {
			panic(err)
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok || !token.Valid {
			panic("Can't claims token")
		}

		exp := claims["exp"].(float64)
		expTime := time.Unix(int64(exp), 0)
		if time.Now().After(expTime) {
			panic("Token ha expired")
		}

		userRes := User{}
		for _, user := range users {
			if user.Email == claims["email"].(string) {
				userRes = user
				break
			}
		}

		return c.Status(fiber.StatusOK).JSON(fiber.Map{
			"success": true,
			"user":    userRes,
		})
	})

	log.Fatal(app.Listen(":3000"))
}
