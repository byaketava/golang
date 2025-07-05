package main

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type TodoList struct {
	ID        int       `json:"id" db:"id"`                 // Уникальный идентификатор списка
	UserID    int       `json:"user_id" db:"user_id"`       // ID пользователя, которому принадлежит список
	Title     string    `json:"title" db:"title"`           // Название списка задач
	CreatedAt time.Time `json:"created_at" db:"created_at"` // Время создания списка
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"` // Время последнего обновления списка
}

type TodoItem struct {
	ID          int       `json:"id" db:"id"`                     // Уникальный идентификатор элемента
	TodoListID  int       `json:"todo_list_id" db:"todo_list_id"` // ID списка, к которому принадлежит задача
	Title       string    `json:"title" db:"title"`               // Название задачи
	Description string    `json:"description" db:"description"`   // Описание задачи (опционально)
	Done        bool      `json:"done" db:"done"`                 // Статус выполнения задачи (true/false)
	CreatedAt   time.Time `json:"created_at" db:"created_at"`     // Время создания задачи
	UpdatedAt   time.Time `json:"updated_at" db:"updated_at"`     // Время последнего обновления задачи
}

type User struct {
	ID       int    `json:"id" db:"id"`
	Username string `json:"username" db:"username"`
	Password string `json:"-" db:"password"`
}

type RegisterRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

// Claims расширяет jwt.StandardClaims, добавлен UserID.
type Claims struct {
	UserID int `json:"user_id"`
	jwt.RegisteredClaims
}
