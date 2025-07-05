package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/jmoiron/sqlx"
	"github.com/joho/godotenv"
	"github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

var DB *sqlx.DB
var jwtKey []byte

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatalf("Error loading .env file: %v", err)
	}

	jwtKey = []byte(os.Getenv("JWT_SECRET_KEY"))
	if len(jwtKey) == 0 {
		log.Fatal("JWT_SECRET_KEY not set in .env file or is empty")
	}

	err = InitDB()
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer DB.Close()

	router := gin.Default()

	//главный маршрут
	router.GET("/", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message": "Welcome to To-Do API!",
		})
	})

	router.POST("/register", Register)
	router.POST("/login", Login)

	authenticated := router.Group("/")
	authenticated.Use(AuthMiddleware())
	{
		listsGroup := authenticated.Group("/lists")
		{
			//маршруты для todo lists
			listsGroup.POST("", CreateTodoList)          //создает новый список задач
			listsGroup.GET("", GetTodoLists)             //получает все списки задач для пользователя
			listsGroup.GET("/id/:id", GetTodoListByID)   //получает конкретный список задач по его ID
			listsGroup.PUT("/id/:id", UpdateTodoList)    //обновляет существующий список задач
			listsGroup.DELETE("/id/:id", DeleteTodoList) //удаляет список задач

			//маршруты для TodoItems, вложенные в группу списков
			itemsGroup := listsGroup.Group("/:list_id/items")
			{
				itemsGroup.POST("", CreateTodoItem)            //создает новый элемент задачи в указанном списке
				itemsGroup.GET("", GetTodoItems)               //получает все элементы задач для указанного списка
				itemsGroup.GET("/:item_id", GetTodoItemByID)   //получает конкретный элемент задачи по его ID внутри указанного списка
				itemsGroup.PUT("/:item_id", UpdateTodoItem)    //обновляет существующий элемент задачи
				itemsGroup.DELETE("/:item_id", DeleteTodoItem) //удаляет элемент задачи
			}
		}
	}

	log.Fatal(router.Run(":8080"))
}

func InitDB() error {
	dbHost := os.Getenv("DB_HOST")
	dbPort := os.Getenv("DB_PORT")
	dbUser := os.Getenv("DB_USER")
	dbPassword := os.Getenv("DB_PASSWORD")
	dbName := os.Getenv("DB_NAME")
	dbSSLMode := os.Getenv("DB_SSLMODE")

	dataSourceName := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		dbHost, dbPort, dbUser, dbPassword, dbName, dbSSLMode)

	var err error

	DB, err = sqlx.Connect("postgres", dataSourceName)
	if err != nil {
		return err
	}

	err = DB.Ping()
	if err != nil {
		return err
	}

	log.Println("Successfully connected to PostgreSQL database!")
	return nil
}

// обработчики для пользователей
func Register(c *gin.Context) {
	var req RegisterRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("Error hashing password: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
		return
	}

	var userID int

	query := `INSERT INTO users (username, password) VALUES ($1, $2) RETURNING id`
	err = DB.QueryRow(query, req.Username, string(hashedPassword)).Scan(&userID)
	if err != nil {
		if pgErr, ok := err.(*pq.Error); ok && pgErr.Code == "23505" { // 23505 - unique_violation
			c.JSON(http.StatusConflict, gin.H{"error": "Username already exists"})
			return
		}
		log.Printf("Error registering user: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to register user"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"message": "User registered successfully", "user_id": userID})
}
func Login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var user User

	err := DB.Get(&user, "SELECT id, username, password FROM users WHERE username = $1", req.Username)
	if err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
			return
		}
		log.Printf("Error fetching user: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to login"})
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password))
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	expirationTime := time.Now().Add(24 * time.Hour)
	claims := &Claims{
		UserID: user.ID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "todo-app",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		log.Printf("Error signing token: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"token": tokenString})
}

// middleware для проверки JWT токена
func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString := c.GetHeader("Authorization")

		if tokenString == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization token required"})
			c.Abort()
			return
		}

		if len(tokenString) < 7 || tokenString[:7] != "Bearer " {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token format"})
			c.Abort()
			return
		}
		tokenString = tokenString[7:]

		claims := &Claims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})

		if err != nil {
			if err == jwt.ErrSignatureInvalid {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token signature"})
				c.Abort()
				return
			}
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized: " + err.Error()})
			c.Abort()
			return
		}

		if !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		c.Set("userID", claims.UserID)
		c.Next()
	}
}

// обработчики запросов
func CreateTodoList(c *gin.Context) {
	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "User ID not found in context"})
		return
	}
	currentUserID := userID.(int)

	var newList TodoList

	if err := c.ShouldBindJSON(&newList); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	newList.UserID = currentUserID

	query := `INSERT INTO todo_lists (user_id, title) VALUES ($1, $2) RETURNING id, created_at, updated_at`
	err := DB.QueryRow(query, newList.UserID, newList.Title).Scan(&newList.ID, &newList.CreatedAt, &newList.UpdatedAt)

	if err != nil {
		log.Printf("Error creating todo list: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create todo list"})
		return
	}

	c.JSON(http.StatusCreated, newList)
}
func GetTodoLists(c *gin.Context) {
	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "User ID not found in context"})
		return
	}
	currentUserID := userID.(int)

	var lists []TodoList

	err := DB.Select(&lists, "SELECT id, user_id, title, created_at, updated_at FROM todo_lists WHERE user_id = $1 ORDER BY created_at DESC", currentUserID)

	if err != nil {
		log.Printf("Error fetching todo lists: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch todo lists"})
		return
	}

	c.JSON(http.StatusOK, lists)
}
func GetTodoListByID(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.Atoi(idStr)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid list ID"})
		return
	}

	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "User ID not found in context"})
		return
	}
	currentUserID := userID.(int)

	var list TodoList

	err = DB.Get(&list, "SELECT id, user_id, title, created_at, updated_at FROM todo_lists WHERE id = $1 AND user_id = $2", id, currentUserID)

	if err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "Todo list not found or unauthorized"})
			return
		}
		log.Printf("Error fetching todo list by ID: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch todo list"})
		return
	}

	c.JSON(http.StatusOK, list)
}
func UpdateTodoList(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.Atoi(idStr)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid list ID"})
		return
	}

	var updatedList TodoList

	if err := c.ShouldBindJSON(&updatedList); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "User ID not found in context"})
		return
	}
	currentUserID := userID.(int)

	result, err := DB.Exec("UPDATE todo_lists SET title = $1 WHERE id = $2 AND user_id = $3",
		updatedList.Title, id, currentUserID)
	if err != nil {
		log.Printf("Error updating todo list: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update todo list"})
		return
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		log.Printf("Error getting rows affected: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to check update result"})
		return
	}
	if rowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Todo list not found or unauthorized"})
		return
	}

	var list TodoList
	err = DB.Get(&list, "SELECT id, user_id, title, created_at, updated_at FROM todo_lists WHERE id = $1 AND user_id = $2", id, currentUserID)
	if err != nil {
		log.Printf("Error re-fetching todo list after update: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve updated todo list"})
		return
	}

	c.JSON(http.StatusOK, list)
}
func DeleteTodoList(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid list ID"})
		return
	}

	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "User ID not found in context"})
		return
	}
	currentUserID := userID.(int)

	result, err := DB.Exec("DELETE FROM todo_lists WHERE id = $1 AND user_id = $2", id, currentUserID)
	if err != nil {
		log.Printf("Error deleting todo list: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete todo list"})
		return
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		log.Printf("Error getting rows affected: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to check delete result"})
		return
	}
	if rowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Todo list not found or unauthorized"})
		return
	}

	c.JSON(http.StatusNoContent, nil) //204 No Content это успешное удаление
}

func CreateTodoItem(c *gin.Context) {
	listIDStr := c.Param("list_id")
	listID, err := strconv.Atoi(listIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid list ID"})
		return
	}

	var newItem TodoItem
	if err := c.ShouldBindJSON(&newItem); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "User ID not found in context"})
		return
	}
	currentUserID := userID.(int)

	var existingList TodoList
	err = DB.Get(&existingList, "SELECT id FROM todo_lists WHERE id = $1 AND user_id = $2", listID, currentUserID)
	if err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "Todo list not found or unauthorized to add item"})
			return
		}
		log.Printf("Error checking todo list existence: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to check todo list"})
		return
	}

	newItem.TodoListID = listID

	query := `INSERT INTO todo_items (todo_list_id, title, description, done) VALUES ($1, $2, $3, $4) RETURNING id, created_at, updated_at`
	err = DB.QueryRow(query, newItem.TodoListID, newItem.Title, newItem.Description, newItem.Done).Scan(&newItem.ID, &newItem.CreatedAt, &newItem.UpdatedAt)
	if err != nil {
		log.Printf("Error creating todo item: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create todo item"})
		return
	}

	c.JSON(http.StatusCreated, newItem)
}
func GetTodoItems(c *gin.Context) {
	listIDStr := c.Param("list_id")
	listID, err := strconv.Atoi(listIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid list ID"})
		return
	}

	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "User ID not found in context"})
		return
	}
	currentUserID := userID.(int)

	var existingList TodoList
	err = DB.Get(&existingList, "SELECT id FROM todo_lists WHERE id = $1 AND user_id = $2", listID, currentUserID)
	if err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "Todo list not found or unauthorized to view items"})
			return
		}
		log.Printf("Error checking todo list existence: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to check todo list"})
		return
	}

	var items []TodoItem
	err = DB.Select(&items, "SELECT id, todo_list_id, title, description, done, created_at, updated_at FROM todo_items WHERE todo_list_id = $1 ORDER BY created_at ASC", listID)
	if err != nil {
		log.Printf("Error fetching todo items: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch todo items"})
		return
	}

	c.JSON(http.StatusOK, items)
}
func GetTodoItemByID(c *gin.Context) {
	listIDStr := c.Param("list_id")
	listID, err := strconv.Atoi(listIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid list ID"})
		return
	}

	itemIDStr := c.Param("item_id")
	itemID, err := strconv.Atoi(itemIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid item ID"})
		return
	}

	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "User ID not found in context"})
		return
	}
	currentUserID := userID.(int)

	var existingList TodoList
	err = DB.Get(&existingList, "SELECT id FROM todo_lists WHERE id = $1 AND user_id = $2", listID, currentUserID)
	if err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "Todo list not found or unauthorized to view item"})
			return
		}
		log.Printf("Error checking todo list existence: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to check todo list"})
		return
	}

	var item TodoItem
	err = DB.Get(&item, "SELECT id, todo_list_id, title, description, done, created_at, updated_at FROM todo_items WHERE id = $1 AND todo_list_id = $2", itemID, listID)
	if err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "Todo item not found in this list"})
			return
		}
		log.Printf("Error fetching todo item by ID: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch todo item"})
		return
	}

	c.JSON(http.StatusOK, item)
}
func UpdateTodoItem(c *gin.Context) {
	listIDStr := c.Param("list_id")
	listID, err := strconv.Atoi(listIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid list ID"})
		return
	}

	itemIDStr := c.Param("item_id")
	itemID, err := strconv.Atoi(itemIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid item ID"})
		return
	}

	var updatedItem TodoItem
	if err := c.ShouldBindJSON(&updatedItem); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "User ID not found in context"})
		return
	}
	currentUserID := userID.(int)

	var existingList TodoList
	err = DB.Get(&existingList, "SELECT id FROM todo_lists WHERE id = $1 AND user_id = $2", listID, currentUserID)
	if err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "Todo list not found or unauthorized to update item"})
			return
		}
		log.Printf("Error checking todo list existence: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to check todo list"})
		return
	}

	result, err := DB.Exec("UPDATE todo_items SET title = $1, description = $2, done = $3 WHERE id = $4 AND todo_list_id = $5",
		updatedItem.Title, updatedItem.Description, updatedItem.Done, itemID, listID)
	if err != nil {
		log.Printf("Error updating todo item: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update todo item"})
		return
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		log.Printf("Error getting rows affected: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to check update result"})
		return
	}
	if rowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Todo item not found in this list"})
		return
	}

	var item TodoItem
	err = DB.Get(&item, "SELECT id, todo_list_id, title, description, done, created_at, updated_at FROM todo_items WHERE id = $1 AND todo_list_id = $2", itemID, listID)
	if err != nil {
		log.Printf("Error re-fetching todo item after update: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve updated todo item"})
		return
	}

	c.JSON(http.StatusOK, item)
}
func DeleteTodoItem(c *gin.Context) {
	listIDStr := c.Param("list_id")
	listID, err := strconv.Atoi(listIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid list ID"})
		return
	}

	itemIDStr := c.Param("item_id")
	itemID, err := strconv.Atoi(itemIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid item ID"})
		return
	}

	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "User ID not found in context"})
		return
	}
	currentUserID := userID.(int)

	var existingList TodoList
	err = DB.Get(&existingList, "SELECT id FROM todo_lists WHERE id = $1 AND user_id = $2", listID, currentUserID)
	if err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "Todo list not found or unauthorized to delete item"})
			return
		}
		log.Printf("Error checking todo list existence: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to check todo list"})
		return
	}

	result, err := DB.Exec("DELETE FROM todo_items WHERE id = $1 AND todo_list_id = $2", itemID, listID)
	if err != nil {
		log.Printf("Error deleting todo item: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete todo item"})
		return
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		log.Printf("Error getting rows affected: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to check delete result"})
		return
	}
	if rowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Todo item not found in this list"})
		return
	}

	c.JSON(http.StatusNoContent, nil)
}
