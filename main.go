package main

// Import our dependencies. We'll use the standard http library as well as the gorilla router for this app
import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	// "github.com/auth0-comcdmunity/auth0"
	"github.com/auth0/go-jwt-middleware"
	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
  "golang.org/x/crypto/bcrypt"
  rdb "github.com/dancannon/gorethink"
	// jose "gopkg.in/square/go-jose.v2"
)

type Product struct {
	Id          int
	Name        string
	Slug        string
	Description string
}

type LoginInfo struct {
	Username string `json:"username" gorethink:"id"`
	Password string `json:"password" gorethink:"password"`
}

type Post struct {
	Id        string    `json:"id" gorethink:"id,omitempty"`
	Hash      string    `json:"hash" gorethink:"hash"`    
	Body      string    `json:"body" gorethink:"body"`    
	Author    string    `json:"author" gorethink:"author"`    
	CreatedAt time.Time `json:"createdAt" gorethink:"createdAt"` 
}

/* We will create our catalog of VR experiences and store them in a slice. */
var products = []Product{
	Product{Id: 1, Name: "Hover Shooters", Slug: "hover-shooters", Description: "Shoot your way to the top on 14 different hoverboards"},
	Product{Id: 2, Name: "Ocean Explorer", Slug: "ocean-explorer", Description: "Explore the depths of the sea in this one of a kind underwater experience"},
	Product{Id: 3, Name: "Dinosaur Park", Slug: "dinosaur-park", Description: "Go back 65 million years in the past and ride a T-Rex"},
	Product{Id: 4, Name: "Cars VR", Slug: "cars-vr", Description: "Get behind the wheel of the fastest cars in the world."},
	Product{Id: 5, Name: "Robin Hood", Slug: "robin-hood", Description: "Pick up the bow and arrow and master the art of archery"},
	Product{Id: 6, Name: "Real World VR", Slug: "real-world-vr", Description: "Explore the seven wonders of the world in VR"},
}

var mySigningKey = []byte("secret")

func main() {
	// Here we are instantiating the gorilla/mux router
	r := mux.NewRouter()

	// On the default page we will simply serve our static index page.
	r.Handle("/", http.FileServer(http.Dir("./views/")))
	// We will setup our server so we can serve static assest like images, css from the /static/{file} route
	r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("./static/"))))

	// Our API is going to consist of three routes
	// /status - which we will call to make sure that our API is up and running
	// /products - which will retrieve a list of products that the user can leave feedback on
	// /products/{slug}/feedback - which will capture user feedback on products
	r.Handle("/status", StatusHandler).Methods("GET")
	/* We will add the middleware to our products and feedback routes. The status route will be publicly accessible */
	r.Handle("/userstatus", jwtMiddleware.Handler(UserStatus)).Methods("GET")
	r.Handle("/products", jwtMiddleware.Handler(ProductsHandler)).Methods("GET")
	r.Handle("/test", jwtMiddleware.Handler(AddFeedbackHandler)).Methods("GET")
	r.Handle("/tester", jwtMiddleware.Handler(Test)).Methods("GET")

	r.Handle("/products/{slug}/feedback", jwtMiddleware.Handler(AddFeedbackHandler)).Methods("POST")
	r.Handle("/addpost", jwtMiddleware.Handler(AddPost)).Methods("POST")
	r.Handle("/getposts", jwtMiddleware.Handler(GetPosts)).Methods("GET")

	r.Handle("/register", RegisterHandler).Methods("Post")
	r.Handle("/login", LoginHandler).Methods("POST")

	// Our application will run on port 3000. Here we declare the port and pass in our router.
	log.Fatal(http.ListenAndServe(":3030",
		handlers.LoggingHandler(os.Stdout, handlers.CORS(
		handlers.AllowedOrigins([]string{"http://localhost:3000"}),
		handlers.AllowedHeaders([]string{"Authorization"}))(r))))

}

func getDBSession() *rdb.Session{
  session, err := rdb.Connect(rdb.ConnectOpts{
    Address: "localhost:28015",
    Database: "hashapp",
  })

  if err != nil {
    log.Panic(err.Error())
  }

  return session
}

var StatusHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("API is up and running"))
})

/* The products handler will be called when the user makes a GET request to the /products endpoint.
   This handler will return a list of products available for users to review */
var ProductsHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	// Here we are converting the slice of products to json
	payload, _ := json.Marshal(products)

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(payload))
})

/* The feedback handler will add either positive or negative feedback to the product
   We would normally save this data to the database - but for this demo we'll fake it
   so that as long as the request is successful and we can match a product to our catalog of products
   we'll return an OK status. */
var AddFeedbackHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	var product Product
	vars := mux.Vars(r)
	slug := vars["slug"]

	for _, p := range products {
		if p.Slug == slug {
			product = p
		}
	}

	w.Header().Set("Content-Type", "application/json")
	if product.Slug != "" {
		payload, _ := json.Marshal(product)
		w.Write([]byte(payload))
	} else {
		w.Write([]byte("Product Not Found"))
	}
})

func getToken(username string) string {
	/* Create the token */
	token := jwt.New(jwt.SigningMethodHS256)

	/* Create a map to store our claims */
	claims := token.Claims.(jwt.MapClaims)

	/* Set token claims */
	claims["username"] = username
	claims["exp"] = time.Now().Add(time.Minute * 60).Unix()

	/* Sign the token with our secret */
	tokenString, _ := token.SignedString(mySigningKey)
	return tokenString
	/* Finally, write the token to the browser window */
}

var jwtMiddleware = jwtmiddleware.New(jwtmiddleware.Options{
	ValidationKeyGetter: func(token *jwt.Token) (interface{}, error) {
		fmt.Println("jwtMiddleware")
		return mySigningKey, nil
	},
	SigningMethod: jwt.SigningMethodHS256,
})

var AddPost = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	var post Post
	dec := json.NewDecoder(r.Body)
	err := dec.Decode(&post)
	if err != nil {
		fmt.Println(err)
		return
	}
	claims, extractClaimsSucess := extractClaims(r)
	if(!extractClaimsSucess) {
		fmt.Println("error parsing claim")
		return
	}
	tokenUsername := claims["username"].(string)
	post.Author = tokenUsername 
	post.CreatedAt = time.Now()
	fmt.Println(post)
	dbSession := getDBSession()
	err = rdb.Table("posts").Insert(post).Exec(dbSession)
	if err!=nil{
		fmt.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
	}

})

//hashes string and returns hashed value
func hash(val string) string {
  hash, err :=  bcrypt.GenerateFromPassword([]byte(val), 14)
  if err != nil {
    fmt.Print(err)
    return "FIX THIS SHIT LATER"
  }
  return string(hash)
}


var LoginHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	dec := json.NewDecoder(r.Body)
	var loginInfo LoginInfo
	var hashedLoginInfo LoginInfo
	dec.Decode(&loginInfo)
	fmt.Println(loginInfo)
	dbSession := getDBSession()
	res, err := rdb.Table("users").Get(loginInfo.Username).Run(dbSession)
	if err != nil {
		fmt.Print(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	res.Next(&hashedLoginInfo)
	fmt.Println(hashedLoginInfo)
	err = bcrypt.CompareHashAndPassword([]byte(hashedLoginInfo.Password), []byte(loginInfo.Password))
	if err == nil {
		w.Write([]byte(getToken(loginInfo.Username)))
	} else {
		fmt.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
	}
})

var RegisterHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
  dec := json.NewDecoder(r.Body)
  var loginInfo LoginInfo
  var hashedLoginInfo LoginInfo
  dec.Decode(&loginInfo)
  fmt.Println(loginInfo)
  hashedLoginInfo.Username = loginInfo.Username
  hashedLoginInfo.Password = hash(loginInfo.Password)
  dbSession := getDBSession()
  /*Check if user already exists */
  res, getErr := rdb.Table("users").Get(loginInfo.Username).Run(dbSession)
  if getErr != nil {
  	w.WriteHeader(http.StatusInternalServerError)
  	fmt.Println(getErr)

  } else if res.IsNil() {
	  insertErr := rdb.Table("users").Insert(hashedLoginInfo).Exec(dbSession)
	  if insertErr != nil {
	  	fmt.Println(insertErr)
	    w.WriteHeader(http.StatusInternalServerError)
	  } else {
	  	w.Write([]byte(getToken(loginInfo.Username)))
	  }
  } else {
  	w.WriteHeader(http.StatusBadRequest)
  }
  
  fmt.Println(hashedLoginInfo)
})

var Test = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
  w.Write([]byte("AUTHORIZED!!"))
})

var UserStatus = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
  w.WriteHeader(http.StatusOK)
})

func extractClaims(r *http.Request) (jwt.MapClaims, bool) {
	tokenStr := r.Header["Authorization"][0][7:]
    hmacSecretString := "secret"
    hmacSecret := []byte(hmacSecretString)
    token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
         // check token signing method etc
         return hmacSecret, nil
    })

    if err != nil {
    	fmt.Println(err)
        return nil, false
    }

    if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
    	fmt.Println("Valid JWT Token")
        return claims, true
    } else 
{        log.Printf("Invalid JWT Token")
        return nil, false
    }
}

var GetPosts = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	hash := r.URL.Query().Get("hash")
	var post Post
	var posts []Post
	// enc := json.NewEncoder()
	dbSession := getDBSession()
	res, getErr := rdb.Table("posts").GetAllByIndex("hash", hash).Run(dbSession)
	if getErr != nil {
			fmt.Println(getErr)
			w.WriteHeader(http.StatusInternalServerError)
			return
	}
	for (!res.IsNil()) {
		res.Next(&post)
		posts = append(posts, post)
	}
	fmt.Println(posts)
	postsJSON, err := json.Marshal(posts)
	if err != nil {
			fmt.Println(err)
			w.WriteHeader(http.StatusInternalServerError)
			return
	}
	w.Write([]byte(postsJSON))
	w.WriteHeader(http.StatusOK)
})
