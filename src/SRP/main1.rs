use actix_web::{web, App, HttpServer, HttpResponse, Responder};
use serde::{Deserialize, Serialize};
use srp::server::SrpServer;
use srp::groups::G_2048;
use diesel::prelude::*;
use diesel::r2d2::{self, ConnectionManager};
use bcrypt::{hash, verify, DEFAULT_COST};
use std::env;
use dotenv::dotenv;

// Database connection pool
type DbPool = r2d2::Pool<ConnectionManager<SqliteConnection>>;

// User model
#[derive(Queryable, Insertable, Serialize, Deserialize)]
#[table_name = "users"]
struct User {
    id: i32,
    username: String,
    password_hash: String,
}

// User registration request
#[derive(Deserialize)]
struct RegisterRequest {
    username: String,
    password: String,
}

// User login request
#[derive(Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let manager = ConnectionManager::<SqliteConnection>::new(database_url);
    let pool = r2d2::Pool::builder().build(manager).expect("Failed to create pool.");

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(pool.clone()))
            .route("/register", web::post().to(register_user))
            .route("/login", web::post().to(login_user))
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}

// Register a new user
async fn register_user(pool: web::Data<DbPool>, form: web::Json<RegisterRequest>) -> impl Responder {
    let conn = pool.get().expect("couldn't get db connection from pool");
    
    let password_hash = hash(&form.password, DEFAULT_COST).unwrap();
    let new_user = User {
        id: 0, // Auto-increment by DB
        username: form.username.clone(),
        password_hash,
    };

    // Insert user into the database
    diesel::insert_into(users::table)
        .values(&new_user)
        .execute(&conn)
        .expect("Error saving new user");

    HttpResponse::Ok().json("User registered")
}

// Login user
async fn login_user(pool: web::Data<DbPool>, form: web::Json<LoginRequest>) -> impl Responder {
    use self::users::dsl::*;

    let conn = pool.get().expect("couldn't get db connection from pool");
    
    let result = users
        .filter(username.eq(&form.username))
        .first::<User>(&conn)
        .optional()
        .expect("Error loading user");

    if let Some(user) = result {
        if verify(&form.password, &user.password_hash).unwrap() {
            return HttpResponse::Ok().json("Login successful");
        } else {
            return HttpResponse::Unauthorized().json("Invalid credentials");
        }
    }

    HttpResponse::Unauthorized().json("Invalid credentials")
}
