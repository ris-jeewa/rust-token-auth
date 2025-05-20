use axum::{
    routing::{get, post},
    Router,
    middleware,
    extract::State,
};
use sqlx::PgPool;
use std::net::SocketAddr;
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use std::sync::Arc;

mod auth;
mod routes;
mod rbac;

#[derive(Clone)]
struct AppState {
    auth: Arc<auth::AuthState>,
    rbac: Arc<rbac::RbacEnforcer>,
}

async fn add_state_to_extensions(
    State(state): State<Arc<AppState>>,
    req: axum::http::Request<axum::body::Body>,
    next: middleware::Next,
) -> Result<axum::http::Response<axum::body::Body>, axum::http::StatusCode> {
    let mut req = req;
    req.extensions_mut().insert(state.auth.clone());
    req.extensions_mut().insert(state.rbac.clone());
    Ok(next.run(req).await)
}

#[tokio::main]
async fn main() {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "debug".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Load environment variables
    dotenvy::dotenv().ok();

    // Database connection
    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let pool = PgPool::connect(&database_url)
        .await
        .expect("Failed to connect to Postgres");

    // JWT secret
    let jwt_secret = std::env::var("JWT_SECRET").expect("JWT_SECRET must be set");

    // Initialize auth state
    let auth_state = Arc::new(auth::AuthState::new(pool.clone(), jwt_secret));

    // Initialize RBAC enforcer
    let rbac_enforcer = Arc::new(rbac::RbacEnforcer::new().await.expect("Failed to initialize RBAC enforcer"));

    // Create app state
    let app_state = Arc::new(AppState {
        auth: auth_state.clone(),
        rbac: rbac_enforcer.clone(),
    });

    // Build our application with a route
    let app = Router::new()
        .route("/", get(routes::home))
        .route("/login", post(routes::login))
        .route("/register", post(routes::register))
        .route("/protected", get(routes::protected))
        .with_state(app_state.clone())
        .layer(middleware::from_fn_with_state(
            app_state,
            add_state_to_extensions,
        ))
        .layer(TraceLayer::new_for_http());

    // Run it
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    tracing::info!("listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
