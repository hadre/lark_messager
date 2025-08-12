use crate::auth::AuthService;
use crate::config::Config;
use crate::database::Database;
use crate::error::AppResult;
use crate::handlers::AppState;
use crate::lark::LarkClient;
use crate::logging;
use crate::routes::create_router;
use axum::serve;
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tracing::info;

pub struct Server {
    config: Config,
}

impl Server {
    pub fn new(config: Config) -> Self {
        Self { config }
    }

    pub async fn run(&self) -> AppResult<()> {
        // Initialize logging
        logging::init_logging(&self.config.log_level)
            .map_err(|e| crate::error::AppError::Config(format!("Failed to initialize logging: {}", e)))?;

        info!("Starting Lark Messager Server v{}", env!("CARGO_PKG_VERSION"));
        info!("Log level: {}", self.config.log_level);

        // Initialize database
        info!("Connecting to database: {}", self.config.database_url);
        let db = Database::new(&self.config.database_url).await?;
        info!("Database connection established and migrations applied");

        // Initialize authentication service
        let auth = AuthService::new(self.config.jwt_secret.clone(), db.clone());
        info!("Authentication service initialized");

        // Initialize Lark client
        let lark = LarkClient::new(
            self.config.lark_app_id.clone(),
            self.config.lark_app_secret.clone(),
        );
        info!("Lark client initialized");

        // Create application state
        let state = AppState { db, auth, lark };

        // Create router
        let app = create_router(state);

        // Start server
        let addr = SocketAddr::from(([0, 0, 0, 0], self.config.server_port));
        let listener = TcpListener::bind(&addr).await
            .map_err(|e| crate::error::AppError::Config(format!("Failed to bind to address {}: {}", addr, e)))?;

        info!("Server listening on http://{}", addr);
        info!("API Documentation:");
        info!("  POST /auth/login - User authentication");
        info!("  POST /auth/api-keys - Create API key (admin only)");
        info!("  DELETE /auth/api-keys/{{id}} - Revoke API key (admin only)");
        info!("  POST /messages/send - Send message to user");
        info!("  POST /messages/send-group - Send message to group");
        info!("  POST /recipients/verify - Verify recipient exists");
        info!("  GET /health - Health check");

        serve(listener, app).await
            .map_err(|e| crate::error::AppError::Internal(format!("Server error: {}", e)))?;

        Ok(())
    }
}