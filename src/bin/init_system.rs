use lark_messager::config::Config;
use lark_messager::database::Database;
use std::process;

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();

    let config = match Config::from_env() {
        Ok(cfg) => cfg,
        Err(err) => {
            eprintln!("[init] Failed to load configuration: {err}");
            process::exit(1);
        }
    };

    if !config.first_deployment {
        println!("[init] FIRST_DEPLOYMENT is false; skipping initialisation (no changes applied).");
        return;
    }

    println!("[init] FIRST_DEPLOYMENT=true; applying migrations and seed data.");
    println!("[init] Connecting to database: {}", config.database_url);
    if let Err(err) = Database::new_with_migrations(&config.database_url).await {
        eprintln!("[init] Database initialisation failed: {err}");
        process::exit(1);
    }

    println!("[init] Database schema initialised successfully.");
    println!("[init] Seeded super_admin account from migrations; rotate credentials immediately.");
}
