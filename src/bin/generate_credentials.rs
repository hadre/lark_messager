use lark_messager::auth::AuthService;
use lark_messager::config::Config;
use lark_messager::database::Database;
use std::env;

#[derive(Debug)]
struct Options {
    username: String,
    password: String,
    is_admin: bool,
    is_super_admin: bool,
}

fn parse_args() -> Result<Options, String> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    if args.is_empty() {
        print_help();
        return Err("Missing arguments".to_string());
    }

    let mut username = None;
    let mut password = None;
    let mut is_admin = true; // 默认创建管理员
    let mut is_super_admin = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--user" | "-u" => {
                if i + 1 >= args.len() {
                    return Err("--user requires a value".to_string());
                }
                username = Some(args[i + 1].clone());
                i += 2;
            }
            "--password" | "-p" => {
                if i + 1 >= args.len() {
                    return Err("--password requires a value".to_string());
                }
                password = Some(args[i + 1].clone());
                i += 2;
            }
            "--non-admin" => {
                is_admin = false;
                i += 1;
            }
            "--super-admin" => {
                is_super_admin = true;
                is_admin = true;
                i += 1;
            }
            "--help" | "-h" => {
                print_help();
                std::process::exit(0);
            }
            other => {
                return Err(format!("Unknown argument: {}", other));
            }
        }
    }

    if is_super_admin && !is_admin {
        return Err("Super admin must also be admin".to_string());
    }

    if is_super_admin && args.contains(&"--non-admin".to_string()) {
        return Err("--super-admin cannot be combined with --non-admin".to_string());
    }

    let username = username.ok_or_else(|| "--user is required".to_string())?;
    let password = password.ok_or_else(|| "--password is required".to_string())?;

    Ok(Options {
        username,
        password,
        is_admin,
        is_super_admin,
    })
}

fn print_help() {
    println!("Lark Messager Bootstrap Utility");
    println!();
    println!("Create initial users (default admin) in the unified auth system.");
    println!();
    println!("USAGE:");
    println!("    cargo run --bin generate_credentials -- --user admin --password secret");
    println!();
    println!("OPTIONS:");
    println!("    -u, --user <USERNAME>         Username to create");
    println!("    -p, --password <PASSWORD>     Password for the user");
    println!("        --non-admin               Create a non-admin user");
    println!("        --super-admin            Create the unique super admin (only once)");
    println!("    -h, --help                    Show this help message");
}

#[tokio::main]
async fn main() -> Result<(), String> {
    dotenvy::dotenv().ok();
    let options = parse_args()?;

    let config = Config::from_env().map_err(|e| format!("Failed to load config: {}", e))?;
    let database = Database::new(&config.database_url)
        .await
        .map_err(|e| format!("Database connection failed: {}", e))?;
    let auth_service = AuthService::new(config.jwt_secret.clone(), database.clone())
        .await
        .map_err(|e| e.to_string())?;

    let user = if options.is_super_admin {
        auth_service
            .create_super_admin(&options.username, &options.password)
            .await
            .map_err(|e| format!("Failed to create super admin: {}", e))?
    } else {
        auth_service
            .create_user(&options.username, &options.password, options.is_admin)
            .await
            .map_err(|e| format!("Failed to create user: {}", e))?
    };

    println!("=== Unified Auth User Created ===");
    println!("User ID   : {}", user.id);
    println!("Username  : {}", user.username);
    let role = if user.is_super_admin {
        "super_admin"
    } else if user.is_admin {
        "admin"
    } else {
        "user"
    };
    println!("Role      : {}", role);
    println!("Created At: {}", user.created_at);
    println!();
    println!(
        "User password stored as secure hash; use provided credentials to login via /auth/login."
    );
    println!("Admin users can create additional users and API keys through the HTTP API.");

    Ok(())
}
