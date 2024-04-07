use crate::models::{ConnectDbConfig, Entity as Leaks, Leak};
use chrono::Local;
use sea_orm::*;
use std::env;

/// Sets up the database connection using the application's configuration settings.
///
/// This function attempts to establish a connection to the database using environment variables for the database configuration.
/// It reads configuration values such as host, port, user, password, and database name from environment variables
/// and uses them to construct the database URL.
///
/// # Returns
///
/// Returns a `Result<DatabaseConnection, DbErr>`:
/// - `Ok(DatabaseConnection)` if the connection is successfully established.
/// - `Err(DbErr)` if there is an error connecting to the database.
pub async fn set_up_db() -> Result<DatabaseConnection, DbErr> {
    let config = get_db_config();
    let db_url = config.to_connection_url();                    
    let db = Database::connect(&db_url).await?;
    Ok(db)
}

/// Inserts a vector of `Leak` entities into the database and ensures that the `Leaks` table exists.
///
/// This function first checks if the `Leaks` table exists in the database and creates it if not.
/// Then, it proceeds to insert the provided vector of `Leak` entities into the `Leaks` table.
///
/// # Arguments
///
/// * `_leaks` - A reference to a vector of `Leak` entities to be inserted into the database.
///
/// # Returns
///
/// Returns a `Result<(), DbErr>` indicating the outcome of the operation:
/// - `Ok(())` if the insertion is successful and the `Leaks` table is either found or successfully created.
/// - `Err(DbErr)` if there is an error during the table check/creation or insertion process.
pub async fn insert_leaks(_leaks: &Vec<Leak>) -> Result<(), DbErr> {
    let db = match set_up_db().await {
        Ok(db) => db,
        Err(err) => panic!("{}", err),
    };

    // Check if the table Leaks exists and create it if not
    let builder = db.get_database_backend();
    let schema = Schema::new(builder);

    let stmt = schema
        .create_table_from_entity(Leaks)
        .if_not_exists()
        .to_owned();

    let stmt = builder.build(&stmt);

    db.execute(stmt).await?;
      
    println!(
        "\x1b[34m[INFO]\x1b[0m[{}] Create Success ...",
        Local::now().format("%Y-%m-%d %H:%M:%S"),
    );

    // Insert leaks
    for leak in _leaks.iter() {
        let active_model = leak.to_active_model();

        let insert_result = Leaks::insert(active_model)
            .exec(&db)
            .await?;
        println!("Inserted leak with result: {:?}", insert_result);
    }

    println!(
        "\x1b[34m[INFO]\x1b[0m[{}] Insert Success ...",
        Local::now().format("%Y-%m-%d %H:%M:%S"),
    );

    Ok(())
}

/// Retrieves database connection configuration from environment variables.
///
/// This function constructs a `ConnectDbConfig` struct with database connection details
/// such as host, port, username, password, and database name, reading the values from
/// environment variables. If an environment variable is not set, it defaults to a predefined value.
///
/// # Returns
///
/// Returns a `ConnectDbConfig` struct populated with the database connection details.
fn get_db_config() -> ConnectDbConfig {
    let mut config = ConnectDbConfig::default();
    config.host = env::var("PG_HOST").unwrap_or("localhost".to_string());
    config.port = env::var("PG_PORT").unwrap_or("5432".to_string());
    config.user = env::var("PG_USER").unwrap_or("postgres".to_string());
    config.password = env::var("PG_PASSWORD").unwrap_or("postgres".to_string());
    config.dbname = env::var("PG_DBNAME").unwrap_or("postgres".to_string());
    config
}