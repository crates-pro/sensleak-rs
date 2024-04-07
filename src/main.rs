use sensleak::service::detect_service::sensleaks;

/// The entry of the project
#[tokio::main]
async fn main() {
    sensleaks().await;
}

 