use sensleak::start;
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("The API document is located at http://localhost:7000/swagger-ui/#/");
    start().await?;
    Ok(())
}

 