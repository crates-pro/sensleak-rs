mod errors;

mod utils {
    pub mod detect_utils;
    pub mod git_util;
}

pub mod entity{
    pub mod models;
}

pub mod service{
    pub mod detect_service;
    pub mod git_service;
    pub mod db_service;
}
 
pub use entity::models;
pub use errors::*;
pub use utils::detect_utils;
pub use utils::git_util;
pub use git_util::*;
pub use models::*;

use actix_web::{web, App, HttpServer};
use actix_cors::Cors;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

mod routes{
    pub mod scan;
    pub mod rules;
}
pub use routes::scan::*;
pub use routes::rules::*;

use crate::routes::*;

pub async fn start() -> Result<(), Box<dyn std::error::Error>> {
    #[derive(OpenApi)]
    #[openapi(
        paths(
            scan::scan_repo,
            rules::get_all,
            rules::add_rules,
            rules::delete_rules_by_id,
            rules::update_rules
        ),
        components(
            schemas(ConfigDto,ScanResponse,RulesDto,JsonResponse,Rule,Allowlist,Leak)
        ),
     
        tags(
            (name = "scan", description = "Scan Git repositories API"),
            (name = "rules", description = "Rules management API"),
        )
    )]
    struct ApiDoc;

    HttpServer::new(|| {
        let cors = Cors::default()
            .allow_any_origin()
            .allow_any_method()
            .allow_any_header();

        App::new()
            .wrap(cors)
            .service(
                SwaggerUi::new("/swagger-ui/{_:.*}")
                    .url("/api-docs/openapi.json", ApiDoc::openapi())
            )
            .service(scan_repo)
            .service(rules::get_all)
            .service(rules::add_rules)
            .service(rules::delete_rules_by_id)
            .service(rules::update_rules)
    })
    .bind("0.0.0.0:7000")?
    .run()
    .await?;

    Ok(())
}
