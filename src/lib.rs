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
}
 
pub use entity::models;
 

pub use errors::*;
 
 
pub use utils::detect_utils;
pub use utils::git_util;
 
pub use git_util::*;
pub use models::*;

use axum::{routing, Router};
use utoipa::{
     OpenApi,
};
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
            schemas(ConfigDto,ScanResponse,RulesDto,JsonResponse,Rule,Allowlist)
        ),
     
        tags(
            (name = "scan", description = "Scan Git repositories API"),
            (name = "rules", description = "Rules management API"),

        )
    )]
    struct ApiDoc;

 
    let app = Router::new()
        .merge(SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", ApiDoc::openapi()))
        .route("/scan", routing::post(scan_repo))
        .route("/rules/get_all", routing::post(get_all))
        .route("/rules/add_rules", routing::post(add_rules))
        .route("/rules/delete_rules_by_id", routing::post(delete_rules_by_id))
        .route("/rules/update", routing::post(update_rules));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:7000").await.unwrap();
    axum::serve(listener, app.into_make_service()).await?;
    Ok(())
}

 