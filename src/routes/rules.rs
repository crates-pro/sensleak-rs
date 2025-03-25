use crate::utils::detect_utils::*;
use crate::models::{Allowlist, Rule};
use actix_web::{post, web, HttpResponse, Responder};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Rules Dto
#[derive(Serialize, Deserialize, Debug, ToSchema)]
pub struct RulesDto {
    config: String,
    rule: Option<Rule>,
    rule_id: Option<String>,
}

/// The response object
#[derive(Serialize, ToSchema)]
pub struct JsonResponse {
    code: usize,
    allowlist: Option<Allowlist>,
    ruleslist: Option<Vec<Rule>>,
    message: Option<String>,
}

/// Load the rules
/// 
/// Load the allowlists and ruleslist.
#[utoipa::path(
    post,
    path = "/rules/get_all",
    request_body = RulesDto,
    responses(
        (status = 200, description = "success", body = JsonResponse),
        (status = 400, description = "fail", body = JsonResponse)
    )
)]
#[post("/rules/get_all")]
pub async fn get_all(body: web::Json<RulesDto>) -> impl Responder {
    match load_config_file(&body.config) {
        Ok(scan) => HttpResponse::Ok().json(JsonResponse {
            code: 200,
            allowlist: Some(scan.allowlist),
            ruleslist: Some(scan.ruleslist),
            message: None,
        }),
        Err(err) => HttpResponse::BadRequest().json(JsonResponse {
            code: 400,
            message: Some(err.to_string()),
            allowlist: None,
            ruleslist: None,
        }),
    }
}

/// Add rules.
/// 
/// Add one single rule.
#[utoipa::path(
    post,
    path = "/rules/add_rules",
    request_body = RulesDto,
    responses(
        (status = 200, description = "success", body = JsonResponse),
        (status = 400, description = "fail", body = JsonResponse)
    )
)]
#[post("/rules/add_rules")]
pub async fn add_rules(body: web::Json<RulesDto>) -> impl Responder {
    let rule: Rule = match &body.rule {
        Some(value) => value.clone(),
        None => {
            return HttpResponse::BadRequest().json(JsonResponse {
                code: 400,
                message: Some("It is not a Rule struct".to_string()),
                allowlist: None,
                ruleslist: None,
            })
        }
    };

    match append_rule_to_toml(&rule, &body.config) {
        Ok(_) => HttpResponse::Ok().json(JsonResponse {
            code: 200,
            message: Some("success".to_string()),
            allowlist: None,
            ruleslist: None,
        }),
        Err(err) => HttpResponse::BadRequest().json(JsonResponse {
            code: 400,
            message: Some(err.to_string()),
            allowlist: None,
            ruleslist: None,
        }),
    }
}

/// Delete rules.
/// 
/// Delete one rule by id.
#[utoipa::path(
    post,
    path = "/rules/delete_rules_by_id",
    request_body = RulesDto,
    responses(
        (status = 200, description = "success", body = JsonResponse),
        (status = 400, description = "fail", body = JsonResponse)
    )
)]
#[post("/rules/delete_rules_by_id")]
pub async fn delete_rules_by_id(body: web::Json<RulesDto>) -> impl Responder {
    let rule_id = match &body.rule_id {
        Some(value) => value.clone(),
        None => {
            return HttpResponse::BadRequest().json(JsonResponse {
                code: 400,
                message: Some("It is not a rule id".to_string()),
                allowlist: None,
                ruleslist: None,
            })
        }
    };

    match delete_rule_by_id(&body.config, &rule_id) {
        Ok(_) => HttpResponse::Ok().json(JsonResponse {
            code: 200,
            message: Some("success".to_string()),
            allowlist: None,
            ruleslist: None,
        }),
        Err(err) => HttpResponse::BadRequest().json(JsonResponse {
            code: 400,
            message: Some(err.to_string()),
            allowlist: None,
            ruleslist: None,
        }),
    }
}

/// Update rules.
/// 
/// Update one rule by id.
#[utoipa::path(
    post,
    path = "/rules/update",
    request_body = RulesDto,
    responses(
        (status = 200, description = "success", body = JsonResponse),
        (status = 400, description = "fail", body = JsonResponse)
    )
)]
#[post("/rules/update")]
pub async fn update_rules(body: web::Json<RulesDto>) -> impl Responder {
    let rule_id = match &body.rule_id {
        Some(value) => value.clone(),
        None => {
            return HttpResponse::BadRequest().json(JsonResponse {
                code: 400,
                message: Some("It is not a rule id".to_string()),
                allowlist: None,
                ruleslist: None,
            })
        }
    };
    
    let rule: Rule = match &body.rule {
        Some(value) => value.clone(),
        None => {
            return HttpResponse::BadRequest().json(JsonResponse {
                code: 400,
                message: Some("It is not a Rule struct".to_string()),
                allowlist: None,
                ruleslist: None,
            })
        }
    };

    match update_rule_by_id(&body.config, &rule_id, &rule) {
        Ok(_) => HttpResponse::Ok().json(JsonResponse {
            code: 200,
            message: Some("success".to_string()),
            allowlist: None,
            ruleslist: None,
        }),
        Err(err) => HttpResponse::BadRequest().json(JsonResponse {
            code: 400,
            message: Some(err.to_string()),
            allowlist: None,
            ruleslist: None,
        }),
    }
}
