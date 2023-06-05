use crate::utils::detect_utils::*;
use crate::models::{Allowlist, Rule};
use axum::Json;
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
    path = "/rule/get_rules",
    request_body = RulesDto,
    responses(
        (status = 200, description = "success", body = JsonResponse),
        (status = 400, description = "fail", body = JsonResponse)
    )
)]
pub async fn get_all(Json(body): Json<RulesDto>) -> Json<JsonResponse> {
    match load_config_file(&body.config) {
        Ok(scan) => Json(JsonResponse {
            code: 200,
            allowlist: Some(scan.allowlist),
            ruleslist: Some(scan.ruleslist),
            message: None,
        }),
        Err(err) => Json(JsonResponse {
            code: 400,
            message: Some(err.to_string()),
            allowlist: None,
            ruleslist: None,
            // message: Some(String::from("Failed to load the configuration file.")),
        }),
    }
}

/// Add rules.
/// 
/// Add one single rule.
#[utoipa::path(
    post,
    path = "/rule/add_rules",
    request_body = RulesDto,
    responses(
        (status = 200, description = "success", body = JsonResponse),
        (status = 400, description = "fail", body = JsonResponse)
    )
)]
pub async fn add_rules(Json(body): Json<RulesDto>) -> Json<JsonResponse> {
    let rule: Rule = match body.rule {
        Some(value) => value,
        None => {
            return Json(JsonResponse {
                code: 400,
                message: Some("It is not a Rule struct".to_string()),
                allowlist: None,
                ruleslist: None,
            })
        }
    };

    match append_rule_to_toml(&rule, &body.config) {
        Ok(_) => Json(JsonResponse {
            code: 200,
            message: Some("success".to_string()),
            allowlist: None,
            ruleslist: None,
        }),
        Err(err) => Json(JsonResponse {
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
    path = "/rule/delete_rules_by_id",
    request_body = RulesDto,
    responses(
        (status = 200, description = "success", body = JsonResponse),
        (status = 400, description = "fail", body = JsonResponse)
    )
)]
pub async fn delete_rules_by_id(Json(body): Json<RulesDto>) -> Json<JsonResponse> {
    let rule_id = match body.rule_id {
        Some(value) => value,
        None => {
            return Json(JsonResponse {
                code: 400,
                message: Some("It is not a rule id".to_string()),
                allowlist: None,
                ruleslist: None,
            })
        }
    };

    match delete_rule_by_id(&body.config, &rule_id) {
        Ok(_) => Json(JsonResponse {
            code: 200,
            message: Some("success".to_string()),
            allowlist: None,
            ruleslist: None,
        }),
        Err(err) => Json(JsonResponse {
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
    path = "/rule/update",
    request_body = RulesDto,
    responses(
        (status = 200, description = "success", body = JsonResponse),
        (status = 400, description = "fail", body = JsonResponse)
    )
)]
pub async fn update_rules(Json(body): Json<RulesDto>) -> Json<JsonResponse> {
    let rule_id = match body.rule_id {
        Some(value) => value,
        None => {
            return Json(JsonResponse {
                code: 400,
                message: Some("It is not a rule id".to_string()),
                allowlist: None,
                ruleslist: None,
            })
        }
    };
    let rule: Rule = match body.rule {
        Some(value) => value,
        None => {
            return Json(JsonResponse {
                code: 400,
                message: Some("It is not a Rule struct".to_string()),
                allowlist: None,
                ruleslist: None,
            })
        }
    };

    match update_rule_by_id(&body.config, &rule_id,&rule) {
        Ok(_) => Json(JsonResponse {
            code: 200,
            message: Some("success".to_string()),
            allowlist: None,
            ruleslist: None,
        }),
        Err(err) => Json(JsonResponse {
            code: 400,
            message: Some(err.to_string()),
            allowlist: None,
            ruleslist: None,
        }),
    }
}
