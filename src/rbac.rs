use casbin::{DefaultModel, Enforcer, FileAdapter, CoreApi};
use std::sync::Arc;
use tokio::sync::RwLock;
use axum::{
    async_trait,
    extract::FromRequestParts,
    http::{request::Parts, StatusCode},
    response::{IntoResponse, Response},
};
use tracing::{error};

pub struct RbacEnforcer {
    enforcer: Arc<RwLock<Enforcer>>,
}

impl RbacEnforcer {
    pub async fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let model = DefaultModel::from_file("rbac_model.conf").await?;
        let adapter = FileAdapter::new("rbac_policy.csv");
        let enforcer = Enforcer::new(model, adapter).await?;
        
        Ok(Self {
            enforcer: Arc::new(RwLock::new(enforcer)),
        })
    }

    pub async fn check_permission(
        &self,
        subject: &str,
        object: &str,
        action: &str,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        let enforcer = self.enforcer.read().await;
        Ok(enforcer.enforce((subject, object, action))?)
    }
}

#[derive(Debug)]
pub struct RequirePermission {
    pub object: String,
    pub action: String,
}

#[async_trait]
impl<S> FromRequestParts<S> for RequirePermission
where
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let object = parts.uri.path().to_string();
        let action = parts.method.to_string();
        
        Ok(RequirePermission {
            object,
            action,
        })
    }
}

pub async fn check_permission(
    enforcer: &RbacEnforcer,
    user_role: &str,
    object: &str,
    action: &str,
) -> Result<bool, Response> {
    match enforcer.check_permission(user_role, object, action).await {
        Ok(allowed) => {
            if !allowed {
                error!("Permission denied for role {} on {} {}", user_role, object, action);
                return Err((StatusCode::FORBIDDEN, "Permission denied").into_response());
            }
            Ok(true)
        }
        Err(e) => {
            error!("Error checking permission: {:?}", e);
            Err((StatusCode::INTERNAL_SERVER_ERROR, "Error checking permission").into_response())
        }
    }
} 