//! Task management endpoints
//!
//! Provides HTTP endpoints for creating, querying, and transitioning tasks.
//! Write operations require `tasks:write` scope; reads require `tasks:read`.

use axum::{
    extract::{Path, Query, State},
    Json,
};
use chrono::{DateTime, Utc};
#[cfg(feature = "db")]
use epigraph_db::{TaskRepository, TaskRow};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{errors::ApiError, state::AppState};

// =============================================================================
// RESPONSE TYPES
// =============================================================================

/// HTTP response for a single task
#[derive(Serialize, Debug)]
pub struct TaskResponse {
    pub id: Uuid,
    pub description: String,
    pub task_type: String,
    pub state: String,
    pub assigned_agent: Option<Uuid>,
    pub priority: i32,
    pub workflow_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[cfg(feature = "db")]
impl From<TaskRow> for TaskResponse {
    fn from(row: TaskRow) -> Self {
        Self {
            id: row.id,
            description: row.description,
            task_type: row.task_type,
            state: row.state,
            assigned_agent: row.assigned_agent,
            priority: row.priority,
            workflow_id: row.workflow_id,
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }
}

// =============================================================================
// REQUEST TYPES
// =============================================================================

/// Request body for creating a task
#[derive(Deserialize, Debug)]
pub struct CreateTaskRequest {
    pub description: String,
    pub task_type: String,
    pub input: Option<serde_json::Value>,
    pub priority: Option<i32>,
    pub workflow_id: Option<Uuid>,
    pub timeout_seconds: Option<i32>,
}

/// Query parameters for listing tasks
#[derive(Deserialize, Debug, Default)]
pub struct ListTasksQuery {
    pub state: Option<String>,
    pub workflow_id: Option<Uuid>,
    pub limit: Option<i64>,
}

/// Request body for assigning a task to an agent
#[derive(Deserialize, Debug)]
pub struct AssignTaskRequest {
    pub agent_id: Uuid,
}

/// Request body for completing a task
#[derive(Deserialize, Debug)]
pub struct CompleteTaskRequest {
    pub result: serde_json::Value,
}

/// Request body for failing a task
#[derive(Deserialize, Debug)]
pub struct FailTaskRequest {
    pub error: String,
}

// =============================================================================
// HANDLERS
// =============================================================================

/// Create a new task
///
/// POST /api/v1/tasks
///
/// Requires `tasks:write` scope when OAuth2-authenticated.
#[cfg(feature = "db")]
pub async fn create_task(
    State(state): State<AppState>,
    auth_ctx: Option<axum::Extension<crate::middleware::bearer::AuthContext>>,
    Json(request): Json<CreateTaskRequest>,
) -> Result<Json<TaskResponse>, ApiError> {
    if let Some(axum::Extension(ref auth)) = auth_ctx {
        crate::middleware::scopes::check_scopes(auth, &["tasks:write"])?;
    }

    let now = Utc::now();
    let row = TaskRow {
        id: Uuid::new_v4(),
        description: request.description,
        task_type: request.task_type,
        input: request.input.unwrap_or(serde_json::Value::Null),
        output_schema: None,
        assigned_agent: None,
        priority: request.priority.unwrap_or(0),
        state: "created".to_string(),
        parent_task_id: None,
        workflow_id: request.workflow_id,
        timeout_seconds: request.timeout_seconds,
        retry_max: 3,
        retry_count: 0,
        result: None,
        error_message: None,
        created_at: now,
        updated_at: now,
        started_at: None,
        completed_at: None,
    };

    let created = TaskRepository::create(&state.db_pool, row).await?;

    Ok(Json(created.into()))
}

/// Create a new task (placeholder — no database)
///
/// POST /api/v1/tasks
#[cfg(not(feature = "db"))]
pub async fn create_task(
    State(_state): State<AppState>,
    Json(_request): Json<CreateTaskRequest>,
) -> Result<Json<TaskResponse>, ApiError> {
    Err(ApiError::ServiceUnavailable {
        service: "Task creation requires database".to_string(),
    })
}

/// Get a task by ID
///
/// GET /api/v1/tasks/:id
///
/// Requires `tasks:read` scope when OAuth2-authenticated.
#[cfg(feature = "db")]
pub async fn get_task(
    State(state): State<AppState>,
    auth_ctx: Option<axum::Extension<crate::middleware::bearer::AuthContext>>,
    Path(id): Path<Uuid>,
) -> Result<Json<TaskResponse>, ApiError> {
    if let Some(axum::Extension(ref auth)) = auth_ctx {
        crate::middleware::scopes::check_scopes(auth, &["tasks:read"])?;
    }

    let row = TaskRepository::get_by_id(&state.db_pool, id)
        .await?
        .ok_or_else(|| ApiError::NotFound {
            entity: "Task".to_string(),
            id: id.to_string(),
        })?;

    Ok(Json(row.into()))
}

/// Get a task by ID (placeholder — no database)
///
/// GET /api/v1/tasks/:id
#[cfg(not(feature = "db"))]
pub async fn get_task(
    State(_state): State<AppState>,
    Path(_id): Path<Uuid>,
) -> Result<Json<TaskResponse>, ApiError> {
    Err(ApiError::ServiceUnavailable {
        service: "Task retrieval requires database".to_string(),
    })
}

/// List tasks
///
/// GET /api/v1/tasks
///
/// Optional query params: state, workflow_id, limit (default 50).
/// Requires `tasks:read` scope when OAuth2-authenticated.
#[cfg(feature = "db")]
pub async fn list_tasks(
    State(state): State<AppState>,
    auth_ctx: Option<axum::Extension<crate::middleware::bearer::AuthContext>>,
    Query(params): Query<ListTasksQuery>,
) -> Result<Json<Vec<TaskResponse>>, ApiError> {
    if let Some(axum::Extension(ref auth)) = auth_ctx {
        crate::middleware::scopes::check_scopes(auth, &["tasks:read"])?;
    }

    let limit = params.limit.unwrap_or(50);

    let rows = match (params.state.as_deref(), params.workflow_id) {
        // Filter by workflow_id
        (None, Some(wf_id)) => TaskRepository::list_by_workflow(&state.db_pool, wf_id).await?,
        // Filter by state (use list_pending for created/queued, otherwise list pending as approximation)
        (Some(_state_filter), None) => {
            // list_pending covers created/queued; for other states, fall back to pending list
            // A future enhancement could add a list_by_state repo method
            TaskRepository::list_pending(&state.db_pool, limit).await?
        }
        // No filters — return pending tasks up to limit
        (None, None) => TaskRepository::list_pending(&state.db_pool, limit).await?,
        // Both filters — workflow takes precedence, then we filter by state in memory
        (Some(state_filter), Some(wf_id)) => {
            let wf_rows = TaskRepository::list_by_workflow(&state.db_pool, wf_id).await?;
            let sf = state_filter.to_string();
            wf_rows.into_iter().filter(|r| r.state == sf).collect()
        }
    };

    let tasks: Vec<TaskResponse> = rows.into_iter().map(Into::into).collect();

    Ok(Json(tasks))
}

/// List tasks (placeholder — no database)
///
/// GET /api/v1/tasks
#[cfg(not(feature = "db"))]
pub async fn list_tasks(
    State(_state): State<AppState>,
    Query(_params): Query<ListTasksQuery>,
) -> Result<Json<Vec<TaskResponse>>, ApiError> {
    Err(ApiError::ServiceUnavailable {
        service: "Task listing requires database".to_string(),
    })
}

/// Assign a task to an agent
///
/// POST /api/v1/tasks/:id/assign
///
/// Requires `tasks:write` scope when OAuth2-authenticated.
#[cfg(feature = "db")]
pub async fn assign_task(
    State(state): State<AppState>,
    auth_ctx: Option<axum::Extension<crate::middleware::bearer::AuthContext>>,
    Path(id): Path<Uuid>,
    Json(request): Json<AssignTaskRequest>,
) -> Result<Json<TaskResponse>, ApiError> {
    if let Some(axum::Extension(ref auth)) = auth_ctx {
        crate::middleware::scopes::check_scopes(auth, &["tasks:write"])?;
    }

    // Verify task exists
    let _ = TaskRepository::get_by_id(&state.db_pool, id)
        .await?
        .ok_or_else(|| ApiError::NotFound {
            entity: "Task".to_string(),
            id: id.to_string(),
        })?;

    TaskRepository::assign(&state.db_pool, id, request.agent_id).await?;

    let updated = TaskRepository::get_by_id(&state.db_pool, id)
        .await?
        .ok_or_else(|| ApiError::InternalError {
            message: "Task disappeared after assign".to_string(),
        })?;

    Ok(Json(updated.into()))
}

/// Assign a task to an agent (placeholder — no database)
///
/// POST /api/v1/tasks/:id/assign
#[cfg(not(feature = "db"))]
pub async fn assign_task(
    State(_state): State<AppState>,
    Path(_id): Path<Uuid>,
    Json(_request): Json<AssignTaskRequest>,
) -> Result<Json<TaskResponse>, ApiError> {
    Err(ApiError::ServiceUnavailable {
        service: "Task assignment requires database".to_string(),
    })
}

/// Mark a task as completed
///
/// POST /api/v1/tasks/:id/complete
///
/// Requires `tasks:write` scope when OAuth2-authenticated.
#[cfg(feature = "db")]
pub async fn complete_task(
    State(state): State<AppState>,
    auth_ctx: Option<axum::Extension<crate::middleware::bearer::AuthContext>>,
    Path(id): Path<Uuid>,
    Json(request): Json<CompleteTaskRequest>,
) -> Result<Json<TaskResponse>, ApiError> {
    if let Some(axum::Extension(ref auth)) = auth_ctx {
        crate::middleware::scopes::check_scopes(auth, &["tasks:write"])?;
    }

    // Verify task exists
    let _ = TaskRepository::get_by_id(&state.db_pool, id)
        .await?
        .ok_or_else(|| ApiError::NotFound {
            entity: "Task".to_string(),
            id: id.to_string(),
        })?;

    TaskRepository::complete(&state.db_pool, id, request.result).await?;

    let updated = TaskRepository::get_by_id(&state.db_pool, id)
        .await?
        .ok_or_else(|| ApiError::InternalError {
            message: "Task disappeared after complete".to_string(),
        })?;

    Ok(Json(updated.into()))
}

/// Mark a task as completed (placeholder — no database)
///
/// POST /api/v1/tasks/:id/complete
#[cfg(not(feature = "db"))]
pub async fn complete_task(
    State(_state): State<AppState>,
    Path(_id): Path<Uuid>,
    Json(_request): Json<CompleteTaskRequest>,
) -> Result<Json<TaskResponse>, ApiError> {
    Err(ApiError::ServiceUnavailable {
        service: "Task completion requires database".to_string(),
    })
}

/// Mark a task as failed
///
/// POST /api/v1/tasks/:id/fail
///
/// Requires `tasks:write` scope when OAuth2-authenticated.
#[cfg(feature = "db")]
pub async fn fail_task(
    State(state): State<AppState>,
    auth_ctx: Option<axum::Extension<crate::middleware::bearer::AuthContext>>,
    Path(id): Path<Uuid>,
    Json(request): Json<FailTaskRequest>,
) -> Result<Json<TaskResponse>, ApiError> {
    if let Some(axum::Extension(ref auth)) = auth_ctx {
        crate::middleware::scopes::check_scopes(auth, &["tasks:write"])?;
    }

    // Verify task exists
    let _ = TaskRepository::get_by_id(&state.db_pool, id)
        .await?
        .ok_or_else(|| ApiError::NotFound {
            entity: "Task".to_string(),
            id: id.to_string(),
        })?;

    TaskRepository::fail(&state.db_pool, id, &request.error).await?;

    let updated = TaskRepository::get_by_id(&state.db_pool, id)
        .await?
        .ok_or_else(|| ApiError::InternalError {
            message: "Task disappeared after fail".to_string(),
        })?;

    Ok(Json(updated.into()))
}

/// Mark a task as failed (placeholder — no database)
///
/// POST /api/v1/tasks/:id/fail
#[cfg(not(feature = "db"))]
pub async fn fail_task(
    State(_state): State<AppState>,
    Path(_id): Path<Uuid>,
    Json(_request): Json<FailTaskRequest>,
) -> Result<Json<TaskResponse>, ApiError> {
    Err(ApiError::ServiceUnavailable {
        service: "Task failure recording requires database".to_string(),
    })
}
