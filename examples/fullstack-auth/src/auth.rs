
use serde::{Deserialize, Serialize};

use async_trait::async_trait;
use axum::{
    http::Method,
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use axum_session::{SessionConfig,SessionLayer,SessionStore,SessionAnyPool};
use axum_session_auth::*;
use core::pin::Pin;
use dioxus_fullstack::prelude::*;
use sqlx::sqlite::{SqlitePool,SqliteConnectOptions,SqlitePoolOptions};
use std::error::Error;
use std::future::Future;
use std::{collections::HashSet,net::SocketAddr,str::FromStr};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: i32,
    pub anonymous: bool,
    pub username: String,
    pub permissions: HashSet<String>,
}

#[derive(sqlx::FromRow, Clone)]
pub struct SqlPermissionToken {
    pub token: String,
}

impl Default for User {
    fn default() -> Self {
        let mut permissions = HashSet::new();
        permissions.insert("Category::View".to_owned());

        Self {
            id: 1,
            anonymous: true,
            username: "".to_owned(),
            permissions,
        }
    }
}

#[async_trait]
impl Authentication<User, i64, SqlitePool> for User {
    async fn load_user(userid: i64, pool: Option<&SqlitePool>) -> Result<User, anyhow::Error> {
        let pool = pool.unwrap();

        User::get_user(userid, pool)
            .await
            .ok_or_else(|| anyhow::anyhow!("User not found"))
    }

    fn is_authenticated(&self) -> bool {
        !self.anonymous
    }

    fn is_active(&self) -> bool {
        !self.anonymous
    }

    fn is_anonymous(&self) -> bool {
        self.anonymous
    }
}

#[async_trait]
impl HashPermission<SqlitePool> for User {
    async fn has(&self, perm: &str, _pool: &Option<&SqlitePool>) -> bool {
        self.permissions.contains(perm)
    }
}

impl User {
    pub async fn get_user(id: i64, pool: &SqlitePool) -> Option<Self> {
        let sqluser = sqlx::query_as::<_, SqlUser>("SELECT * FROM users WHERE id = $1")
            .bind(id)
            .fetch_one(pool)
            .await
            .ok()?;

        let sql_user_perms = sqlx::query_as::<_, SqlPermissionToken>(
            "SELECT * FROM user_permissions WHERE user_id = $1",
        )
        .bind(id)
        .fetch_all(pool)
        .await
        .ok()?;

        Some(sqluser.into_user(Some(sql_user_perms)))
    }

    pub async fn create_user_table(pool: &SqlitePool) {
        sqlx::query(
            r#"
            create table if not exists users(
                id integer primary key,
                anonymous boolean not null,
                username varchar(255) not null
            )
            "#,
        )
        .execute(pool)
        .await
        .unwrap();

        sqlx::query(
            r#"
            create table if not exists user_permissions(
                user_id integer not null,
                token varchar(255) not null
            )
            "#,
        )
        .execute(pool)
        .await
        .unwrap();

        sqlx::query(
            r#"
            insert into users
            (id,anonymous,username) select 1,true,'Guest' 
            on conflict(id) do update set 
            anonymous = excluded.anonymous,
            username = excluded.username
            "#,
        )
        .execute(pool)
        .await
        .unwrap();

        sqlx::query(
            r#"
                insert into users 
                (id,anonymous,username) select 2,false,'Test'
                on conflict(id) do update set
                anonymous = excluded.anonymous,
                username = excluded.username
            "#,
        )
        .execute(pool)
        .await
        .unwrap();

        sqlx::query(
            r#"
                insert into user_permissions
                (user_id,token) select 1,'Category::View'
            "#,
        )
        .execute(pool)
        .await
        .unwrap();
    }
}

#[derive(sqlx::FromRow, Clone)]
pub struct SqlUser {
    pub id: i32,
    pub anonymous: bool,
    pub username: String,
}

impl SqlUser {
    pub fn into_user(self, sql_user_perms: Option<Vec<SqlPermissionToken>>) -> User {
        User {
            id: self.id,
            anonymous: self.anonymous,
            username: self.username,
            permissions: if let Some(user_perms) = sql_user_perms {
                user_perms
                    .into_iter()
                    .map(|x| x.token)
                    .collect::<HashSet<String>>()
            } else {
                HashSet::<String>::new()
            },
        }
    }
}

pub async fn connect_to_database() -> SqlitePool {
    let connect_opts = SqliteConnectOptions::from_str("sqlit::memory:").unwrap();
    SqlitePoolOptions::new()
        .max_connections(5)
        .connect_with(connect_opts)
        .await
        .unwrap()
}

pub type Session = axum_session_auth::AuthSession<
    crate::auth::User,
    i64,
    axum_session_auth::SessionAnyPool,
    sqlx::SqlitePool,
>;

pub async fn get_session() -> Result<Session, ServerFnError> {
    extract::<Session, _>()
        .await
        .map_err(|_| ServerFnError::new("AuthSessionLayer was not found"))
}
