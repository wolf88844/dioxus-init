#![allow(non_snake_case,unused)]


#[cfg(feature="server")]
mod auth;

use dioxus::prelude::*;
use dioxus_fullstack::prelude::*;
use serde::{Serialize,Deserialize};
use server_fn::ServerFn;

fn main() {
    dioxus::logger::initialize_default();

    #[cfg(feature="web")]
    dioxus_web::launch::launch_cfg(app,dioxus_web::Config::new().hydrate(true));

    #[cfg(feature="server")]
    {
        use crate::auth::*;
        use axum::routing::*;
        use axum_session::SessionConfig;
        use axum_session::SessionStore;
        use axum_session_auth::AuthConfog;
        use axum_session_auth::SessionSqlitePool;

        tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(
            async move{

            }
        );
    }
}

fn app()->Element{
    let mut user_name = use_signal(||"?".to_string());
    let mut permissions = use_signal(||"?".to_string());

    rsx!(
        div { 
            button { 
                onclick:move|_|{
                    async move{
                        login().await.unwrap();
                    }
                },
                "Login Test User"
             }
         }
         div { 
            button { 
                onclick:move|_| async move{
                    if let Ok(data) = get_user_name().await{
                        user_name.set(data);
                    }
                },
                "Get User Name"
             }
             "User name:{user_name}"
          }
          div { 
            button {
                onclick:move|_| async move{
                    if let Ok(data) = get_user_permissions().await{
                        permissions.set(data);
                    }
                },
                "Get Permissions"
             }
             "Permissions:{permissions}"
           }
    )
}

#[server]
pub async fn get_user_name()->Result<String,ServerFnError>{
    let auth = auth::get_session().await?;
    Ok(auth.current_user.unwrap().username.to_string())
}

#[server]
pub async fn login()->Result<(),ServerFnError>{
    let auth = auth::get_session().await?;
    auth.login_USER(2);
    Ok(())
}

#[server]
pub async fn get_user_permissions()->Result<String,ServerFnError>{
    let method = execute().await?;
    let auth = auth::get_session().await?;
    let current_user = auth.current_user.clone().unwrap_or_default();

    if !auxm_session_auth::Auth::<crate::auth::User,i64,sqlx::SqlitePool>::build(
        [axum::http::Method::POST],
        false,
    )
    .requires(axum_session_auth::Rights::any([
        axum_session_auth::Rights::permissions("Category::View"),
        axum_session_auth::Rights::permission("Admin::View"),
    ]))
    .validate(&current_user,&method,None)
    .await{
        return Ok(format!(
            "User {},Dees not have permissions needed to view this page please login",
            current_user.username
        ));
    }

    Ok(format!(
        "User has Permissions needed.Here are the permissions:{:?}",
        current_user.permissions
    ))
}