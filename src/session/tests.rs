use std::collections::HashMap;

use super::*;
use crate::session::store::MemoryStore;
use serde::{Deserialize, Serialize};
use time::{Duration, UtcDateTime};

#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct TestData {
    data: String,
    map: HashMap<String, u32>,
}

// Helper function to create a test session manager
fn create_test_manager() -> SessionManager {
    SessionManager::new(Arc::new(MemoryStore::new()))
}

// Helper function to create test data
fn create_test_data() -> TestData {
    TestData {
        data: "test data".to_string(),
        map: HashMap::from([("key1".into(), 1), ("key2".into(), 2)]),
    }
}

#[tokio::test]
async fn test_new_session_manager_default_values() {
    let manager = create_test_manager();

    // Should return default values
    assert_eq!(manager.expiry, DEFAULT_DURATION);
    assert_eq!(manager.max_sessions, DEFAULT_MAX_SESSIONS);
}

#[tokio::test]
async fn test_method_chaining() {
    let manager = SessionManager::new(Arc::new(MemoryStore::new()))
        .with_expiry(Duration::minutes(45))
        .with_max_sessions(75_000);

    assert_eq!(manager.expiry, Duration::minutes(45));
    assert_eq!(manager.max_sessions, 75_000);
}

#[tokio::test]
async fn test_session_manager_flow() {
    let manager = create_test_manager();
    let session_id = "test_id";
    let data = create_test_data();

    // Insert and verify it exists
    manager.insert(session_id, &data).await.unwrap();
    let retrieved: Option<TestData> = manager.get(session_id).await.unwrap();
    assert_eq!(retrieved, Some(data));

    // Remove and verify it's gone
    manager.remove(session_id).await.unwrap();
    let retrieved: Option<TestData> = manager.get(session_id).await.unwrap();
    assert_eq!(retrieved, None);
}

#[tokio::test]
async fn test_multiple_sessions() {
    let manager = create_test_manager();
    let sessions = vec![
        ("session1", "data1"),
        ("session2", "data2"),
        ("session3", "data3"),
    ];

    // Insert multiple sessions
    for (id, data) in &sessions {
        manager.insert(*id, data).await.unwrap();
    }

    // Verify all sessions exist
    for (id, expected_data) in &sessions {
        let retrieved: Option<String> = manager.get(*id).await.unwrap();
        assert_eq!(retrieved, Some(expected_data.to_string()));
    }

    // Remove one session and verify others still exist
    manager.remove(sessions[1].0).await.unwrap();

    let retrieved: Option<String> = manager.get(sessions[0].0).await.unwrap();
    assert_eq!(retrieved, Some(sessions[0].1.to_string()));

    // Verify the removed session is gone
    let retrieved: Option<String> = manager.get(sessions[1].0).await.unwrap();
    assert_eq!(retrieved, None);

    let retrieved: Option<String> = manager.get(sessions[2].0).await.unwrap();
    assert_eq!(retrieved, Some(sessions[2].1.to_string()));
}

#[tokio::test]
async fn test_set_expiry() {
    let manager = create_test_manager();
    let session_id = "expiry_test";
    let data = create_test_data();
    let new_duration = Duration::minutes(16);

    manager.insert(session_id, &data).await.unwrap();

    // override the global expiry for this session
    manager.set_expiry(session_id, new_duration).await.unwrap();

    // Verify session still exists
    let retrieved: Option<TestData> = manager.get(session_id).await.unwrap();
    assert_eq!(retrieved, Some(data));

    // The expire date (now + 16 minutes) should now be greater than the default expiry
    // since the global expiry is set to 15 minutes from now
    let expiry_date = manager.get_expiry_date(session_id).await.unwrap();
    assert!(expiry_date > Some(UtcDateTime::now() + DEFAULT_DURATION));
}

#[tokio::test]
async fn test_get_expiry_date() {
    let manager = create_test_manager();
    let session_id = "expiry_date_test";
    let data = create_test_data();

    let before_insert = UtcDateTime::now();
    manager.insert(session_id, data).await.unwrap();
    let after_insert = UtcDateTime::now();

    let expiry_date = manager.get_expiry_date(session_id).await.unwrap();
    assert!(expiry_date.is_some());

    let expiry = expiry_date.unwrap();
    // Expiry should be approximately 15 minutes (default) after insertion
    let expected_min = before_insert + DEFAULT_DURATION;
    let expected_max = after_insert + DEFAULT_DURATION;

    assert!(expiry >= expected_min && expiry <= expected_max);
}

#[tokio::test]
async fn test_custom_expiry_duration() {
    let store = MemoryStore::new();
    let custom_duration = Duration::hours(2);
    let manager = SessionManager::new(Arc::new(store)).with_expiry(custom_duration);

    let session_id = "custom_expiry_test";
    let data = create_test_data();

    let before_insert = UtcDateTime::now();
    manager.insert(session_id, data).await.unwrap();
    let after_insert = UtcDateTime::now();

    let expiry_date = manager.get_expiry_date(session_id).await.unwrap().unwrap();

    // Expiry should be approximately 2 hours after insertion
    let expected_min = before_insert + custom_duration;
    let expected_max = after_insert + custom_duration;

    assert!(expiry_date >= expected_min && expiry_date <= expected_max);
}

#[tokio::test]
async fn test_max_sessions_limit() {
    let store = MemoryStore::new();
    let max_sessions = 2;
    let manager = SessionManager::new(Arc::new(store)).with_max_sessions(max_sessions);

    // Insert sessions up to the limit
    manager.insert("session1", "data1").await.unwrap();
    manager.insert("session2", "data2").await.unwrap();

    // Should fail to insert another
    let result = manager.insert("session3", "data3").await;
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), SessionError::MaxSessions));

    // Remove one session
    manager.remove("session1").await.unwrap();

    // Should now be able to insert a new session
    let result = manager.insert("session3", "data3").await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_session_expiration() {
    let store = MemoryStore::new();
    let manager = SessionManager::new(Arc::new(store)).with_expiry(Duration::seconds(1));

    let id1 = "expiration_test";
    let data1 = create_test_data();
    let id2 = "expiration_test2";
    let data2 = create_test_data();

    manager.insert(id1, &data1).await.unwrap();
    manager.insert(id2, &data2).await.unwrap();
    // override the global expiry for the second session
    manager
        .set_expiry(id2, Duration::seconds(15))
        .await
        .unwrap();

    // Wait for session 1 to expire
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    // Session 1 should be expired and removed
    let retrieved: Option<TestData> = manager.get(id1).await.unwrap();
    assert_eq!(retrieved, None);

    // Session 2 should still be valid
    let retrieved: Option<TestData> = manager.get(id2).await.unwrap();
    assert_eq!(retrieved, Some(data2));
}
