use std::env;
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::Connection;

use super::{
    NewRule, PatternType, delete_rules, init_rule_db, init_rule_db_from_file, insert_rule, list_rules,
};

#[test]
// PatternType 문자열 매핑과 역매핑을 검증해 타입 변환 규칙이 깨지지 않음을 확인.
fn pattern_type_roundtrip() {
    assert_eq!(PatternType::Exact.as_str(), "exact");
    assert_eq!(PatternType::Contains.as_str(), "contains");
    assert_eq!(PatternType::Regex.as_str(), "regex");
    assert_eq!(PatternType::Hash.as_str(), "hash");
    assert_eq!(PatternType::FilePath.as_str(), "file_path");

    assert_eq!(PatternType::from_str("exact"), Some(PatternType::Exact));
    assert_eq!(
        PatternType::from_str("contains"),
        Some(PatternType::Contains)
    );
    assert_eq!(PatternType::from_str("regex"), Some(PatternType::Regex));
    assert_eq!(PatternType::from_str("hash"), Some(PatternType::Hash));
    assert_eq!(
        PatternType::from_str("file_path"),
        Some(PatternType::FilePath)
    );
    assert_eq!(PatternType::from_str("invalid"), None);
}

#[test]
// 빈 DB에서 규칙 목록 조회 시 빈 배열이 반환되는지 확인.
fn init_and_list_rules_from_empty_db() {
    let conn = Connection::open_in_memory().unwrap();

    init_rule_db(&conn).unwrap();

    let rules = list_rules(&conn).unwrap();
    assert!(rules.is_empty());
}

#[test]
// 두 건을 insert 후 목록 조회 시 저장된 순서와 모든 필드가 정확한지 확인.
fn insert_and_list_rules_keeps_order_and_fields() {
    let conn = Connection::open_in_memory().unwrap();
    init_rule_db(&conn).unwrap();

    insert_rule(
        &conn,
        &NewRule {
            name: "virus sig".into(),
            pattern: "abc".into(),
            pattern_type: PatternType::Exact,
            severity: 100,
        },
    )
    .unwrap();
    insert_rule(
        &conn,
        &NewRule {
            name: "suspicious".into(),
            pattern: "temp".into(),
            pattern_type: PatternType::Contains,
            severity: 20,
        },
    )
    .unwrap();

    let rules = list_rules(&conn).unwrap();
    assert_eq!(rules.len(), 2);

    assert_eq!(rules[0].idx, 1);
    assert_eq!(rules[0].name, "virus sig");
    assert_eq!(rules[0].pattern, "abc");
    assert_eq!(rules[0].pattern_type, PatternType::Exact);
    assert_eq!(rules[0].severity, 100);

    assert_eq!(rules[1].idx, 2);
    assert_eq!(rules[1].name, "suspicious");
    assert_eq!(rules[1].pattern, "temp");
    assert_eq!(rules[1].pattern_type, PatternType::Contains);
    assert_eq!(rules[1].severity, 20);
}

#[test]
// 지원되지 않는 pattern_type 값이 DB에 기록되었을 때 list 시 에러가 발생해야 함을 확인.
fn list_rules_returns_error_for_invalid_pattern_type() {
    let conn = Connection::open_in_memory().unwrap();
    init_rule_db(&conn).unwrap();

    conn.execute(
        "INSERT INTO rule_db (name, pattern, pattern_type, severity) VALUES (?1, ?2, ?3, ?4)",
        rusqlite::params!["bad", "malware", "not_exists", 50],
    )
    .unwrap();

    let err = list_rules(&conn).unwrap_err();
    match err {
        rusqlite::Error::InvalidColumnType(_, _, _) => {}
        _ => panic!("Expected InvalidColumnType, got {:?}", err),
    }
}

#[test]
// 파일 기반 DB 초기화/재시작 후에도 데이터가 영속 저장되는지 확인.
fn init_rule_db_from_file_persists_data() {
    let mut file_path = env::temp_dir();
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| std::time::Duration::from_secs(0))
        .as_nanos();
    file_path.push(format!("lightweight_antivirus_rule_{}.db", ts));
    let _ = fs::remove_file(&file_path);

    let path = file_path.to_string_lossy().into_owned();
    {
        let conn = init_rule_db_from_file(&path).unwrap();
        init_rule_db(&conn).unwrap();
        insert_rule(
            &conn,
            &NewRule {
                name: "file rule".into(),
                pattern: "C:/Windows".into(),
                pattern_type: PatternType::FilePath,
                severity: 90,
            },
        )
        .unwrap();
    }

    let conn = init_rule_db_from_file(&path).unwrap();
    let rules = list_rules(&conn).unwrap();
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].name, "file rule");
    assert_eq!(rules[0].pattern_type, PatternType::FilePath);

    let _ = fs::remove_file(&file_path);
}

#[test]
// 특정 idx 삭제 시 해당 레코드만 제거되고 나머지는 유지되는지 확인.
fn delete_rules_removes_only_requested() {
    let conn = Connection::open_in_memory().unwrap();
    init_rule_db(&conn).unwrap();

    let first = insert_rule(
        &conn,
        &NewRule {
            name: "r1".into(),
            pattern: "alpha".into(),
            pattern_type: PatternType::Exact,
            severity: 10,
        },
    )
    .unwrap();

    insert_rule(
        &conn,
        &NewRule {
            name: "r2".into(),
            pattern: "beta".into(),
            pattern_type: PatternType::Contains,
            severity: 20,
        },
    )
    .unwrap();

    let mut conn = conn;
    let deleted = delete_rules(&mut conn, &[first]).unwrap();
    assert_eq!(deleted, 1);

    let rules = list_rules(&conn).unwrap();
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].name, "r2");
}

#[test]
// 빈 인덱스 배열 또는 존재하지 않는 idx 삭제는 삭제 건수 0을 반환해야 함을 확인.
fn delete_rules_with_empty_or_missing_indices() {
    let conn = Connection::open_in_memory().unwrap();
    init_rule_db(&conn).unwrap();

    let first = insert_rule(
        &conn,
        &NewRule {
            name: "only".into(),
            pattern: "pattern".into(),
            pattern_type: PatternType::Regex,
            severity: 30,
        },
    )
    .unwrap();

    let mut conn = conn;
    let deleted_none = delete_rules(&mut conn, &[]).unwrap();
    assert_eq!(deleted_none, 0);

    let deleted_missing = delete_rules(&mut conn, &[first + 999]).unwrap();
    assert_eq!(deleted_missing, 0);

    let rules = list_rules(&conn).unwrap();
    assert_eq!(rules.len(), 1);
}
