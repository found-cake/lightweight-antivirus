use std::env;
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::Connection;

use super::{NewRule, PatternType, init_rule_db, init_rule_db_from_file, insert_rule, list_rules};

#[test]
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
fn init_and_list_rules_from_empty_db() {
    let conn = Connection::open_in_memory().unwrap();

    init_rule_db(&conn).unwrap();

    let rules = list_rules(&conn).unwrap();
    assert!(rules.is_empty());
}

#[test]
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
