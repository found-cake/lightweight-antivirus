use rusqlite::{Connection, Result, params};

use crate::user::rule::{NewRule, PatternType, Rule};

pub fn insert_rule(conn: &Connection, rule: &NewRule) -> Result<i64> {
    conn.execute(
        "INSERT INTO rule_db (name, pattern, pattern_type, severity)
         VALUES (?1, ?2, ?3, ?4)",
        params![
            rule.name,
            rule.pattern,
            rule.pattern_type.as_str(),
            rule.severity
        ],
    )?;

    Ok(conn.last_insert_rowid())
}

pub fn list_rules(conn: &Connection) -> Result<Vec<Rule>> {
    let mut stmt = conn.prepare(
        "SELECT idx, name, pattern, pattern_type, severity
         FROM rule_db
         ORDER BY idx ASC",
    )?;

    let rules = stmt.query_map([], |row| {
        let raw_pattern_type: String = row.get(3)?;
        let pattern_type =
            PatternType::from_str(&raw_pattern_type).ok_or(rusqlite::Error::InvalidColumnType(
                3,
                "pattern_type".to_string(),
                rusqlite::types::Type::Text,
            ))?;

        Ok(Rule {
            idx: row.get(0)?,
            name: row.get(1)?,
            pattern: row.get(2)?,
            pattern_type,
            severity: row.get(4)?,
        })
    })?;

    rules.collect()
}

pub fn delete_rules(conn: &mut Connection, indices: &[i64]) -> Result<usize> {
    if indices.is_empty() {
        return Ok(0);
    }

    let tx = conn.transaction()?;
    let mut deleted = 0usize;

    {
        let mut stmt = tx.prepare("DELETE FROM rule_db WHERE idx = ?1")?;
        for idx in indices {
            deleted += stmt.execute([idx])?;
        }
    }

    tx.commit()?;
    Ok(deleted)
}
