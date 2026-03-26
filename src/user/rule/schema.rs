use rusqlite::{Connection, Result};

pub fn init_rule_db(conn: &Connection) -> Result<()> {
    conn.execute(
        "CREATE TABLE IF NOT EXISTS rule_db (
            idx INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            pattern TEXT NOT NULL,
            pattern_type TEXT NOT NULL,
            severity INTEGER NOT NULL
        )",
        [],
    )?;
    Ok(())
}

pub fn init_rule_db_from_file(db_file_name: &str) -> Result<Connection> {
    let conn = Connection::open(db_file_name)?;
    init_rule_db(&conn)?;
    Ok(conn)
}
