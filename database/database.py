import sqlite3
import json


# ============================================================
# DATABASE
# ============================================================

DATABASE = "database/netsecure.db"


# ============================================================
# DATABASE CONNECTION
# ============================================================

def get_connection():

    connection = sqlite3.connect(
        DATABASE
    )

    connection.row_factory = sqlite3.Row

    return connection


# ============================================================
# INITIALIZE DATABASE
# ============================================================

def init_database():

    connection = get_connection()

    connection.execute("""
        CREATE TABLE IF NOT EXISTS scans (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            target TEXT NOT NULL,

            scan_type TEXT,

            open_ports INTEGER NOT NULL,

            status TEXT NOT NULL,

            scan_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

            results TEXT,

            client_id TEXT

        )
    """)


    # ========================================================
    # CHECK EXISTING COLUMNS
    # ========================================================

    columns = connection.execute(
        "PRAGMA table_info(scans)"
    ).fetchall()


    column_names = [
        column["name"]
        for column in columns
    ]


    # ========================================================
    # ADD MISSING COLUMNS
    # ========================================================

    if "scan_type" not in column_names:

        connection.execute("""
            ALTER TABLE scans
            ADD COLUMN scan_type TEXT
        """)


    if "results" not in column_names:

        connection.execute("""
            ALTER TABLE scans
            ADD COLUMN results TEXT
        """)


    if "client_id" not in column_names:

        connection.execute("""
            ALTER TABLE scans
            ADD COLUMN client_id TEXT
        """)


    connection.commit()

    connection.close()


# ============================================================
# SAVE SCAN
# ============================================================

def save_scan(
    target,
    open_ports,
    status,
    scan_type=None,
    results=None,
    client_id=None
):

    connection = get_connection()


    results_json = (
        json.dumps(results)
        if results is not None
        else None
    )


    connection.execute("""
        INSERT INTO scans
        (
            target,
            scan_type,
            open_ports,
            status,
            results,
            client_id
        )

        VALUES (?, ?, ?, ?, ?, ?)
    """, (

        target,

        scan_type,

        open_ports,

        status,

        results_json,

        client_id

    ))


    connection.commit()

    connection.close()


# ============================================================
# GET SCANS FOR CURRENT BROWSER
# ============================================================

def get_all_scans(client_id=None):

    connection = get_connection()


    if client_id:

        scans = connection.execute("""
            SELECT
                id,
                target,
                scan_type,
                open_ports,
                status,
                scan_time,
                client_id
            FROM scans
            WHERE client_id = ?
            ORDER BY id DESC
        """, (
            client_id,
        )).fetchall()

    else:

        scans = connection.execute("""
            SELECT
                id,
                target,
                scan_type,
                open_ports,
                status,
                scan_time,
                client_id
            FROM scans
            ORDER BY id DESC
        """).fetchall()


    connection.close()


    return scans


# ============================================================
# GET SINGLE SCAN
# ============================================================

def get_scan_by_id(
    scan_id,
    client_id=None
):

    connection = get_connection()


    if client_id:

        scan = connection.execute("""
            SELECT
                id,
                target,
                scan_type,
                open_ports,
                status,
                scan_time,
                results,
                client_id
            FROM scans
            WHERE id = ?
            AND client_id = ?
        """, (
            scan_id,
            client_id
        )).fetchone()

    else:

        scan = connection.execute("""
            SELECT
                id,
                target,
                scan_type,
                open_ports,
                status,
                scan_time,
                results,
                client_id
            FROM scans
            WHERE id = ?
        """, (
            scan_id,
        )).fetchone()


    connection.close()


    return scan