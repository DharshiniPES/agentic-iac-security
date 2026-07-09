import sqlite3


class DatabaseManager:

    def __init__(self):

        self.connection = sqlite3.connect(
            "database/scans.db",
            check_same_thread=False
        )

        self.cursor = self.connection.cursor()

        self.create_table()


    def create_table(self):

        self.cursor.execute("""

        CREATE TABLE IF NOT EXISTS scans(

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            scan_time TEXT,

            rule_id TEXT,

            severity TEXT,

            resource_name TEXT,

            finding TEXT,

            risk_score INTEGER

        )

        """)

        self.connection.commit()


    def save_scan(self, findings, scan_time):

        for finding in findings:

            self.cursor.execute("""

            INSERT INTO scans(

                scan_time,

                rule_id,

                severity,

                resource_name,

                finding,

                risk_score

            )

            VALUES(?,?,?,?,?,?)

            """,

            (

                scan_time,

                finding["rule_id"],

                finding["severity"],

                finding["resource_name"],

                finding["finding"],

                finding["risk_score"]

            ))

        self.connection.commit()


    def get_all_scans(self):

        self.cursor.execute(

            "SELECT * FROM scans ORDER BY id DESC"

        )

        return self.cursor.fetchall()