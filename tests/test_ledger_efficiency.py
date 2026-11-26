import os
import sqlite3
import tempfile
import threading
import unittest
from unittest.mock import patch

import agents.ledger as ledger


class _TrackedConnection:
    """Proxy around sqlite3.Connection that records close() and optionally injects errors."""

    def __init__(self, real_conn: sqlite3.Connection, fail_on_execute: bool = False):
        self._real = real_conn
        self._fail_on_execute = fail_on_execute
        self.closed = False

    def execute(self, sql, parameters=()):
        if self._fail_on_execute and not sql.lstrip().upper().startswith("PRAGMA"):
            raise sqlite3.OperationalError("injected sqlite3 error")
        return self._real.execute(sql, parameters)

    def executemany(self, sql, seq_of_parameters):
        if self._fail_on_execute:
            raise sqlite3.OperationalError("injected sqlite3 error")
        return self._real.executemany(sql, seq_of_parameters)

    def close(self):
        self.closed = True
        return self._real.close()

    def __enter__(self):
        self._real.__enter__()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        return self._real.__exit__(exc_type, exc_val, exc_tb)

    def __getattr__(self, name):
        return getattr(self._real, name)


class TestLedgerEfficiency(unittest.TestCase):
    def setUp(self):
        ledger._reset_schema_cache()

    def tearDown(self):
        ledger._reset_schema_cache()

    def test_fd_closure_normal_and_error_across_helpers(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "ledger.sqlite3")
            # Seed initial schema
            c = ledger._connect(db_path)
            c.close()

            # 1. Normal calls must close every connection they open
            opened_normal = []
            orig_connect = ledger._connect

            def track_connect(path=ledger.DB_PATH):
                tc = _TrackedConnection(orig_connect(path), fail_on_execute=False)
                opened_normal.append(tc)
                return tc

            with patch.object(ledger, "_connect", side_effect=track_connect):
                ledger.log_canonical_attempt("1", "caesar", {"word": "ALPHA"}, "d1", 0.5, False, db_path=db_path)
                ledger.has_attempt_been_tried("1", "caesar", {"word": "ALPHA"}, "d1", db_path=db_path)
                ledger.count_attempts(db_path=db_path)
                ledger.log_attempt("1", "caesar", key="ALPHA", result="ok", success=True, db_path=db_path)
                ledger.has_been_tried("1", "caesar", key="ALPHA", db_path=db_path)
                ledger.get_history(page="1", db_path=db_path)
                ledger.summary(db_path=db_path)
                ledger.get_tested_words(page="1", db_dir=tmpdir)
                ledger.record_attempts_batch(
                    [{"page": "1", "word": "BETA", "method": "caesar", "score": 0.4}],
                    db_dir=tmpdir,
                    sync_vector=False,
                )

            self.assertGreaterEqual(len(opened_normal), 9)
            self.assertTrue(all(tc.closed for tc in opened_normal))

            # 2. Raised sqlite3.Error must also close every connection
            opened_error = []

            def track_connect_fail(path=ledger.DB_PATH):
                tc = _TrackedConnection(orig_connect(path), fail_on_execute=True)
                opened_error.append(tc)
                return tc

            with patch.object(ledger, "_connect", side_effect=track_connect_fail):
                self.assertFalse(
                    ledger.log_canonical_attempt("1", "caesar", {"word": "GAMMA"}, "d2", 0.1, False, db_path=db_path)
                )
                with self.assertRaises(sqlite3.Error):
                    ledger.has_attempt_been_tried("1", "caesar", {"word": "GAMMA"}, "d2", db_path=db_path)
                self.assertEqual(ledger.count_attempts(db_path=db_path), 0)
                with self.assertRaises(sqlite3.Error):
                    ledger.log_attempt("1", "caesar", key="GAMMA", db_path=db_path)
                with self.assertRaises(sqlite3.Error):
                    ledger.has_been_tried("1", "caesar", key="GAMMA", db_path=db_path)
                with self.assertRaises(sqlite3.Error):
                    ledger.get_history(db_path=db_path)
                with self.assertRaises(sqlite3.Error):
                    ledger.summary(db_path=db_path)
                ledger.get_tested_words(db_dir=tmpdir)
                ledger.record_attempts_batch(
                    [{"page": "1", "word": "DELTA", "method": "caesar", "score": 0.4}],
                    db_dir=tmpdir,
                    sync_vector=False,
                )

            self.assertEqual(len(opened_error), 9)
            self.assertTrue(all(tc.closed for tc in opened_error))

    def test_connect_closes_connection_when_pragma_or_ddl_fails(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "broken.sqlite3")
            real_conn = sqlite3.connect(db_path)
            tracked = _TrackedConnection(real_conn, fail_on_execute=True)

            with patch("agents.ledger.sqlite3.connect", return_value=tracked):
                with self.assertRaises(sqlite3.Error):
                    ledger._connect(db_path)

            self.assertTrue(tracked.closed)

    def test_memory_creates_zero_disk_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cwd = os.getcwd()
            try:
                os.chdir(tmpdir)
                conn = ledger._connect(":memory:")
                try:
                    tables = {
                        r[0]
                        for r in conn.execute(
                            "SELECT name FROM sqlite_master WHERE type='table'"
                        ).fetchall()
                    }
                    self.assertIn("attempts", tables)
                    self.assertIn("canonical_attempts", tables)
                finally:
                    conn.close()
                self.assertEqual(os.listdir(tmpdir), [])
                self.assertEqual(len(ledger._INITIALIZED_DB_KEYS), 0)
            finally:
                os.chdir(cwd)

    def test_cache_invalidation_on_unlink_and_zero_byte_truncation(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "cache_test.sqlite3")

            # Initial creation populates cache
            conn1 = ledger._connect(db_path)
            conn1.close()
            self.assertEqual(len(ledger._INITIALIZED_DB_KEYS), 1)

            # Unlink and recreate empty file -> must re-initialize schema
            os.unlink(db_path)
            open(db_path, "wb").close()
            conn2 = ledger._connect(db_path)
            try:
                tables = {
                    r[0]
                    for r in conn2.execute(
                        "SELECT name FROM sqlite_master WHERE type='table'"
                    ).fetchall()
                }
                self.assertIn("canonical_attempts", tables)
            finally:
                conn2.close()

            # 0-byte truncation -> _db_cache_key returns None -> must re-initialize schema
            with open(db_path, "wb") as f:
                f.truncate(0)
            self.assertIsNone(ledger._db_cache_key(os.path.abspath(db_path)))

            conn3 = ledger._connect(db_path)
            try:
                tables = {
                    r[0]
                    for r in conn3.execute(
                        "SELECT name FROM sqlite_master WHERE type='table'"
                    ).fetchall()
                }
                self.assertIn("canonical_attempts", tables)
                self.assertIn("attempts", tables)
            finally:
                conn3.close()

    def test_concurrent_connect_and_batch_zero_locked_errors(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "ledger.sqlite3")
            errors = []
            barrier = threading.Barrier(8)

            def worker(tid: int):
                try:
                    barrier.wait(timeout=5.0)
                    batch = [
                        {
                            "page": str(tid),
                            "word": f"WORD_{tid}_{i}",
                            "method": "vigenere",
                            "score": 0.1 * i,
                            "passed": False,
                        }
                        for i in range(50)
                    ]
                    count = ledger.record_attempts_batch(batch, db_dir=tmpdir, sync_vector=False)
                    if count != 50:
                        errors.append(AssertionError(f"Expected 50, got {count}"))
                    conn = ledger._connect(db_path)
                    try:
                        conn.execute("SELECT COUNT(*) FROM canonical_attempts").fetchone()
                    finally:
                        conn.close()
                except Exception as exc:
                    errors.append(exc)

            threads = [threading.Thread(target=worker, args=(t,)) for t in range(8)]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=30.0)

            self.assertEqual(errors, [])
            self.assertEqual(ledger.count_attempts(db_path=db_path), 400)

    def test_record_attempts_batch_empty_500_duplicates_rollback_and_parity(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "ledger.sqlite3")

            # Empty batch fast-returns without creating DB file
            self.assertEqual(ledger.record_attempts_batch([], db_dir=tmpdir, sync_vector=False), 0)
            self.assertEqual(
                ledger.record_attempts_batch([{"page": "1", "word": "   "}], db_dir=tmpdir, sync_vector=False),
                0,
            )
            self.assertFalse(os.path.exists(db_path))

            # 500-row batch
            batch_500 = [
                {
                    "page": "3",
                    "word": f"KEY_{i:04d}",
                    "method": "VIGENERE",
                    "score": float(i) / 500.0,
                    "passed": (i % 10 == 0),
                    "result_preview": f"preview_{i}",
                }
                for i in range(500)
            ]
            self.assertEqual(ledger.record_attempts_batch(batch_500, db_dir=tmpdir, sync_vector=False), 500)
            self.assertEqual(ledger.count_attempts(db_path=db_path), 500)

            # Duplicate batch uses INSERT OR IGNORE: returns len(valid_attempts) but keeps 500 rows
            self.assertEqual(ledger.record_attempts_batch(batch_500[:50], db_dir=tmpdir, sync_vector=False), 50)
            self.assertEqual(ledger.count_attempts(db_path=db_path), 500)

            # Row-parity with log_canonical_attempt
            single_db = os.path.join(tmpdir, "single.sqlite3")
            sample = {
                "page": "page_07.md",
                "word": "divinity",
                "method": "AUTOKEY",
                "score": 0.875,
                "passed": True,
                "result_preview": "parable of the cicada",
            }
            ledger.log_canonical_attempt(
                page=ledger.canonical_page(sample["page"]),
                method=sample["method"],
                parameters={"word": sample["word"].upper()},
                input_digest=f"word_{sample['word'].upper()}",
                score=sample["score"],
                passed=sample["passed"],
                result_preview=sample["result_preview"],
                word=sample["word"].upper(),
                db_path=single_db,
            )

            batch_dir = os.path.join(tmpdir, "batch_parity")
            os.makedirs(batch_dir, exist_ok=True)
            batch_db = os.path.join(batch_dir, "ledger.sqlite3")
            ledger.record_attempts_batch([sample], db_dir=batch_dir, sync_vector=False)

            cols = (
                "page, method, method_version, parameters_json, input_digest, "
                "canonical_key, score, scorer_version, passed_gatekeeper, result_preview, word"
            )
            c1 = ledger._connect(single_db)
            c2 = ledger._connect(batch_db)
            try:
                r1 = c1.execute(f"SELECT {cols} FROM canonical_attempts").fetchone()
                r2 = c2.execute(f"SELECT {cols} FROM canonical_attempts").fetchone()
                self.assertEqual(r1, r2)
            finally:
                c1.close()
                c2.close()

            # Rollback on mid-batch error: none of the new rows are committed
            orig_connect = ledger._connect

            def failing_batch_connect(path=ledger.DB_PATH):
                return _TrackedConnection(orig_connect(path), fail_on_execute=True)

            with patch.object(ledger, "_connect", side_effect=failing_batch_connect):
                ledger.record_attempts_batch(
                    [{"page": "9", "word": "UNCOMMITTED", "method": "caesar", "score": 0.9}],
                    db_dir=tmpdir,
                    sync_vector=False,
                )
            self.assertEqual(ledger.count_attempts(db_path=db_path), 500)


if __name__ == "__main__":
    unittest.main()
