# INF601 - Advanced Programming in Python
# Chase Coble
# Mini Project 6

import socket
import sqlite3
import pytest


def test_the_suite_blocks_real_network_access():
    with pytest.raises(RuntimeError, match="network"):
        socket.create_connection(("127.0.0.1", 9), timeout=1)


def test_sqlite_is_new_enough_for_upsert():
    assert sqlite3.sqlite_version_info >= (3, 24), sqlite3.sqlite_version
