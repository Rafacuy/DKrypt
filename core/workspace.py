#!/usr/bin/env python3
import os
import sqlite3
from datetime import datetime

class WorkspaceManager:
    """Manage workspaces for organizing scan results"""
    def __init__(self, db_path=".dkrypt/workspaces.db"):
        self.db_path = db_path
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self._init_db()
        
    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS workspaces
                     (id INTEGER PRIMARY KEY, name TEXT UNIQUE, created TEXT, description TEXT)''')
        c.execute('''CREATE TABLE IF NOT EXISTS scan_results
                     (id INTEGER PRIMARY KEY, workspace_id INTEGER, module TEXT, 
                      target TEXT, timestamp TEXT, results TEXT)''')
        c.execute('''CREATE TABLE IF NOT EXISTS targets
                     (id INTEGER PRIMARY KEY, workspace_id INTEGER, host TEXT, 
                      ports TEXT, services TEXT, notes TEXT)''')
        conn.commit()
        conn.close()
        
    def create_workspace(self, name, description=""):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        try:
            c.execute("INSERT INTO workspaces VALUES (NULL, ?, ?, ?)",
                     (name, datetime.now().isoformat(), description))
            conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False
        finally:
            conn.close()
            
    def list_workspaces(self):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("SELECT * FROM workspaces")
        workspaces = c.fetchall()
        conn.close()
        return workspaces
        
    def delete_workspace(self, name):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("SELECT id FROM workspaces WHERE name=?", (name,))
        ws = c.fetchone()
        if ws:
            c.execute("DELETE FROM scan_results WHERE workspace_id=?", (ws[0],))
            c.execute("DELETE FROM targets WHERE workspace_id=?", (ws[0],))
            c.execute("DELETE FROM workspaces WHERE name=?", (name,))
            conn.commit()
        conn.close()
        
    def add_scan_result(self, workspace_name, module, target, results):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("SELECT id FROM workspaces WHERE name=?", (workspace_name,))
        ws = c.fetchone()
        if ws:
            c.execute("INSERT INTO scan_results VALUES (NULL, ?, ?, ?, ?, ?)",
                     (ws[0], module, target, datetime.now().isoformat(), results))
            conn.commit()
        conn.close()
        
    def get_scan_results(self, workspace_name):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("SELECT id FROM workspaces WHERE name=?", (workspace_name,))
        ws = c.fetchone()
        if ws:
            c.execute("SELECT * FROM scan_results WHERE workspace_id=?", (ws[0],))
            results = c.fetchall()
            conn.close()
            return results
        conn.close()
        return []

class SessionManager:
    """Manage active sessions and targets"""
    def __init__(self):
        self.sessions = {}
        self.active_session = None
        
    def create_session(self, target, module):
        session_id = len(self.sessions) + 1
        self.sessions[session_id] = {
            'target': target,
            'module': module,
            'created': datetime.now().isoformat(),
            'status': 'active',
            'data': {}
        }
        return session_id
        
    def list_sessions(self):
        return self.sessions
        
    def kill_session(self, session_id):
        if session_id in self.sessions:
            self.sessions[session_id]['status'] = 'killed'
            return True
        return False
        
    def interact_session(self, session_id):
        if session_id in self.sessions:
            self.active_session = session_id
            return True
        return False
