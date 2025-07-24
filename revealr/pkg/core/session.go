// pkg/core/session.go
package core

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"sync"

	"revealr/pkg/output" // Corrected import path

	_ "github.com/mattn/go-sqlite3" // SQLite driver import
)

// Session manages the state and results of a scan, persisting to a database.
type Session struct {
	db     *sql.DB
	dbPath string
	mu     sync.Mutex // Mutex for concurrent database access
}

// NewSession initializes a new scan session, creating or opening the SQLite database.
func NewSession(dbPath string) (*Session, error) {
	dbDir := "data/db"
	if _, err := os.Stat(dbDir); os.IsNotExist(err) {
		err = os.MkdirAll(dbDir, 0755)
		if err != nil {
			return nil, fmt.Errorf("failed to create database directory %s: %w", dbDir, err)
		}
	}

	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	if err = db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	session := &Session{
		db:     db,
		dbPath: dbPath,
	}

	if err = session.initSchema(); err != nil {
		session.Close()
		return nil, fmt.Errorf("failed to initialize database schema: %w", err)
	}

	output.PrintInfo("Session initialized with database: %s", dbPath)
	return session, nil
}

// Close closes the database connection.
func (s *Session) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db != nil {
		output.PrintInfo("Closing database connection for session: %s", s.dbPath)
		return s.db.Close()
	}
	return nil
}

// initSchema creates necessary tables if they don't exist.
func (s *Session) initSchema() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	schemaSQL := `
	CREATE TABLE IF NOT EXISTS hosts (
		id TEXT PRIMARY KEY,
		ip_address TEXT UNIQUE,
		is_up BOOLEAN,
		details TEXT
	);
	CREATE TABLE IF NOT EXISTS ports (
		host_id TEXT,
		port_number INTEGER,
		protocol TEXT,
		is_open BOOLEAN,
		service_name TEXT,
		service_version TEXT,
		details TEXT,
		PRIMARY KEY (host_id, port_number, protocol),
		FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE
	);
	`
	_, err := s.db.Exec(schemaSQL)
	if err != nil {
		return fmt.Errorf("failed to create database schema: %w", err)
	}
	return nil
}

// SaveHost saves or updates a host and its discovered ports to the database.
func (s *Session) SaveHost(host *Host) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	hostDetailsJSON, err := json.Marshal(host.Details)
	if err != nil {
		return fmt.Errorf("failed to marshal host details: %w", err)
	}

	_, err = tx.Exec(`
		INSERT OR REPLACE INTO hosts (id, ip_address, is_up, details)
		VALUES (?, ?, ?, ?);
	`, host.ID, host.IPAddress.String(), host.IsUp, string(hostDetailsJSON))
	if err != nil {
		return fmt.Errorf("failed to save host %s: %w", host.ID, err)
	}

	_, err = tx.Exec(`DELETE FROM ports WHERE host_id = ?;`, host.ID)
	if err != nil {
		return fmt.Errorf("failed to clear existing ports for host %s: %w", host.ID, err)
	}

	stmt, err := tx.Prepare(`
		INSERT INTO ports (host_id, port_number, protocol, is_open, service_name, service_version, details)
		VALUES (?, ?, ?, ?, ?, ?, ?);
	`)
	if err != nil {
		return fmt.Errorf("failed to prepare port insert statement: %w", err)
	}
	defer stmt.Close()

	for _, port := range host.Ports {
		// No need for serviceDetailsJSON if its content is already reflected in service_name/version columns
		// and port.Details is used for generic port info.
		portDetailsJSON, err := json.Marshal(port.Details) // Marshal port's own details
		if err != nil {
			return fmt.Errorf("failed to marshal port details for port %d: %w", port.PortNumber, err)
		}

		_, err = stmt.Exec(
			host.ID,
			port.PortNumber,
			port.Protocol,
			port.IsOpen,
			port.Service.Name,
			port.Service.Version,
			string(portDetailsJSON),
		)
		if err != nil {
			return fmt.Errorf("failed to save port %d for host %s: %w", port.PortNumber, host.ID, err)
		}
	}

	return tx.Commit()
}

// LoadHost (Future: loads a host and its ports from DB)
func (s *Session) LoadHost(hostID string) (*Host, error) {
	return nil, fmt.Errorf("LoadHost not implemented yet")
}

// GetAllHosts (Future: retrieves all hosts from DB)
func (s *Session) GetAllHosts() ([]*Host, error) {
	return nil, fmt.Errorf("GetAllHosts not implemented yet")
}
