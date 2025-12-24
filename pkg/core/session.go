// pkg/core/session.go
package core

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"revealr/pkg/models" // Import models
	"revealr/pkg/output"

	_ "github.com/glebarez/go-sqlite"
)

// Session manages the state/results of a scan, persisting to SQLite.
type Session struct {
	db            *sql.DB
	dbPath        string
	mu            sync.Mutex
	currentScanID string
}

// NewSession initializes a new scan session and database.
func NewSession(dbPath string) (*Session, error) {
	dbDir := "data/db"
	if _, err := os.Stat(dbDir); os.IsNotExist(err) {
		if err := os.MkdirAll(dbDir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create database directory %s: %w", dbDir, err)
		}
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	if err = db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	scanID := fmt.Sprintf("scan-%d", time.Now().UnixNano())
	session := &Session{db: db, dbPath: dbPath, currentScanID: scanID}

	if err = session.initSchema(); err != nil {
		session.Close()
		return nil, fmt.Errorf("failed to initialize database schema: %w", err)
	}

	output.PrintInfo("Session initialized with database: %s (Scan ID: %s)", dbPath, scanID)
	return session, nil
}

// GetCurrentScanID returns the current scan ID.
func (s *Session) GetCurrentScanID() string {
	return s.currentScanID
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

// initSchema ensures the DB schema exists.
func (s *Session) initSchema() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	schemaSQL := `
	CREATE TABLE IF NOT EXISTS hosts (
		id TEXT PRIMARY KEY,
		ip_address TEXT UNIQUE,
		is_up BOOLEAN,
		details TEXT,
		scan_id TEXT
	);
	CREATE TABLE IF NOT EXISTS ports (
    host_id TEXT,
    port_number INTEGER,
    protocol TEXT,
    is_open BOOLEAN,
    service_name TEXT,
    service_version TEXT,
    details TEXT,
    scan_id TEXT,
    PRIMARY KEY (host_id, port_number, protocol, scan_id),
    FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE
	);
	`
	_, err := s.db.Exec(schemaSQL)
	if err != nil {
		return fmt.Errorf("failed to create schema: %w", err)
	}
	return nil
}

// SaveHost saves/updates host and its ports.
func (s *Session) SaveHost(host *models.Host) error {
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
	output.PrintDebug("DB: Host %s details JSON for saving: %s", host.ID, string(hostDetailsJSON))

	_, err = tx.Exec(`
		INSERT OR REPLACE INTO hosts (id, ip_address, is_up, details, scan_id)
		VALUES (?, ?, ?, ?, ?);
	`, host.ID, host.IPAddress.String(), host.IsUp, string(hostDetailsJSON), s.currentScanID)
	if err != nil {
		return fmt.Errorf("failed to save host %s: %w", host.ID, err)
	}

	// Deduplicate ports before inserting
	finalPorts := make(map[string]*models.Port)
	for _, p := range host.Ports {
		key := fmt.Sprintf("%d/%s", p.PortNumber, p.Protocol)
		finalPorts[key] = p
	}

	stmt, err := tx.Prepare(`
		INSERT INTO ports (host_id, port_number, protocol, is_open, service_name, service_version, details, scan_id)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(host_id, port_number, protocol, scan_id) DO UPDATE SET
			is_open = excluded.is_open,
			service_name = excluded.service_name,
			service_version = excluded.service_version,
			details = excluded.details;
	`)
	if err != nil {
		return fmt.Errorf("failed to prepare port UPSERT: %w", err)
	}
	defer stmt.Close()

	for _, port := range finalPorts {
		// Persist the precise State in the details map so we can restore it later
		// without altering the DB schema right now.
		port.Details["state"] = string(port.State)

		portDetailsJSON, err := json.Marshal(port.Details)
		if err != nil {
			return fmt.Errorf("failed to marshal port details for port %d: %w", port.PortNumber, err)
		}

		// Map complex states to the simple is_open boolean for legacy compatibility
		isOpen := (port.State == models.PortOpen || port.State == models.PortOpenFiltered)

		_, err = stmt.Exec(
			host.ID,
			port.PortNumber,
			port.Protocol,
			isOpen,
			port.Service.Name,
			port.Service.Version,
			string(portDetailsJSON),
			s.currentScanID,
		)
		if err != nil {
			return fmt.Errorf("failed to save port %d for host %s: %w", port.PortNumber, host.ID, err)
		}
	}

	return tx.Commit()
}

// GetHostsByScanID retrieves all hosts and ports for a scan ID.
func (s *Session) GetHostsByScanID(scanID string) ([]*models.Host, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	hosts := make(map[string]*models.Host)

	rows, err := s.db.Query(`SELECT id, ip_address, is_up, details FROM hosts WHERE scan_id = ?;`, scanID)
	if err != nil {
		return nil, fmt.Errorf("failed to query hosts: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var id, ipAddress, detailsJSON string
		var isUp bool
		if err := rows.Scan(&id, &ipAddress, &isUp, &detailsJSON); err != nil {
			return nil, fmt.Errorf("failed to scan host row: %w", err)
		}

		host := &models.Host{
			ID:         id,
			IPAddress:  net.ParseIP(ipAddress),
			IsUp:       isUp,
			Ports:      make([]*models.Port, 0),
			Details:    make(map[string]string),
			// addedPorts is private/internal, init it manually or use constructor logic if accessable
			// Since we are in core package and models is external, we can't access private fields.
			// But models should expose a way or we just don't populate addedPorts if it's only for runtime dedup.
		}
		// Reset addedPorts map via reflection or just ignore it for read-only retrieval?
		// Actually duplicate Port check is for scanning. Retrieval is usually for display.
		// NOTE: We can't access 'addedPorts' field of models.Host directly if it is private/lower-case in models package.
		// Check pkg/models/models.go: 'addedPorts' is lowercase.
		// We should add a method in models "Init()" or something, or just ignore it here since we are reading BACK from DB.
		
		if detailsJSON != "" {
			_ = json.Unmarshal([]byte(detailsJSON), &host.Details)
		}
		hosts[id] = host
	}

	// Query ports
	portRows, err := s.db.Query(`
		SELECT host_id, port_number, protocol, is_open, service_name, service_version, details
		FROM ports WHERE scan_id = ?;`, scanID)
	if err != nil {
		return nil, fmt.Errorf("failed to query ports: %w", err)
	}
	defer portRows.Close()

	for portRows.Next() {
		var hostID, protocol, serviceName, serviceVersion, detailsJSON string
		var portNumber int
		var isOpen bool

		if err := portRows.Scan(&hostID, &portNumber, &protocol, &isOpen, &serviceName, &serviceVersion, &detailsJSON); err != nil {
			return nil, fmt.Errorf("failed to scan port row: %w", err)
		}

		if host, ok := hosts[hostID]; ok {
			port := &models.Port{
				PortNumber: portNumber,
				Protocol:   protocol,
				State:      models.PortClosed, // Default, will be overwritten
				Service:    &models.Service{Name: serviceName, Version: serviceVersion, Details: make(map[string]string)},
				Details:    make(map[string]string),
			}
			if detailsJSON != "" {
				_ = json.Unmarshal([]byte(detailsJSON), &port.Details)
			}

			// Restore State from details if available, otherwise fallback to boolean
			if stateStr, ok := port.Details["state"]; ok {
				port.State = models.PortState(stateStr)
			} else {
				if isOpen {
					port.State = models.PortOpen
				} else {
					port.State = models.PortClosed
				}
			}
			
			// We can't call AddPort if it relies on private addedPorts map being initialized.
			// host.Ports = append(host.Ports, port) -> simple append
			host.Ports = append(host.Ports, port)
		}
	}

	finalHosts := make([]*models.Host, 0, len(hosts))
	for _, host := range hosts {
		finalHosts = append(finalHosts, host)
	}
	return finalHosts, nil
}
