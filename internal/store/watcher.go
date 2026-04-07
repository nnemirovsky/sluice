package store

import (
	"context"
	"database/sql"
	"log"
	"time"
)

// Watcher polls SQLite's PRAGMA data_version to detect changes from external
// connections (e.g. CLI commands). When a change is detected, the onChange
// callback is invoked. This enables hot-reload without signals or IPC.
type Watcher struct {
	db       *sql.DB
	interval time.Duration
	onChange func()
	cancel   context.CancelFunc
}

const defaultWatchInterval = 2 * time.Second

// NewWatcher creates a watcher that polls the database for changes.
// The onChange callback is called when the data_version changes, indicating
// another connection (CLI, API, Telegram) modified the database.
func NewWatcher(db *sql.DB, onChange func(), interval ...time.Duration) *Watcher {
	iv := defaultWatchInterval
	if len(interval) > 0 && interval[0] > 0 {
		iv = interval[0]
	}
	return &Watcher{
		db:       db,
		interval: iv,
		onChange: onChange,
	}
}

// Start begins polling in a goroutine. Call Stop to terminate.
func (w *Watcher) Start() {
	ctx, cancel := context.WithCancel(context.Background())
	w.cancel = cancel
	go w.poll(ctx)
}

// Stop terminates the polling goroutine.
func (w *Watcher) Stop() {
	if w.cancel != nil {
		w.cancel()
	}
}

func (w *Watcher) poll(ctx context.Context) {
	var lastVersion int64
	// Read initial version.
	if err := w.db.QueryRow("PRAGMA data_version").Scan(&lastVersion); err != nil {
		log.Printf("db watcher: initial data_version read failed: %v", err)
		return
	}

	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			var version int64
			if err := w.db.QueryRow("PRAGMA data_version").Scan(&version); err != nil {
				log.Printf("db watcher: data_version read failed: %v", err)
				continue
			}
			if version != lastVersion {
				lastVersion = version
				log.Printf("db watcher: change detected (version %d), triggering reload", version)
				w.onChange()
			}
		}
	}
}
