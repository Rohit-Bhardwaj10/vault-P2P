package store

// DB is an interface representing local storage operations
type DB interface {
	Init() error
	Close() error

	// Storage methods for Chunks, Manifests, Spaces, Peers
}

// Engine combines SQLite (metadata/manifests) and BoltDB (Write-Ahead Log)
type Engine struct {
	sqlite *SQLiteStore
	bolt   *BoltStore
}

func NewEngine(dbPath, walPath string) *Engine {
	return &Engine{
		sqlite: NewSQLiteStore(dbPath),
		bolt:   NewBoltStore(walPath),
	}
}

func (e *Engine) Init() error {
	if err := e.sqlite.Init(); err != nil {
		return err
	}
	if err := e.bolt.Init(); err != nil {
		return err
	}
	return nil
}

func (e *Engine) Close() error {
	if err := e.sqlite.Close(); err != nil {
		return err
	}
	return e.bolt.Close()
}
