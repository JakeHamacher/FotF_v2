-- Users table
CREATE TABLE users (
    id TEXT PRIMARY KEY,
    provider TEXT NOT NULL,
    email TEXT NOT NULL,
    name TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Documents table
CREATE TABLE documents (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    summary TEXT,
    author TEXT,
    language TEXT,
    tags TEXT, -- Store as JSON
    topics TEXT,
    r2_key TEXT NOT NULL,
    mime_type TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    visibility TEXT DEFAULT 'public',
    status TEXT DEFAULT 'processing',
    created_by TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    body_text TEXT
);

-- Document tags junction table
CREATE TABLE document_tags (
    document_id TEXT NOT NULL,
    tag TEXT NOT NULL,
    FOREIGN KEY (document_id) REFERENCES documents(id) ON DELETE CASCADE,
    PRIMARY KEY (document_id, tag)
);
CREATE INDEX idx_document_tags_tag ON document_tags(tag);

-- FTS5 virtual table for search
CREATE VIRTUAL TABLE documents_fts USING fts5(
    title,
    summary,
    body_text,
    author,
    content='documents',
    content_rowid='id'
);

-- Triggers to keep FTS index updated
CREATE TRIGGER documents_ai AFTER INSERT ON documents BEGIN
    INSERT INTO documents_fts(rowid, title, summary, body_text, author)
    VALUES (new.id, new.title, new.summary, new.body_text, new.author);
END;

CREATE TRIGGER documents_ad AFTER DELETE ON documents BEGIN
    INSERT INTO documents_fts(documents_fts, rowid, title, summary, body_text, author)
    VALUES('delete', old.id, old.title, old.summary, old.body_text, old.author);
END;

CREATE TRIGGER documents_au AFTER UPDATE ON documents BEGIN
    INSERT INTO documents_fts(documents_fts, rowid, title, summary, body_text, author)
    VALUES('delete', old.id, old.title, old.summary, old.body_text, old.author);
    INSERT INTO documents_fts(rowid, title, summary, body_text, author)
    VALUES (new.id, new.title, new.summary, new.body_text, new.author);
END;

-- Favorites table
CREATE TABLE favorites (
    user_id TEXT NOT NULL,
    document_id TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (document_id) REFERENCES documents(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, document_id)
);

-- Notes table
CREATE TABLE notes (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    document_id TEXT NOT NULL,
    content TEXT NOT NULL,
    visibility TEXT DEFAULT 'private',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (document_id) REFERENCES documents(id) ON DELETE CASCADE
);
