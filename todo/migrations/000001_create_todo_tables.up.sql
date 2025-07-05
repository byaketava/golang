CREATE TABLE IF NOT EXISTS todo_lists (
    id SERIAL PRIMARY KEY, 
    user_id INTEGER NOT NULL, 
    title VARCHAR(255) NOT NULL, 
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP 
);

--индекс для user_id в todo_lists
CREATE INDEX IF NOT EXISTS idx_todo_lists_user_id ON todo_lists (user_id);

CREATE TABLE IF NOT EXISTS todo_items (
    id SERIAL PRIMARY KEY,
    todo_list_id INTEGER NOT NULL,
    title VARCHAR(255) NOT NULL,
    description TEXT, 
    done BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_todo_list
        FOREIGN KEY (todo_list_id)
        REFERENCES todo_lists(id)
        ON DELETE CASCADE
);

--индекс для todo_list_id в todo_items
CREATE INDEX IF NOT EXISTS idx_todo_items_todo_list_id ON todo_items (todo_list_id);

--функциz для автоматического обновления updated_at
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

--триггеры для автоматического обновления updated_at при изменении
CREATE TRIGGER update_todo_lists_updated_at
BEFORE UPDATE ON todo_lists
FOR EACH ROW
EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_todo_items_updated_at
BEFORE UPDATE ON todo_items
FOR EACH ROW
EXECUTE FUNCTION update_updated_at_column();