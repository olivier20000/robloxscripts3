const express  = require('express');
const cors     = require('cors');
const path     = require('path');
const crypto   = require('crypto');
const fs       = require('fs');
const initSqlJs = require('sql.js');

const app  = express();
const PORT = process.env.PORT || 3000;
const DB_FILE = path.join(__dirname, 'cerberus.db');

app.use(cors());

app.use((req, res, next) => {
    res.setHeader('ngrok-skip-browser-warning', 'true');
    next();
});


app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// ─────────────────────────────────────────────────────────
// SQL.JS — pure JS SQLite
// ─────────────────────────────────────────────────────────
let SQL, db;

async function initDB() {
    SQL = await initSqlJs();
    if (fs.existsSync(DB_FILE)) {
        const data = fs.readFileSync(DB_FILE);
        db = new SQL.Database(data);
    } else {
        db = new SQL.Database();
    }

    db.run(`CREATE TABLE IF NOT EXISTS users (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        hwid         TEXT UNIQUE NOT NULL,
        secret_token TEXT UNIQUE NOT NULL,
        roblox_name  TEXT,
        created_at   INTEGER,
        last_seen    INTEGER
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS commands (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        secret_token TEXT NOT NULL,
        command      TEXT NOT NULL,
        payload      TEXT DEFAULT '{}',
        status       TEXT DEFAULT 'pending',
        created_at   INTEGER,
        executed_at  INTEGER
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS brainrots (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        name       TEXT UNIQUE NOT NULL,
        rarity     TEXT DEFAULT 'Common',
        generation REAL DEFAULT 0,
        cost       REAL DEFAULT 0
    )`);

    // Tabela para brainrots do inventário atual do jogador (para dupe)
    db.run(`CREATE TABLE IF NOT EXISTS player_inventory (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        secret_token TEXT NOT NULL,
        name         TEXT NOT NULL,
        mutation     TEXT DEFAULT 'None',
        traits       TEXT DEFAULT '[]',
        slot_index   INTEGER DEFAULT 0,
        updated_at   INTEGER
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS global_flags (
        key   TEXT PRIMARY KEY,
        value TEXT NOT NULL
    )`);

    saveDB();
    console.log('✅ Banco de dados inicializado');
}

function saveDB() {
    const data = db.export();
    fs.writeFileSync(DB_FILE, Buffer.from(data));
}

function dbGet(sql, params = []) {
    try {
        const stmt = db.prepare(sql);
        stmt.bind(params);
        const row = stmt.step() ? stmt.getAsObject() : null;
        stmt.free();
        return row;
    } catch(e) { return null; }
}

function dbAll(sql, params = []) {
    try {
        const stmt = db.prepare(sql);
        stmt.bind(params);
        const rows = [];
        while (stmt.step()) rows.push(stmt.getAsObject());
        stmt.free();
        return rows;
    } catch(e) { return []; }
}

function dbRun(sql, params = []) {
    db.run(sql, params);
    saveDB();
    const res = db.exec('SELECT last_insert_rowid() as id');
    return res[0]?.values[0][0];
}

function now() { return Math.floor(Date.now() / 1000); }

function generateToken(hwid) {
    return 'CRB-' + crypto
        .createHash('sha256')
        .update(hwid + Date.now() + Math.random())
        .digest('hex')
        .substring(0, 32)
        .toUpperCase();
}

function authMiddleware(req, res, next) {
    const token = req.headers['x-secret-token']
        || req.body?.secret_token
        || req.query?.secret_token;
    if (!token) return res.status(401).json({ error: 'Token obrigatório' });
    const user = dbGet('SELECT * FROM users WHERE secret_token = ?', [token]);
    if (!user) return res.status(401).json({ error: 'Token inválido' });
    db.run('UPDATE users SET last_seen = ? WHERE secret_token = ?', [now(), token]);
    saveDB();
    req.user = user;
    next();
}

// ─────────────────────────────────────────────────────────
// ROTAS — JOGO → SERVIDOR
// ─────────────────────────────────────────────────────────

// Registro por HWID → retorna secret_token
app.post('/api/auth/register', (req, res) => {
    const { hwid, roblox_name } = req.body;
    if (!hwid) return res.status(400).json({ error: 'hwid obrigatório' });

    let user = dbGet('SELECT * FROM users WHERE hwid = ?', [hwid]);
    let is_new = false;

    if (!user) {
        const token = generateToken(hwid);
        dbRun('INSERT INTO users (hwid, secret_token, roblox_name, created_at, last_seen) VALUES (?,?,?,?,?)',
            [hwid, token, roblox_name || null, now(), now()]);
        user = dbGet('SELECT * FROM users WHERE hwid = ?', [hwid]);
        is_new = true;
    } else {
        if (roblox_name && roblox_name !== user.roblox_name) {
            db.run('UPDATE users SET roblox_name = ?, last_seen = ? WHERE hwid = ?',
                [roblox_name, now(), hwid]);
            saveDB();
            user.roblox_name = roblox_name;
        }
    }

    res.json({ secret_token: user.secret_token, is_new });
});

// Poll de comandos — jogo chama a cada ~3s
app.get('/api/commands/poll', (req, res) => {
    const token = req.query.secret_token;
    if (!token) return res.status(401).json({ error: 'Token obrigatório' });

    const user = dbGet('SELECT id FROM users WHERE secret_token = ?', [token]);
    if (!user) return res.status(401).json({ error: 'Token inválido' });

    const cmds = dbAll(
        'SELECT * FROM commands WHERE secret_token = ? AND status = ? ORDER BY id ASC LIMIT 10',
        [token, 'pending']
    );

    for (const c of cmds) {
        db.run('UPDATE commands SET status = ? WHERE id = ?', ['delivered', c.id]);
    }
    if (cmds.length > 0) saveDB();

    res.json({
        commands: cmds.map(c => ({
            id: c.id,
            command: c.command,
            payload: (() => { try { return JSON.parse(c.payload || '{}'); } catch(_) { return {}; } })()
        }))
    });
});

// Jogo confirma que executou um comando
app.post('/api/commands/confirm', (req, res) => {
    const { secret_token, command_id } = req.body;
    if (!secret_token || !command_id)
        return res.status(400).json({ error: 'Parâmetros inválidos' });

    db.run('UPDATE commands SET status = ?, executed_at = ? WHERE id = ? AND secret_token = ?',
        ['executed', now(), command_id, secret_token]);
    saveDB();
    res.json({ ok: true });
});

// Jogo envia lista de brainrots (primeira vez global)
app.post('/api/brainrots/upload', (req, res) => {
    const { secret_token, brainrots } = req.body;
    if (!secret_token || !Array.isArray(brainrots))
        return res.status(400).json({ error: 'Dados inválidos' });

    const user = dbGet('SELECT id FROM users WHERE secret_token = ?', [secret_token]);
    if (!user) return res.status(401).json({ error: 'Token inválido' });

    const flag = dbGet('SELECT value FROM global_flags WHERE key = ?', ['brainrots_collected']);
    if (flag && flag.value === 'true')
        return res.json({ ok: true, skipped: true });

    let inserted = 0;
    for (const b of brainrots) {
        try {
            db.run('INSERT OR IGNORE INTO brainrots (name, rarity, generation, cost) VALUES (?,?,?,?)',
                [b.name, b.rarity || 'Common', b.generation || 0, b.cost || 0]);
            inserted++;
        } catch (_) {}
    }
    db.run('INSERT OR REPLACE INTO global_flags (key, value) VALUES (?,?)',
        ['brainrots_collected', 'true']);
    saveDB();

    console.log(`📋 ${inserted} brainrots salvos`);
    res.json({ ok: true, inserted });
});

// Jogo envia inventário atual (brainrots no plot) para dupe
app.post('/api/inventory/sync', (req, res) => {
    const { secret_token, items } = req.body;
    if (!secret_token || !Array.isArray(items))
        return res.status(400).json({ error: 'Dados inválidos' });

    const user = dbGet('SELECT id FROM users WHERE secret_token = ?', [secret_token]);
    if (!user) return res.status(401).json({ error: 'Token inválido' });

    // Limpa inventário antigo e insere novo
    db.run('DELETE FROM player_inventory WHERE secret_token = ?', [secret_token]);
    for (const item of items) {
        db.run('INSERT INTO player_inventory (secret_token, name, mutation, traits, slot_index, updated_at) VALUES (?,?,?,?,?,?)',
            [secret_token, item.name, item.mutation || 'None', JSON.stringify(item.traits || []), item.slot || 0, now()]);
    }
    saveDB();
    res.json({ ok: true, count: items.length });
});

// ─────────────────────────────────────────────────────────
// ROTAS — SITE → SERVIDOR
// ─────────────────────────────────────────────────────────

app.post('/api/auth/login', (req, res) => {
    const { secret_token } = req.body;
    if (!secret_token) return res.status(400).json({ error: 'Token obrigatório' });

    const user = dbGet('SELECT * FROM users WHERE secret_token = ?', [secret_token]);
    if (!user) return res.status(401).json({
        error: 'Token não encontrado. Execute o script no Roblox primeiro para gerar seu token.'
    });

    db.run('UPDATE users SET last_seen = ? WHERE id = ?', [now(), user.id]);
    saveDB();

    res.json({
        ok: true,
        user: {
            roblox_name: user.roblox_name,
            secret_token: user.secret_token,
            last_seen: user.last_seen,
            created_at: user.created_at
        }
    });
});

// Lista de brainrots do banco
app.get('/api/brainrots', authMiddleware, (req, res) => {
    const brainrots = dbAll('SELECT * FROM brainrots ORDER BY rarity, name', []);
    const flag = dbGet('SELECT value FROM global_flags WHERE key = ?', ['brainrots_collected']);
    res.json({ brainrots, collected: flag?.value === 'true' });
});

// Inventário atual do jogador (para dupe)
app.get('/api/inventory', authMiddleware, (req, res) => {
    const items = dbAll(
        'SELECT * FROM player_inventory WHERE secret_token = ? ORDER BY slot_index ASC',
        [req.user.secret_token]
    );
    res.json({
        items: items.map(i => ({
            ...i,
            traits: (() => { try { return JSON.parse(i.traits || '[]'); } catch(_) { return []; } })()
        }))
    });
});

// Enviar comando ao jogo
const VALID_COMMANDS = new Set([
    'spawn_brainrot', 'despawn_all', 'set_mutation', 'set_trait', 'remove_trait',
    'remove_all_traits', 'launch_fake_trade', 'send_notification', 'toggle_auto_restore',
    'set_base_skin', 'toggle_share_community', 'toggle_webhook', 'clear_spawned',
    'spawn_multi', 'sell_animal', 'toggle_index', 'set_animal', 'launch_game',
    'hub_open', 'hub_close', 'set_other_sign', 'trade_add_item', 'trade_launch',
    'trade_accept', 'trade_cancel', 'trade_last_player', 'trade_force_accept',
    'trade_notify', 'dupe_brainrot', 'set_accept_mode',
    // NOVO: força o Lua a re-escanear plots e enviar inventário imediatamente
    'scan_inventory',
]);

app.post('/api/commands/send', authMiddleware, (req, res) => {
    const { command, payload } = req.body;
    if (!command) return res.status(400).json({ error: 'Comando obrigatório' });
    if (!VALID_COMMANDS.has(command)) return res.status(400).json({ error: 'Comando inválido: ' + command });

    const cmdId = dbRun(
        'INSERT INTO commands (secret_token, command, payload, status, created_at) VALUES (?,?,?,?,?)',
        [req.user.secret_token, command, JSON.stringify(payload || {}), 'pending', now()]
    );

    res.json({ ok: true, command_id: cmdId });
});

// Histórico de comandos para o dashboard
app.get('/api/commands/recent', authMiddleware, (req, res) => {
    const cmds = dbAll(
        'SELECT * FROM commands WHERE secret_token = ? ORDER BY id DESC LIMIT 30',
        [req.user.secret_token]
    );
    res.json({ commands: cmds });
});

// Info do usuário atual
app.get('/api/me', authMiddleware, (req, res) => {
    res.json({ user: req.user });
});

// ─────────────────────────────────────────────────────────
// FRONTEND — catch-all
// ─────────────────────────────────────────────────────────
app.get('*', (_req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ─────────────────────────────────────────────────────────
// START
// ─────────────────────────────────────────────────────────
initDB().then(() => {
    app.listen(PORT, () => {
        console.log(`\n🔴 CERBERUS HUB API → http://localhost:${PORT}`);
        console.log(`📦 Banco: ${DB_FILE}`);
        console.log(`🌐 Dashboard: http://localhost:${PORT}\n`);
    });
}).catch(e => {
    console.error('Erro ao iniciar:', e);
    process.exit(1);
});
