const crypto = require('node:crypto');
const path = require('node:path');
const { promisify } = require('node:util');
const express = require('express');
const Database = require('better-sqlite3');

const app = express();
const db = new Database('tasks.db');
const scrypt = promisify(crypto.scrypt);
const sessionCookieName = 'todo_session';
const sessionDuration = 7 * 24 * 60 * 60 * 1000;

// Раздаём файлы интерфейса и разбираем JSON в теле запросов.
app.use(express.static('./'));
app.use(express.json());

// Включаем журнал транзакций и проверку внешних ключей SQLite.
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

// Создаём таблицы пользователей, задач и серверных сессий при первом запуске.
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    password_hash TEXT NOT NULL
  )
`);
db.exec(`
  CREATE UNIQUE INDEX IF NOT EXISTS users_username_unique
  ON users(username COLLATE NOCASE)
`);
db.exec(`
  CREATE TABLE IF NOT EXISTS tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    details TEXT NOT NULL,
    user_id INTEGER NOT NULL,
    done INTEGER DEFAULT 0,
    FOREIGN KEY (user_id) REFERENCES users(id)
  )
`);
db.exec(`
  CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  )
`);

// В базе хранится только хеш токена сессии, а не сам токен из cookie.
function hashToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

// Cookie недоступна JavaScript-коду и действует столько же, сколько сессия.
function setSessionCookie(res, token) {
  const secure = process.env.NODE_ENV === 'production' ? '; Secure' : '';
  res.setHeader(
    'Set-Cookie',
    `${sessionCookieName}=${token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${sessionDuration / 1000}${secure}`
  );
}

// Удаляем cookie браузера при выходе пользователя.
function clearSessionCookie(res) {
  res.setHeader(
    'Set-Cookie',
    `${sessionCookieName}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0`
  );
}

// Находим токен сессии в заголовке Cookie запроса.
function getSessionToken(req) {
  const cookies = (req.headers.cookie || '').split(';');
  for (const cookie of cookies) {
    const separator = cookie.indexOf('=');
    if (separator !== -1 && cookie.slice(0, separator).trim() === sessionCookieName) {
      return cookie.slice(separator + 1).trim();
    }
  }
  return null;
}

// Для каждого запроса проверяем cookie и добавляем данные пользователя в req.
app.use((req, res, next) => {
  const token = getSessionToken(req);
  if (!token) {
    req.user = null;
    return next();
  }

  const session = db.prepare(`
    SELECT users.id, users.username
    FROM sessions
    JOIN users ON users.id = sessions.user_id
    WHERE sessions.token_hash = ? AND sessions.expires_at > ?
  `).get(hashToken(token), Date.now());

  if (!session) {
    clearSessionCookie(res);
    req.user = null;
    return next();
  }

  req.user = session;
  next();
});

// Закрывает доступ к маршрутам, которым нужна действующая сессия.
function requireAuth(req, res, next) {
  if (!req.user) {
    return res.status(401).json({ error: 'Требуется авторизация' });
  }
  next();
}

// Создаёт случайную серверную сессию и отправляет её токен в cookie.
async function createSession(userId, res) {
  const token = crypto.randomBytes(32).toString('hex');
  db.prepare('DELETE FROM sessions WHERE expires_at <= ?').run(Date.now());
  db.prepare('INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)')
    .run(hashToken(token), userId, Date.now() + sessionDuration);
  setSessionCookie(res, token);
}

// Ограничивает формат логина и длину пароля при регистрации.
function validateCredentials(username, password) {
  return typeof username === 'string' &&
    /^[a-zA-Z0-9_]{3,32}$/.test(username) &&
    typeof password === 'string' &&
    password.length >= 8 &&
    password.length <= 128;
}

// Регистрирует пользователя; уникальный индекс не допускает повтор логина.
app.post('/api/auth/register', async (req, res) => {
  if (!req.body || typeof req.body !== 'object') {
    return res.status(400).json({ error: 'Укажите логин и пароль' });
  }
  const { username, password } = req.body;
  if (!validateCredentials(username, password)) {
    return res.status(400).json({
      error: 'Логин: 3–32 символа (латинские буквы, цифры или _); пароль: 8–128 символов'
    });
  }

  // Соль индивидуальна для каждого пользователя; пароль хранится как scrypt-хеш.
  const salt = crypto.randomBytes(16);
  const passwordHash = await scrypt(password, salt, 64);
  let result;
  try {
    result = db.prepare('INSERT INTO users (username, password_hash) VALUES (?, ?)')
      .run(username, `${salt.toString('hex')}:${passwordHash.toString('hex')}`);
  } catch (error) {
    if (error.code === 'SQLITE_CONSTRAINT_UNIQUE') {
      return res.status(409).json({ error: 'Такой логин уже существует' });
    }
    throw error;
  }

  const user = { id: Number(result.lastInsertRowid), username };
  await createSession(user.id, res);
  res.status(201).json({ user });
});

// Проверяет пароль по сохранённому хешу и создаёт сессию при успехе.
app.post('/api/auth/login', async (req, res) => {
  if (!req.body || typeof req.body !== 'object') {
    return res.status(400).json({ error: 'Укажите логин и пароль' });
  }
  const { username, password } = req.body;
  if (typeof username !== 'string' || typeof password !== 'string' ||
      !username.trim() || password.length < 1 || password.length > 128) {
    return res.status(400).json({ error: 'Укажите логин и пароль' });
  }

  const user = db.prepare('SELECT id, username, password_hash FROM users WHERE username = ? COLLATE NOCASE')
    .get(username);
  if (!user) {
    return res.status(401).json({ error: 'Неверный логин или пароль' });
  }

  const [saltHex, passwordHashHex] = user.password_hash.split(':');
  if (!/^[a-f0-9]{32}$/i.test(saltHex) || !/^[a-f0-9]{128}$/i.test(passwordHashHex)) {
    throw new Error('Некорректный формат хеша пароля в базе данных');
  }
  const expectedHash = Buffer.from(passwordHashHex, 'hex');
  const actualHash = await scrypt(password, Buffer.from(saltHex, 'hex'), expectedHash.length);
  if (!crypto.timingSafeEqual(expectedHash, actualHash)) {
    return res.status(401).json({ error: 'Неверный логин или пароль' });
  }

  await createSession(user.id, res);
  res.json({ user: { id: user.id, username: user.username } });
});

app.get('/api/auth/me', (req, res) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Требуется авторизация' });
  }
  res.json({ user: req.user });
});

// Удаляет серверную сессию и сбрасывает cookie.
app.post('/api/auth/logout', requireAuth, (req, res) => {
  const token = getSessionToken(req);
  if (token) {
    db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(hashToken(token));
  }
  clearSessionCookie(res);
  res.json({ success: true });
});

// Возвращает только задачи текущего пользователя.
app.get('/api/tasks', requireAuth, (req, res) => {
  const tasks = db.prepare('SELECT * FROM tasks WHERE user_id = ?').all(req.user.id);
  res.json(tasks);
});

// Создаёт задачу от имени пользователя из сессии, а не из тела запроса.
app.post('/api/tasks', requireAuth, (req, res) => {
  if (!req.body || typeof req.body !== 'object') {
    return res.status(400).json({ error: 'Укажите название и описание задачи' });
  }
  const { title } = req.body;
  const details = req.body.description ?? req.body.details;
  if (typeof title !== 'string' || !title.trim() ||
      typeof details !== 'string' || !details.trim()) {
    return res.status(400).json({ error: 'Укажите название и описание задачи' });
  }

  const info = db.prepare('INSERT INTO tasks (title, details, user_id) VALUES (?, ?, ?)')
    .run(title.trim(), details.trim(), req.user.id);
  res.status(201).json({
    id: Number(info.lastInsertRowid),
    title: title.trim(),
    details: details.trim(),
    user_id: req.user.id,
    done: 0
  });
});

// Удаляет задачу, только если она принадлежит текущему пользователю.
app.delete('/api/tasks/:id', requireAuth, (req, res) => {
  const taskId = Number(req.params.id);
  if (!Number.isInteger(taskId) || taskId < 1) {
    return res.status(400).json({ error: 'Укажите корректный id задачи' });
  }

  const result = db.prepare('DELETE FROM tasks WHERE id = ? AND user_id = ?')
    .run(taskId, req.user.id);
  if (result.changes === 0) {
    return res.status(404).json({ error: 'Задача не найдена' });
  }

  res.json({ success: true });
});

// Меняет статус задачи только у её владельца.
app.put('/api/tasks/:id', requireAuth, (req, res) => {
  const taskId = Number(req.params.id);
  if (!Number.isInteger(taskId) || taskId < 1 ||
      !req.body || typeof req.body.done !== 'boolean') {
    return res.status(400).json({ error: 'Укажите корректный id и статус задачи' });
  }

  const result = db.prepare('UPDATE tasks SET done = ? WHERE id = ? AND user_id = ?')
    .run(req.body.done ? 1 : 0, taskId, req.user.id);
  if (result.changes === 0) {
    return res.status(404).json({ error: 'Задача не найдена' });
  }

  res.json({ success: true });
});

// Отдаём главную страницу и клиентские файлы приложения.
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});
app.get('/script.js', (req, res) => {
  res.sendFile(path.join(__dirname, 'script.js'));
});
app.get('/style.css', (req, res) => {
  res.sendFile(path.join(__dirname, 'style.css'));
});

app.listen(3000, () => console.log('Сервер запущен на http://localhost:3000'));