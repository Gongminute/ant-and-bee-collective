const express = require('express');
const crypto = require('crypto');
const fs = require('fs/promises');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

const ROOT = __dirname;
const WRITINGS_DIR = path.join(ROOT, 'writings');
const ARCHIVE_FILES = [path.join(ROOT, 'Writings.html')];

const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'admin';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'change-this-password';
const SESSION_SECRET = process.env.SESSION_SECRET || 'change-this-secret';
const SESSION_COOKIE_NAME = 'admin_session';
const SESSION_MAX_AGE_SECONDS = 8 * 60 * 60;

app.use(express.urlencoded({ extended: true, limit: '2mb' }));
app.use(express.json({ limit: '2mb' }));
app.use(express.static(ROOT));

if (!process.env.ADMIN_PASSWORD || !process.env.SESSION_SECRET) {
  console.warn('Warning: Using default admin credentials/session secret. Set ADMIN_PASSWORD and SESSION_SECRET in your environment.');
}

function parseCookies(header) {
  if (!header) {
    return {};
  }

  return header
    .split(';')
    .map((part) => part.trim())
    .filter(Boolean)
    .reduce((acc, part) => {
      const idx = part.indexOf('=');
      if (idx === -1) {
        return acc;
      }

      const key = part.slice(0, idx);
      const value = part.slice(idx + 1);
      acc[key] = value;
      return acc;
    }, {});
}

function signPayload(payload) {
  return crypto.createHmac('sha256', SESSION_SECRET).update(payload).digest('hex');
}

function createSessionToken(username) {
  const timestamp = Date.now();
  const payload = `${username}:${timestamp}`;
  const signature = signPayload(payload);
  return Buffer.from(`${payload}:${signature}`, 'utf8').toString('base64url');
}

function verifySessionToken(token) {
  try {
    const decoded = Buffer.from(token, 'base64url').toString('utf8');
    const parts = decoded.split(':');
    if (parts.length !== 3) {
      return null;
    }

    const [username, issuedAtRaw, signature] = parts;
    if (!username || !issuedAtRaw || !signature) {
      return null;
    }

    const payload = `${username}:${issuedAtRaw}`;
    const expected = signPayload(payload);

    const signatureBuffer = Buffer.from(signature, 'hex');
    const expectedBuffer = Buffer.from(expected, 'hex');

    if (signatureBuffer.length !== expectedBuffer.length) {
      return null;
    }

    if (!crypto.timingSafeEqual(signatureBuffer, expectedBuffer)) {
      return null;
    }

    const issuedAt = Number(issuedAtRaw);
    if (!Number.isFinite(issuedAt)) {
      return null;
    }

    if (Date.now() - issuedAt > SESSION_MAX_AGE_SECONDS * 1000) {
      return null;
    }

    if (username !== ADMIN_USERNAME) {
      return null;
    }

    return { username };
  } catch (error) {
    return null;
  }
}

function setSessionCookie(res, token) {
  res.setHeader(
    'Set-Cookie',
    `${SESSION_COOKIE_NAME}=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${SESSION_MAX_AGE_SECONDS}`
  );
}

function clearSessionCookie(res) {
  res.setHeader('Set-Cookie', `${SESSION_COOKIE_NAME}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0`);
}

function getAuthenticatedUser(req) {
  const cookies = parseCookies(req.headers.cookie || '');
  const token = cookies[SESSION_COOKIE_NAME];

  if (!token) {
    return null;
  }

  return verifySessionToken(token);
}

function requireAdminAuth(req, res, next) {
  const user = getAuthenticatedUser(req);

  if (user) {
    req.adminUser = user;
    return next();
  }

  const expectsJson =
    (req.headers.accept || '').includes('application/json') ||
    (req.headers['content-type'] || '').includes('application/json');

  if (expectsJson || req.path.startsWith('/admin/writing')) {
    return res.status(401).json({ error: 'Unauthorized. Please log in at /admin/login.' });
  }

  return res.redirect('/admin/login');
}

function escapeHtml(input) {
  return String(input)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function decodeHtml(input) {
  return String(input)
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&amp;/g, '&');
}

function normalizeTags(input) {
  if (Array.isArray(input)) {
    return [...new Set(input.map((item) => String(item).trim()).filter(Boolean))];
  }

  return [...new Set(String(input || '')
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean))];
}

function parseImage(input) {
  return String(input || '').trim();
}

function sanitizeBodyText(input) {
  return String(input || '').replace(/\r\n/g, '\n').trim();
}

function toParagraphs(text) {
  return text
    .split(/\n{2,}/)
    .map((block) => block.trim())
    .filter(Boolean)
    .map((block) => `<p>${escapeHtml(block).replace(/\n/g, '<br>')}</p>`)
    .join('\n        ');
}

function tagsHtml(tags) {
  if (!tags.length) {
    return '';
  }

  return `<ul class="tag-list">${tags
    .map((tag) => `<li>${escapeHtml(tag)}</li>`)
    .join('')}</ul>`;
}

function writingHtmlTemplate({ title, content, tags, image }) {
  const contentHtml = toParagraphs(content);
  const encodedMeta = escapeHtml(JSON.stringify({ tags, image }));
  const encodedRaw = escapeHtml(JSON.stringify({ content }));

  return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>${escapeHtml(title)}</title>
    <style>
        body {
            margin: 0;
            padding: 2rem 1.25rem;
            color: #1f1f1f;
            background: #f9f9f7;
            font-family: "Noto Serif KR", "Iowan Old Style", serif;
            line-height: 1.7;
        }

        main {
            max-width: 780px;
            margin: 0 auto;
            background: #ffffff;
            border: 1px solid rgba(0, 0, 0, 0.08);
            box-shadow: 0 6px 20px rgba(0, 0, 0, 0.06);
            padding: 2rem 1.25rem;
        }

        h1 {
            margin-top: 0;
            font-size: 1.7rem;
            line-height: 1.3;
        }

        p {
            margin: 0 0 1rem;
            white-space: normal;
        }

        .hero-image {
            width: 100%;
            border: 1px solid rgba(0, 0, 0, 0.08);
            margin: 0 0 1.1rem;
            display: block;
        }

        .tag-list {
            list-style: none;
            display: flex;
            flex-wrap: wrap;
            gap: 0.4rem;
            padding: 0;
            margin: 0 0 1rem;
        }

        .tag-list li {
            border: 1px solid rgba(0, 0, 0, 0.18);
            background: #f5f4ef;
            padding: 0.18rem 0.48rem;
            font-size: 0.78rem;
            line-height: 1.25;
        }
    </style>
    <script id="writing-meta" type="application/json">${encodedMeta}</script>
    <script id="writing-raw" type="application/json">${encodedRaw}</script>
</head>
<body>
    <main>
        <h1>${escapeHtml(title)}</h1>
        ${image ? `<img class="hero-image" src="${escapeHtml(image)}" alt="${escapeHtml(title)}" />` : ''}
        ${tagsHtml(tags)}
        ${contentHtml || '<p></p>'}
    </main>
</body>
</html>
`;
}

function parseWritingFile(html, number) {
  const titleMatch = html.match(/<title>([\s\S]*?)<\/title>/i);
  const title = titleMatch ? decodeHtml(titleMatch[1]).trim() : `Writing ${number}`;

  let tags = [];
  let image = '';
  let content = '';

  const metaMatch = html.match(/<script id="writing-meta" type="application\/json">([\s\S]*?)<\/script>/i);
  if (metaMatch) {
    try {
      const parsedMeta = JSON.parse(decodeHtml(metaMatch[1]));
      tags = normalizeTags(parsedMeta.tags || []);
      image = parseImage(parsedMeta.image || '');
    } catch (error) {
      tags = [];
      image = '';
    }
  }

  const rawMatch = html.match(/<script id="writing-raw" type="application\/json">([\s\S]*?)<\/script>/i);
  if (rawMatch) {
    try {
      const parsedRaw = JSON.parse(decodeHtml(rawMatch[1]));
      content = sanitizeBodyText(parsedRaw.content || '');
    } catch (error) {
      content = '';
    }
  }

  return {
    number,
    fileName: `writing-${number}.html`,
    href: `writings/writing-${number}.html`,
    title,
    tags,
    image,
    content
  };
}

function buildCard(entry, index) {
  const safeTitle = escapeHtml(entry.title || `Writing ${entry.number}`);
  const tags = normalizeTags(entry.tags || []);
  const encodedTags = tags.join('|');
  const tagsMarkup = tags.length
    ? `<p class="thumb-tags">${tags.map((tag) => `<span class="tag-pill">${escapeHtml(tag)}</span>`).join('')}</p>`
    : '';

  return `            <li class="thumb-item" style="--index: ${index}; z-index: ${index + 1};">
                <a class="thumb-card" href="${entry.href}" data-source="${entry.href}" data-tags="${escapeHtml(encodedTags)}" data-id="${entry.number}">
                    <h2 class="thumb-title">${safeTitle}</h2>
                    ${tagsMarkup}
                    <p class="thumb-preview">Loading preview...</p>
                </a>
            </li>`;
}

function renderArchiveList(entries) {
  return entries.map((entry, idx) => buildCard(entry, idx)).join('\n');
}

async function getWritingEntries() {
  const files = await fs.readdir(WRITINGS_DIR);

  const numbers = files
    .map((name) => {
      const match = name.match(/^writing-(\d+)\.html$/i);
      return match ? Number(match[1]) : null;
    })
    .filter((num) => Number.isInteger(num))
    .sort((a, b) => a - b);

  const entries = [];

  for (const number of numbers) {
    const filePath = path.join(WRITINGS_DIR, `writing-${number}.html`);
    const html = await fs.readFile(filePath, 'utf8');
    entries.push(parseWritingFile(html, number));
  }

  return entries;
}

async function findEntry(number) {
  const filePath = path.join(WRITINGS_DIR, `writing-${number}.html`);
  const html = await fs.readFile(filePath, 'utf8');
  return parseWritingFile(html, number);
}

async function updateArchiveFile(filePath, entries) {
  let html;

  try {
    html = await fs.readFile(filePath, 'utf8');
  } catch (error) {
    return;
  }

  const listMarkup = renderArchiveList(entries);

  const updated = html
    .replace(/(<ul class="thumb-grid">)[\s\S]*?(<\/ul>)/, `$1\n${listMarkup}\n        $2`)
    .replace(/--card-count:\s*\d+\s*;/, `--card-count: ${Math.max(entries.length, 1)};`);

  await fs.writeFile(filePath, updated, 'utf8');
}

async function rebuildArchivePages() {
  const entries = await getWritingEntries();

  for (const filePath of ARCHIVE_FILES) {
    await updateArchiveFile(filePath, entries);
  }

  return entries;
}

async function saveWriting(number, payload) {
  const title = String(payload.title || '').trim();
  const content = sanitizeBodyText(payload.content || '');
  const tags = normalizeTags(payload.tags || '');
  const image = parseImage(payload.image || '');

  if (!title || !content) {
    throw new Error('Title and content are required.');
  }

  const filePath = path.join(WRITINGS_DIR, `writing-${number}.html`);
  const html = writingHtmlTemplate({ title, content, tags, image });
  await fs.writeFile(filePath, html, 'utf8');

  return {
    number,
    fileName: `writing-${number}.html`,
    href: `writings/writing-${number}.html`,
    title,
    content,
    tags,
    image
  };
}

app.get('/admin/login', (req, res) => {
  const hasError = req.query.error === '1';

  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Login</title>
    <style>
        :root {
            --bg: #efece2;
            --panel: #fffef8;
            --ink: #201f1b;
            --muted: #656154;
            --accent: #1f3d2f;
            --danger: #8a1c1c;
            --edge: rgba(0, 0, 0, 0.14);
        }

        * { box-sizing: border-box; }

        body {
            margin: 0;
            min-height: 100vh;
            background:
                radial-gradient(circle at 14% 16%, rgba(255, 255, 255, 0.68), transparent 33%),
                radial-gradient(circle at 87% 82%, rgba(255, 255, 255, 0.5), transparent 37%),
                var(--bg);
            color: var(--ink);
            font-family: "Noto Serif KR", "Iowan Old Style", serif;
            display: grid;
            place-items: center;
            padding: 1rem;
        }

        .panel {
            width: min(460px, 100%);
            background: var(--panel);
            border: 1px solid var(--edge);
            box-shadow: 0 14px 35px rgba(0, 0, 0, 0.09);
            padding: 1.2rem;
        }

        h1 {
            margin: 0 0 0.45rem;
            font-size: 1.5rem;
        }

        p {
            margin: 0 0 0.8rem;
            color: var(--muted);
        }

        .error {
            color: var(--danger);
            min-height: 1.2rem;
            margin-bottom: 0.6rem;
            font-size: 0.94rem;
        }

        label {
            display: block;
            margin: 0.55rem 0 0.35rem;
            font-weight: 600;
            font-size: 0.93rem;
        }

        input,
        button {
            font: inherit;
        }

        input {
            width: 100%;
            border: 1px solid rgba(0, 0, 0, 0.18);
            background: #fff;
            color: var(--ink);
            padding: 0.63rem 0.68rem;
        }

        button {
            margin-top: 0.8rem;
            border: 0;
            background: var(--accent);
            color: #fff;
            padding: 0.65rem 0.9rem;
            cursor: pointer;
        }
    </style>
</head>
<body>
    <main class="panel">
        <h1>Admin Login</h1>
        <p>Sign in to create and manage writings.</p>
        <div class="error">${hasError ? 'Invalid username or password.' : ''}</div>
        <form method="post" action="/admin/login">
            <label for="username">Username</label>
            <input id="username" name="username" type="text" required autocomplete="username" />

            <label for="password">Password</label>
            <input id="password" name="password" type="password" required autocomplete="current-password" />

            <button type="submit">Log in</button>
        </form>
    </main>
</body>
</html>`);
});

app.post('/admin/login', (req, res) => {
  const username = String(req.body.username || '').trim();
  const password = String(req.body.password || '');

  if (username !== ADMIN_USERNAME || password !== ADMIN_PASSWORD) {
    return res.redirect('/admin/login?error=1');
  }

  const token = createSessionToken(username);
  setSessionCookie(res, token);
  return res.redirect('/admin');
});

app.post('/admin/logout', (req, res) => {
  clearSessionCookie(res);
  return res.redirect('/admin/login');
});

app.get('/admin', requireAdminAuth, async (req, res) => {
  const entries = await getWritingEntries();

  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>꿀벌이 만든 관리자 서버/title>
    <style>
        :root {
            --bg: #f4f2ec;
            --panel: #fffef9;
            --ink: #1f1d1a;
            --muted: #5c5852;
            --accent: #1f3d2f;
            --danger: #8a1c1c;
            --border: rgba(0, 0, 0, 0.12);
        }

        * { box-sizing: border-box; }

        body {
            margin: 0;
            min-height: 100vh;
            background:
                radial-gradient(circle at 20% 15%, rgba(255, 255, 255, 0.7), transparent 30%),
                radial-gradient(circle at 85% 75%, rgba(255, 255, 255, 0.58), transparent 34%),
                var(--bg);
            color: var(--ink);
            font-family: "Noto Serif KR", "Iowan Old Style", serif;
            padding: 2rem 1rem 3rem;
        }

        .panel {
            max-width: 980px;
            margin: 0 auto;
            background: var(--panel);
            border: 1px solid var(--border);
            box-shadow: 0 14px 34px rgba(0, 0, 0, 0.08);
            padding: 1.4rem;
        }

        .topbar {
            display: flex;
            gap: 0.7rem;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
        }

        h1 {
            margin: 0;
            font-size: clamp(1.4rem, 3vw, 2rem);
        }

        p.meta {
            margin: 0.25rem 0 1rem;
            color: var(--muted);
        }

        .grid {
            display: grid;
            grid-template-columns: 1.2fr 1fr;
            gap: 1rem;
        }

        .panel-block {
            border: 1px solid rgba(0, 0, 0, 0.1);
            padding: 0.9rem;
            background: #fff;
        }

        label {
            display: block;
            font-size: 0.93rem;
            margin: 0.8rem 0 0.45rem;
            font-weight: 600;
        }

        input,
        textarea,
        button {
            font: inherit;
        }

        input,
        textarea {
            width: 100%;
            border: 1px solid rgba(0, 0, 0, 0.2);
            background: #fff;
            color: var(--ink);
            padding: 0.65rem 0.7rem;
        }

        textarea {
            min-height: 260px;
            resize: vertical;
            line-height: 1.5;
        }

        .actions {
            display: flex;
            gap: 0.5rem;
            flex-wrap: wrap;
        }

        button {
            margin-top: 0.95rem;
            border: 0;
            background: var(--accent);
            color: #fff;
            padding: 0.7rem 1rem;
            cursor: pointer;
        }

        button.secondary {
            background: #6f6a63;
        }

        button.danger {
            background: var(--danger);
        }

        .status {
            margin-top: 0.8rem;
            min-height: 1.2rem;
            color: #0f5132;
            font-size: 0.92rem;
        }

        .status.error {
            color: var(--danger);
        }

        .entry-list {
            list-style: none;
            margin: 0;
            padding: 0;
            display: grid;
            gap: 0.6rem;
        }

        .entry-row {
            border: 1px solid rgba(0, 0, 0, 0.14);
            background: #faf9f5;
            padding: 0.65rem;
        }

        .entry-row h3 {
            margin: 0 0 0.35rem;
            font-size: 0.98rem;
        }

        .entry-row p {
            margin: 0 0 0.4rem;
            font-size: 0.84rem;
            color: var(--muted);
        }

        .entry-tags {
            display: flex;
            gap: 0.35rem;
            flex-wrap: wrap;
            margin-bottom: 0.45rem;
        }

        .entry-tags span {
            border: 1px solid rgba(0, 0, 0, 0.2);
            padding: 0.1rem 0.4rem;
            font-size: 0.75rem;
            background: #fff;
        }

        .entry-actions {
            display: flex;
            gap: 0.4rem;
        }

        .entry-actions button {
            margin-top: 0;
            padding: 0.45rem 0.62rem;
            font-size: 0.82rem;
        }

        @media (max-width: 900px) {
            .grid {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
    <main class="panel">
        <div class="topbar">
            <h1>개미와 꿀벌 글 등록하기</h1>
            <form method="post" action="/admin/logout">
                <button class="secondary" type="submit">Log out</button>
            </form>
        </div>

        <p class="meta">Create, edit, delete entries. Tags and image URL are stored per writing and used by your archive page.</p>

        <div class="grid">
            <section class="panel-block">
                <h2 id="form-heading">새 글 작성하기</h2>
                <form id="writing-form">
                    <input id="mode" type="hidden" value="create" />
                    <input id="writing-number" type="hidden" />

                    <label for="title">제목</label>
                    <input id="title" name="title" type="text" required placeholder="Enter writing title" />

                    <label for="tags">태그 (쉼표로 구분)</label>
                    <input id="tags" name="tags" type="text" placeholder="essay, poetry, memory" />

                    <label for="image">이미지 URL (선택 사항)</label>
                    <input id="image" name="image" type="text" placeholder="https://... or /images/photo.jpg" />

                    <label for="content">본문</label>
                    <textarea id="content" name="content" required placeholder="여기에 글을 작성하세요. 단락은 엔터로 구분합니다."></textarea>

                    <div class="actions">
                        <button type="submit" id="save-btn">글 작성</button>
                        <button type="button" class="secondary" id="reset-btn">초기화</button>
                        <button type="button" class="danger" id="delete-btn" hidden>글 삭제</button>
                    </div>

                    <p class="status" id="status"></p>
                </form>
            </section>

            <section class="panel-block">
                <h2>기존 글 (${entries.length})</h2>
                <ul class="entry-list" id="entry-list">
                    ${entries
                      .map((entry) => {
                        const tagsText = normalizeTags(entry.tags).map((tag) => `<span>${escapeHtml(tag)}</span>`).join('');
                        return `<li class="entry-row" data-number="${entry.number}">
                            <h3>#${entry.number} ${escapeHtml(entry.title)}</h3>
                            <p>${escapeHtml(entry.fileName)}</p>
                            ${tagsText ? `<div class="entry-tags">${tagsText}</div>` : ''}
                            <div class="entry-actions">
                                <button type="button" data-action="edit" data-number="${entry.number}">Edit</button>
                                <button type="button" class="danger" data-action="delete" data-number="${entry.number}">Delete</button>
                            </div>
                        </li>`;
                      })
                      .join('')}
                </ul>
            </section>
        </div>
    </main>

    <script>
        const form = document.getElementById('writing-form');
        const modeInput = document.getElementById('mode');
        const numberInput = document.getElementById('writing-number');
        const titleInput = document.getElementById('title');
        const tagsInput = document.getElementById('tags');
        const imageInput = document.getElementById('image');
        const contentInput = document.getElementById('content');
        const saveBtn = document.getElementById('save-btn');
        const resetBtn = document.getElementById('reset-btn');
        const deleteBtn = document.getElementById('delete-btn');
        const statusEl = document.getElementById('status');
        const formHeading = document.getElementById('form-heading');
        const entryList = document.getElementById('entry-list');

        function setStatus(message, isError) {
            statusEl.textContent = message;
            statusEl.classList.toggle('error', Boolean(isError));
        }

        function setCreateMode() {
            modeInput.value = 'create';
            numberInput.value = '';
            formHeading.textContent = 'Create new writing';
            saveBtn.textContent = 'Create writing';
            deleteBtn.hidden = true;
            form.reset();
        }

        async function loadEntry(number) {
            const response = await fetch('/admin/writing/' + number, {
                headers: { 'Accept': 'application/json' }
            });

            if (!response.ok) {
                const data = await response.json();
                throw new Error(data.error || 'Failed to load writing');
            }

            return response.json();
        }

        async function deleteEntry(number) {
            const response = await fetch('/admin/writing/' + number, {
                method: 'DELETE',
                headers: { 'Accept': 'application/json' }
            });

            if (!response.ok) {
                const data = await response.json();
                throw new Error(data.error || 'Failed to delete writing');
            }

            return response.json();
        }

        entryList.addEventListener('click', async (event) => {
            const target = event.target;
            if (!(target instanceof HTMLElement)) {
                return;
            }

            const action = target.getAttribute('data-action');
            const number = target.getAttribute('data-number');
            if (!action || !number) {
                return;
            }

            if (action === 'edit') {
                try {
                    setStatus('Loading writing ' + number + '...', false);
                    const data = await loadEntry(number);
                    modeInput.value = 'edit';
                    numberInput.value = String(data.number);
                    formHeading.textContent = 'Edit writing #' + data.number;
                    saveBtn.textContent = 'Update writing';
                    deleteBtn.hidden = false;
                    titleInput.value = data.title || '';
                    tagsInput.value = (data.tags || []).join(', ');
                    imageInput.value = data.image || '';
                    contentInput.value = data.content || '';
                    setStatus('Loaded writing #' + data.number, false);
                } catch (error) {
                    setStatus(error.message, true);
                }
                return;
            }

            if (action === 'delete') {
                if (!window.confirm('Delete writing #' + number + '? This cannot be undone.')) {
                    return;
                }

                try {
                    setStatus('Deleting writing ' + number + '...', false);
                    await deleteEntry(number);
                    setStatus('Deleted writing #' + number, false);
                    window.setTimeout(() => window.location.reload(), 450);
                } catch (error) {
                    setStatus(error.message, true);
                }
            }
        });

        deleteBtn.addEventListener('click', async () => {
            const number = numberInput.value;
            if (!number) {
                return;
            }

            if (!window.confirm('Delete writing #' + number + '? This cannot be undone.')) {
                return;
            }

            try {
                setStatus('Deleting writing ' + number + '...', false);
                await deleteEntry(number);
                setStatus('Deleted writing #' + number, false);
                window.setTimeout(() => window.location.reload(), 450);
            } catch (error) {
                setStatus(error.message, true);
            }
        });

        resetBtn.addEventListener('click', () => {
            setCreateMode();
            setStatus('', false);
        });

        form.addEventListener('submit', async (event) => {
            event.preventDefault();

            const payload = {
                title: titleInput.value.trim(),
                content: contentInput.value,
                tags: tagsInput.value,
                image: imageInput.value.trim()
            };

            const isEdit = modeInput.value === 'edit';
            const number = numberInput.value;
            const endpoint = isEdit ? '/admin/writing/' + number : '/admin/create-writing';
            const method = isEdit ? 'PUT' : 'POST';

            try {
                setStatus(isEdit ? 'Updating...' : 'Creating...', false);
                const response = await fetch(endpoint, {
                    method,
                    headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
                    body: JSON.stringify(payload)
                });

                const data = await response.json();
                if (!response.ok) {
                    throw new Error(data.error || 'Save failed');
                }

                setStatus(isEdit ? 'Updated writing #' + data.number : 'Created ' + data.fileName, false);
                window.setTimeout(() => window.location.reload(), 500);
            } catch (error) {
                setStatus(error.message, true);
            }
        });
    </script>
</body>
</html>`);
});

app.get('/admin/writing/:number', requireAdminAuth, async (req, res) => {
  try {
    const number = Number(req.params.number);

    if (!Number.isInteger(number) || number <= 0) {
      return res.status(400).json({ error: 'Invalid writing number.' });
    }

    const entry = await findEntry(number);
    return res.status(200).json(entry);
  } catch (error) {
    if (error && error.code === 'ENOENT') {
      return res.status(404).json({ error: 'Writing not found.' });
    }

    return res.status(500).json({ error: error.message || 'Unexpected server error.' });
  }
});

app.post('/admin/create-writing', requireAdminAuth, async (req, res) => {
  try {
    const entries = await getWritingEntries();
    const nextNumber = entries.length > 0 ? entries[entries.length - 1].number + 1 : 1;

    const entry = await saveWriting(nextNumber, req.body);
    await rebuildArchivePages();

    return res.status(201).json({
      message: 'Writing created successfully.',
      number: entry.number,
      fileName: entry.fileName,
      href: entry.href
    });
  } catch (error) {
    return res.status(400).json({ error: error.message || 'Failed to create writing.' });
  }
});

app.put('/admin/writing/:number', requireAdminAuth, async (req, res) => {
  try {
    const number = Number(req.params.number);

    if (!Number.isInteger(number) || number <= 0) {
      return res.status(400).json({ error: 'Invalid writing number.' });
    }

    await fs.access(path.join(WRITINGS_DIR, `writing-${number}.html`));
    const entry = await saveWriting(number, req.body);
    await rebuildArchivePages();

    return res.status(200).json({
      message: 'Writing updated successfully.',
      number: entry.number,
      fileName: entry.fileName,
      href: entry.href
    });
  } catch (error) {
    if (error && error.code === 'ENOENT') {
      return res.status(404).json({ error: 'Writing not found.' });
    }

    return res.status(400).json({ error: error.message || 'Failed to update writing.' });
  }
});

app.delete('/admin/writing/:number', requireAdminAuth, async (req, res) => {
  try {
    const number = Number(req.params.number);

    if (!Number.isInteger(number) || number <= 0) {
      return res.status(400).json({ error: 'Invalid writing number.' });
    }

    const filePath = path.join(WRITINGS_DIR, `writing-${number}.html`);
    await fs.unlink(filePath);
    await rebuildArchivePages();

    return res.status(200).json({ message: 'Writing deleted successfully.', number });
  } catch (error) {
    if (error && error.code === 'ENOENT') {
      return res.status(404).json({ error: 'Writing not found.' });
    }

    return res.status(500).json({ error: error.message || 'Failed to delete writing.' });
  }
});

app.post('/admin/rebuild-archive', requireAdminAuth, async (req, res) => {
  try {
    const entries = await rebuildArchivePages();
    return res.status(200).json({ message: 'Archive rebuilt.', count: entries.length });
  } catch (error) {
    return res.status(500).json({ error: error.message || 'Unexpected server error.' });
  }
});

app.listen(PORT, () => {
  console.log(`Admin backend running at http://localhost:${PORT}/admin`);
});
