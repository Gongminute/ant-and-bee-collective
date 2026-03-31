# ant-and-bee-collective

## Writing Admin Backend

This repo now includes a small local backend for creating new writing pages from an admin form.

### What it does

- Opens a local admin page at `/admin` with title and body text fields.
- Creates a new file in `writings/` as `writing-N.html`.
- Updates `writings.html` and `Writings.html` cards automatically.
- Supports editing and deleting existing writing entries.
- Supports tags and optional image URL per writing.
- Renders pressable tag buttons on `Writings.html` that generate tag-based card stacks.

### 1) Install Node.js (if missing)

On macOS (Homebrew):

```bash
brew install node
```

### 2) Install dependencies

```bash
npm install
```

### 3) Start the backend

```bash
export ADMIN_USERNAME="admin"
export ADMIN_PASSWORD="your-strong-password"
export SESSION_SECRET="your-long-random-secret"
npm start
```

Then open:

`http://localhost:3000/admin`

You will be redirected to the login page:

`http://localhost:3000/admin/login`

### Admin authentication notes

- `ADMIN_USERNAME`: admin login username.
- `ADMIN_PASSWORD`: required password for admin login.
- `SESSION_SECRET`: used to sign the admin session cookie.

If you skip these environment variables, the server falls back to defaults for local testing only.

### Optional API usage

Create a writing via JSON POST:

```bash
curl -X POST http://localhost:3000/admin/create-writing \
	-H "Content-Type: application/json" \
	-d '{"title":"My new writing","content":"First paragraph.\n\nSecond paragraph."}'
```

Rebuild cards manually:

```bash
curl -X POST http://localhost:3000/admin/rebuild-archive
```

Update an existing writing:

```bash
curl -X PUT http://localhost:3000/admin/writing/7 \
	-H "Content-Type: application/json" \
	-d '{"title":"Updated title","content":"Updated body","tags":"essay,archive","image":"https://example.com/photo.jpg"}'
```

Delete a writing:

```bash
curl -X DELETE http://localhost:3000/admin/writing/7
```
