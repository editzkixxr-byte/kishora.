# KISHORA — owner-only affiliate site

## How it works
- Public site (`/`) shows ONLY products you published. Drafts are never returned by the public API, and draft images return 404 to visitors.
- Admin (`/admin`) works only after login. There is no signup route. Every `/api/admin/*` call is checked on the server (session + header check).
- Data: SQLite file + uploaded images in `DATA_DIR`. Passwords are bcrypt-hashed; sessions are httpOnly, SameSite=Strict, Secure in production; login is rate-limited (8 / 15 min).
- Uploads: 5 MB max, real JPG/PNG/WebP verified by file signature (not filename), saved under random names. Affiliate links must be https on amazon.in/.com, amzn.to, a.co, flipkart.com or fkrt.it/.cc.

## Run locally
1. `npm install`
2. `cp .env.example .env`, set SESSION_SECRET (`node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"`), OWNER_EMAIL, OWNER_PASSWORD (12+ chars), and NODE_ENV=development
3. `npm start` → http://localhost:3000 and /admin
4. After "Owner account created", delete OWNER_PASSWORD from `.env`.

## Deploy (Render example; Railway/Fly work the same way)
1. Push to a PRIVATE GitHub repo (`.env` and `data/` are git-ignored).
2. New Web Service → Build `npm install`, Start `npm start`.
3. Add a **Persistent Disk** mounted at `/var/data` (a paid plan is required; without it, data vanishes on redeploy).
4. Environment: NODE_ENV=production, SESSION_SECRET, OWNER_EMAIL, OWNER_PASSWORD, DATA_DIR=/var/data.
5. Deploy, open `/admin`, sign in, then DELETE OWNER_PASSWORD from the dashboard. Always use the https URL.
6. Forgot password: set a new OWNER_PASSWORD, delete the row with `sqlite3 /var/data/kishora.db "DELETE FROM admin"`, restart, then remove the variable again.

## Test checklist
1. Visit `/admin` logged out → only login form. `curl -i /api/admin/products` → 401.
2. Wrong password 9 times → rate-limited.
3. Add product with image, Save as Draft → NOT on `/`. Open its image URL in a private window → 404.
4. Publish → appears on `/`. Image is the exact file you uploaded. View on Amazon/Flipkart opens your exact URL.
5. Unpublish → disappears. Edit (change image) → old file is deleted. Delete → gone.
6. Try uploading a renamed .txt as .jpg → rejected. Try a non-Amazon link → rejected.
7. Redeploy/restart → products and images still there.

## Connecting your existing design
Keep your current HTML/CSS and fetch `/api/products` (fields: id, name, description, features, category, price, image, amazon_url, flipkart_url). Reuse `public/app.js` render logic as a reference.
