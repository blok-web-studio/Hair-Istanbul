# Hair Istanbul — Website & Admin Dashboard

This repository contains the source for the Hair Istanbul website (public-facing pages, booking form and assets) together with a lightweight Node.js admin dashboard used for visitor analytics and booking management.

Summary
- Purpose: A small business site for Hair Istanbul with a booking/contact form and an optional secure admin dashboard that stores submissions and tracks visitors.
- Who this repo is for: developers maintaining the site, agency deployers, or clients reviewing the code.

What’s included
- Frontend: static HTML/CSS/JS pages in the repo root and `Assets/` (main public pages like `index.html`, `dashboard.html`, and related static prototypes).
- Backend (optional): `server.js` and `database.js` — a simple Express server that records visitors and bookings into a JSON-backed database (`hair_istanbul_db.json`).
- Admin: a secure dashboard (protected route) used to view analytics, bookings, and manage users.

Key features
- Booking form: collects visitor booking requests and saves them to the local JSON DB.
- Visitor tracking: client-side tracking that posts visitor info to the backend (IP, user-agent, timestamp).
- Admin dashboard: visual analytics, booking list, and basic user management (JWT-based auth).
- No external DB required: uses `lowdb` / JSON file storage by default.

Quick start (development)
1. Install dependencies:

   npm install

2. Run the server (starts the backend and serves the dashboard endpoints):

   npm start

   or

   node server.js

3. Open the public site in your browser:

   - Public pages: open `index.html` (file:// or served by a static host)
   - Dashboard (local): http://localhost:3000/admin-dashboard-secure-2024 (default; check `server.js` for `ADMIN_PATH`)

Notes
- Environment: set `JWT_SECRET` and other sensitive values in your environment (do not commit `.env`).
- Data file: `hair_istanbul_db.json` holds visitors/bookings/users when running locally — back this up before deploying.
- Static hosting: the frontend is static and can be deployed to GitHub Pages, Netlify, or Vercel; the backend requires a Node-capable host.

Project structure (high level)
- `index.html` — main public page
- `dashboard.html`, `dashboard-login.html` — admin-facing frontends
- `server.js` — Express server for API and dashboard
- `database.js` — local JSON DB helpers
- `hair_istanbul_db.json` — local data store (bookings, visitors, users)
- `Assets/` — images, CSS, JS and other static assets
- `prototype-*/` — development prototypes / demos

How to deploy
- Static-only: deploy the public HTML files to a static host (GitHub Pages, Netlify, Vercel static). Remove or disable client-side calls to the backend if you choose static-only.
- Full site (recommended if you need dashboard/features): deploy the Node backend to Render, Vercel (serverless functions), Railway, or a VPS. Update frontend API URLs to point to the backend.

Contributing
- Make changes on a feature branch and open a pull request. Include steps to reproduce and any env vars required.

Contact
- Maintainer: contact details are not included in the repo. If you need help running or deploying, open an issue or contact the repository owner.

License
- Check project owner for licensing; no license file included by default.
