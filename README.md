# CipherDrop

Anonymous one-time messaging app with auth-code login, request approval, CRUD flows, and persistent storage.

## Features

- Account creation with generated 6 digit auth code and 8 digit password
- Password hashing on the server
- Login by auth code + password
- Add users by auth code
- Add requests must be accepted before messaging is allowed
- Create, read, edit, and delete outgoing messages while unread
- Recipient opens a message once; the server then destroys the message body
- Contacts, requests, profile editing, dashboard, empty states, loading states, responsive UI
- No demo accounts are created
- Storage modes:
  - Local JSON for development: `data/db.json`
  - Firebase Firestore for real persistent production storage

## Local development

```bash
npm install
npm start
```

Open:

```text
http://localhost:3000
```

If Firebase environment variables are not set, the app uses local JSON storage and creates `data/db.json` automatically.

## Firebase production setup

1. Create a Firebase project at https://console.firebase.google.com/.
2. In Firebase Console, go to **Build → Firestore Database**.
3. Click **Create database**.
4. Choose **Production mode**.
5. Pick the closest region.
6. Go to **Project settings → Service accounts**.
7. Click **Generate new private key** and download the JSON file.
8. Add these values from that JSON file to your server environment:

```bash
FIREBASE_PROJECT_ID="your-project-id"
FIREBASE_CLIENT_EMAIL="firebase-adminsdk-xxxxx@your-project-id.iam.gserviceaccount.com"
FIREBASE_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n"
```

Important: keep `FIREBASE_PRIVATE_KEY` secret. Do not put it in frontend code or commit it to GitHub.

## Deployment notes

Deploy this as a Node.js server app, not as a static-only site. Good options:

- Render Web Service
- Railway
- Fly.io
- Google Cloud Run
- Heroku-style Node host
- VPS

Build/start commands:

```bash
npm install
npm start
```

After deployment, create your first real account from the app UI. There are no built-in demo users.

## Reset local development data

For local JSON mode only:

```bash
rm -f data/db.json
npm start
```

The next start creates a fresh empty database.
