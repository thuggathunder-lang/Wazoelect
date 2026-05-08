[README.md](https://github.com/user-attachments/files/27520143/README.md)
# WAZOBIA ELECT AI — Full Stack v3.0
## Africa's Digital Democracy Infrastructure · Nigeria 2027

---

## 🚀 Quick Start

### Prerequisites
- Node.js 18+
- MongoDB (local or Atlas)

### 1. Install dependencies
```bash
npm install
```

### 2. Environment variables (optional — defaults work for demo)
```bash
# Create .env file:
PORT=5000
MONGO_URI=mongodb://127.0.0.1:27017/wazobia_elect_ai
JWT_SECRET=your_super_secret_key_here
ADMIN_KEY=INEC_ADMIN_2027
```

### 3. Start MongoDB
```bash
# macOS/Linux:
mongod --dbpath /data/db

# Or use MongoDB Atlas (cloud) — set MONGO_URI to your connection string
```

### 4. Start the server
```bash
npm start        # production
npm run dev      # development (auto-restart)
```

### 5. Open the frontend
Place the HTML file at: `public/index.html`  
Then visit: `http://localhost:5000`

---

## 📡 API Reference

### Authentication
| Method | Endpoint       | Description              |
|--------|---------------|--------------------------|
| POST   | /register      | Register new voter       |
| POST   | /login         | Login + get JWT token    |
| POST   | /verify-nin    | Verify NIN (BVAS step)   |

### Voting
| Method | Endpoint       | Description              |
|--------|---------------|--------------------------|
| POST   | /vote          | Cast single-level vote   |
| POST   | /vote/batch    | Cast all 6 levels at once|
| GET    | /verify/:hash  | Verify receipt hash      |

### Results
| Method | Endpoint           | Description            |
|--------|--------------------|------------------------|
| GET    | /results           | All live results       |
| GET    | /results/:level    | Results by level       |
| GET    | /blockchain        | Blockchain ledger      |

### Admin (requires `x-admin-key: INEC_ADMIN_2027` header)
| Method | Endpoint              | Description          |
|--------|-----------------------|----------------------|
| GET    | /admin/dashboard      | Full stats dashboard |
| GET    | /admin/fraud          | Fraud flags          |
| GET    | /admin/audit          | Audit log            |
| GET    | /admin/export         | Export results CSV   |
| PATCH  | /admin/fraud/:id/resolve | Resolve fraud flag|

### System
| Method | Endpoint  | Description   |
|--------|-----------|---------------|
| GET    | /health   | Health check  |

---

## 🔐 Demo Data (auto-seeded on first run)

| Name              | NIN           | Email               | Password    |
|-------------------|---------------|---------------------|-------------|
| Adaeze Okonkwo    | 12345678901   | adaeze@demo.ng      | Demo1234!   |
| Emeka Nwosu       | 98765432109   | emeka@demo.ng       | Demo1234!   |
| Babatunde Adeyemi | 55443322110   | tunde@demo.ng       | Demo1234!   |
| Fatima Musa       | 11223344556   | fatima@demo.ng      | Demo1234!   |

**Admin:** `admin@inec.gov.ng` / `WazobiaAdmin2027!`  
**Admin header:** `x-admin-key: INEC_ADMIN_2027`

---

## ⛓️ Blockchain

Each vote is:
1. SHA-256 hashed with timestamp + user data
2. AES-256-CBC encrypted
3. A zero-knowledge proof is generated
4. Anchored as a block on the distributed ledger
5. Broadcast via Socket.io to all live dashboards

---

## 🔌 Socket.io Events

| Event           | Direction    | Payload                        |
|-----------------|--------------|-------------------------------|
| `liveResults`   | Server → All | Full results object            |
| `newBlock`      | Server → All | New blockchain block           |
| `voteCast`      | Server → All | `{ level, state, totalVotes }` |
| `voterRegistered`| Server → All| `{ state, total }`            |
| `clientCount`   | Server → All | Number of connected clients    |
| `subscribeState`| Client → Server | Subscribe to state updates |

---

## 🏗️ Architecture

```
wazobia/
├── server.js          # Express + Socket.io backend
├── package.json       # Dependencies
├── .env               # Environment variables (create this)
├── public/
│   └── index.html     # Frontend (place wazobia_ultimate_v3.html here)
└── README.md
```

---

## 🌍 Production Deployment

### MongoDB Atlas
```bash
MONGO_URI=mongodb+srv://user:pass@cluster.mongodb.net/wazobia_elect_ai
```

### Deploy to Railway / Render / Heroku
```bash
# Railway
railway up

# Render — connect GitHub repo, set env vars in dashboard
# Heroku
heroku create wazobia-elect-ai
git push heroku main
```

### Nginx reverse proxy (production)
```nginx
server {
    listen 80;
    server_name wazobiaelect.ai;
    location / {
        proxy_pass http://localhost:5000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
    }
}
```

---

*WAZOBIA ELECT AI — "We are not building an app. We are building the future of democracy."*
