# Farmsky — Deployment Guide (AWS + Cloudflare)

This guide is written like a tutorial for a student. Follow it top to bottom.

Farmsky now ships in **two forms** from the same codebase:

| Build | Command | Runs on | Database |
|-------|---------|---------|----------|
| **Node server** (for AWS) | `npm run build:node` → `npm start` | Any Linux server (AWS EC2 / App Runner / VPS) | SQLite file (`data/farmsky.db`) |
| **Cloudflare Pages** (original) | `npm run build` → `npm run deploy` | Cloudflare edge | Cloudflare D1 |

Pick the section you need.

---

## PART 0 — Quick answer: Does Cloudflare have a FREE version?

**Yes.** Cloudflare's free tier is generous and this app was *built* for it, so it's
actually the **easiest and cheapest** way to host Farmsky:

| Service | Free tier |
|---------|-----------|
| Cloudflare **Pages** (hosting + functions) | Unlimited sites, 500 builds/month, 100k requests/day |
| Cloudflare **Workers** | 100,000 requests/day |
| Cloudflare **D1** (database) | 5 GB storage, 5 million reads/day |

No credit card needed for the free tier. If you just want it live fast and cheap,
**use Cloudflare** (see PART 3). If you specifically want it on **AWS**, use PART 1 or 2.

---

## PART 1 — Deploy to AWS EC2 (recommended, "easy Option B")

You will create one small virtual machine, copy the app onto it, and run it 24/7.

### Step 1 — Create the EC2 instance
1. Log in to the **AWS Console** → search **EC2** → **Launch instance**.
2. **Name:** `farmsky`.
3. **OS image:** *Amazon Linux 2023* (or *Ubuntu 22.04*).
4. **Instance type:** `t3.micro` (free-tier eligible) or `t3.small`.
5. **Key pair:** click *Create key pair*, name it `farmsky`, download the
   `farmsky.pem` file (this is your SSH key — keep it safe).
6. **Network settings → Edit:** add inbound rules:
   - SSH (port 22) — Source: *My IP*
   - HTTP (port 80) — Source: *Anywhere*
   - HTTPS (port 443) — Source: *Anywhere*
7. **Launch instance.** Note its **Public IPv4 address** (e.g. `13.51.x.x`).

### Step 2 — Connect to the server
On your computer:
```bash
chmod 400 farmsky.pem
ssh -i farmsky.pem ec2-user@<PUBLIC_IP>      # Amazon Linux
# (Ubuntu uses: ssh -i farmsky.pem ubuntu@<PUBLIC_IP>)
```

### Step 3 — Install Node.js, git, build tools, PM2
`better-sqlite3` is a native module, so we need a compiler toolchain.
```bash
# Amazon Linux 2023:
sudo dnf install -y nodejs npm git gcc-c++ make python3
# Ubuntu:  sudo apt update && sudo apt install -y nodejs npm git build-essential python3

sudo npm install -g pm2
```

### Step 4 — Get the code onto the server
Pick ONE:

**A) Upload the tar.gz** (from the download link your assistant gave you):
```bash
# On YOUR computer:
scp -i farmsky.pem farmsky.tar.gz ec2-user@<PUBLIC_IP>:~/
# Back on the server:
mkdir -p ~/farmsky && tar -xzf ~/farmsky.tar.gz -C ~/farmsky --strip-components=1
cd ~/farmsky
```

**B) Or clone from GitHub** (if you pushed it there):
```bash
git clone https://github.com/<you>/farmsky.git && cd farmsky
```

### Step 5 — Install dependencies & build
```bash
npm install            # compiles better-sqlite3 (takes ~1 min)
npm run build:node     # bundles the server into dist-node/server.js
```

### Step 6 — Configure M-Pesa (and other env vars)
```bash
cp .env.example .env
nano .env              # fill MPESA_* keys (see comments in the file)
```
> Leave the M-Pesa keys blank to run in **simulation mode** first — everything
> works, no real money moves. Add the keys when you're ready for live payments.
> **Where to copy the credentials is fully explained inside `.env.example`.**

### Step 7 — Start the app with PM2 (auto-restarts on crash/reboot)
```bash
pm2 start dist-node/server.js --name farmsky
pm2 startup            # prints a command — copy & run it (sets up boot autostart)
pm2 save
```
Test it locally on the server:
```bash
curl http://localhost:8080            # should return Farmsky HTML
```

### Step 8 — Put it on port 80/443 with HTTPS (Nginx + free certificate)
Right now the app is on port 8080. Let's expose it on the web with HTTPS.

```bash
# Install Nginx
sudo dnf install -y nginx      # (Ubuntu: sudo apt install -y nginx)
sudo systemctl enable --now nginx
```
Create the reverse-proxy config:
```bash
sudo tee /etc/nginx/conf.d/farmsky.conf > /dev/null <<'EOF'
server {
    listen 80;
    server_name YOUR_DOMAIN_OR_IP;
    client_max_body_size 10M;          # allows product image uploads
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
EOF
sudo nginx -t && sudo systemctl reload nginx
```
Now `http://<PUBLIC_IP>` shows Farmsky.

**Add free HTTPS (needs a domain name pointing at the IP):**
```bash
sudo dnf install -y certbot python3-certbot-nginx   # (Ubuntu: sudo apt install -y certbot python3-certbot-nginx)
sudo certbot --nginx -d yourdomain.com
```
Certbot auto-edits Nginx and gives you `https://yourdomain.com`. 🎉

### Step 9 — Point M-Pesa callback at your live URL
In `.env` set:
```
MPESA_CALLBACK_URL=https://yourdomain.com/api/mpesa/callback
```
Then restart: `pm2 restart farmsky`.

### Step 10 — Updating the app later
```bash
cd ~/farmsky
git pull            # or re-upload the tar.gz
npm install
npm run build:node
pm2 restart farmsky
```

---

## PART 2 — (Alternative) AWS App Runner — no servers to manage

If you prefer not to manage a VM, use **App Runner** with the included `Dockerfile`.

1. Push the code to a GitHub repo (or to AWS ECR as a container image).
2. AWS Console → **App Runner** → **Create service**.
3. Source: your GitHub repo (or ECR image).
4. Build settings: it auto-detects the `Dockerfile`.
5. Port: **8080**.
6. Add environment variables (the `MPESA_*` ones) under *Configure service → Environment variables*.
7. Create & deploy. App Runner gives you an HTTPS URL automatically.

> Note: App Runner instances have ephemeral disk. The SQLite file resets on
> redeploy. That's fine for a demo. For persistent production data on AWS,
> migrate to **Amazon RDS (PostgreSQL)** or **EFS** — ask and I can wire that up.

---

## PART 3 — (Easiest & free) Deploy to Cloudflare Pages

This uses the original Cloudflare build — no AWS account needed.

```bash
# One-time: create the production D1 database
npx wrangler d1 create webapp-production
# Copy the printed database_id into wrangler.jsonc

# Apply schema + deploy
npm run build
npx wrangler d1 migrations apply webapp-production       # remote DB
npm run deploy                                           # publishes to *.pages.dev
```
Set M-Pesa secrets (never commit them):
```bash
npx wrangler pages secret put MPESA_CONSUMER_KEY --project-name webapp
npx wrangler pages secret put MPESA_CONSUMER_SECRET --project-name webapp
npx wrangler pages secret put MPESA_SHORTCODE --project-name webapp
npx wrangler pages secret put MPESA_PASSKEY --project-name webapp
npx wrangler pages secret put MPESA_CALLBACK_URL --project-name webapp
```
Your app is live at `https://webapp.pages.dev` on the free tier.

---

## Test credentials (all builds)

| Role | Phone | Password |
|------|-------|----------|
| Admin (Super Admin) | `+2547500000` | `1224` |
| Agent | `+2547400000` | `1225` |
| Customer / Farmer | `+2547300000` | `1226` |
| Customer Support | `+2547200000` | `1227` |

---

## How M-Pesa STK Push works in Farmsky (so you can demo it)

1. A logged-in customer opens a credit contract and taps **Pay** → enters phone + amount.
2. Backend calls Daraja **STK Push** (`POST /api/mpesa/stkpush`). The customer's
   phone gets a "Enter M-Pesa PIN" prompt.
3. Frontend then **polls** `POST /api/mpesa/confirm` to apply the payment once it
   succeeds (updates `amount_paid` / `outstanding` and stores the M-Pesa receipt).
4. Safaricom also calls your public `POST /api/mpesa/callback` URL with the result.
5. **No keys set?** The app simulates all of this so the demo still works end-to-end.

Everything Sharia-compliant: fixed markup, **no interest, no penalties, no compounding.**
