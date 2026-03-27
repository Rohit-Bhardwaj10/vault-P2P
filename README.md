# 🏺 Vault P2P

> **Private. Encrypted. Direct.**  
> A high-performance peer-to-peer file sharing protocol and application built for the modern decentralised web.

---

### 🚀 Strategic Pillars

*   **Offline-First Sync** — Seamlessly resume transfers and sync when peers reappear.
*   **Cryptographic ACL** — Permissions enforced by Ed25519 capabilities, not servers.
*   **Content-Defined Chunking** — Rabin fingerprinting for true delta sync and deduplication.
*   **QUIC Native** — Low-latency, multiplexed transport with built-in TLS and NAT hole-punching.

---

### 🛠️ Technology Stack

| Layer | Technology | Purpose |
| :--- | :--- | :--- |
| **Backend** | `Go` | High-concurrency core and networking |
| **Frontend** | `Next.js / TypeScript` | Premium observability dashboard |
| **Transport** | `QUIC / UDP` | Multiplexed P2P communications |
| **Database** | `SQLite / bbolt` | Efficient metadata & sync WAL |
| **Security** | `AES-256-GCM / BLAKE3` | End-to-end encryption & content addressing |

---

### ⚡ Quick Start

```bash
# Install dependencies
npm install

# Run the development environment
npm run dev

# Build the entire monorepo
npm run build
```

---

### 📂 Repository Structure

- `apps/backend` — Go-based P2P core engine.
- `apps/web` — Next.js administrative dashboard.
- `packages/ui` — Shared component library.
- `packages/typescript-config` — Standardised TS configurations.

---

<p align="center">
  <i>Part of the Vault P2P Initiative • 2025</i>
</p>
