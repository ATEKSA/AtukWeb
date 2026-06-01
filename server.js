const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const zlib = require('zlib');
const multer = require('multer');

const app = express();
const PORT = process.env.PORT || 3000;
const DB_PATH = path.join(__dirname, 'database.json');

// Configure multer storage for in-memory file upload processing
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 50 * 1024 * 1024 } // 50MB max payload
});

app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// Helper to read database
function readDb() {
  try {
    if (!fs.existsSync(DB_PATH)) {
      return { packages: {} };
    }
    const raw = fs.readFileSync(DB_PATH, 'utf8');
    return JSON.parse(raw);
  } catch (err) {
    console.error('Error reading database file:', err);
    return { packages: {} };
  }
}

// Helper to write database
function writeDb(data) {
  try {
    fs.writeFileSync(DB_PATH, JSON.stringify(data, null, 2), 'utf8');
  } catch (err) {
    console.error('Error writing database file:', err);
  }
}

// --- API ENDPOINTS ---

// Check for updates
app.post('/api/check', (req, res) => {
  const { hwid } = req.body;
  if (!hwid) {
    return res.status(400).json({ error: 'hwid is required' });
  }

  const cleanHwid = hwid.replace(/-/g, '').trim().toUpperCase();
  const db = readDb();
  const pkg = db.packages[cleanHwid];

  if (pkg) {
    return res.json({
      updateAvailable: true,
      gameName: pkg.gameName,
      version: pkg.version
    });
  }

  return res.json({
    updateAvailable: false,
    gameName: '',
    version: ''
  });
});

// Download payload
app.post('/api/download', (req, res) => {
  const { hwid } = req.body;
  if (!hwid) {
    return res.status(400).json({ error: 'hwid is required' });
  }

  const cleanHwid = hwid.replace(/-/g, '').trim().toUpperCase();
  const db = readDb();
  const pkg = db.packages[cleanHwid];

  if (pkg) {
    return res.json({
      success: true,
      payload: pkg.payload
    });
  }

  return res.status(404).json({
    success: false,
    error: 'No package found for this HWID'
  });
});

// Helper: Secure Envelope Encryption matching C# client keys
function encryptEnvelope(plainText) {
  try {
    const key = crypto.createHash('sha256').update('AtukEnvelopeKey2026').digest();
    const iv = crypto.createHash('md5').update('AtukEnvelopeIV2026').digest();
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    let encrypted = cipher.update(plainText, 'utf8', 'base64');
    encrypted += cipher.final('base64');
    return encrypted;
  } catch (err) {
    console.error('Envelope Encryption Error:', err);
    return '';
  }
}

// Helper: Compress string content using Gzip into base64 for safe client storage
function compressGzipToBase64(buffer) {
  try {
    const compressed = zlib.gzipSync(buffer);
    return compressed.toString('base64');
  } catch (err) {
    console.error('Gzip Compression Error:', err);
    return '';
  }
}

// Direct Web Upload / API Upload
app.post('/api/upload', (req, res) => {
  const { hwid, gameName, version, payload } = req.body;
  if (!hwid || !gameName || !version || !payload) {
    return res.status(400).json({ error: 'All fields (hwid, gameName, version, payload) are required' });
  }

  const cleanHwid = hwid.replace(/-/g, '').trim().toUpperCase();
  const db = readDb();
  
  db.packages[cleanHwid] = {
    hwid: cleanHwid,
    gameName,
    version,
    payload,
    uploadedAt: new Date().toISOString()
  };

  writeDb(db);
  return res.json({ success: true, message: 'Package uploaded successfully!' });
});

// Endpoint: Dynamic direct packaging from raw LUA and multiple Manifest uploads
app.post('/api/upload-raw', upload.fields([
  { name: 'luaFile', maxCount: 1 },
  { name: 'manifestFiles', maxCount: 10 }
]), (req, res) => {
  try {
    const { hwid, gameName, version, appId } = req.body;
    if (!hwid || !gameName || !version || !appId) {
      return res.status(400).json({ error: 'Client HWID, Game Name, Version, and Steam AppID are all required.' });
    }

    const cleanHwid = hwid.replace(/-/g, '').trim().toUpperCase();

    // 1. Pack and compress LUA
    let luaPart = '';
    if (req.files && req.files.luaFile && req.files.luaFile.length > 0) {
      const file = req.files.luaFile[0];
      const compressedBase64 = compressGzipToBase64(file.buffer);
      const tag = `---LUA_START:${file.originalname}---`;
      luaPart = `${tag}\n${compressedBase64}\n---LUA_END---`;
    }

    // 2. Pack and compress manifests
    let manifestsPart = '';
    if (req.files && req.files.manifestFiles && req.files.manifestFiles.length > 0) {
      req.files.manifestFiles.forEach(file => {
        const compressedBase64 = compressGzipToBase64(file.buffer);
        manifestsPart += `---MANIFEST_START:${file.originalname}---\n${compressedBase64}\n---MANIFEST_END---\n`;
      });
    }

    // 3. Assemble compile block
    const assembledText = `APPID=${appId}\n${luaPart}\n${manifestsPart}`;

    // 4. Encrypt using custom envelope AES cipher
    const encryptedBlock = encryptEnvelope(assembledText);
    if (!encryptedBlock) {
      return res.status(500).json({ error: 'Failed to encrypt the package envelope.' });
    }

    // 5. Store payload mapping to target HWID
    const db = readDb();
    db.packages[cleanHwid] = {
      hwid: cleanHwid,
      gameName,
      version,
      payload: encryptedBlock,
      uploadedAt: new Date().toISOString()
    };
    writeDb(db);

    return res.json({ success: true, message: 'Package compiled and deployed to client successfully!' });
  } catch (err) {
    console.error('Raw compile and upload error:', err);
    return res.status(500).json({ error: 'Internal server error while compiling package: ' + err.message });
  }
});

// Direct Web Delete
app.delete('/api/packages/:hwid', (req, res) => {
  const { hwid } = req.params;
  const cleanHwid = hwid.replace(/-/g, '').trim().toUpperCase();
  const db = readDb();

  if (db.packages[cleanHwid]) {
    delete db.packages[cleanHwid];
    writeDb(db);
    return res.json({ success: true, message: 'Package deleted successfully!' });
  }

  return res.status(404).json({ success: false, error: 'Package not found' });
});


// --- ADMIN WEB INTERFACE DASHBOARD (Cyberpunk Theme) ---
app.get('/', (req, res) => {
  const db = readDb();
  const packagesList = Object.values(db.packages);

  let tableRows = '';
  if (packagesList.length === 0) {
    tableRows = `<tr><td colspan="5" class="empty-state">No active game packages configured. Upload a package below to get started!</td></tr>`;
  } else {
    packagesList.forEach((pkg, index) => {
      // Format HWID as XXXX-XXXX-XXXX-XXXX
      let formattedHwid = pkg.hwid;
      if (pkg.hwid.length === 16) {
        formattedHwid = `${pkg.hwid.substring(0,4)}-${pkg.hwid.substring(4,8)}-${pkg.hwid.substring(8,12)}-${pkg.hwid.substring(12,16)}`;
      }
      
      tableRows += `
        <tr>
          <td>${index + 1}</td>
          <td class="hwid-cell">${formattedHwid}</td>
          <td class="game-cell">${pkg.gameName}</td>
          <td><span class="badge-version">v${pkg.version}</span></td>
          <td>
            <button class="delete-btn" onclick="deletePackage('${pkg.hwid}')">🗑 Delete</button>
          </td>
        </tr>
      `;
    });
  }

  const html = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>AtukTools Cloud — Distribution Portal</title>
  <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;800&family=JetBrains+Mono:wght@400;700&display=swap" rel="stylesheet">
  <style>
    :root {
      --accent: #10b981;
      --accent-glow: rgba(16, 185, 129, 0.4);
      --bg: #07070c;
      --card-bg: #14141c;
      --border: #22222e;
      --text: #e2e8f0;
      --text-muted: #64748b;
    }

    * {
      box-sizing: border-box;
      margin: 0;
      padding: 0;
    }

    body {
      background-color: var(--bg);
      color: var(--text);
      font-family: 'Outfit', sans-serif;
      line-height: 1.5;
      padding: 40px 20px;
    }

    .container {
      max-width: 1000px;
      margin: 0 auto;
    }

    header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 40px;
      border-bottom: 1px solid var(--border);
      padding-bottom: 20px;
    }

    .logo-container h1 {
      font-size: 24px;
      font-weight: 800;
      letter-spacing: 1px;
      color: #fff;
    }

    .logo-container h1 span {
      color: var(--accent);
      text-shadow: 0 0 10px var(--accent-glow);
    }

    .logo-container p {
      font-size: 13px;
      color: var(--text-muted);
      margin-top: 4px;
    }

    .api-status {
      display: flex;
      align-items: center;
      background: rgba(16, 185, 129, 0.1);
      border: 1px solid rgba(16, 185, 129, 0.3);
      padding: 8px 16px;
      border-radius: 20px;
      font-size: 13px;
      font-weight: 600;
      color: var(--accent);
    }

    .status-dot {
      width: 8px;
      height: 8px;
      background: var(--accent);
      border-radius: 50%;
      margin-right: 8px;
      box-shadow: 0 0 8px var(--accent);
      animation: pulse 1.5s infinite;
    }

    @keyframes pulse {
      0% { opacity: 0.5; }
      50% { opacity: 1; }
      100% { opacity: 0.5; }
    }

    .grid {
      display: grid;
      grid-template-columns: 1fr;
      gap: 30px;
    }

    @media (min-width: 768px) {
      .grid {
        grid-template-columns: 3fr 2fr;
      }
    }

    .card {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 24px;
      box-shadow: 0 4px 20px rgba(0, 0, 0, 0.5);
    }

    .card-title {
      font-size: 16px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      margin-bottom: 20px;
      color: #fff;
      display: flex;
      align-items: center;
      justify-content: space-between;
    }

    .card-title::after {
      content: '';
      flex: 1;
      height: 1px;
      background: var(--border);
      margin-left: 15px;
    }

    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 14px;
    }

    th {
      text-align: left;
      color: var(--text-muted);
      font-weight: 600;
      padding: 12px 8px;
      border-bottom: 1px solid var(--border);
    }

    td {
      padding: 16px 8px;
      border-bottom: 1px solid rgba(34, 34, 46, 0.5);
      vertical-align: middle;
    }

    .hwid-cell {
      font-family: 'JetBrains Mono', monospace;
      font-weight: 700;
      color: var(--accent);
    }

    .game-cell {
      font-weight: 600;
      color: #fff;
    }

    .badge-version {
      background: rgba(255, 255, 255, 0.05);
      border: 1px solid rgba(255, 255, 255, 0.1);
      padding: 3px 8px;
      border-radius: 4px;
      font-size: 12px;
      font-family: 'JetBrains Mono', monospace;
    }

    .empty-state {
      text-align: center;
      color: var(--text-muted);
      padding: 40px 0;
      font-style: italic;
    }

    .form-group {
      margin-bottom: 16px;
    }

    label {
      display: block;
      font-size: 12px;
      font-weight: 600;
      text-transform: uppercase;
      color: var(--text-muted);
      margin-bottom: 6px;
    }

    input, textarea {
      width: 100%;
      background: #0a0a0f;
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 10px 12px;
      color: #fff;
      font-family: inherit;
      font-size: 14px;
      transition: all 0.2s;
    }

    input:focus, textarea:focus {
      outline: none;
      border-color: var(--accent);
      box-shadow: 0 0 8px rgba(16, 185, 129, 0.2);
    }

    textarea {
      resize: vertical;
      font-family: 'JetBrains Mono', monospace;
      font-size: 12px;
    }

    button {
      cursor: pointer;
      font-family: inherit;
      font-weight: 600;
      border-radius: 6px;
      transition: all 0.2s;
    }

    .submit-btn {
      width: 100%;
      background: var(--accent);
      color: #07070c;
      border: none;
      padding: 12px;
      font-size: 14px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      box-shadow: 0 4px 12px var(--accent-glow);
    }

    .submit-btn:hover {
      background: #059669;
      box-shadow: 0 6px 16px var(--accent-glow);
    }

    .delete-btn {
      background: rgba(239, 68, 68, 0.1);
      color: #ef4444;
      border: 1px solid rgba(239, 68, 68, 0.2);
      padding: 6px 12px;
      font-size: 12px;
    }

    .delete-btn:hover {
      background: rgba(239, 68, 68, 0.2);
      border-color: #ef4444;
    }

    .toast {
      position: fixed;
      bottom: 20px;
      right: 20px;
      background: #10b981;
      color: #000;
      padding: 12px 24px;
      border-radius: 6px;
      font-weight: 600;
      box-shadow: 0 4px 12px rgba(0,0,0,0.3);
      transform: translateY(100px);
      opacity: 0;
      transition: all 0.3s cubic-bezier(0.175, 0.885, 0.32, 1.275);
    }

    .toast.show {
      transform: translateY(0);
      opacity: 1;
    }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div class="logo-container">
        <h1>ATUKTOOLS<span>.CLOUD</span></h1>
        <p>Dynamic HWID Game Files Patching & Distribution Backend</p>
      </div>
      <div class="api-status">
        <div class="status-dot"></div>
        ACTIVE PORTAL
      </div>
    </header>

    <div class="grid">
      <!-- Active Packages Card -->
      <div class="card">
        <div class="card-title">Cloud Packages Distribution</div>
        <div style="overflow-x: auto;">
          <table>
            <thead>
              <tr>
                <th style="width: 50px;">#</th>
                <th>Client HWID</th>
                <th>Target Game Name</th>
                <th>Package Version</th>
                <th style="width: 100px;">Actions</th>
              </tr>
            </thead>
            <tbody>
              ${tableRows}
            </tbody>
          </table>
        </div>
      </div>

      <!-- Upload Package Card -->
      <div class="card">
        <div class="card-title">Assign New Package</div>
        
        <!-- Tab Selectors -->
        <div style="display: flex; gap: 10px; margin-bottom: 20px; border-bottom: 1px solid var(--border); padding-bottom: 12px;">
          <button id="tabRawBtn" class="submit-btn" style="background: var(--accent); color: #000; flex: 1; font-size: 12px; padding: 8px;" onclick="switchTab('raw')">🎮 Raw LUA + Manifests</button>
          <button id="tabEncBtn" class="submit-btn" style="background: rgba(255,255,255,0.05); color: var(--text-muted); border: 1px solid var(--border); flex: 1; font-size: 12px; padding: 8px; box-shadow: none;" onclick="switchTab('enc')">🔒 Pre-Encrypted Payload</button>
        </div>

        <!-- Mode A: RAW FILE COMPILER AND UPLOADER -->
        <form id="uploadRawForm">
          <div class="form-group">
            <label for="rawHwid">Client HWID</label>
            <input type="text" id="rawHwid" placeholder="e.g. ABCD-EF12-3456-7890" required autocomplete="off">
          </div>
          <div class="form-group">
            <label for="rawGameName">Target Game Name</label>
            <input type="text" id="rawGameName" placeholder="e.g. Counter-Strike 2" required autocomplete="off">
          </div>
          <div class="form-group">
            <label for="rawVersion">Package Version</label>
            <input type="text" id="rawVersion" placeholder="e.g. 1.0.0" required autocomplete="off">
          </div>
          <div class="form-group">
            <label for="rawAppId">Steam AppID (e.g. 730)</label>
            <input type="text" id="rawAppId" placeholder="e.g. 730" required autocomplete="off">
          </div>
          <div class="form-group" style="background: rgba(255,255,255,0.02); padding: 12px; border: 1px dashed var(--border); border-radius: 6px;">
            <label for="luaFile" style="color: var(--accent);">Upload LUA Bypass File (.lua)</label>
            <input type="file" id="luaFile" accept=".lua" style="padding: 6px;">
          </div>
          <div class="form-group" style="background: rgba(255,255,255,0.02); padding: 12px; border: 1px dashed var(--border); border-radius: 6px; margin-top: 10px;">
            <label for="manifestFiles" style="color: var(--accent);">Upload Steam Manifest Files (.acf/.manifest)</label>
            <input type="file" id="manifestFiles" accept=".acf,.manifest" multiple style="padding: 6px;">
            <span style="font-size: 11px; color: var(--text-muted);">You can select multiple files at once.</span>
          </div>
          <button type="submit" class="submit-btn" style="margin-top: 15px;">🚀 Compile & Deploy To Client</button>
        </form>

        <!-- Mode B: PRE-ENCRYPTED FILE IMPORT -->
        <form id="uploadForm" style="display: none;">
          <div class="form-group">
            <label for="hwid">Client HWID</label>
            <input type="text" id="hwid" placeholder="e.g. ABCD-EF12-3456-7890" required autocomplete="off">
          </div>
          <div class="form-group">
            <label for="gameName">Target Game Name</label>
            <input type="text" id="gameName" placeholder="e.g. Counter-Strike 2" required autocomplete="off">
          </div>
          <div class="form-group">
            <label for="version">Package Version</label>
            <input type="text" id="version" placeholder="e.g. 1.0.0" required autocomplete="off">
          </div>
          <div class="form-group">
            <label for="payloadFile">Upload Encrypted Package File (.txt)</label>
            <input type="file" id="payloadFile" accept=".txt" style="padding: 6px;">
          </div>
          <div class="form-group">
            <label for="payload">Or Paste Encrypted Payload Block</label>
            <textarea id="payload" rows="4" placeholder="Or paste raw text payload here..."></textarea>
          </div>
          <button type="submit" class="submit-btn">🚀 Import & Deploy To Client</button>
        </form>
      </div>
    </div>
  </div>

  <div id="toast" class="toast">Action completed!</div>

  <script>
    let activeTab = 'raw';

    function switchTab(tab) {
      activeTab = tab;
      const tabRawBtn = document.getElementById('tabRawBtn');
      const tabEncBtn = document.getElementById('tabEncBtn');
      const rawForm = document.getElementById('uploadRawForm');
      const encForm = document.getElementById('uploadForm');

      if (tab === 'raw') {
        tabRawBtn.style.background = 'var(--accent)';
        tabRawBtn.style.color = '#000';
        tabRawBtn.style.border = 'none';

        tabEncBtn.style.background = 'rgba(255,255,255,0.05)';
        tabEncBtn.style.color = 'var(--text-muted)';
        tabEncBtn.style.border = '1px solid var(--border)';

        rawForm.style.display = 'block';
        encForm.style.display = 'none';
      } else {
        tabEncBtn.style.background = 'var(--accent)';
        tabEncBtn.style.color = '#000';
        tabEncBtn.style.border = 'none';

        tabRawBtn.style.background = 'rgba(255,255,255,0.05)';
        tabRawBtn.style.color = 'var(--text-muted)';
        tabRawBtn.style.border = '1px solid var(--border)';

        encForm.style.display = 'block';
        rawForm.style.display = 'none';
      }
    }

    function showToast(message, isError = false) {
      const toast = document.getElementById('toast');
      toast.innerText = message;
      toast.style.background = isError ? '#ef4444' : '#10b981';
      toast.style.color = isError ? '#fff' : '#000';
      toast.classList.add('show');
      setTimeout(() => {
        toast.classList.remove('show');
      }, 3000);
    }

    // Auto-detect HWID from selected text payload file
    document.getElementById('payloadFile').addEventListener('change', function(e) {
      if (e.target.files.length > 0) {
        const file = e.target.files[0];
        const reader = new FileReader();
        reader.onload = function(evt) {
          const content = evt.target.result;
          const hwidMatch = content.match(/\[HWID:([A-F0-9\-]+)\]/i);
          if (hwidMatch && hwidMatch[1]) {
            const detectedHwid = hwidMatch[1].trim();
            document.getElementById('hwid').value = detectedHwid;
            showToast('Auto-detected HWID: ' + detectedHwid);
          }
        };
        reader.readAsText(file);
      }
    });

    document.getElementById('uploadForm').addEventListener('submit', async (e) => {
      e.preventDefault();
      const hwid = document.getElementById('hwid').value.trim();
      const gameName = document.getElementById('gameName').value.trim();
      const version = document.getElementById('version').value.trim();
      
      const fileInput = document.getElementById('payloadFile');
      const textPayload = document.getElementById('payload').value.trim();

      if (fileInput.files.length > 0) {
        const file = fileInput.files[0];
        const reader = new FileReader();
        reader.onload = async function(evt) {
          const payloadContent = evt.target.result.trim();
          await sendPackage(hwid, gameName, version, payloadContent);
        };
        reader.readAsText(file);
      } else if (textPayload) {
        await sendPackage(hwid, gameName, version, textPayload);
      } else {
        showToast('Please upload a package file or paste the payload text!', true);
      }
    });

    async function sendPackage(hwid, gameName, version, payload) {
      try {
        const response = await fetch('/api/upload', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ hwid, gameName, version, payload })
        });
        
        const result = await response.json();
        if (response.ok) {
          showToast('Package successfully deployed!');
          setTimeout(() => {
            window.location.reload();
          }, 1000);
        } else {
          showToast(result.error || 'Failed to upload package.', true);
        }
      } catch (err) {
        showToast('Network error occurred.', true);
      }
    }

    // Submit handler for Mode A: Raw LUA and Manifest files
    document.getElementById('uploadRawForm').addEventListener('submit', async (e) => {
      e.preventDefault();
      
      const hwid = document.getElementById('rawHwid').value.trim();
      const gameName = document.getElementById('rawGameName').value.trim();
      const version = document.getElementById('rawVersion').value.trim();
      const appId = document.getElementById('rawAppId').value.trim();
      
      const luaInput = document.getElementById('luaFile');
      const manifestInput = document.getElementById('manifestFiles');
      
      const formData = new FormData();
      formData.append('hwid', hwid);
      formData.append('gameName', gameName);
      formData.append('version', version);
      formData.append('appId', appId);
      
      if (luaInput.files.length > 0) {
        formData.append('luaFile', luaInput.files[0]);
      }
      
      if (manifestInput.files.length > 0) {
        for (let i = 0; i < manifestInput.files.length; i++) {
          formData.append('manifestFiles', manifestInput.files[i]);
        }
      }
      
      try {
        showToast('Compiling and encrypting package...');
        const response = await fetch('/api/upload-raw', {
          method: 'POST',
          body: formData
        });
        
        const result = await response.json();
        if (response.ok) {
          showToast('Package compiled and successfully deployed!');
          setTimeout(() => {
            window.location.reload();
          }, 1200);
        } else {
          showToast(result.error || 'Compilation or deployment failed.', true);
        }
      } catch (err) {
        showToast('Network error occurred during raw file compilation.', true);
      }
    });

    async function deletePackage(hwid) {
      if (!confirm('Are you sure you want to delete this game package? The client will no longer be able to download it.')) {
        return;
      }
      try {
        const response = await fetch('/api/packages/' + hwid, {
          method: 'DELETE'
        });
        const result = await response.json();
        if (response.ok) {
          showToast('Package deleted.');
          setTimeout(() => {
            window.location.reload();
          }, 1000);
        } else {
          showToast(result.error || 'Failed to delete package.', true);
        }
      } catch (err) {
        showToast('Network error occurred.', true);
      }
    }
  </script>
</body>
</html>
  `;

  res.send(html);
});

// Start Server
app.listen(PORT, () => {
  console.log(`================================================================`);
  console.log(`🚀 ATUKTOOLS DISTRIBUTION PORTAL IS RUNNING SUCCESSFULLY!`);
  console.log(`👉 Web Portal Admin Dashboard: http://localhost:${PORT}`);
  console.log(`👉 Client Update API Endpoint: http://localhost:${PORT}/api/check`);
  console.log(`================================================================`);
});
