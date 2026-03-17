#!/usr/bin/env node

const os = require('os');
const fs = require('fs');
const path = require('path');
const https = require('https');
const { spawn } = require('child_process');

const platformMap = {
  darwin: 'darwin',
  linux: 'linux',
  win32: 'windows',
};

const archMap = {
  x64: 'amd64',
  arm64: 'arm64',
};

const sysPlatform = os.platform();
const sysArch = os.arch();

const goos = platformMap[sysPlatform];
const goarch = archMap[sysArch];

if (!goos || !goarch) {
  console.error(`Unsupported platform/architecture: ${sysPlatform}/${sysArch}`);
  process.exit(1);
}

const suffix = goos === 'windows' ? '.exe' : '';
const binName = `tooltrust-mcp_${goos}_${goarch}${suffix}`;
const downloadUrl = `https://github.com/AgentSafe-AI/tooltrust-scanner/releases/latest/download/${binName}`;

const cacheDir = path.join(os.homedir(), '.tooltrust-mcp', 'bin');
const binPath = path.join(cacheDir, binName);

function downloadFile(url, dest) {
  return new Promise((resolve, reject) => {
    https.get(url, (res) => {
      if (res.statusCode === 301 || res.statusCode === 302) {
        return downloadFile(res.headers.location, dest).then(resolve).catch(reject);
      }
      if (res.statusCode !== 200) {
        return reject(new Error(`Failed to download, status code: ${res.statusCode}`));
      }
      
      const file = fs.createWriteStream(dest);
      res.pipe(file);
      file.on('finish', () => {
        file.close();
        fs.chmodSync(dest, 0o755);
        resolve();
      });
      file.on('error', (err) => {
        fs.unlink(dest, () => reject(err));
      });
    }).on('error', (err) => {
      fs.unlink(dest, () => reject(err));
    });
  });
}

function runBinary(args) {
  const child = spawn(binPath, args, { stdio: 'inherit' });
  child.on('error', (err) => {
    console.error(`Failed to start subprocess: ${err}`);
  });
  child.on('exit', (code) => {
    process.exit(code || 0);
  });
}

async function main() {
  const args = process.argv.slice(2);
  if (args.includes('--help') || args.includes('-h')) {
    console.log('Usage: tooltrust-mcp [options]\n');
    console.log('Starts the ToolTrust Scanner as an MCP stdio server.\n');
    console.log('Options:');
    console.log('  -h, --help    Show this help message\n');
    console.log('The server communicates over stdin/stdout using the MCP protocol.');
    console.log('Configure it in your MCP client (e.g. Claude Desktop) as:\n');
    console.log('  {"command": "npx", "args": ["-y", "@agentsafe/tooltrust-mcp"]}');
    process.exit(0);
  }

  if (!fs.existsSync(binPath)) {
    console.error(`Downloading ToolTrust MCP binary for ${sysPlatform}-${sysArch}...`);
    fs.mkdirSync(cacheDir, { recursive: true });
    try {
      await downloadFile(downloadUrl, binPath);
    } catch (e) {
      console.error(`Error downloading binary: ${e.message}`);
      console.error("Failed to download binary. If you are behind a proxy, try setting NODE_TLS_REJECT_UNAUTHORIZED=0 or download the binary manually from GitHub Releases.");
      process.exit(1);
    }
  }
  
  runBinary(args);
}

main();
