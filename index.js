#!/usr/bin/env node


'use strict';

const fs       = require('fs');
const path     = require('path');
const os       = require('os');
const koffi    = require('koffi');
const sqlite3  = require('better-sqlite3');

const VERSION = '1.2.0';
let verbosity = 0;

const EXIT = {
  CLEAN: 0, ERROR: 1, MISSING_PROFILEINI: 2, MISSING_SECRETS: 3,
  BAD_PROFILEINI: 4, LOCATION_NO_DIRECTORY: 5, BAD_SECRETS: 6,
  FAIL_LOCATE_NSS: 10, FAIL_LOAD_NSS: 11, FAIL_INIT_NSS: 12,
  FAIL_NSS_KEYSLOT: 13, FAIL_SHUTDOWN_NSS: 14, BAD_PRIMARY_PASSWORD: 15,
  NEED_PRIMARY_PASSWORD: 16, DECRYPTION_FAILED: 17, READ_GOT_EOF: 30,
  MISSING_CHOICE: 31, NO_SUCH_PROFILE: 32, UNKNOWN_ERROR: 100,
};

const log = {
  debug: (...a) => { if (verbosity >= 2) console.error('[DEBUG]', ...a); },
  info: (...a) => { if (verbosity >= 1) console.error('[INFO]', ...a); },
  warn: (...a) => console.error('[WARN]', ...a),
  error: (...a) => console.error('[ERROR]', ...a),
};

const SECItem = koffi.struct('SECItem', {
  type: 'uint',
  data: 'uint8_t *',
  len: 'uint',
});
const PK11SlotInfo = koffi.opaque('PK11SlotInfo');

function loadNSS() {
  const pf = process.env['ProgramFiles'] || 'C:\\Program Files';
  const pf86 = process.env['ProgramFiles(x86)'] || 'C:\\Program Files (x86)';
  const local = process.env['LOCALAPPDATA'] || path.join(os.homedir(), 'AppData', 'Local');
  const envP = process.env['NSS_LIB_PATH'];

  const browsers = ['Mozilla Firefox', 'Firefox Developer Edition', 'Mozilla Thunderbird', 'Nightly', 'SeaMonkey', 'Waterfox'];
  const dirs = [];
  
  if (envP) dirs.push(envP);
  for (const b of browsers) {
    dirs.push(path.join(pf, b), path.join(pf86, b), path.join(local, b));
  }

  for (const d of (process.env.PATH || '').split(';')) dirs.push(d.trim());

  const candidates = [];
  for (const d of dirs) {
    if (!d) continue;
    const dll = path.join(d, 'nss3.dll');
    if (fs.existsSync(dll)) candidates.push({ dll, dir: d });
  }

  if (!candidates.length) {
    log.error('Could not find nss3.dll in any standard location.');
    log.error('Set NSS_LIB_PATH to the directory containing nss3.dll and try again.');
    process.exit(EXIT.FAIL_LOCATE_NSS);
  }

  for (const { dll, dir } of candidates) {
    log.debug('Trying to load', dll);
    process.env.PATH = dir + ';' + process.env.PATH;
    
    try {
      const lib = koffi.load(dll);
      log.info('Loaded NSS from', dll);
      return {
        NSS_Init: lib.func('int NSS_Init(const char *configdir)'),
        NSS_Shutdown: lib.func('int NSS_Shutdown()'),
        PK11_GetInternalKeySlot: lib.func('PK11SlotInfo *PK11_GetInternalKeySlot()'),
        PK11_FreeSlot: lib.func('void PK11_FreeSlot(PK11SlotInfo *slot)'),
        PK11_NeedLogin: lib.func('int PK11_NeedLogin(PK11SlotInfo *slot)'),
        PK11_CheckUserPassword: lib.func('int PK11_CheckUserPassword(PK11SlotInfo *slot, const char *pw)'),
        PK11SDR_Decrypt: lib.func('int PK11SDR_Decrypt(SECItem *data, SECItem *result, void *cx)'),
        SECITEM_ZfreeItem: lib.func('void SECITEM_ZfreeItem(void *zap, int freeit)'),
        PORT_GetError: lib.func('int PORT_GetError()'),
        PR_ErrorToName: lib.func('const char *PR_ErrorToName(int code)'),
        PR_ErrorToString: lib.func('const char *PR_ErrorToString(int code, uint32_t language)'),
      };
    } catch (e) {
      log.debug('Failed to load', dll, '-', e.message);
    }
  }

  log.error("Couldn't load nss3.dll from any candidate path.");
  process.exit(EXIT.FAIL_LOAD_NSS);
}

// NSSProxy – thin JS wrapper
class NSSProxy {
  constructor(nonFatalDecryption = false) {
    this.nss = loadNSS();
    this.nonFatalDecryption = nonFatalDecryption;
  }

  initialize(profileDir) {
    const profilePath = 'sql:' + profileDir;
    log.debug('NSS_Init with', profilePath);
    const rc = this.nss.NSS_Init(profilePath);
    log.debug('NSS_Init returned', rc);
    if (rc !== 0) {
      const code = this.nss.PORT_GetError();
      const name = this.nss.PR_ErrorToName(code) || 'NULL';
      const text = this.nss.PR_ErrorToString(code, 0) || '';
      throw new Error(`Couldn't initialise NSS for profile: ${profileDir} (${name}: ${text})`);
    }
  }

  shutdown() {
    try {
      const rc = this.nss.NSS_Shutdown();
      if (rc !== 0) log.warn("NSS_Shutdown returned non-zero, but continuing...");
    } catch (e) {
      log.warn("Error during NSS_Shutdown:", e.message);
    }
  }

  needsLogin() {
    const slot = this.nss.PK11_GetInternalKeySlot();
    if (!slot) throw new Error('Failed to get internal key slot');
    try {
      return this.nss.PK11_NeedLogin(slot) !== 0;
    } finally {
      this.nss.PK11_FreeSlot(slot);
    }
  }

  decrypt(data64) {
    const raw = Buffer.from(data64, 'base64');
    const inpObj = { type: 0, data: raw, len: raw.length };
    const outBuf = Buffer.alloc(koffi.sizeof(SECItem));
    const rc = this.nss.PK11SDR_Decrypt(inpObj, outBuf, null);
    log.debug('PK11SDR_Decrypt returned', rc);

    try {
      if (rc !== 0) {
        const msg = 'Decryption failed – damaged entry or cert/key mismatch.';
        if (this.nonFatalDecryption) throw new Error(msg);
        const code = this.nss.PORT_GetError();
        const name = this.nss.PR_ErrorToName(code) || 'NULL';
        const text = this.nss.PR_ErrorToString(code, 0) || '';
        log.error(msg);
        log.debug(`NSS error ${code}: ${name} – ${text}`);
        process.exit(EXIT.DECRYPTION_FAILED);
      }

      const outItem = koffi.decode(outBuf, SECItem);
      log.debug('outItem.len:', outItem.len, 'outItem.data:', outItem.data);
      if (!outItem.data || outItem.len === 0) return '';
      return koffi.decode(outItem.data, 'char', outItem.len);
    } finally {
      this.nss.SECITEM_ZfreeItem(outBuf, 0);
    }
  }
}

// Find all Firefox profiles and read credentials
function findAllFirefoxProfiles() {
  const appData = process.env.APPDATA || path.join(os.homedir(), 'AppData', 'Roaming');
  const browsers = ['Mozilla\\Firefox'];
  const allProfiles = [];

  for (const browser of browsers) {
    const basePath = path.join(appData, browser);
    if (!fs.existsSync(basePath)) continue;

    const iniPath = path.join(basePath, 'profiles.ini');
    if (!fs.existsSync(iniPath)) {
      log.warn('profiles.ini not found at', iniPath);
      continue;
    }

    log.debug('Reading', iniPath);
    const iniText = fs.readFileSync(iniPath, 'utf8');
    const sections = {};
    let current = null;
    
    for (const line of iniText.split(/\r?\n/)) {
      const sm = line.match(/^\[(.+)\]$/);
      if (sm) { current = sm[1]; sections[current] = {}; continue; }
      const kv = line.match(/^([^=]+)=(.*)$/);
      if (kv && current) sections[current][kv[1].trim()] = kv[2].trim();
    }

    let i = 1;
    for (const [sec, vals] of Object.entries(sections)) {
      if (!sec.startsWith('Profile')) continue;
      const profilePath = vals.Path;
      if (!profilePath) continue;

      const fullPath = path.isAbsolute(profilePath) ? profilePath : path.join(basePath, profilePath);
      if (fs.existsSync(fullPath) && fs.statSync(fullPath).isDirectory()) {
        allProfiles.push({
          name: path.basename(fullPath),
          path: fullPath,
          browser: browser.replace(/\\/g, '-').toLowerCase(),
        });
      }
    }
  }

  return allProfiles;
}

// Get credentials from logins.json or signons.sqlite
function obtainCredentials(profileDir) {
  const jsonPath = path.join(profileDir, 'logins.json');
  const sqlitePath = path.join(profileDir, 'signons.sqlite');

  if (fs.existsSync(jsonPath)) {
    log.debug('Reading credentials from logins.json');
    const data = JSON.parse(fs.readFileSync(jsonPath, 'utf8'));
    if (!data.logins) {
      log.error('Unrecognized format in logins.json');
      process.exit(EXIT.BAD_SECRETS);
    }
    return data.logins.filter(login => 
      login.hostname != null && login.encryptedUsername != null && login.encryptedPassword != null
    ).map(login => ({
      url: login.hostname,
      encUser: login.encryptedUsername,
      encPass: login.encryptedPassword,
      encType: login.encType
    }));
  }

  if (fs.existsSync(sqlitePath)) {
    log.debug('Reading credentials from signons.sqlite');
    const conn = new sqlite3(sqlitePath, { readonly: true });
    try {
      return conn.prepare('SELECT hostname, encryptedUsername, encryptedPassword, encType FROM moz_logins').all()
        .map(row => ({
          url: row.hostname,
          encUser: row.encryptedUsername,
          encPass: row.encryptedPassword,
          encType: row.encType
        }));
    } finally {
      conn.close();
    }
  }

  log.error("Couldn't find logins.json or signons.sqlite in:", profileDir);
  process.exit(EXIT.MISSING_SECRETS);
}

// Decrypt all passwords for a profile
function decryptPasswords(proxy, profileDir) {
  const outputs = [];
  for (const { url, encUser, encPass, encType } of obtainCredentials(profileDir)) {
    let user = encUser, passw = encPass;
    if (encType) {
      try {
        user = proxy.decrypt(encUser);
        passw = proxy.decrypt(encPass);
      } catch (e) {
        log.warn('Failed to decrypt entry for', url, '-', e.message);
        user = '*** decryption failed ***';
        passw = '*** decryption failed ***';
      }
    }
    log.debug(`Decoded: ${url}  user=${user}`);
    outputs.push({ url, user, password: passw });
  }
  return outputs;
}

// Safe append to file with race condition prevention
function safeAppendToFile(filePath, content) {
  const maxRetries = 10;
  const retryDelay = 50;
  
  for (let i = 0; i < maxRetries; i++) {
    try {
      // Use 'a' flag for append mode, creates file if doesn't exist
      fs.appendFileSync(filePath, content, { flag: 'a', encoding: 'utf8' });
      return;
    } catch (err) {
      if (err.code === 'EBUSY' || err.code === 'EPERM' || err.code === 'EACCES') {
        if (i === maxRetries - 1) {
          log.error(`Failed to append to ${filePath} after ${maxRetries} retries: ${err.message}`);
          throw err;
        }
        // Wait before retry with exponential backoff
        const delay = retryDelay * (i + 1);
        const start = Date.now();
        while (Date.now() - start < delay) { /* busy wait */ }
      } else {
        throw err;
      }
    }
  }
}

// Parse command line arguments
function parseArgs() {
  const args = process.argv.slice(2);
  const options = {
    outputPath: null,
    profiles: [],
    listProfiles: false,
    format: 'txt',
    verbose: 0,
    help: false,
    version: false,
  };

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    
    switch (arg) {
      case '-h':
      case '--help':
        options.help = true;
        break;
      
      case '-v':
      case '--version':
        options.version = true;
        break;
      
      case '-o':
      case '--output':
        if (i + 1 < args.length) {
          options.outputPath = args[++i];
        } else {
          log.error('--output requires a path argument');
          process.exit(EXIT.ERROR);
        }
        break;
      
      case '-p':
      case '--profile':
        if (i + 1 < args.length) {
          options.profiles.push(args[++i]);
        } else {
          log.error('--profile requires a profile name argument');
          process.exit(EXIT.ERROR);
        }
        break;
      
      case '-l':
      case '--list':
        options.listProfiles = true;
        break;
      
      case '-f':
      case '--format':
        if (i + 1 < args.length) {
          const fmt = args[++i].toLowerCase();
          if (['txt', 'json', 'csv'].includes(fmt)) {
            options.format = fmt;
          } else {
            log.error('Format must be one of: txt, json, csv');
            process.exit(EXIT.ERROR);
          }
        } else {
          log.error('--format requires a format argument (txt, json, csv)');
          process.exit(EXIT.ERROR);
        }
        break;
      
      case '--verbose':
        options.verbose = 2;
        break;
      
      case '-q':
      case '--quiet':
        options.verbose = 0;
        break;
      
      default:
        if (arg.startsWith('-')) {
          log.error(`Unknown option: ${arg}`);
          log.error('Use --help for usage information');
          process.exit(EXIT.ERROR);
        }
        break;
    }
  }

  return options;
}

// Display help message
function showHelp() {
  console.log(`
Firefox Password Extractor v${VERSION}

USAGE:
  firefox-decrypt [OPTIONS]

OPTIONS:
  -h, --help              Show this help message
  -v, --version           Show version information
  -o, --output PATH       Output directory for password files
                          (default: %TEMP%\\firefox-passwords)
  -p, --profile NAME      Process only specific profile(s) by name
                          Can be specified multiple times
                          (default: process all profiles)
  -l, --list              List all available Firefox profiles and exit
  -f, --format FORMAT     Output format: txt, json, or csv
                          (default: txt)
  --verbose               Enable detailed debug output
  -q, --quiet             Suppress info messages (errors only)

EXAMPLES:
  # Extract all profiles to default location
  firefox-decrypt

  # List available profiles
  firefox-decrypt --list

  # Extract specific profile only
  firefox-decrypt --profile "default-release"

  # Extract to custom directory
  firefox-decrypt --output "C:\\MyBackups\\passwords"

  # Extract multiple specific profiles
  firefox-decrypt -p "Profile1" -p "Profile2"

  # Export as JSON format
  firefox-decrypt --format json

  # Verbose output for debugging
  firefox-decrypt --verbose

NOTES:
  - Profiles with Primary/Master Password will be skipped
  - Requires NSS3.dll from Firefox installation
  - Only works on Windows systems

LICENSE:
  GPL v3.0 - Based on original work from dumpzilla.org
`);
}

// List all available profiles
function listProfiles() {
  console.log(`\nFirefox Password Extractor v${VERSION}`);
  console.log('Available Firefox Profiles:\n');
  
  const allProfiles = findAllFirefoxProfiles();
  
  if (allProfiles.length === 0) {
    console.log('No Firefox profiles found on this system.');
    return;
  }

  allProfiles.forEach((profile, idx) => {
    console.log(`${idx + 1}. ${profile.name}`);
    console.log(`   Browser: ${profile.browser}`);
    console.log(`   Path: ${profile.path}\n`);
  });
  
  console.log(`Total: ${allProfiles.length} profile(s) found\n`);
}

// Format output based on selected format
function formatOutput(records, format, profileName) {
  switch (format) {
    case 'json':
      return JSON.stringify(records.map(r => ({
        profile: profileName,
        website: r.url,
        username: r.user,
        password: r.password
      })), null, 2);
    
    case 'csv':
      const header = 'Profile,Website,Username,Password\n';
      const rows = records.map(r => 
        `"${profileName}","${r.url}","${r.user}","${r.password}"`
      ).join('\n');
      return header + rows;
    
    case 'txt':
    default:
      return records.map(r => 
        `Website: ${r.url}\nUsername: '${r.user}'\nPassword: '${r.password}'\n`
      ).join('\n');
  }
}

// Main async function
async function main() {
  const options = parseArgs();
  
  if (options.help) {
    showHelp();
    process.exit(EXIT.CLEAN);
  }
  
  if (options.version) {
    console.log(`Firefox Password Extractor v${VERSION}`);
    process.exit(EXIT.CLEAN);
  }
  
  verbosity = options.verbose || 1;
  
  if (options.listProfiles) {
    listProfiles();
    process.exit(EXIT.CLEAN);
  }

  console.log(`\nFirefox Password Extractor v${VERSION}`);
  console.log('Extracting passwords from Firefox profiles...\n');

  const allProfiles = findAllFirefoxProfiles();
  if (allProfiles.length === 0) {
    log.error('No Firefox profiles found.');
    process.exit(EXIT.MISSING_PROFILEINI);
  }

  // Filter profiles if specific ones requested
  let profilesToProcess = allProfiles;
  if (options.profiles.length > 0) {
    profilesToProcess = allProfiles.filter(p => 
      options.profiles.some(requested => 
        p.name.toLowerCase().includes(requested.toLowerCase())
      )
    );
    
    if (profilesToProcess.length === 0) {
      log.error(`No profiles matched the requested names: ${options.profiles.join(', ')}`);
      log.info('Use --list to see available profiles');
      process.exit(EXIT.NO_SUCH_PROFILE);
    }
  }

  log.info(`Found ${allProfiles.length} total profile(s), processing ${profilesToProcess.length}`);

  // Set output directory
  const ComputerUsername = os.userInfo().username;
  const defaultOutput = path.join(process.env['TEMP'], `firefox-passwords-${ComputerUsername}`);
  const outputDir = options.outputPath || defaultOutput;

  // Create output directory
  if (!fs.existsSync(outputDir)) {
    fs.mkdirSync(outputDir, { recursive: true });
  }

  const allPasswordsPath = path.join(outputDir, `all-passwords.${options.format}`);

  for (const profile of profilesToProcess) {
    console.log(`\n${'='.repeat(60)}`);
    log.info(`Processing profile: ${profile.name}`);
    log.info(`Path: ${profile.path}`);

    let proxy = null;
    try {
      proxy = new NSSProxy(true);
      proxy.initialize(profile.path);

      if (proxy.needsLogin()) {
        log.warn(`Profile "${profile.name}" requires a Primary Password. Skipping...`);
        continue;
      }

      const records = decryptPasswords(proxy, profile.path);

      if (records.length === 0) {
        log.warn(`No passwords found in profile "${profile.name}"`);
      } else {
        const cleanProfileName = `${profile.browser}-${profile.name}`.replace(/[^a-zA-Z0-9.\-_]/g, '-');
        const formattedRecords = formatOutput(records, options.format, cleanProfileName);

        // Write to individual profile file
        const individualFilePath = path.join(outputDir, `${cleanProfileName}.${options.format}`);
        fs.writeFileSync(individualFilePath, formattedRecords);
        
        // Append to combined file
        let allPasswordsContent;
        if (options.format === 'txt') {
          allPasswordsContent = `\n${'='.repeat(80)}\nSOURCE: ${cleanProfileName}\n${'='.repeat(80)}\n\n${formattedRecords}\n\n`;
        } else if (options.format === 'json') {
          // For JSON, we need to handle array concatenation
          let existingData = [];
          if (fs.existsSync(allPasswordsPath)) {
            try {
              existingData = JSON.parse(fs.readFileSync(allPasswordsPath, 'utf8'));
            } catch (e) {
              existingData = [];
            }
          }
          const newData = JSON.parse(formattedRecords);
          existingData.push(...newData);
          fs.writeFileSync(allPasswordsPath, JSON.stringify(existingData, null, 2));
        } else {
          // CSV format
          if (!fs.existsSync(allPasswordsPath)) {
            allPasswordsContent = formattedRecords;
          } else {
            // Skip header for subsequent profiles
            allPasswordsContent = formattedRecords.split('\n').slice(1).join('\n');
          }
        }
        
        if (options.format !== 'json') {
          safeAppendToFile(allPasswordsPath, allPasswordsContent);
        }
        
        log.info(`Saved ${records.length} passwords to ${cleanProfileName}.${options.format}`);
      }
    } catch (error) {
      log.error(`Failed to process profile "${profile.name}":`, error.message);
      log.warn('Skipping this profile and continuing...');
    } finally {
      if (proxy) proxy.shutdown();
    }
  }

  console.log(`\n${'='.repeat(60)}`);
  console.log('\n✓ Password extraction complete!');
  console.log(`Output directory: ${outputDir}`);
  console.log(`Combined file: ${allPasswordsPath}\n`);
}

main().catch(error => {
  log.error('Unexpected error:', error);
  process.exit(EXIT.UNKNOWN_ERROR);
});
