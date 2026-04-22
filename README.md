# Firefox Password Extractor

A Node.js tool to extract and decrypt saved passwords from Firefox profiles on Windows. This tool automatically locates all Firefox profiles and decrypts stored credentials without requiring manual configuration.

## 🔒 Security Notice

**This tool is designed for legitimate password recovery purposes only.** Use it responsibly:
- Only use on your own computer and Firefox profiles
- Only extract passwords you have permission to access
- Keep extracted password files secure
- Delete extracted files after use

## ✨ Features

- 🔍 **Automatic Profile Detection** - Finds all Firefox profiles automatically
- 🔐 **NSS-based Decryption** - Uses Mozilla's NSS library for secure decryption
- 📁 **Multiple Output Formats** - Export as TXT, JSON, or CSV
- 🎯 **Selective Extraction** - Process all profiles or specific ones
- 💾 **Flexible Output** - Custom output directory support
- 📊 **Multiple Browsers** - Supports Firefox, Firefox Developer Edition, Thunderbird, Waterfox, SeaMonkey, and Nightly

## 📋 Requirements

### System Requirements
- **Operating System**: Windows (Windows 10/11 recommended)
- **Node.js**: Version 16.0.0 or higher
- **Firefox**: Any recent version installed

### Browser Compatibility

| Browser | Supported Versions | Notes |
|---------|-------------------|-------|
| Mozilla Firefox | 60+ | Fully tested |
| Firefox Developer Edition | All versions | Fully tested |
| Mozilla Thunderbird | 60+ | Fully tested |
| Waterfox | All versions | Compatible |
| SeaMonkey | Recent versions | Compatible |
| Firefox Nightly | All versions | Compatible |

### Profile Compatibility

- ✅ **logins.json** - Modern Firefox password storage (Firefox 60+)
- ✅ **signons.sqlite** - Legacy password storage (older Firefox versions)
- ⚠️ **Primary/Master Password** - Profiles with master passwords will be skipped

## 🚀 Installation



### Option 1: Install from source

```bash
# Clone the repository
git clone https://github.com/00nx/firefox-password-extraction.git
cd firefox-password-extraction

# Install dependencies
npm install

```

## 📖 Usage

### Basic Usage

Extract all passwords from all profiles to default location:

```bash
node index.js
```

### List Available Profiles

```bash
node index.js --list
```

### Extract Specific Profile

```bash
node index.js --profile "default-release"
```

### Custom Output Directory

```bash
node index.js --output "C:\MyBackups\passwords"
```

### Export as JSON

```bash
node index.js --format json
```

### Export as CSV

```bash
node index.js --format csv
```

### Multiple Profiles

```bash
node index.js -p "Profile1" -p "Profile2"
```

### Verbose Output (for debugging)

```bash
node index.js --verbose
```

## 🎮 Command Line Options

| Option | Alias | Description | Default |
|--------|-------|-------------|---------|
| `--help` | `-h` | Show help message | - |
| `--version` | `-v` | Show version number | - |
| `--output PATH` | `-o` | Output directory for password files | `%TEMP%\firefox-passwords-{username}` |
| `--profile NAME` | `-p` | Process specific profile(s) only | All profiles |
| `--list` | `-l` | List available profiles and exit | - |
| `--format FORMAT` | `-f` | Output format: txt, json, csv | `txt` |
| `--verbose` | - | Enable detailed debug output | - |
| `--quiet` | `-q` | Suppress info messages | - |

## 📂 Output Structure

### Default Output Location
```
%TEMP%\firefox-passwords-{username}\
├── all-passwords.txt          # Combined passwords from all profiles
├── mozilla-firefox-profile1.txt
├── mozilla-firefox-profile2.txt
└── ...
```

### Text Format (.txt)
```
Website: https://example.com
Username: 'user@example.com'
Password: 'mypassword123'

Website: https://github.com
Username: 'myusername'
Password: 'github_password'
```

### JSON Format (.json)
```json
[
  {
    "profile": "mozilla-firefox-default-release",
    "website": "https://example.com",
    "username": "user@example.com",
    "password": "mypassword123"
  }
]
```

### CSV Format (.csv)
```csv
Profile,Website,Username,Password
"mozilla-firefox-default-release","https://example.com","user@example.com","mypassword123"
```

## 🔧 Technical Details

### How It Works

1. **Profile Discovery**: Scans `%APPDATA%\Mozilla\Firefox\profiles.ini` to find all Firefox profiles
2. **NSS Library Loading**: Locates and loads `nss3.dll` from Firefox installation
3. **Credential Extraction**: Reads encrypted credentials from `logins.json` or `signons.sqlite`
4. **Decryption**: Uses NSS (Network Security Services) to decrypt passwords
5. **Export**: Formats and saves decrypted credentials

### Dependencies

- **[koffi](https://www.npmjs.com/package/koffi)** (v2.15.6+) - FFI library for calling NSS functions
- **[better-sqlite3](https://www.npmjs.com/package/better-sqlite3)** (v9.4.3+) - SQLite database access for legacy profiles

### NSS Library Detection

The tool searches for `nss3.dll` in the following locations (in order):

1. `NSS_LIB_PATH` environment variable
2. `C:\Program Files\Mozilla Firefox`
3. `C:\Program Files (x86)\Mozilla Firefox`
4. `%LOCALAPPDATA%\Mozilla Firefox`
5. Firefox Developer Edition directories
6. Thunderbird directories
7. System PATH directories

## ⚠️ Troubleshooting

### "Could not find nss3.dll"

**Solution**: Ensure Firefox is installed. If using a portable version, set the `NSS_LIB_PATH` environment variable:

```bash
set NSS_LIB_PATH=C:\Path\To\Firefox
firefox-decrypt
```

### "Profile requires Primary Password"

**Solution**: This tool cannot decrypt profiles protected with a Primary/Master Password. You must either:
- Remove the Primary Password from Firefox settings
- Skip that profile (tool does this automatically)

### "No Firefox profiles found"

**Solution**: 
- Verify Firefox is installed and has been run at least once
- Check that `%APPDATA%\Mozilla\Firefox\profiles.ini` exists
- Use `--verbose` flag for detailed debugging

### Permission Errors

**Solution**: Run with administrator privileges if encountering permission issues:
```bash
# Run Command Prompt as Administrator
node index.js
```

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

### Development Setup

```bash
git clone https://github.com/00nx/firefox-password-extraction.git
cd firefox-password-extraction
npm install
```

### Running Tests

```bash
npm test
```


## 📜 License

This project is licensed under the **GNU General Public License v3.0** - see the [LICENSE](LICENSE) file for details.

Based on original work from [dumpzilla.org](http://www.dumpzilla.org/).

## ⚖️ Legal Disclaimer

This software is provided for educational and legitimate password recovery purposes only. Users are solely responsible for ensuring they have proper authorization before extracting passwords. The authors assume no liability for misuse of this tool.

**Use this tool ethically and legally.**

## 🙏 Acknowledgments

- Original Python implementation by [firefox_decrypt](https://github.com/unode/firefox_decrypt)
- Mozilla NSS (Network Security Services)
- The open-source community

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/00nx/firefox-password-extraction/issues)
- **Discussions**: [GitHub Discussions](https://github.com/00nx/firefox-password-extraction/discussions)



**⭐ If this tool helped you, please consider giving it a star on GitHub!**