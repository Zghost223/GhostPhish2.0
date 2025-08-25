# GhostPhish - AI-Enabled Phishing Detection & Alert System

## 🛡️ Overview
GhostPhish is an intelligent security solution that combines a Flask-based backend with a browser extension to protect users from phishing threats in real-time. The system leverages AI-driven analysis and the VirusTotal API to detect malicious URLs, suspicious attachments, and potential fraud attempts.

## ✨ Key Features
- 🔍 Real-time URL scanning and monitoring
- 🤖 AI-powered phishing detection algorithm
- 📷 Screenshot analysis with OCR capabilities
- 📎 Email attachment scanning
- 🌐 Firefox browser extension integration
- 📊 Modern dark-themed dashboard

## 🚀 Getting Started

### Prerequisites
- Python 3.8+
- Firefox Browser
- Tesseract OCR
- VirusTotal API key

### Installation

1. **Clone the repository**
```bash
git clone https://github.com/yourusername/ghostphish.git
cd ghostphish
```

2. **Set up virtual environment**
```bash
python -m venv venv
source venv/bin/activate  # On Linux/Mac
```

3. **Install Python dependencies**
```bash
pip install flask pillow pytesseract requests
```

4. **Install Tesseract OCR**
```bash
sudo apt install tesseract-ocr  # On Ubuntu/Debian
```

5. **Create required directories**
```bash
mkdir static uploads
```

6. **Add your logo**
- Place your logo at `static/ghostphish_logo.png`

7. **Configure VirusTotal API**
- Replace `API_KEY` in `import_requests.py` with your VirusTotal API key

### Firefox Extension Setup
1. Open Firefox
2. Navigate to `about:debugging#/runtime/this-firefox`
3. Click "Load Temporary Add-on"
4. Select `manifest.json` from the `extension` folder

## 💻 Usage

### Start the Application
```bash
python import_requests.py
```
Access the dashboard at: http://127.0.0.1:5000

### Features

#### 1. URL Scanning
- Enter any URL in the scan box
- Get instant analysis results
- View AI-based risk assessment

#### 2. Screenshot Analysis
- Upload screenshots containing suspicious content
- OCR extracts and analyzes text/URLs
- Get comprehensive scan results

#### 3. Attachment Scanning
- Upload files for malware/phishing analysis
- Multiple engine scanning via VirusTotal
- Detailed threat assessment

#### 4. Browser Extension
- Automatic URL monitoring
- Real-time threat alerts
- Visual indicators for suspicious links

## 🔧 Project Structure
```
ghostphish/
├── import_requests.py    # Flask backend
├── static/              # Static assets
│   └── ghostphish_logo.png
├── uploads/             # Temporary file storage
├── extension/           # Firefox extension
│   ├── manifest.json
│   ├── background.js
│   ├── content.js
│   └── popup.html
└── README.md
```

## 🔌 API Endpoints

### URL Scanning
```http
POST /api/scan_url
Content-Type: application/json

{
    "url": "https://example.com"
}
```

### Text Analysis
```http
POST /api/scan_text
Content-Type: application/json

{
    "text": "content to analyze"
}
```

## 🛠️ Technology Stack
- **Backend**: Python/Flask
- **Frontend**: HTML5, CSS3, JavaScript
- **API Integration**: VirusTotal
- **OCR Engine**: Tesseract
- **Browser Extension**: Firefox Add-on
- **AI Component**: Custom scoring algorithm

## 🤝 Contributing
1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## 📝 License
This project is licensed under the MIT License.

## 🙏 Acknowledgments
- VirusTotal API for threat detection
- Tesseract OCR for image processing
- Flask framework community

## 📞 Support
For support, please open an issue in the GitHub repository or contact [your-email@example.com]
