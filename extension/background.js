// Store scanned URLs to avoid duplicate scans
let scannedUrls = new Set();

// Listen for new URLs being loaded
browser.webRequest.onBeforeRequest.addListener(
  async function(details) {
    const url = details.url;
    
    // Skip if already scanned or is our API
    if (scannedUrls.has(url) || url.includes('127.0.0.1:5000')) {
      return;
    }

    scannedUrls.add(url);

    // Scan URL using our API
    try {
      const response = await fetch('http://127.0.0.1:5000/api/scan_url', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ url: url })
      });
      
      const result = await response.json();
      
      // If malicious/suspicious, show warning
      if (result.summary && result.summary.includes('Warning')) {
        browser.notifications.create({
          type: 'basic',
          iconUrl: 'icons/ghostphish-48.png',
          title: 'GhostPhish Warning',
          message: `Suspicious URL detected: ${url}`
        });
      }
    } catch (error) {
      console.error('Error scanning URL:', error);
    }
  },
  { urls: ["<all_urls>"] }
);

// Listen for downloads (attachments)
browser.downloads.onCreated.addListener(async function(downloadItem) {
  const file = downloadItem.filename;
  
  try {
    // Create form data with file
    const formData = new FormData();
    formData.append('attachment', file);

    // Scan file using our API
    const response = await fetch('http://127.0.0.1:5000/scan_attachment', {
      method: 'POST',
      body: formData
    });
    
    const result = await response.text();
    
    // If malicious/suspicious, show warning
    if (result.includes('Warning')) {
      browser.notifications.create({
        type: 'basic',
        iconUrl: 'icons/ghostphish-48.png',
        title: 'GhostPhish Warning',
        message: `Suspicious file detected: ${file}`
      });
    }
  } catch (error) {
    console.error('Error scanning file:', error);
  }
});