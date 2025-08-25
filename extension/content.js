// Monitor DOM changes for new links and attachments
const observer = new MutationObserver(mutations => {
  mutations.forEach(mutation => {
    mutation.addedNodes.forEach(node => {
      // Check for new links
      if (node.tagName === 'A') {
        checkUrl(node.href);
      }
      
      // Check for new attachments
      if (node.tagName === 'INPUT' && node.type === 'file') {
        node.addEventListener('change', checkAttachment);
      }
    });
  });
});

observer.observe(document.body, {
  childList: true,
  subtree: true
});

async function checkUrl(url) {
  try {
    const response = await fetch('http://127.0.0.1:5000/api/scan_url', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ url: url })
    });
    
    const result = await response.json();
    
    if (result.summary && result.summary.includes('Warning')) {
      highlightDangerousUrl(url);
    }
  } catch (error) {
    console.error('Error scanning URL:', error);
  }
}

async function checkAttachment(event) {
  const file = event.target.files[0];
  if (!file) return;
  
  const formData = new FormData();
  formData.append('attachment', file);
  
  try {
    const response = await fetch('http://127.0.0.1:5000/scan_attachment', {
      method: 'POST',
      body: formData
    });
    
    const result = await response.text();
    
    if (result.includes('Warning')) {
      alert(`Warning: Suspicious file detected - ${file.name}`);
    }
  } catch (error) {
    console.error('Error scanning attachment:', error);
  }
}

function highlightDangerousUrl(url) {
  document.querySelectorAll(`a[href="${url}"]`).forEach(link => {
    link.style.border = '2px solid red';
    link.style.padding = '2px';
    link.title = 'Warning: This link may be dangerous!';
  });
}