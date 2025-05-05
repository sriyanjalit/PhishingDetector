document.addEventListener('DOMContentLoaded', function() {
    const scanButton = document.getElementById('scanButton');
    const loadingDiv = document.getElementById('loading');
    const resultDiv = document.getElementById('result');
    const statusDiv = document.getElementById('status');
    const riskFactorsUl = document.getElementById('riskFactors');
    const confidenceDiv = document.getElementById('confidence');

    // Function to analyze the current URL
    async function analyzeCurrentUrl() {
        // Get the active tab
        const tabs = await chrome.tabs.query({active: true, currentWindow: true});
        const currentUrl = tabs[0].url;

        // Show loading state
        scanButton.disabled = true;
        loadingDiv.style.display = 'block';
        resultDiv.style.display = 'none';
        
        try {
            // Send request to backend
            const response = await fetch('http://localhost:5000/analyze', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ url: currentUrl })
            });

            if (!response.ok) {
                throw new Error('Server response was not ok');
            }

            const result = await response.json();
            
            // Update UI with results
            updateUI(result);
        } catch (error) {
            // Show error state
            statusDiv.textContent = 'Error analyzing website';
            resultDiv.className = 'result-box error';
            riskFactorsUl.innerHTML = '<li>Failed to connect to analysis server. Please ensure the server is running.</li>';
            confidenceDiv.textContent = '';
        } finally {
            // Hide loading state and show results
            loadingDiv.style.display = 'none';
            resultDiv.style.display = 'block';
            scanButton.disabled = false;
        }
    }

    // Function to update the UI with analysis results
    function updateUI(result) {
        // Clear previous results
        riskFactorsUl.innerHTML = '';
        
        // Update result box class and status message
        if (result.confidence < 0.3) {
            resultDiv.className = 'result-box safe';
            resultDiv.style.backgroundColor = '#00ff00'; // Green for safe websites
            statusDiv.textContent = 'Website Appears Safe';
        } else if (result.confidence >= 0.3 && result.confidence < 0.5) {
            resultDiv.className = 'result-box warning';
            resultDiv.style.backgroundColor = '#ffa500'; // Orange for potential phishing
            statusDiv.textContent = 'Caution: Website May Be Phished';
        } else {
            resultDiv.className = 'result-box phishing';
            resultDiv.style.backgroundColor = '#ff0000'; // Red for unsafe websites
            statusDiv.textContent = 'Warning: Website Not Safe';
        }

        // Add risk factors if any
        if (result.risk_factors && result.risk_factors.length > 0) {
            result.risk_factors.forEach(factor => {
                const li = document.createElement('li');
                li.textContent = factor;
                riskFactorsUl.appendChild(li);
            });
        } else {
            const li = document.createElement('li');
            li.textContent = 'No specific risk factors detected';
            riskFactorsUl.appendChild(li);
        }

        // Update confidence score
        confidenceDiv.textContent = `Confidence Score: ${(result.confidence * 100).toFixed(1)}%`;
    }

    // Add click handler for scan button
    scanButton.addEventListener('click', analyzeCurrentUrl);
});
