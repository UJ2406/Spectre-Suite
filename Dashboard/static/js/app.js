document.addEventListener("DOMContentLoaded", () => {
    
    // --- Helper Functions ---
    const showLoading = (el) => el.innerHTML = '<p class="loading">Scanning... Dedicate your heart!</p>';
    const showError = (el, msg) => el.innerHTML = `<p class="error">Error: ${msg}</p>`;

    // --- Form Handler (for Scans page) ---
    const handleForm = (id, endpoint, renderer) => {
        const form = document.getElementById(id);
        if (!form) return;
        form.addEventListener("submit", (e) => {
            e.preventDefault();
            const resDiv = document.getElementById(id.replace("form", "results"));
            showLoading(resDiv);
            fetch(endpoint, { method: "POST", body: new FormData(form) })
                .then(r => r.json())
                .then(data => {
                    if (data.error) showError(resDiv, data.error);
                    else resDiv.innerHTML = renderer(data);
                })
                .catch(() => showError(resDiv, "Client error."));
        });
    };

    // --- Helper to create download button ---
    const createDownloadButton = (data) => {
        if (!data.report_filename) return `<p>${data.message || ''}</p>`;
        return `
            <div class="report-download-box">
                <p>${data.message || 'Scan complete.'}</p>
                <a href="/static/reports/${data.report_filename}" class="btn-download" download>Download Report</a>
            </div>
        `;
    };

    // --- Renderers for Scan Results ---

    const renderPort = (d) => {
        let html = `
            <div class="scan-target">Target: ${d.target} (${d.target_ip})</div>
            <table class="scan-table">
                <thead><tr><th>Port</th><th>Service / Banner</th><th>CVE</th></tr></thead>
                <tbody>
        `;
        d.results.forEach(r => {
            html += `
                <tr>
                    <td class="port-open">${r.port}</td>
                    <td>${r.banner}</td>
                    ${r.cve ? `<td class="vulnerability-found">[!!] ${r.cve}</td>` : `<td>None</td>`}
                </tr>
            `;
        });
        html += `</tbody></table>${createDownloadButton(d)}`;
        return html;
    };

    const renderDomain = (d) => {
        let html = `<div class="scan-target">Domain: ${d.domain}</div>`;
        html += `<h3>Found Subdomains (${d.subdomains.length})</h3>`;
        if (d.subdomains.length > 0) {
            html += `<ul class="results-list">
                ${d.subdomains.map(sub => `<li><a href="https://${sub}" target="_blank">${sub}</a></li>`).join('')}
            </ul>`;
        } else {
            html += `<p>No common subdomains found.</p>`;
        }
        html += `<h3>DNS Records</h3><ul class="results-list">
            ${Object.keys(d.dns).map(k => `<li><b>${k}:</b> ${d.dns[k].length > 0 ? d.dns[k].join(', ') : 'N/A'}</li>`).join('')}
        </ul>`;
        html += `<h3>WHOIS</h3><ul class="results-list">
            <li><b>Registrar:</b> ${d.whois.registrar || 'N/A'}</li>
            <li><b>Creation Date:</b> ${d.whois.creation_date || 'N/A'}</li>
            <li><b>Expires:</b> ${d.whois.expiration_date || 'N/A'}</li>
        </ul>`;
        html += createDownloadButton(d);
        return html;
    };

    const renderSocial = (d) => {
        let html = `
            <div class="scan-target">User: ${d.username}</div>
            <p>Found ${d.results.length} accounts:</p>
            <ul class="results-list">
                ${d.results.map(r => `<li><a href="${r.url}" target="_blank">${r.site}</a></li>`).join('')}
            </ul>
        `;
        html += createDownloadButton(d);
        return html;
    };
    
    const renderEmail = (d) => {
        let h = `<div class="scan-target">Email: ${d.email}</div>`;
        if (d.status === 'safe') {
            h += '<p class="status-safe">Good news! No breaches found.</p>';
        } else {
            h += `<p class="status-pwned">Breached! Found in ${d.breaches.length} breaches:</p>
                  <ul class="results-list">`;
            d.breaches.forEach(b => {
                // NEW: Show new data format
                h += `<li>
                        <b>${b.name}</b>
                        <span class="data-classes">(Domain: ${b.domain} | Records: ${b.count})</span>
                      </li>`;
            });
            h += `</ul>`;
        }
        h += createDownloadButton(d);
        return h;
    };

    const renderTech = (d) => {
        let html = `<div class="scan-target">URL: ${d.url}</div>`;
        html += `<h3>Interesting Headers</h3><ul class="results-list">
            ${Object.keys(d.headers).map(k => `<li><b>${k}:</b> ${d.headers[k]}</li>`).join('')}
        </ul>`;
        html += `<h3>Technology Stack</h3><ul class="results-list">
            ${Object.keys(d.tech_stack).map(k => `<li><b>${k}:</b> ${d.tech_stack[k].join(', ')}</li>`).join('')}
        </ul>`;
        html += createDownloadButton(d);
        return html;
    };

    const renderDir = (d) => {
        let html = `<div class="scan-target">Target: ${d.target}</div>`;
        if (d.results.length === 0) {
            html += `<p>No common paths found.</p>`;
        } else {
            html += `
                <table class="scan-table">
                    <thead><tr><th>Status</th><th>Path Found</th></tr></thead>
                    <tbody>
            `;
            d.results.forEach(r => {
                html += `
                    <tr>
                        <td class="status-${r.status_code}">${r.status_code}</td>
                        <td><a href="${r.url}" target="_blank">${r.url}</a></td>
                    </tr>
                `;
            });
            html += `</tbody></table>`;
        }
        html += createDownloadButton(d);
        return html;
    };

    // --- Bind forms ---
    handleForm("port-scan-form", "/api/start-port-scan", renderPort);
    handleForm("domain-recon-form", "/api/start-domain-recon", renderDomain);
    handleForm("social-scout-form", "/api/start-social-scout", renderSocial);
    handleForm("email-check-form", "/api/start-email-check", renderEmail);
    handleForm("tech-enum-form", "/api/start-tech-enum", renderTech);
    handleForm("dir-scan-form", "/api/start-dir-scan", renderDir);

    // --- Live Threat Feed ---
    const feedWidget = document.getElementById("threat-feed-output");
    if (feedWidget) {
        fetch("/api/get-cve-feed")
            .then(response => response.json())
            .then(data => {
                if (data.error) {
                    feedWidget.innerHTML = `<p class="error">Error fetching feed: ${data.error}</p>`;
                    return;
                }
                let html = '<ul class="cve-list">';
                data.forEach(vuln => {
                    html += `
                        <li>
                            <div class="cve-header">
                                <span class="cve-id">${vuln.cveID}</span>
                                <span class="cve-date">Added: ${vuln.dateAdded}</span>
                            </div>
                            <div class="cve-name">
                                ${vuln.vulnerabilityName}
                            </div>
                        </li>
                    `;
                });
                html += '</ul>';
                feedWidget.innerHTML = html;
            })
            .catch(err => {
                feedWidget.innerHTML = `<p class="error">Client error fetching feed.</p>`;
            });
    }
});