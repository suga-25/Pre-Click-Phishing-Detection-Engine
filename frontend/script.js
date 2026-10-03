const API_BASE = 'http://127.0.0.1:5000/api';

/**
 * Fetches message list and renders formatted email inbox
 */
async function fetchInbox() {
    const inboxList = document.getElementById('inbox-list');
    if (!inboxList) return;

    try {
        const response = await fetch(`${API_BASE}/messages`);
        const messages = await response.json();

        if (!messages || messages.length === 0) {
            inboxList.innerHTML = '<p class="placeholder">No messages found.</p>';
            return;
        }

        let html = '';
        messages.forEach(msg => {
            const initial = msg.sender ? msg.sender.charAt(0).toUpperCase() : '?';
            html += `
                <div class="message-item" onclick="handleOpenMessage(${msg.id}, this)">
                    <div class="avatar">${initial}</div>
                    <div class="msg-details">
                        <div class="sender">${escapeHtml(msg.sender)}</div>
                        <div class="subject">${escapeHtml(msg.subject)}</div>
                    </div>
                </div>
            `;
        });

        inboxList.innerHTML = html;

    } catch (error) {
        console.error("Fetch inbox error:", error);
        inboxList.innerHTML = '<p class="placeholder" style="color: var(--danger-red);">Failed to connect to backend server.</p>';
    }
}

/**
 * Normalizes backend data fields and builds Phase 3 risk components dynamically
 */
function createPhase3RiskCard(res, index) {
    // 1. Resolve risk score regardless of backend key naming variations
    const score = res.risk_score ?? res.score ?? res.heuristic_score ?? 0;
    
    // 2. Resolve classification level
    let classification = (res.classification || res.threat_level || '').toUpperCase();
    if (!['HIGH', 'MEDIUM', 'LOW'].includes(classification)) {
        if (score >= 70) classification = 'HIGH';
        else if (score >= 30) classification = 'MEDIUM';
        else classification = 'LOW';
    }

    const riskLabel = res.risk_label || res.verdict || classification;
    const recText = res.recommendation || (classification === 'HIGH' ? 'BLOCK & DO NOT CLICK' : classification === 'MEDIUM' ? 'PROCEED WITH CAUTION' : 'SAFE TO VISIT');
    
    // 3. Resolve Array payloads with fallbacks
    const contributions = res.score_contributions || res.contributions || res.breakdown || [];
    const reasons = res.explainable_reasons || res.risk_reasons || res.reasons || [];
    const attackChain = res.attack_chain || res.chain || [];

    const card = document.createElement('div');
    card.className = 'risk-card';

    // Header & Badges
    let html = `
        <div style="color: var(--accent-blue); font-weight: bold; font-family: monospace; font-size: 0.8rem; margin-bottom: 6px;">[URL #${index + 1}]</div>
        <div class="url-box">${escapeHtml(res.target_url || res.url || 'Unknown Target URL')}</div>

        <div class="risk-header">
            <div class="score-badge ${classification}">${score}/100</div>
            <div class="risk-meta">
                <h3 class="${classification}">${escapeHtml(riskLabel)}</h3>
                <span class="rec-banner ${classification}">${escapeHtml(recText)}</span>
            </div>
        </div>

        <h4 class="section-title">Why is this URL Risky? (Score Breakdown)</h4>
        <div class="breakdown-container">
    `;

    // Render Contributions Bars
    if (contributions.length === 0) {
        html += `<p class="placeholder">No penalty categories triggered (Base Score: ${score}).</p>`;
    } else {
        contributions.forEach(item => {
            const categoryName = item.category || item.name || item.rule || 'Risk Factor';
            const val = item.score ?? item.points ?? item.value ?? 0;
            const barWidth = Math.min(100, Math.max(0, (val / 30) * 100)); // Normalized to max ~30 pts per category

            html += `
                <div class="breakdown-row">
                    <span class="breakdown-label">${escapeHtml(categoryName)}</span>
                    <div class="bar-track">
                        <div class="bar-fill" style="width: ${barWidth}%;"></div>
                    </div>
                    <span class="breakdown-val">+${val}</span>
                </div>
            `;
        });
    }
    html += `</div>`;

    // Render Human-Readable Reasons
    html += `<h4 class="section-title">Key Risk Reasons</h4><ul class="reasons-list">`;
    if (reasons.length === 0) {
        html += `<li>No threat indicators identified.</li>`;
    } else {
        reasons.forEach(reasonText => {
            html += `<li>${escapeHtml(reasonText)}</li>`;
        });
    }
    html += `</ul>`;

    // Render Attack-Chain Flowchart
    html += `<h4 class="section-title">Detected Threat Attack-Chain</h4><div class="attack-chain-container">`;
    if (attackChain.length === 0) {
        const defaultChain = classification === 'HIGH' 
            ? ['Email Received', 'Suspicious URL Embedded', 'Credential Harvesting Target']
            : ['Email Received', 'Clean Domain Check'];
        
        defaultChain.forEach((step, idx) => {
            html += `<div class="chain-node">${escapeHtml(step)}</div>`;
            if (idx < defaultChain.length - 1) html += `<span class="chain-arrow">&#8594;</span>`;
        });
    } else {
        attackChain.forEach((step, idx) => {
            html += `<div class="chain-node">${escapeHtml(step)}</div>`;
            if (idx < attackChain.length - 1) html += `<span class="chain-arrow">&#8594;</span>`;
        });
    }
    html += `</div>`;

    card.innerHTML = html;
    return card;
}

/**
 * Handles opening a message, parsing body links, and displaying clean message viewer + Phase 3 results
 */
window.handleOpenMessage = async function(id, element) {
    // Highlight selected item in Panel 1
    document.querySelectorAll('.message-item').forEach(el => el.classList.remove('active'));
    if (element) element.classList.add('active');

    const viewer = document.getElementById('message-viewer');
    const urlOutput = document.getElementById('url-detector-output');

    if (viewer) viewer.innerHTML = '<h2>Message Viewer</h2><p class="placeholder">Opening message...</p>';
    if (urlOutput) urlOutput.innerHTML = '<h2>Pre-Click Link Inspector & Explainability</h2><p class="placeholder">Running multi-vector analysis...</p>';

    try {
        const response = await fetch(`${API_BASE}/messages/${id}/open`, { method: 'POST' });
        const data = await response.json();

        // 1. Render Panel 2 (Realistic Email Viewer)
        if (viewer) {
            const ctx = data.context_module || {};
            const initial = data.sender ? data.sender.charAt(0).toUpperCase() : '?';
            const urgencyPhrases = (ctx.detected_urgency_phrases && ctx.detected_urgency_phrases.length > 0) 
                ? ctx.detected_urgency_phrases.join(', ') 
                : 'None';

            viewer.innerHTML = `
                <h2>Message Viewer</h2>
                <div class="email-card">
                    <div class="email-header-meta">
                        <h3 class="email-subject-title">${escapeHtml(data.subject)}</h3>
                        <div class="sender-row">
                            <div class="avatar">${initial}</div>
                            <div class="sender-info-text">
                                <span class="sender-name-label">${escapeHtml(data.sender.split('@')[0])}</span>
                                <span class="sender-email-label">From: ${escapeHtml(data.sender)}</span>
                            </div>
                        </div>
                    </div>

                    <div class="email-body-content">${escapeHtml(data.body)}</div>

                    <div class="context-pill-bar">
                        <span class="context-pill">Urgency Score: <strong>${ctx.urgency_score || 0}/100</strong></span>
                        <span class="context-pill">Urgency Words: <strong>${escapeHtml(urgencyPhrases)}</strong></span>
                        <span class="context-pill">Sender Domain: <strong style="color: ${ctx.suspicious_sender_domain ? 'var(--danger-red)' : 'var(--safe-green)'}">${ctx.suspicious_sender_domain ? 'SUSPICIOUS' : 'Standard'}</strong></span>
                    </div>
                </div>
            `;
        }

        // 2. Render Panel 3 (Phase 3 Link Analysis & Explainability)
        if (urlOutput) {
            urlOutput.innerHTML = '<h2>Pre-Click Link Inspector & Explainability</h2>';

            if (data.analysis_results && data.analysis_results.length > 0) {
                data.analysis_results.forEach((res, idx) => {
                    const card = createPhase3RiskCard(res, idx);
                    urlOutput.appendChild(card);
                });
            } else {
                urlOutput.innerHTML += '<p class="placeholder" style="margin-top:12px;">No URLs detected in this message.</p>';
            }
        }

    } catch (err) {
        console.error("Open message error:", err);
        if (viewer) viewer.innerHTML = '<h2>Message Viewer</h2><p class="placeholder" style="color: var(--danger-red);">Error loading message details.</p>';
    }
};

function escapeHtml(text) {
    if (!text) return '';
    return String(text).replace(/[&<>"']/g, m => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[m]));
}

document.addEventListener('DOMContentLoaded', fetchInbox);