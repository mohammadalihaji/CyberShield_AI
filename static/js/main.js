document.addEventListener('DOMContentLoaded', function() {
    
    // ==========================================
    // 0. Active Utilities and Constants
    // ==========================================
    
    let chatHistory = [];
    
    // Live clock ticker
    function startClock() {
        const clockEl = document.getElementById('live-clock');
        if (!clockEl) return;
        setInterval(() => {
            const now = new Date();
            clockEl.textContent = now.toTimeString().split(' ')[0];
        }, 1000);
    }
    startClock();

    // Enhanced Markdown Parser with XAI report support
    function parseMarkdown(text) {
        if (!text) return '';
        
        let html = text;

        // Headers
        html = html.replace(/^#### (.*?)$/gm, '<h4>$1</h4>');
        html = html.replace(/^### (.*?)$/gm, '<h3><i class="fa-solid fa-chevron-right text-cyan"></i> $1</h3>');
        html = html.replace(/^## (.*?)$/gm, '<h2>$1</h2>');
        html = html.replace(/^# (.*?)$/gm, '<h1>$1</h1>');
        
        // Horizontal rules
        html = html.replace(/^---+$/gm, '<hr class="dark-hr">');
        
        // Strong / Bold
        html = html.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');
        html = html.replace(/\*(.*?)\*/g, '<em>$1</em>');
        
        // Inline code blocks
        html = html.replace(/`(.*?)`/g, '<code>$1</code>');
        
        // Unordered lists
        html = html.replace(/^\s*[\*\-]\s+(.*?)$/gm, '<li>$1</li>');
        html = html.replace(/(<li>.*?<\/li>)/gs, function(m) { return '<ul>' + m + '</ul>'; });
        html = html.replace(/<\/ul>\s*<ul>/g, '');

        // Ordered lists (e.g. "1. item", "2) item")
        html = html.replace(/^\s*\d+[\.\)]\s+(.*?)$/gm, '<li>$1</li>');
        html = html.replace(/(<li>[\s\S]*?<\/li>)/g, function(m) { return '<ol>' + m + '</ol>'; });
        html = html.replace(/<\/ol>\s*<ol>/g, '');

        // Paragraphs
        const lines = html.split(/\n{2,}/);
        const processedLines = lines.map(line => {
            const t = line.trim();
            if (!t) return '';
            if (t.startsWith('<h') || t.startsWith('<ul') || t.startsWith('<ol') || t.startsWith('<li') || t.startsWith('<hr') || t.startsWith('<blockquote')) {
                return line;
            }
            return `<p>${line.replace(/\n/g, '<br>')}</p>`;
        });
        
        return processedLines.join('');
    }

    // Helper: safely set text content of an element
    function setElementText(id, text, suffix = '') {
        const el = document.getElementById(id);
        if (el && text !== undefined && text !== null && text !== '') {
            el.textContent = text + suffix;
        }
    }

    // Helper: set element text with fallback
    function setElementSafe(id, value, fallback = '--') {
        const el = document.getElementById(id);
        if (!el) return;
        if (value !== undefined && value !== null && value !== '') {
            el.textContent = value;
        } else {
            el.textContent = fallback;
        }
    }

    // Tab Navigation Configuration
    const navItems = document.querySelectorAll('.nav-item');
    const tabPanels = document.querySelectorAll('.tab-panel');

    navItems.forEach(item => {
        item.addEventListener('click', function() {
            const targetTab = this.getAttribute('data-tab');
            
            navItems.forEach(nav => nav.classList.remove('active'));
            this.classList.add('active');
            
            tabPanels.forEach(panel => {
                panel.classList.remove('active');
                if (panel.getAttribute('id') === `panel-${targetTab}`) {
                    panel.classList.add('active');
                }
            });
        });
    });

    // ==========================================
    // 1. Dashboard Metrics and Table Operations
    // ==========================================
    
    function refreshStats() {
        if (!document.getElementById('header-total-scans')) return;
        
        fetch('/api/stats')
            .then(res => res.json())
            .then(data => {
                if (data.success) {
                    const stats = data.stats;
                    
                    document.getElementById('header-total-scans').textContent = stats.total_scans;
                    document.getElementById('header-threats-blocked').textContent = stats.threats_blocked;
                    document.getElementById('header-security-score').textContent = `${stats.security_score}%`;
                    
                    const gaugeCircle = document.getElementById('posture-gauge');
                    const scoreDisplay = document.getElementById('posture-score-display');
                    const scoreLbl = document.getElementById('posture-rating-lbl');
                    
                    if (scoreDisplay) scoreDisplay.textContent = `${stats.security_score}%`;
                    
                    if (gaugeCircle) {
                        const offset = 251.2 - (251.2 * stats.security_score) / 100;
                        gaugeCircle.style.strokeDashoffset = offset;
                        
                        if (stats.security_score >= 80) {
                            gaugeCircle.style.stroke = 'var(--color-safe)';
                            if (scoreLbl) { scoreLbl.textContent = 'SECURE'; scoreLbl.style.background = 'rgba(0, 230, 118, 0.15)'; scoreLbl.style.color = 'var(--color-safe)'; }
                        } else if (stats.security_score >= 50) {
                            gaugeCircle.style.stroke = 'var(--color-warning)';
                            if (scoreLbl) { scoreLbl.textContent = 'VULNERABLE'; scoreLbl.style.background = 'rgba(255, 179, 0, 0.15)'; scoreLbl.style.color = 'var(--color-warning)'; }
                        } else {
                            gaugeCircle.style.stroke = 'var(--color-danger)';
                            if (scoreLbl) { scoreLbl.textContent = 'CRITICAL'; scoreLbl.style.background = 'rgba(255, 51, 102, 0.15)'; scoreLbl.style.color = 'var(--color-danger)'; }
                        }
                    }
                    
                    ['count-website', 'count-image', 'count-email', 'count-password'].forEach(id => {
                        const el = document.getElementById(id);
                        if (el) {
                            const key = id.replace('count-', '');
                            el.textContent = stats.scan_types[key] || 0;
                        }
                    });
                    
                    ['stat-safe', 'stat-suspicious', 'stat-malicious'].forEach(id => {
                        const el = document.getElementById(id);
                        if (el) {
                            const key = id.replace('stat-', '');
                            el.textContent = stats[key + '_count'] || 0;
                        }
                    });
                    
                    const tbody = document.querySelector('#table-logs tbody');
                    if (!tbody) return;
                    tbody.innerHTML = '';
                    
                    if (stats.recent_scans && stats.recent_scans.length > 0) {
                        stats.recent_scans.forEach(scan => {
                            const tr = document.createElement('tr');
                            tr.setAttribute('data-id', scan.id);
                            
                            let typeIcon = '';
                            if (scan.scan_type === 'website') typeIcon = '<i class="fa-solid fa-globe"></i>';
                            else if (scan.scan_type === 'image') typeIcon = '<i class="fa-solid fa-image"></i>';
                            else if (scan.scan_type === 'email') typeIcon = '<i class="fa-solid fa-envelope"></i>';
                            else if (scan.scan_type === 'password') typeIcon = '<i class="fa-solid fa-key"></i>';
                            else typeIcon = '<i class="fa-solid fa-shield"></i>';
                            
                            tr.innerHTML = `
                                <td>
                                    <span class="mod-icon ${scan.scan_type}">
                                        ${typeIcon} ${scan.scan_type.toUpperCase()}
                                    </span>
                                </td>
                                <td><code class="telemetry-input">${scan.input_data}</code></td>
                                <td>
                                    <span class="status-badge ${scan.risk_level.toLowerCase()}">
                                        ${scan.risk_level}
                                    </span>
                                </td>
                                <td><small class="timestamp">${scan.timestamp}</small></td>
                                <td>
                                    <a href="/api/reports/${scan.id}?type=${scan.scan_type}" target="_blank" class="btn-table-action" title="View Full Report">
                                        <i class="fa-solid fa-print"></i> Report
                                    </a>
                                </td>
                            `;
                            tbody.appendChild(tr);
                        });
                    } else {
                        tbody.innerHTML = `
                            <tr class="empty-table-row">
                                <td colspan="5">Zero security scan files registered in database. Run some tool audits to populate.</td>
                            </tr>
                        `;
                    }
                }
            })
            .catch(err => console.error("Database connection failure: ", err));
    }

    // Reset details history database handler
    const btnClearHistory = document.getElementById('btn-clear-history');
    if (btnClearHistory) {
        btnClearHistory.addEventListener('click', function() {
            if (confirm("Execute database wipe? All cached scanning details and metrics will be wiped permanently.")) {
                fetch('/api/clear-history', { method: 'POST' })
                    .then(res => res.json())
                    .then(data => {
                        if (data.success) {
                            refreshStats();
                        } else {
                            alert("Reset failed: " + data.error);
                        }
                    })
                    .catch(err => alert("Clear history failed: " + err));
            }
        });
    }

    // ==========================================
    // 2. ML Website Security Assessment Handler
    // ==========================================
    const formWeb = document.getElementById('form-website');
    const webLoader = document.getElementById('web-loader');
    const webResults = document.getElementById('web-results');
    const webModelStatus = document.getElementById('web-model-status');
    const webModelStatusText = document.getElementById('web-model-status-text');
    
    if (formWeb) {
        formWeb.addEventListener('submit', function(e) {
            e.preventDefault();
            
            const url = document.getElementById('input-web-url').value.trim();
            if (!url) return;
            
            webResults.classList.add('inactive');
            webLoader.classList.remove('hidden');
            if (webModelStatus) webModelStatus.classList.add('hidden');
            
            fetch('/api/check-website', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url: url })
            })
            .then(res => res.json())
            .then(data => {
                webLoader.classList.add('hidden');

                if (data.status === 'MODEL_NOT_READY') {
                    const res = data.result || {};
                    if (webModelStatus) {
                        webModelStatus.classList.remove('hidden');
                        if (webModelStatusText) {
                            webModelStatusText.textContent = data.error || "CompPhish V4 model training required. All feature pipelines ready.";
                        }
                    }
                    const rLevel = document.getElementById('web-risk-level');
                    if (rLevel) {
                        rLevel.textContent = 'AWAITING TRAINING';
                        rLevel.className = 'value badge-display status-badge warning';
                    }
                    setElementSafe('web-trusted-prob', '--');
                    setElementSafe('web-phish-prob', '--');
                    
                    if (res.explanation_markdown) {
                        document.getElementById('web-markdown').innerHTML = parseMarkdown(res.explanation_markdown);
                    }
                    webResults.classList.remove('inactive');
                    return;
                }

                if (data.success) {
                    const res = data.result;
                    if (webModelStatus) webModelStatus.classList.add('hidden');
                    
                    // Calibrated ML Probabilities
                    setElementSafe('web-trusted-prob', `${res.trusted_probability}%`);
                    setElementSafe('web-phish-prob', `${res.phishing_probability}%`);

                    // Threat Classification Badge
                    const rLevel = document.getElementById('web-risk-level');
                    if (rLevel) {
                        rLevel.textContent = res.risk_level;
                        rLevel.className = `value badge-display status-badge ${res.risk_level.toLowerCase()}`;
                    }
                    
                    // XAI Explainable AI Markdown report
                    document.getElementById('web-markdown').innerHTML = parseMarkdown(res.explanation_markdown);
                    
                    webResults.classList.remove('inactive');
                    refreshStats();
                } else {
                    alert("Website audit error: " + (data.error || "Analysis failed"));
                }
            })
            .catch(err => {
                webLoader.classList.add('hidden');
                alert("Error invoking website checking interface: " + err);
            });
        });
    }

    // ==========================================
    // 3. AI Image Authenticity Analyzer — XAI Forensics Enhanced
    // ==========================================
    const dropzone = document.getElementById('image-dropzone');
    const fileInput = document.getElementById('input-image-file');
    const previewContainer = document.getElementById('image-preview-container');
    const previewImg = document.getElementById('image-preview');
    const btnCancelImage = document.getElementById('btn-cancel-image');
    const btnSubmitImage = document.getElementById('btn-submit-image');
    const formImage = document.getElementById('form-image');
    const imgLoader = document.getElementById('image-loader');
    const imgResults = document.getElementById('image-results');

    if (dropzone) {
        ['dragenter', 'dragover'].forEach(eventName => {
            dropzone.addEventListener(eventName, (e) => {
                e.preventDefault();
                dropzone.classList.add('dragover');
            }, false);
        });

        ['dragleave', 'drop'].forEach(eventName => {
            dropzone.addEventListener(eventName, (e) => {
                e.preventDefault();
                dropzone.classList.remove('dragover');
            }, false);
        });

        dropzone.addEventListener('drop', (e) => {
            const dt = e.dataTransfer;
            const files = dt.files;
            if (files.length > 0) {
                fileInput.files = files;
                handleImageSelection(files[0]);
            }
        });

        fileInput.addEventListener('change', function() {
            if (this.files.length > 0) {
                handleImageSelection(this.files[0]);
            }
        });
    }

    function handleImageSelection(file) {
        if (!file.type.startsWith('image/')) {
            alert('File must be an image.');
            return;
        }
        
        const reader = new FileReader();
        reader.onload = function(e) {
            previewImg.src = e.target.result;
            dropzone.classList.add('hidden');
            previewContainer.classList.remove('hidden');
            btnSubmitImage.removeAttribute('disabled');
        };
        reader.readAsDataURL(file);
    }

    if (btnCancelImage) {
        btnCancelImage.addEventListener('click', function() {
            fileInput.value = '';
            previewImg.src = '#';
            previewContainer.classList.add('hidden');
            dropzone.classList.remove('hidden');
            btnSubmitImage.setAttribute('disabled', 'true');
            imgResults.classList.add('inactive');
        });
    }

    if (formImage) {
        formImage.addEventListener('submit', function(e) {
            e.preventDefault();
            
            const file = fileInput.files[0];
            if (!file) return;
            
            const formData = new FormData();
            formData.append('image', file);
            
            imgResults.classList.add('inactive');
            imgLoader.classList.remove('hidden');
            
            fetch('/api/check-image', {
                method: 'POST',
                body: formData
            })
            .then(res => res.json())
            .then(data => {
                imgLoader.classList.add('hidden');
                if (data.success) {
                    const res = data.result;
                    
                    // XAI metrics
                    const displayProb = res.ai_probability !== undefined ? res.ai_probability : res.confidence;
                    setElementSafe('image-confidence', displayProb !== undefined ? displayProb + '%' : '--');

                    
                    // XAI markdown report
                    document.getElementById('image-markdown').innerHTML = parseMarkdown(res.explanation_markdown);
                    imgResults.classList.remove('inactive');
                    refreshStats();
                } else {
                    alert("Image analysis error: " + data.error);
                }
            })
            .catch(err => {
                imgLoader.classList.add('hidden');
                alert("Error invoking image analysis engine: " + err);
            });
        });
    }

    // ==========================================
    // 4. Email Phishing Analyzer — XAI Enhanced
    // ==========================================
    const formEmail = document.getElementById('form-email');
    const emailLoader = document.getElementById('email-loader');
    const emailResults = document.getElementById('email-results');
    
    if (formEmail) {
        formEmail.addEventListener('submit', function(e) {
            e.preventDefault();
            
            const sender = document.getElementById('input-email-sender').value.trim();
            const body = document.getElementById('input-email-body').value.trim();
            
            if (!sender || !body) return;
            
            emailResults.classList.add('inactive');
            emailLoader.classList.remove('hidden');
            
            fetch('/api/check-email', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ sender: sender, body: body })
            })
            .then(res => res.json())
            .then(data => {
                emailLoader.classList.add('hidden');
                if (data.success) {
                    const res = data.result;
                    
                    // Threat Verdict
                    const riskDisplay = document.getElementById('email-risk-level');
                    riskDisplay.textContent = res.risk_level;
                    riskDisplay.className = `value badge-display status-badge ${res.risk_level.toLowerCase()}`;
                    
                    // XAI markdown report
                    document.getElementById('email-markdown').innerHTML = parseMarkdown(res.explanation_markdown);
                    emailResults.classList.remove('inactive');
                    refreshStats();
                } else {
                    alert("Email phishing scan error: " + data.error);
                }
            })
            .catch(err => {
                emailLoader.classList.add('hidden');
                alert("Email checking server error: " + err);
            });
        });
    }

    // ==========================================
    // 5. Password Strength checker — XAI Enhanced
    // ==========================================
    const formPassword = document.getElementById('form-password');
    const pwdInput = document.getElementById('input-password-string');
    const togglePwd = document.getElementById('toggle-pwd-visibility');
    
    const pwdStrengthBar = document.getElementById('pwd-strength-bar');
    const pwdVerbal = document.getElementById('pwd-verbal-strength');
    const pwdEntropyDisplay = document.getElementById('pwd-entropy-display');
    const pwdLoader = document.getElementById('pwd-loader');
    const pwdResults = document.getElementById('pwd-results');

    if (togglePwd) {
        togglePwd.addEventListener('click', function() {
            const type = pwdInput.getAttribute('type') === 'password' ? 'text' : 'password';
            pwdInput.setAttribute('type', type);
            this.innerHTML = type === 'password' ? '<i class="fa-solid fa-eye"></i>' : '<i class="fa-solid fa-eye-slash"></i>';
        });
    }

    if (pwdInput) {
        pwdInput.addEventListener('input', function() {
            const pwd = this.value;
            const length = pwd.length;
            
            if (length === 0) {
                pwdStrengthBar.parentElement.className = 'strength-bar-meter';
                pwdVerbal.parentElement.className = 'entropy-subtext';
                pwdVerbal.textContent = 'Strength: Empty';
                pwdEntropyDisplay.textContent = '0 bits entropy';
                resetPassCheckboxes();
                return;
            }
            
            const hasUpper = /[A-Z]/.test(pwd);
            const hasLower = /[a-z]/.test(pwd);
            const hasDigit = /[0-9]/.test(pwd);
            const hasSpecial = /[^A-Za-z0-9]/.test(pwd);
            
            updatePassCheckbox('badge-char-len', length >= 8);
            updatePassCheckbox('badge-char-upper', hasUpper);
            updatePassCheckbox('badge-char-lower', hasLower);
            updatePassCheckbox('badge-char-number', hasDigit);
            updatePassCheckbox('badge-char-special', hasSpecial);
            
            let charsetSize = 0;
            if (hasLower) charsetSize += 26;
            if (hasUpper) charsetSize += 26;
            if (hasDigit) charsetSize += 10;
            if (hasSpecial) charsetSize += 32;
            
            const entropy = Math.round(length * Math.log2(charsetSize));
            pwdEntropyDisplay.textContent = `${entropy} bits entropy`;
            
            const commonList = ['password', '123456', 'qwerty', 'p@ssword', 'welcome', 'letmein'];
            const isCommon = commonList.some(w => pwd.toLowerCase().includes(w));
            
            let strength = 'weak';
            if (length < 8 || isCommon) {
                strength = 'weak';
                pwdVerbal.textContent = 'Strength: Weak';
            } else if (length < 12 || entropy < 60) {
                strength = 'medium';
                pwdVerbal.textContent = 'Strength: Medium';
            } else {
                strength = 'strong';
                pwdVerbal.textContent = 'Strength: Strong';
            }
            
            pwdStrengthBar.parentElement.className = `strength-bar-meter ${strength}`;
            pwdVerbal.parentElement.className = `entropy-subtext ${strength}`;
        });
    }

    function updatePassCheckbox(id, isMet) {
        const el = document.getElementById(id);
        if (!el) return;
        if (isMet) {
            el.classList.add('met');
            el.innerHTML = '<i class="fa-solid fa-circle-check green-text"></i> ' + el.textContent.split(': ')[0] + ': Pass';
        } else {
            el.classList.remove('met');
            const defaultText = {
                'badge-char-len': 'Length: 8+',
                'badge-char-upper': 'Uppercase [A-Z]',
                'badge-char-lower': 'Lowercase [a-z]',
                'badge-char-number': 'Numbers [0-9]',
                'badge-char-special': 'Symbols [$,%,!]'
            };
            el.innerHTML = '<i class="fa-solid fa-circle-xmark red-text"></i> ' + defaultText[id];
        }
    }

    function resetPassCheckboxes() {
        ['badge-char-len', 'badge-char-upper', 'badge-char-lower', 'badge-char-number', 'badge-char-special'].forEach(id => {
            updatePassCheckbox(id, false);
        });
    }

    if (formPassword) {
        formPassword.addEventListener('submit', function(e) {
            e.preventDefault();
            
            const pwd = pwdInput.value;
            if (!pwd) return;
            
            pwdResults.classList.add('inactive');
            pwdLoader.classList.remove('hidden');
            
            fetch('/api/check-password', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ password: pwd })
            })
            .then(res => res.json())
            .then(data => {
                pwdLoader.classList.add('hidden');
                if (data.success) {
                    const res = data.result;
                    
                    // XAI metrics
                    setElementSafe('pwd-glance-entropy', res.entropy !== undefined ? res.entropy + ' bits' : '--');
                    setElementSafe('pwd-glance-breaches', res.pwned_count > 0 ? res.pwned_count + ' times' : '0 times (Clean)');
                    setElementSafe('pwd-crack-time', res.estimated_crack_time || '--');
                    setElementSafe('pwd-dict-risk', res.dictionary_risk || '--');
                    setElementSafe('pwd-pattern', res.pattern_detection || '--');
                    
                    // Threat classification badge
                    const riskEl = document.getElementById('pwd-risk-level');
                    if (riskEl) {
                        riskEl.textContent = res.risk_level || '--';
                        riskEl.className = `value badge-display status-badge ${(res.risk_level || 'suspicious').toLowerCase()}`;
                    }
                    
                    // XAI markdown report
                    document.getElementById('pwd-markdown').innerHTML = parseMarkdown(res.explanation_markdown);
                    pwdResults.classList.remove('inactive');
                    refreshStats();
                } else {
                    alert("Password evaluation error: " + data.error);
                }
            })
            .catch(err => {
                pwdLoader.classList.add('hidden');
                alert("Password interface checking error: " + err);
            });
        });
    }

    // ==========================================
    // 6. Privacy & Security Advisor — XAI Enhanced
    // ==========================================
    const formAdvisor = document.getElementById('form-advisor');
    const advLoader = document.getElementById('advisor-loader');
    const advResults = document.getElementById('advisor-results');
    
    if (formAdvisor) {
        formAdvisor.addEventListener('submit', function(e) {
            e.preventDefault();
            
            const mfa = document.querySelector('input[name="adv-mfa"]:checked').value;
            const pw_reuse = document.querySelector('input[name="adv-reuse"]:checked').value;
            const updates = document.querySelector('input[name="adv-updates"]:checked').value;
            const backups = document.querySelector('input[name="adv-backups"]:checked').value;
            const phish = document.querySelector('input[name="adv-phish"]:checked').value;
            
            const profile = {
                mfa: mfa,
                pw_reuse: pw_reuse,
                updates: updates,
                backups: backups,
                phish_awareness: phish
            };
            
            advResults.classList.add('inactive');
            advLoader.classList.remove('hidden');
            
            fetch('/api/get-advice', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(profile)
            })
            .then(res => res.json())
            .then(data => {
                advLoader.classList.add('hidden');
                if (data.success) {
                    const res = data.result;
                    
                    document.getElementById('adv-overall-score').textContent = `${res.overall_score}/100`;
                    
                    const mitCount = res.recommendations.length;
                    const mitDisplay = document.getElementById('adv-mitigation-count');
                    mitDisplay.textContent = mitCount;
                    
                    if (mitCount > 2) {
                        mitDisplay.className = 'value text-red';
                        mitDisplay.style.color = 'var(--color-danger)';
                    } else if (mitCount > 0) {
                        mitDisplay.className = 'value text-yellow';
                        mitDisplay.style.color = 'var(--color-warning)';
                    } else {
                        mitDisplay.className = 'value text-green';
                        mitDisplay.style.color = 'var(--color-safe)';
                    }
                    
                    // XAI markdown report (use general_advisor_markdown if available)
                    const markdownContent = res.general_advisor_markdown || res.explanation_markdown || '';
                    document.getElementById('advisor-markdown').innerHTML = parseMarkdown(markdownContent);
                    advResults.classList.remove('inactive');
                    refreshStats();
                } else {
                    alert("Advisor compilation error: " + data.error);
                }
            })
            .catch(err => {
                advLoader.classList.add('hidden');
                alert("Error invoking Advisor profiling engine: " + err);
            });
        });
    }

    // ==========================================
    // 7. Security AI Chatbot Assistant
    // ==========================================
    const formChat = document.getElementById('form-chat');
    const inputChat = document.getElementById('input-chat-query');
    const chatContainer = document.getElementById('chat-messages-container');
    const chatTyping = document.getElementById('chat-typing-indicator');
    
    if (formChat) {
        formChat.addEventListener('submit', function(e) {
            e.preventDefault();
            
            const message = inputChat.value.trim();
            if (!message) return;
            
            appendChatBubble('user', message);
            inputChat.value = '';
            
            chatTyping.classList.remove('hidden');
            chatContainer.scrollTop = chatContainer.scrollHeight;
            
            fetch('/api/chat', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ message: message, history: chatHistory })
            })
            .then(res => res.json())
            .then(data => {
                chatTyping.classList.add('hidden');
                if (data.success) {
                    appendChatBubble('model', data.reply);
                    
                    chatHistory.push({ role: 'user', content: message });
                    chatHistory.push({ role: 'model', content: data.reply });
                } else {
                    appendChatBubble('model', "⚠️ Connection alert: Chat service failed to parse response: " + data.error);
                }
                chatContainer.scrollTop = chatContainer.scrollHeight;
            })
            .catch(err => {
                chatTyping.classList.add('hidden');
                appendChatBubble('model', "⚠️ Network diagnostic alert: Connection to AI Assistant interrupted.");
                chatContainer.scrollTop = chatContainer.scrollHeight;
            });
        });
    }

    function appendChatBubble(role, content) {
        const bubble = document.createElement('div');
        bubble.className = `chat-message ${role}`;
        
        if (role === 'model') {
            bubble.innerHTML = parseMarkdown(content);
        } else {
            bubble.textContent = content;
        }
        
        chatContainer.appendChild(bubble);
    }

    // ==========================================
    // 8. Authentication & User Profile Management
    // ==========================================
    const modalLogin = document.getElementById('modal-login');
    const modalRegister = document.getElementById('modal-register');
    const btnOpenLogin = document.getElementById('btn-open-login');
    const btnOpenRegister = document.getElementById('btn-open-register');
    const btnCloseLogin = document.getElementById('btn-close-login');
    const btnCloseRegister = document.getElementById('btn-close-register');
    const linkToRegister = document.getElementById('link-switch-to-register');
    const linkToLogin = document.getElementById('link-switch-to-login');
    const formLogin = document.getElementById('form-login');
    const formRegister = document.getElementById('form-register');
    const loginError = document.getElementById('login-error-msg');
    const regError = document.getElementById('reg-error-msg');
    const btnLogout = document.getElementById('btn-user-logout');

    if (btnOpenLogin) {
        btnOpenLogin.addEventListener('click', () => {
            modalLogin.classList.remove('hidden');
        });
    }

    // Landing page login buttons
    const landingBtnLogin = document.getElementById('landing-btn-login');
    const heroBtnLogin = document.getElementById('hero-btn-login');

    if (landingBtnLogin) {
        landingBtnLogin.addEventListener('click', () => {
            modalLogin.classList.remove('hidden');
        });
    }

    if (heroBtnLogin) {
        heroBtnLogin.addEventListener('click', () => {
            modalLogin.classList.remove('hidden');
        });
    }

    if (btnOpenRegister) {
        btnOpenRegister.addEventListener('click', () => {
            modalRegister.classList.remove('hidden');
        });
    }

    // Landing page register buttons
    const landingBtnRegister = document.getElementById('landing-btn-register');
    const heroBtnRegister = document.getElementById('hero-btn-register');

    if (landingBtnRegister) {
        landingBtnRegister.addEventListener('click', () => {
            modalRegister.classList.remove('hidden');
        });
    }

    if (heroBtnRegister) {
        heroBtnRegister.addEventListener('click', () => {
            modalRegister.classList.remove('hidden');
        });
    }

    if (btnCloseLogin) {
        btnCloseLogin.addEventListener('click', () => {
            modalLogin.classList.add('hidden');
        });
    }

    if (btnCloseRegister) {
        btnCloseRegister.addEventListener('click', () => {
            modalRegister.classList.add('hidden');
        });
    }

    if (linkToRegister) {
        linkToRegister.addEventListener('click', (e) => {
            e.preventDefault();
            modalLogin.classList.add('hidden');
            modalRegister.classList.remove('hidden');
        });
    }

    if (linkToLogin) {
        linkToLogin.addEventListener('click', (e) => {
            e.preventDefault();
            modalRegister.classList.add('hidden');
            modalLogin.classList.remove('hidden');
        });
    }

    if (formLogin) {
        formLogin.addEventListener('submit', function(e) {
            e.preventDefault();
            const identifier = document.getElementById('login-identifier').value.trim();
            const password = document.getElementById('login-password').value;
            loginError.classList.add('hidden');

            fetch('/api/auth/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ identifier, password })
            })
            .then(res => res.json())
            .then(data => {
                if (data.success) {
                    if (data.token) {
                        localStorage.setItem('cybershield_token', data.token);
                    }
                    window.location.href = '/dashboard';
                } else {
                    loginError.textContent = data.error || "Authentication failed.";
                    loginError.classList.remove('hidden');
                }
            })
            .catch(err => {
                loginError.textContent = "Network error during login request.";
                loginError.classList.remove('hidden');
            });
        });
    }

    if (formRegister) {
        formRegister.addEventListener('submit', function(e) {
            e.preventDefault();
            const username = document.getElementById('reg-username').value.trim();
            const email = document.getElementById('reg-email').value.trim();
            const password = document.getElementById('reg-password').value;
            const firstName = document.getElementById('reg-first-name').value.trim();
            const lastName = document.getElementById('reg-last-name').value.trim();
            regError.classList.add('hidden');

            fetch('/api/auth/register', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    username: username,
                    email: email,
                    password: password,
                    first_name: firstName,
                    last_name: lastName
                })
            })
            .then(res => res.json())
            .then(data => {
                if (data.success) {
                    if (data.token) {
                        localStorage.setItem('cybershield_token', data.token);
                    }
                    window.location.href = '/dashboard';
                } else {
                    regError.textContent = data.error || "Registration failed.";
                    regError.classList.remove('hidden');
                }
            })
            .catch(err => {
                regError.textContent = "Network error during registration request.";
                regError.classList.remove('hidden');
            });
        });
    }

    if (btnLogout) {
        btnLogout.addEventListener('click', function() {
            fetch('/api/auth/logout', { method: 'POST' })
            .then(() => {
                localStorage.removeItem('cybershield_token');
                window.location.href = '/';
            });
        });
    }

    // Profile page logout buttons
    const btnProfileLogout = document.getElementById('btn-profile-logout');
    const btnProfileLogoutAlt = document.getElementById('btn-profile-logout-alt');

    if (btnProfileLogout) {
        btnProfileLogout.addEventListener('click', function() {
            fetch('/api/auth/logout', { method: 'POST' })
            .then(() => {
                localStorage.removeItem('cybershield_token');
                window.location.href = '/';
            });
        });
    }

    if (btnProfileLogoutAlt) {
        btnProfileLogoutAlt.addEventListener('click', function() {
            fetch('/api/auth/logout', { method: 'POST' })
            .then(() => {
                localStorage.removeItem('cybershield_token');
                window.location.href = '/';
            });
        });
    }
});