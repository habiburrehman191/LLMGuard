(() => {
    const root = document.getElementById('uoh-chat');
    if (!root) return;

    const context = root.dataset.context;
    const panel = root.querySelector('#uoh-chat-panel');
    const launcher = root.querySelector('.uoh-chat-launcher');
    const closeButton = root.querySelector('[data-chat-close]');
    const minimizeButton = root.querySelector('[data-chat-minimize]');
    const newButton = root.querySelector('[data-chat-new]');
    const historyButton = root.querySelector('[data-chat-history]');
    const historyPanel = root.querySelector('[data-chat-history-panel]');
    const historyList = root.querySelector('[data-history-list]');
    const messages = root.querySelector('[data-chat-messages]');
    const suggestions = root.querySelector('[data-chat-suggestions]');
    const form = root.querySelector('[data-chat-form]');
    const input = root.querySelector('[data-chat-input]');
    const send = root.querySelector('[data-chat-send]');
    const loading = root.querySelector('[data-chat-loading]');
    const loadingLabel = root.querySelector('[data-loading-label]');
    const loadingDetail = root.querySelector('[data-loading-detail]');
    const feedbackForm = root.querySelector('[data-feedback-form]');
    const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)');
    let conversationId = null;
    let pendingFeedbackMessage = null;
    let lastQuestion = '';
    let loadingStageTimers = [];

    const promptSets = {
        public: ['What BS programs does the university offer?', 'Explain the admission process.', 'What scholarships are available?', 'What facilities are available?'],
        student: ['What is my CGPA?', 'What is my attendance?', 'What is my fee status?', "What are today's classes?"],
        employee: ['Show the student registry.', 'Search university policies.', 'Show employee records.', 'How many students are in each department?']
    };
    const pagePrompts = {
        '/portal/student/results': ['Explain my latest result.', 'What is my CGPA?', 'Which course has my lowest grade?'],
        '/portal/student/attendance': ['What is my attendance?', 'Which course has my lowest attendance?', 'Am I below the attendance requirement?'],
        '/portal/student/fees': ['What is my fee status?', 'Do I have any outstanding amount?', 'When is my next fee due?'],
        '/portal/student/timetable': ["What are today's classes?", 'What classes do I have tomorrow?', 'Show my timetable.'],
        '/university/admissions/eligibility': ['What are the eligibility requirements for BS Software Engineering?', 'What BS eligibility criteria apply?'],
        '/university/admissions/bs-programs': ['What BS programs does the university offer?', 'Is Software Engineering offered?'],
        '/university/admissions/schedule': ['Explain the admission process.', 'When is the admission deadline?']
    };
    const paths = {
        check: 'm5 12 4 4L19 6',
        dislike: 'M7 10v10M3 14v4a2 2 0 0 0 2 2h10.5a2 2 0 0 0 1.9-1.4l2.3-7A2 2 0 0 0 17.8 9H14l.8-4.1A2 2 0 0 0 12.8 3L7 10H3v4h4',
        copy: 'M8 8h11v11H8zM5 16H4V5h11v1',
        retry: 'M20 6v5h-5M4 18v-5h5M18 9a7 7 0 0 0-12-2M6 15a7 7 0 0 0 12 2',
        file: 'M7 3h7l4 4v14H7zM14 3v5h5M10 12h5M10 16h5',
        lock: 'M7 10V8a5 5 0 0 1 10 0v2M5 10h14v11H5z',
        search: 'm4 4 16 16M15 6a6 6 0 1 0-9 9',
        info: 'M12 11v6M12 7h.01M4 12a8 8 0 1 0 16 0 8 8 0 1 0-16 0'
    };

    function element(tag, className, text) {
        const node = document.createElement(tag);
        if (className) node.className = className;
        if (text !== undefined) node.textContent = text;
        return node;
    }

    function icon(path) {
        const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
        svg.setAttribute('viewBox', '0 0 24 24');
        svg.setAttribute('aria-hidden', 'true');
        const shape = document.createElementNS('http://www.w3.org/2000/svg', 'path');
        shape.setAttribute('d', path);
        svg.append(shape);
        return svg;
    }

    function crest(className, alt = '') {
        const crop = element('span', className);
        const logo = document.createElement('img');
        logo.src = '/static/university/images/logo.png';
        logo.alt = alt;
        crop.append(logo);
        return crop;
    }

    function statusLabel(status) {
        return {
            supported: 'Verified from University Records',
            access_restricted: 'Access Restricted',
            insufficient_data: 'Information Not Found',
            unavailable: 'University Assistant is temporarily unavailable'
        }[status] || '';
    }

    function visibleStatusLabel(status, sources, supplied) {
        if (status === 'supported' && sources?.length > 1) return `Verified from ${sources.length} University Sources`;
        return supplied || statusLabel(status);
    }

    function statusClass(status, sources) {
        if (status === 'access_restricted') return 'restricted';
        if (status === 'insufficient_data' || status === 'unavailable') return 'not-found';
        if (sources?.length > 1) return 'multiple';
        return 'verified';
    }

    function greeting() {
        const hour = new Date().getHours();
        return hour < 12 ? 'Good morning' : hour < 18 ? 'Good afternoon' : 'Good evening';
    }

    function renderWelcome() {
        const welcome = element('section', 'uoh-chat-welcome');
        const displayName = root.dataset.displayName;
        let title = root.dataset.welcomeTitle;
        if (context === 'student' && displayName) title = `${greeting()}, ${displayName.split(' ')[0]}`;
        welcome.append(crest('uoh-chat-welcome-crest', 'University of Haripur crest'));
        welcome.append(element('h2', '', title), element('p', '', root.dataset.welcome));
        const note = element('span', 'uoh-chat-welcome-note');
        note.append(element('strong', '', 'Official University AI Assistant'));
        note.append(document.createTextNode(context === 'public' ? 'Answers based on available public University records.' : context === 'student' ? 'Private answers are limited to your own academic record.' : 'Results follow your authorized institutional access.'));
        welcome.append(note);
        messages.append(welcome);
    }

    function showPanel() {
        panel.classList.remove('is-closing');
        panel.hidden = false;
        launcher.setAttribute('aria-expanded', 'true');
        launcher.hidden = true;
        document.body.classList.add('uoh-chat-open');
        window.setTimeout(() => input.focus(), 0);
    }

    function finishHide() {
        panel.hidden = true;
        panel.classList.remove('is-closing');
        historyPanel.hidden = true;
        feedbackForm.hidden = true;
        launcher.setAttribute('aria-expanded', 'false');
        launcher.hidden = false;
        document.body.classList.remove('uoh-chat-open');
        launcher.focus();
    }

    function hidePanel() {
        if (panel.hidden || panel.classList.contains('is-closing')) return;
        panel.classList.add('is-closing');
        if (reducedMotion.matches) finishHide();
        else window.setTimeout(finishHide, 205);
    }

    function renderSuggestions() {
        suggestions.replaceChildren();
        const items = pagePrompts[root.dataset.currentPage] || promptSets[context];
        items.forEach(question => {
            const button = element('button', '', question);
            button.type = 'button';
            button.addEventListener('click', () => { input.value = question; submitQuestion(question); });
            suggestions.append(button);
        });
    }

    function sourceTypeLabel(source) {
        return source.category || String(source.type || 'university_record').replaceAll('_', ' ');
    }

    function renderSources(container, sources, status) {
        if (status !== 'supported' || !sources?.length) return;
        const details = element('details', 'uoh-chat-sources');
        const summary = element('summary');
        summary.setAttribute('aria-label', `Show ${sources.length} University source${sources.length === 1 ? '' : 's'}`);
        summary.append(element('span', '', 'University Sources'), element('span', 'uoh-chat-source-count', String(sources.length)), element('i', 'uoh-chat-source-chevron'));
        const list = element('div', 'uoh-chat-source-list');
        sources.forEach(source => {
            const card = element('article', 'uoh-chat-source-card');
            const sourceIcon = element('span', 'uoh-chat-source-icon');
            sourceIcon.append(icon(paths.file));
            const copy = element('span', 'uoh-chat-source-copy');
            copy.append(element('strong', '', source.title), element('small', '', sourceTypeLabel(source)));
            card.append(sourceIcon, copy);
            if (source.route) {
                const link = element('a', '', 'View source');
                link.href = source.route;
                card.append(link);
            } else card.append(element('span', '', ''));
            list.append(card);
        });
        details.append(summary, list);
        container.append(details);
    }

    function parseKeyValues(text) {
        return text.split('\n').map(line => line.trim()).filter(Boolean).map(line => {
            const match = line.match(/^([^:]{2,45}):\s*(.+)$/);
            return match ? {label: match[1].replace(/^•\s*/, ''), value: match[2]} : null;
        }).filter(Boolean);
    }

    function renderKeyValueGrid(items, primaryLabel = '') {
        const grid = element('div', 'uoh-chat-data-grid');
        items.forEach(item => {
            const cell = element('div', `uoh-chat-data-item${primaryLabel && item.label.toLowerCase().includes(primaryLabel) ? ' is-primary' : ''}`);
            cell.append(element('small', '', item.label), element('strong', '', item.value));
            grid.append(cell);
        });
        return grid;
    }

    function renderFeeAnswer(text) {
        const items = parseKeyValues(text);
        if (items.length < 3) return null;
        const find = label => items.find(item => item.label.toLowerCase().includes(label));
        const total = find('total assessed') || find('total fee');
        const status = find('payment status');
        if (!total || !status) return null;
        const finance = element('div', 'uoh-chat-finance');
        const hero = element('div', 'uoh-chat-finance-hero');
        const amount = element('span');
        amount.append(element('small', '', 'Total Fee'), element('strong', '', total.value));
        hero.append(amount, element('span', 'uoh-chat-finance-state', status.value));
        finance.append(hero);
        const grid = element('div', 'uoh-chat-finance-grid');
        items.filter(item => item !== total && item !== status).forEach(item => {
            const cell = element('div', 'uoh-chat-finance-item');
            cell.append(element('small', '', item.label.replace(' amount', '')), element('strong', '', item.value));
            grid.append(cell);
        });
        finance.append(grid);
        return finance;
    }

    function renderAttendanceAnswer(text) {
        const rows = text.split('\n').map(line => line.trim()).filter(line => line.startsWith('•'));
        const parsed = rows.map(line => line.match(/^•\s*(.+?):\s*([\d.]+)%\s*[—-]\s*(.+)$/)).filter(Boolean);
        if (!parsed.length) return null;
        const list = element('div', 'uoh-chat-attendance-list');
        parsed.forEach(match => {
            const percent = Math.max(0, Math.min(100, Number(match[2])));
            const row = element('div', `uoh-chat-attendance-row${percent < 75 ? ' is-low' : ''}`);
            const heading = element('div', 'uoh-chat-attendance-heading');
            heading.append(element('strong', '', match[1]), element('span', '', `${percent.toFixed(1)}%`));
            const progress = element('div', 'uoh-chat-progress');
            const fill = element('i');
            fill.style.width = `${percent}%`;
            progress.append(fill);
            row.append(heading, progress, element('small', '', match[3]));
            list.append(row);
        });
        return list;
    }

    function renderPolicyAnswer(text) {
        const paragraphs = text.split(/\n\s*\n/).map(item => item.trim()).filter(Boolean);
        if (!paragraphs.length || !/(policy|responsibilities|rules|procedure)/i.test(text)) return null;
        const headline = paragraphs.shift();
        const match = headline.match(/^(.*?)\s*\(([^,]+)(?:,\s*version\s*([^)]*))?\)$/i);
        const policy = element('div', 'uoh-chat-policy');
        const head = element('div', 'uoh-chat-policy-head');
        const fileIcon = element('span', 'uoh-chat-policy-icon');
        fileIcon.append(icon(paths.file));
        const title = element('span');
        title.append(element('small', '', match ? `Policy ID · ${match[2]}` : 'University Policy'), element('strong', '', match ? match[1] : headline));
        head.append(fileIcon, title);
        const body = element('div', 'uoh-chat-policy-body');
        if (match?.[3]) body.append(element('p', '', `Version ${match[3]}`));
        paragraphs.forEach(paragraph => {
            const section = paragraph.match(/^([^:]+):\s*(.+)$/s);
            const p = element('p');
            if (section) p.append(element('strong', '', `${section[1]}: `), document.createTextNode(section[2]));
            else p.textContent = paragraph;
            body.append(p);
        });
        policy.append(head, body);
        return policy;
    }

    function renderAcademicAnswer(text, sources) {
        const cgpa = text.match(/current CGPA (?:is|of)\s*([\d.]+)/i);
        const academicStatus = text.match(/academic status (?:is\s*)?([^.]+)/i);
        if (cgpa) {
            const items = [{label: 'Current CGPA', value: cgpa[1]}];
            if (academicStatus) items.push({label: 'Academic Status', value: academicStatus[1]});
            return renderKeyValueGrid(items, 'current cgpa');
        }
        const keyValues = parseKeyValues(text);
        const sourceType = sources?.[0]?.type || '';
        if (keyValues.length >= 3 && ['result', 'student_record', 'employee_record'].includes(sourceType)) return renderKeyValueGrid(keyValues, keyValues[0].label.toLowerCase());
        return null;
    }

    function renderEditorialAnswer(text) {
        const wrapper = element('div');
        const blocks = text.split(/\n\s*\n/).map(item => item.trim()).filter(Boolean);
        blocks.forEach(block => {
            const lines = block.split('\n').map(line => line.trim()).filter(Boolean);
            const bulletLines = lines.filter(line => /^•\s*/.test(line));
            if (bulletLines.length === lines.length) {
                const list = document.createElement('ul');
                bulletLines.forEach(line => list.append(element('li', '', line.replace(/^•\s*/, ''))));
                wrapper.append(list);
            } else if (lines.length > 1 && bulletLines.length) {
                const lead = lines.filter(line => !line.startsWith('•')).join(' ');
                if (lead) wrapper.append(element('p', '', lead));
                const list = document.createElement('ul');
                bulletLines.forEach(line => list.append(element('li', '', line.replace(/^•\s*/, ''))));
                wrapper.append(list);
            } else wrapper.append(element('p', '', lines.join('\n')));
        });
        return wrapper;
    }

    function renderStatusPanel(text, status) {
        const type = status === 'access_restricted' ? 'restricted' : 'not-found';
        const card = element('div', `uoh-chat-status-panel ${type}`);
        card.append(icon(status === 'access_restricted' ? paths.lock : status === 'unavailable' ? paths.info : paths.search));
        const title = status === 'access_restricted' ? 'Access Restricted' : status === 'unavailable' ? 'University Assistant is temporarily unavailable' : 'Information Not Found';
        const copy = status === 'access_restricted'
            ? `This information is not available through your current ${context === 'public' ? 'public' : `${context[0].toUpperCase()}${context.slice(1)} Portal`} access.`
            : status === 'unavailable' ? 'Please try again shortly.' : (text || 'No matching information was found in the University records available to you.');
        card.append(element('strong', '', title), element('p', '', copy));
        return card;
    }

    function renderAnswer(container, text, options) {
        if (['access_restricted', 'insufficient_data', 'unavailable'].includes(options.status)) {
            container.append(renderStatusPanel(text, options.status));
            return;
        }
        const sourceType = options.sources?.[0]?.type || '';
        let structured = sourceType === 'fee' ? renderFeeAnswer(text) : null;
        if (!structured && sourceType === 'attendance') structured = renderAttendanceAnswer(text);
        if (!structured && sourceType === 'policy') structured = renderPolicyAnswer(text);
        if (!structured) structured = renderAcademicAnswer(text, options.sources);
        container.append(structured || renderEditorialAnswer(text));
    }

    async function copyAnswer(text, button) {
        try { await navigator.clipboard.writeText(text); button.lastChild.textContent = 'Copied'; }
        catch (_) { button.lastChild.textContent = 'Unavailable'; }
    }

    async function submitFeedback(messageId, rating, reason = null, comment = null) {
        const response = await fetch(`/api/university/chat/messages/${messageId}/feedback`, {
            method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({rating, reason, comment})
        });
        const data = await response.json();
        if (!response.ok) throw new Error(data.detail || 'Feedback could not be recorded.');
        return data.message;
    }

    function actionButton(label, path, ariaLabel = label) {
        const button = element('button');
        button.type = 'button';
        button.setAttribute('aria-label', ariaLabel);
        button.append(icon(path), element('span', '', label));
        return button;
    }

    function renderMessage(role, text, options = {}) {
        const article = element('article', `uoh-chat-message ${role}`);
        if (role === 'assistant') article.append(crest('uoh-chat-avatar'));
        const bubble = element('div', 'uoh-chat-bubble');
        if (role === 'user') bubble.append(element('p', '', text));
        else {
            bubble.append(element('span', 'uoh-chat-assistant-name', 'University Assistant'));
            const answer = element('div', 'uoh-chat-answer');
            renderAnswer(answer, text, options);
            const label = visibleStatusLabel(options.status, options.sources, options.statusLabel);
            if (label) answer.append(element('span', `uoh-chat-status ${statusClass(options.status, options.sources)}`, label));
            renderSources(answer, options.sources, options.status);
            bubble.append(answer);
        }
        if (role === 'assistant' && options.messageId) {
            const actions = element('div', 'uoh-chat-message-actions');
            actions.append(element('span', 'uoh-chat-feedback-prompt', 'Was this helpful?'));
            const helpful = actionButton('Helpful', paths.check);
            const notHelpful = actionButton('Not helpful', paths.dislike);
            const copy = actionButton('Copy', paths.copy);
            helpful.addEventListener('click', async () => {
                try {
                    await submitFeedback(options.messageId, 'helpful');
                    helpful.lastChild.textContent = 'Feedback recorded';
                    helpful.disabled = true;
                    notHelpful.disabled = true;
                } catch (_) { helpful.lastChild.textContent = 'Try again'; }
            });
            notHelpful.addEventListener('click', () => {
                pendingFeedbackMessage = options.messageId;
                feedbackForm.hidden = false;
                feedbackForm.querySelector('input[name="uoh-feedback-reason"]:checked')?.focus();
            });
            copy.addEventListener('click', () => copyAnswer(text, copy));
            if (options.feedback === 'helpful') { helpful.lastChild.textContent = 'Feedback recorded'; helpful.disabled = true; notHelpful.disabled = true; }
            if (options.feedback === 'not_helpful') { notHelpful.lastChild.textContent = 'Feedback recorded'; helpful.disabled = true; notHelpful.disabled = true; }
            actions.append(helpful, notHelpful, copy);
            if (options.retry) {
                const retry = actionButton('Retry', paths.retry);
                retry.addEventListener('click', () => submitQuestion(lastQuestion));
                actions.append(retry);
            }
            bubble.append(actions);
        }
        article.append(bubble);
        messages.append(article);
        if (role === 'assistant') messages.scrollTop = Math.max(0, article.offsetTop - 10);
        else messages.scrollTop = messages.scrollHeight;
    }

    function beginLoading() {
        loadingLabel.textContent = 'Searching university records';
        loadingDetail.textContent = 'Reviewing authorized sources…';
        loading.hidden = false;
        loadingStageTimers = [
            window.setTimeout(() => { loadingDetail.textContent = 'Reviewing authorized sources…'; }, 450),
            window.setTimeout(() => { loadingLabel.textContent = 'Preparing response'; loadingDetail.textContent = 'Organizing the available University information…'; }, 1050)
        ];
    }

    function endLoading() {
        loadingStageTimers.forEach(window.clearTimeout);
        loadingStageTimers = [];
        loading.hidden = true;
    }

    async function submitQuestion(question) {
        const clean = (question || input.value).trim();
        if (!clean || send.disabled) return;
        lastQuestion = clean;
        renderMessage('user', clean);
        input.value = '';
        input.style.height = '';
        beginLoading();
        send.disabled = true;
        try {
            const response = await fetch(`/api/university/chat/${context}`, {
                method: 'POST', headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({question: clean, conversation_id: conversationId, current_page: root.dataset.currentPage, page_title: root.dataset.pageTitle})
            });
            const data = await response.json();
            if (!response.ok) throw new Error('The University Assistant is temporarily unavailable.');
            conversationId = data.conversation_id;
            renderMessage('assistant', data.answer, {
                messageId: data.message_id, sources: data.sources, status: data.status,
                statusLabel: data.status_label, retry: data.status === 'unavailable'
            });
        } catch (_) {
            renderMessage('assistant', '', {status: 'unavailable', statusLabel: statusLabel('unavailable'), retry: true});
        } finally {
            endLoading();
            send.disabled = false;
            input.focus();
        }
    }

    function resetMessages() {
        messages.replaceChildren();
        renderWelcome();
        renderSuggestions();
    }

    async function newConversation() {
        try {
            const response = await fetch(`/api/university/chat/${context}/conversations`, {
                method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({title: 'New conversation'})
            });
            const data = await response.json();
            if (!response.ok) throw new Error('A new conversation could not be created.');
            conversationId = data.id;
            historyPanel.hidden = true;
            resetMessages();
            input.focus();
        } catch (_) { renderMessage('assistant', '', {status: 'unavailable', statusLabel: statusLabel('unavailable')}); }
    }

    async function loadConversation(id) {
        const response = await fetch(`/api/university/chat/${context}/conversations/${id}`);
        const data = await response.json();
        if (!response.ok) throw new Error('Conversation could not be loaded.');
        conversationId = data.id;
        messages.replaceChildren();
        data.messages.forEach(item => renderMessage(item.role, item.content, {
            messageId: item.role === 'assistant' ? item.id : null,
            sources: item.sources, status: item.status, statusLabel: statusLabel(item.status), feedback: item.feedback
        }));
        historyPanel.hidden = true;
        input.focus();
    }

    function historyTime(value) {
        const date = new Date(value);
        const today = new Date();
        const yesterday = new Date();
        yesterday.setDate(today.getDate() - 1);
        const day = date.toDateString() === today.toDateString() ? 'Today' : date.toDateString() === yesterday.toDateString() ? 'Yesterday' : date.toLocaleDateString(undefined, {month: 'short', day: 'numeric'});
        return `${day} · ${date.toLocaleTimeString(undefined, {hour: 'numeric', minute: '2-digit'})}`;
    }

    async function loadHistory() {
        historyPanel.hidden = false;
        historyList.replaceChildren(element('p', '', 'Loading history…'));
        try {
            const response = await fetch(`/api/university/chat/${context}/conversations`);
            const data = await response.json();
            if (!response.ok) throw new Error('History could not be loaded.');
            historyList.replaceChildren();
            if (!data.conversations.length) historyList.append(element('p', '', 'No previous conversations. Start a new question when you are ready.'));
            data.conversations.forEach(item => {
                const row = element('div', `uoh-history-item${conversationId === item.id ? ' is-active' : ''}`);
                const open = element('button', 'uoh-history-item-main');
                open.type = 'button';
                open.append(element('strong', '', item.title), element('small', '', historyTime(item.updated_at)));
                const remove = element('button', 'uoh-history-delete', 'Delete');
                remove.type = 'button';
                remove.setAttribute('aria-label', `Delete ${item.title}`);
                open.addEventListener('click', () => loadConversation(item.id).catch(error => { historyList.prepend(element('p', '', error.message)); }));
                remove.addEventListener('click', async () => {
                    const response = await fetch(`/api/university/chat/${context}/conversations/${item.id}`, {method: 'DELETE'});
                    if (response.ok) {
                        if (conversationId === item.id) { conversationId = null; resetMessages(); }
                        loadHistory();
                    }
                });
                row.append(open, remove);
                historyList.append(row);
            });
        } catch (error) { historyList.replaceChildren(element('p', '', error.message)); }
    }

    function trapFocus(event) {
        if (event.key !== 'Tab' || panel.hidden) return;
        const focusable = [...panel.querySelectorAll('button:not([disabled]), textarea:not([disabled]), input:not([disabled]), a[href], summary')].filter(item => !item.closest('[hidden]'));
        if (!focusable.length) return;
        const first = focusable[0];
        const last = focusable[focusable.length - 1];
        if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
        else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
    }

    launcher.addEventListener('click', showPanel);
    closeButton.addEventListener('click', hidePanel);
    minimizeButton.addEventListener('click', hidePanel);
    newButton.addEventListener('click', newConversation);
    historyButton.addEventListener('click', loadHistory);
    root.querySelector('[data-history-close]').addEventListener('click', () => { historyPanel.hidden = true; input.focus(); });
    form.addEventListener('submit', event => { event.preventDefault(); submitQuestion(); });
    input.addEventListener('input', () => { input.style.height = 'auto'; input.style.height = `${Math.min(input.scrollHeight, 116)}px`; });
    input.addEventListener('keydown', event => {
        if (event.key === 'Enter' && !event.shiftKey) { event.preventDefault(); submitQuestion(); }
    });
    document.addEventListener('keydown', event => {
        if (event.key === 'Escape' && !panel.hidden) hidePanel();
        else trapFocus(event);
    });
    root.querySelector('[data-feedback-cancel]').addEventListener('click', () => { feedbackForm.hidden = true; pendingFeedbackMessage = null; input.focus(); });
    root.querySelector('[data-feedback-submit]').addEventListener('click', async event => {
        if (!pendingFeedbackMessage) return;
        const reason = root.querySelector('input[name="uoh-feedback-reason"]:checked')?.value || 'Other';
        const comment = root.querySelector('[data-feedback-comment]').value;
        try {
            await submitFeedback(pendingFeedbackMessage, 'not_helpful', reason, comment);
            event.currentTarget.textContent = 'Feedback recorded';
            window.setTimeout(() => {
                feedbackForm.hidden = true;
                event.currentTarget.textContent = 'Submit Feedback';
                input.focus();
            }, 900);
        } catch (_) { event.currentTarget.textContent = 'Please try again'; }
    });

    window.setTimeout(() => root.classList.add('label-collapsed'), 4800);
    resetMessages();
})();
