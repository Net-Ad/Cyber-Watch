/* --- REVISED LIVE CLOCK (Sidebar) --- */
function updateClock() {
    const clock = document.getElementById("live-clock");
    if (clock) {
        const now = new Date();
        const dateStr = now.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
        const timeStr = now.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: true });
        clock.innerHTML = `${dateStr} <br> ${timeStr}`;
    }
}
setInterval(updateClock, 1000);
updateClock();

/* --- SYSTEM STATUS ROTATOR --- */
const statuses = [
    "All systems nominal — no active threats detected",
    "AI Surveillance Active — Monitoring CCTV Channels",
    "Firewall Protection Enabled — Scanning Networks",
    "Threat Detection Running — Analyzing Traffic"
];
let statusIndex = 0;

function rotateStatus() {
    const statusSpan = document.querySelector(".system-nominal-banner span");
    if (statusSpan) {
        statusIndex = (statusIndex + 1) % statuses.length;
        statusSpan.textContent = statuses[statusIndex];
    }
}
setInterval(rotateStatus, 5000);

/* --- LIVE CAMERA STATUS --- */
function checkCameraFeed() {
    const camera = document.querySelector(".camera-feed");
    const statusText = document.querySelector(".header-left .status-text");
    const statusDot = document.querySelector(".header-left .status-dot");

    if (!camera || !statusText || !statusDot) return;

    camera.onload = () => {
        statusText.textContent = "Camera online";
        statusText.className = "status-text green-text";
        statusDot.className = "status-dot green";
    };

    camera.onerror = () => {
        statusText.textContent = "Camera offline";
        statusText.className = "status-text red-text";
        statusDot.className = "status-dot red";
    };
}
checkCameraFeed();

/* --- THREAT ALERT SOUND & NOTIFICATION --- */
let previousFailedCount = null;

function playThreatAlert() {
    const audio = new Audio("https://assets.mixkit.co/active_storage/sfx/2869/2869-preview.mp3");
    audio.volume = 0.3;
    audio.play().catch(e => console.log("Audio blocked by browser policy"));
}

function showNotification(message) {
    const notification = document.createElement("div");
    notification.className = "cyber-notification";
    notification.innerHTML = `⚠ ${message}`;
    document.body.appendChild(notification);

    setTimeout(() => { notification.classList.add("show"); }, 100);
    setTimeout(() => {
        notification.classList.remove("show");
        setTimeout(() => { notification.remove(); }, 500);
    }, 4000);
}

/* --- SSE: LIVE REAL-TIME UPDATES --- */
(function initSSE() {
    if (!window.EventSource) {
        console.warn("SSE not supported, falling back to polling");
        startPollingFallback();
        return;
    }

    const es = new EventSource("/stream");
    let reconnectDelay = 2000;

    es.addEventListener("open", () => {
        reconnectDelay = 2000;
        console.log("[SSE] connected");
    });

    /* ---- new_log: prepend a row to the alerts list / logs table ---- */
    es.addEventListener("new_log", (e) => {
        const log = JSON.parse(e.data);

        // Flash indicator in tab title
        const origTitle = document.title;
        document.title = "⚡ " + origTitle;
        setTimeout(() => { document.title = origTitle; }, 2000);

        // --- Dashboard: alerts list ---
        const alertsList = document.querySelector(".alerts-list");
        if (alertsList) {
            const isSuccess = log.status === "SUCCESS";
            const isRed    = log.status === "RED_LOGOUT";

            const dotClass  = isSuccess ? "green" : (isRed ? "red" : "yellow");
            const badgeHtml = isRed
                ? `<span class="badge critical" style="min-width:15px;height:15px;padding:0;border-radius:50%;"></span>`
                : `<span class="badge ${isSuccess ? "ok" : "warn"}">${isSuccess ? "Success" : "Warning"}</span>`;

            const item = document.createElement("div");
            item.className = "alert-item sse-new";
            item.innerHTML = `
                <div class="status-indicator ${dotClass}"></div>
                <div class="alert-content">
                    <div class="alert-title-row">
                        <h4>${log.event_type}</h4>
                        ${badgeHtml}
                    </div>
                    <p class="alert-sub">${log.device_id}</p>
                </div>
                <div class="alert-time-col">
                    <span>${log.date_only}</span>
                    <span>${log.time_only}</span>
                </div>`;

            alertsList.insertBefore(item, alertsList.firstChild);
            // trim to 7
            while (alertsList.children.length > 7) {
                alertsList.removeChild(alertsList.lastChild);
            }
            // highlight then settle
            setTimeout(() => item.classList.remove("sse-new"), 1500);
        }

        // --- Threat Logs: prepend to table body ---
        const tbody = document.getElementById("logsTableBody");
        if (tbody) {
            const isSuccess = log.status === "SUCCESS";
            const isRed    = log.status === "RED_LOGOUT";

            const badgeHtml = isRed
                ? `<span class="badge critical" style="min-width:15px;height:15px;padding:0;border-radius:50%;"></span>`
                : `<span class="badge ${isSuccess ? "ok" : "critical"}">${log.status}</span>`;

            const tr = document.createElement("tr");
            tr.className = "log-row sse-new";
            tr.setAttribute("data-status", log.status);
            tr.innerHTML = `
                <td class="text-clip" style="color:var(--text-muted)">${log.device_id}</td>
                <td>${log.event_type}</td>
                <td>${badgeHtml}</td>
                <td>${log.created_at}</td>`;

            tbody.insertBefore(tr, tbody.firstChild);
            while (tbody.children.length > 50) {
                tbody.removeChild(tbody.lastChild);
            }
            setTimeout(() => tr.classList.remove("sse-new"), 1500);

            // update result count
            const countText = document.querySelector(".results-count");
            if (countText) {
                const vis = tbody.querySelectorAll("tr:not([style*='none'])").length;
                countText.textContent = `${vis} results`;
            }
        }

        // Threat alert notification for failed logins
        if (log.status === "FAILED" || log.status === "BLOCKED" || log.status === "ALERT") {
            playThreatAlert();
            showNotification("Unauthorized access attempt detected!");
        }
    });

    /* ---- counts: update stat cards live ---- */
    es.addEventListener("counts", (e) => {
        const c = JSON.parse(e.data);

        // Dashboard stat cards
        const cards = document.querySelectorAll(".stat-card h1");
        if (cards.length >= 3) {
            // Card order: Today's access, Unauthorized, Blocked devices
            const todayEl  = document.querySelector(".stats-grid .stat-card:nth-child(1) h1");
            const failEl   = document.querySelector(".stats-grid .stat-card:nth-child(2) h1");
            const blockEl  = document.querySelector(".stats-grid .stat-card:nth-child(3) h1");

            if (todayEl)  todayEl.textContent  = c.today_access;
            if (failEl)   failEl.textContent   = c.unauthorized;
            if (blockEl)  blockEl.textContent  = c.unique_attackers;

            // Trigger warning sound if unauthorized count grew
            if (previousFailedCount !== null && c.unauthorized > previousFailedCount) {
                playThreatAlert();
                showNotification("Unauthorized access attempt detected!");
            }
            previousFailedCount = c.unauthorized;
        }

        // Analytics stat cards
        const analyticsCards = document.querySelectorAll(".analytics-stats-grid .stat-card h1");
        if (analyticsCards.length >= 3) {
            analyticsCards[0].textContent = c.success_count;
            analyticsCards[1].textContent = c.failed_count;
            analyticsCards[2].textContent = c.blocked_count;
        }
    });

    es.onerror = () => {
        console.warn("[SSE] connection lost, will retry...");
    };
})();

/* --- Polling fallback (no EventSource) --- */
function startPollingFallback() {
    setInterval(() => {
        fetch(window.location.href)
            .then(r => r.text())
            .then(html => {
                const parser = new DOMParser();
                const doc = parser.parseFromString(html, 'text/html');
                const newAlerts = doc.querySelector('.alerts-list');
                const currentAlerts = document.querySelector('.alerts-list');
                if (newAlerts && currentAlerts) {
                    currentAlerts.innerHTML = newAlerts.innerHTML;
                }
            })
            .catch(err => console.log("Refresh skipped or failed."));
    }, 5000);
}

/* --- THREAT LOGS FILTERING & SEARCH LOGIC --- */
document.addEventListener("DOMContentLoaded", () => {
    const filterPills = document.querySelectorAll('.filter-pill');
    const logRows = document.querySelectorAll('.log-row');
    const searchInput = document.getElementById('logSearch');
    const searchBtn = document.getElementById('searchBtn');
    const countText = document.querySelector('.results-count');

    if (logRows.length === 0) return;

    let currentStatusFilter = 'all';
    let currentSearchQuery = '';

    function applyFilters() {
        const allRows = document.querySelectorAll('.log-row'); // re-query to catch SSE-added rows
        let visibleCount = 0;
        allRows.forEach(row => {
            const rowStatus = row.getAttribute('data-status');
            const rowText = row.textContent.toLowerCase();
            const matchesStatus = (currentStatusFilter === 'all' || rowStatus === currentStatusFilter);
            const matchesSearch = (currentSearchQuery === '' || rowText.includes(currentSearchQuery));

            if (matchesStatus && matchesSearch) {
                row.style.display = '';
                visibleCount++;
            } else {
                row.style.display = 'none';
            }
        });
        if (countText) countText.textContent = `${visibleCount} results`;
    }

    if (filterPills.length > 0) {
        filterPills.forEach(pill => {
            pill.addEventListener('click', () => {
                filterPills.forEach(p => p.classList.remove('active'));
                pill.classList.add('active');
                currentStatusFilter = pill.getAttribute('data-filter');
                applyFilters();
            });
        });
    }

    if (searchInput && searchBtn) {
        searchBtn.addEventListener('click', () => {
            currentSearchQuery = searchInput.value.toLowerCase().trim();
            applyFilters();
        });
        searchInput.addEventListener('input', () => {
            currentSearchQuery = searchInput.value.toLowerCase().trim();
            applyFilters();
        });
    }
});
