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

/* --- AUTO REFRESH ALERTS (Dashboard Only) --- */
setInterval(() => {
    fetch(window.location.href)
        .then(response => response.text())
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
let previousFailedCount = 0;

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

function monitorThreats() {
    const failedCard = document.querySelector(".stat-card.border-red h1");
    if (!failedCard) return;

    const currentFailed = parseInt(failedCard.innerText) || 0;

    if (currentFailed > previousFailedCount && previousFailedCount !== 0) {
        playThreatAlert();
        showNotification("Unauthorized access attempt detected!");
    }
    previousFailedCount = currentFailed;
}
setInterval(monitorThreats, 4000);

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
        let visibleCount = 0;
        logRows.forEach(row => {
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
