/* LIVE CLOCK */

function updateClock() {

    const clock = document.getElementById("live-clock");

    if (clock) {

        const now = new Date();

        const date = now.toLocaleDateString(undefined, {
            year: 'numeric',
            month: 'long',
            day: 'numeric'
        });

        const time = now.toLocaleTimeString();

        clock.innerHTML = `${date} | ${time}`;
    }
}

setInterval(updateClock, 1000);
updateClock();


/* SYSTEM STATUS ROTATOR */

const statuses = [
    "AI Surveillance Active",
    "Monitoring CCTV Channels",
    "Firewall Protection Enabled",
    "Threat Detection Running",
    "Scanning Unauthorized Access",
    "All Systems Operational"
];

let statusIndex = 0;

function rotateStatus() {

    const status = document.getElementById("system-status");

    if (status) {

        status.innerHTML = statuses[statusIndex];

        statusIndex++;

        if (statusIndex >= statuses.length) {
            statusIndex = 0;
        }
    }
}

setInterval(rotateStatus, 4000);


/* AUTO REFRESH ALERTS */

setInterval(() => {

    fetch(window.location.href)
        .then(response => response.text())
        .then(html => {

            const parser = new DOMParser();
            const doc = parser.parseFromString(html, 'text/html');

            const newAlerts =
                doc.querySelector('.alerts-list');

            const currentAlerts =
                document.querySelector('.alerts-list');

            if (newAlerts && currentAlerts) {
                currentAlerts.innerHTML =
                    newAlerts.innerHTML;
            }
        });

}, 5000);


/* LIVE CAMERA STATUS */

function checkCameraFeed() {

    const camera =
        document.querySelector(".camera-feed");

    const cameraStatus =
        document.getElementById("camera-status");

    if (!camera || !cameraStatus) return;

    camera.onload = () => {
        cameraStatus.innerHTML = "CAMERA ONLINE";
        cameraStatus.style.color = "#22c55e";
    };

    camera.onerror = () => {
        cameraStatus.innerHTML = "CAMERA OFFLINE";
        cameraStatus.style.color = "#ef4444";
    };
}

checkCameraFeed();


/* THREAT ALERT SOUND */

function playThreatAlert() {

    const audio = new Audio(
        "https://assets.mixkit.co/active_storage/sfx/2869/2869-preview.mp3"
    );

    audio.volume = 0.3;

    audio.play();
}


/* DETECT NEW FAILED LOGIN */

let previousFailedCount = 0;

function monitorThreats() {

    const failedCard =
        document.querySelector(".stat-card.red h1");

    if (!failedCard) return;

    const currentFailed =
        parseInt(failedCard.innerText);

    if (currentFailed > previousFailedCount &&
        previousFailedCount !== 0) {

        playThreatAlert();

        showNotification(
            "Unauthorized login attempt detected!"
        );
    }

    previousFailedCount = currentFailed;
}

setInterval(monitorThreats, 4000);


/* CYBER NOTIFICATION SYSTEM */

function showNotification(message) {

    const notification =
        document.createElement("div");

    notification.className = "cyber-notification";

    notification.innerHTML = `
        ⚠ ${message}
    `;

    document.body.appendChild(notification);

    setTimeout(() => {
        notification.classList.add("show");
    }, 100);

    setTimeout(() => {

        notification.classList.remove("show");

        setTimeout(() => {
            notification.remove();
        }, 500);

    }, 4000);
}