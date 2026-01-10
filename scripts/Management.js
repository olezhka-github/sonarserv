// DOM готовий
document.addEventListener('DOMContentLoaded', function() {
    const domName = document.getElementById('dom-username');
    
    fetch("/api/me", { credentials: "include" })
        .then(response => response.json())
        .then(data => {
            if (data.success && domName) {
                domName.textContent = `Вітання, ${data.user.username}`;
            }
        })
        .catch(() => {});

    а
    
});
