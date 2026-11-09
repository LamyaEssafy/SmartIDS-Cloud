// main.js - Front-end logic for SmartIDS

document.addEventListener('DOMContentLoaded', function() {
    // Mode selection interaction
    const modeOptions = document.querySelectorAll('.mode-option');
    modeOptions.forEach(option => {
        option.addEventListener('click', function() {
            modeOptions.forEach(opt => opt.classList.remove('active'));
            this.classList.add('active');
            
            const radio = this.querySelector('input[type="radio"]');
            if (radio) {
                radio.checked = true;
            }
        });
    });

    // Drag and Drop Upload Zone
    const uploadZone = document.getElementById('upload-zone');
    const fileInput = document.getElementById('file-input');
    const uploadForm = document.getElementById('upload-form');

    if (uploadZone && fileInput) {
        // Highlight drag area
        ['dragenter', 'dragover'].forEach(eventName => {
            uploadZone.addEventListener(eventName, highlight, false);
        });

        ['dragleave', 'drop'].forEach(eventName => {
            uploadZone.addEventListener(eventName, unhighlight, false);
        });

        function highlight(e) {
            e.preventDefault();
            uploadZone.classList.add('dragover');
        }

        function unhighlight(e) {
            e.preventDefault();
            uploadZone.classList.remove('dragover');
        }

        // Handle dropped files
        uploadZone.addEventListener('drop', handleDrop, false);

        function handleDrop(e) {
            e.preventDefault();
            e.stopPropagation();
            let dt = e.dataTransfer;
            let files = dt.files;
            if (files && files.length > 0) {
                fileInput.files = files;
                updateUploadLabel(files[0].name);
            }
        }

        // Click to upload
        uploadZone.addEventListener('click', (e) => {
            if (e.target !== fileInput) {
                fileInput.click();
            }
        });

        fileInput.addEventListener('change', function() {
            if (this.files.length > 0) {
                updateUploadLabel(this.files[0].name);
            }
        });

        function updateUploadLabel(fileName) {
            const icon = uploadZone.querySelector('.upload-icon');
            const text = uploadZone.querySelector('.upload-text');
            const hint = uploadZone.querySelector('.upload-hint');
            
            if (icon && text && hint) {
                icon.className = 'fas fa-file-csv upload-icon';
                icon.style.color = 'var(--neon-blue)';
                text.textContent = 'Fichier sélectionné :';
                hint.textContent = fileName + ' (Cliquez ou glissez pour modifier)';
                hint.style.fontWeight = '600';
                hint.style.color = 'var(--color-text)';
            }
        }
    }

    // Auto submit form on file selection if desired or let user click button
    // We will let the user click the Analyse button.
});

// Chart Rendering Function (Called in result.html)
function renderResultsChart(normalCount, attackCount, multiData = null) {
    const ctx = document.getElementById('resultsChart');
    if (!ctx) return;

    if (multiData) {
        // Multiclass chart
        const labels = Object.keys(multiData);
        const data = Object.values(multiData);
        
        // Colors based on threats
        const backgroundColors = labels.map(label => {
            const l = label.toLowerCase();
            if (l === 'normal') return 'rgba(0, 255, 136, 0.8)';
            if (l === 'dos') return 'rgba(255, 0, 85, 0.8)';
            if (l === 'probe') return 'rgba(0, 240, 255, 0.8)';
            if (l === 'r2l') return 'rgba(245, 158, 11, 0.8)';
            if (l === 'u2r') return 'rgba(139, 92, 246, 0.8)';
            return 'rgba(148, 163, 184, 0.8)';
        });

        const borderColors = labels.map(label => {
            const l = label.toLowerCase();
            if (l === 'normal') return '#00ff88';
            if (l === 'dos') return '#ff0055';
            if (l === 'probe') return '#00f0ff';
            if (l === 'r2l') return '#f59e0b';
            if (l === 'u2r') return '#8b5cf6';
            return '#94a3b8';
        });

        new Chart(ctx, {
            type: 'bar',
            data: {
                labels: labels,
                datasets: [{
                    label: 'Nombre de connexions',
                    data: data,
                    backgroundColor: backgroundColors,
                    borderColor: borderColors,
                    borderWidth: 1.5,
                    borderRadius: 6
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        display: false
                    }
                },
                scales: {
                    y: {
                        grid: {
                            color: 'rgba(0, 0, 0, 0.06)'
                        },
                        ticks: {
                            color: '#64748b',
                            precision: 0
                        }
                    },
                    x: {
                        grid: {
                            display: false
                        },
                        ticks: {
                            color: '#64748b'
                        }
                    }
                }
            }
        });
    } else {
        // Binary chart (pie/doughnut)
        new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: ['Normal', 'Attaque'],
                datasets: [{
                    data: [normalCount, attackCount],
                    backgroundColor: [
                        'rgba(0, 255, 136, 0.85)',
                        'rgba(255, 0, 85, 0.85)'
                    ],
                    borderColor: [
                        '#00ff88',
                        '#ff0055'
                    ],
                    borderWidth: 1.5
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: {
                            color: '#475569',
                            padding: 20,
                            font: {
                                size: 13
                            }
                        }
                    }
                },
                cutout: '70%'
            }
        });
    }
}
