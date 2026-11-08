/**
 * Security Operations Center (SOC) Admin Dashboard Visualizations
 * Renders Chart.js charts and handles live audit log filtering.
 */

let activityChartInstance = null;
let statusChartInstance = null;
let strengthChartInstance = null;

async function loadDashboardCharts() {
  try {
    const response = await fetch('/api/security-stats');
    if (!response.ok) return;

    const stats = await response.json();
    renderActivityChart(stats.daily_stats || []);
    renderStatusChart(stats.success_count || 0, stats.failed_count || 0, stats.blocked_count || 0);
    renderStrengthChart(stats.strength_dist || {});
  } catch (err) {
    console.error('Failed to load chart metrics:', err);
  }
}

function renderActivityChart(dailyStats) {
  const ctx = document.getElementById('activityChart');
  if (!ctx) return;

  const labels = dailyStats.map(item => item.day);
  const successData = dailyStats.map(item => item.success);
  const failedData = dailyStats.map(item => item.failed);

  if (activityChartInstance) {
    activityChartInstance.destroy();
  }

  activityChartInstance = new Chart(ctx, {
    type: 'line',
    data: {
      labels: labels.length > 0 ? labels : ['Day 1', 'Day 2', 'Day 3', 'Day 4', 'Day 5'],
      datasets: [
        {
          label: 'Successful Authentications',
          data: successData.length > 0 ? successData : [10, 15, 12, 18, 14],
          borderColor: '#10b981',
          backgroundColor: 'rgba(16, 185, 129, 0.1)',
          fill: true,
          tension: 0.35,
          borderWidth: 2,
          pointBackgroundColor: '#10b981'
        },
        {
          label: 'Failed / Attacker Attempts',
          data: failedData.length > 0 ? failedData : [2, 5, 8, 3, 11],
          borderColor: '#ef4444',
          backgroundColor: 'rgba(239, 68, 68, 0.1)',
          fill: true,
          tension: 0.35,
          borderWidth: 2,
          pointBackgroundColor: '#ef4444'
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          labels: { color: '#9ca3af' }
        }
      },
      scales: {
        x: {
          ticks: { color: '#6b7280' },
          grid: { color: 'rgba(255, 255, 255, 0.05)' }
        },
        y: {
          beginAtZero: true,
          ticks: { color: '#6b7280', precision: 0 },
          grid: { color: 'rgba(255, 255, 255, 0.05)' }
        }
      }
    }
  });
}

function renderStatusChart(success, failed, blocked) {
  const ctx = document.getElementById('statusChart');
  if (!ctx) return;

  if (statusChartInstance) {
    statusChartInstance.destroy();
  }

  statusChartInstance = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: ['Successful', 'Invalid Password / User', 'Blocked (Lockout)'],
      datasets: [{
        data: [success, failed, blocked],
        backgroundColor: ['#10b981', '#ef4444', '#f59e0b'],
        borderWidth: 0,
        hoverOffset: 6
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          position: 'bottom',
          labels: { color: '#9ca3af', boxWidth: 12, padding: 15 }
        }
      },
      cutout: '70%'
    }
  });
}

function renderStrengthChart(strengthDist) {
  const ctx = document.getElementById('strengthChart');
  if (!ctx) return;

  const categories = ['Very Weak', 'Weak', 'Moderate', 'Strong', 'Very Strong'];
  const counts = categories.map(cat => strengthDist[cat] || 0);

  if (strengthChartInstance) {
    strengthChartInstance.destroy();
  }

  strengthChartInstance = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: categories,
      datasets: [{
        label: 'User Accounts',
        data: counts,
        backgroundColor: [
          'rgba(239, 68, 68, 0.8)',
          'rgba(249, 115, 22, 0.8)',
          'rgba(245, 158, 11, 0.8)',
          'rgba(59, 130, 246, 0.8)',
          'rgba(16, 185, 129, 0.8)'
        ],
        borderRadius: 6
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false }
      },
      scales: {
        x: {
          ticks: { color: '#9ca3af' },
          grid: { display: false }
        },
        y: {
          beginAtZero: true,
          ticks: { color: '#6b7280', precision: 0 },
          grid: { color: 'rgba(255, 255, 255, 0.05)' }
        }
      }
    }
  });
}

// ----------------- Dynamic Audit Log Filtering -----------------

async function filterAuditLogs() {
  const searchInput = document.getElementById('logSearchInput');
  const statusSelect = document.getElementById('logStatusFilter');
  const tableBody = document.getElementById('auditLogsTableBody');
  if (!tableBody) return;

  const search = searchInput ? searchInput.value.trim() : '';
  const status = statusSelect ? statusSelect.value : '';

  try {
    let url = `/api/audit-logs?limit=50`;
    if (search) url += `&search=${encodeURIComponent(search)}`;
    if (status) url += `&status=${encodeURIComponent(status)}`;

    const response = await fetch(url);
    if (!response.ok) return;

    const logs = await response.json();
    if (logs.length === 0) {
      tableBody.innerHTML = '<tr><td colspan="6" class="text-center text-muted py-4">No matching audit events found.</td></tr>';
      return;
    }

    let html = '';
    logs.forEach(log => {
      let badgeClass = 'badge-status-failed';
      if (log.status === 'SUCCESS') badgeClass = 'badge-status-success';
      else if (log.status === 'BLOCKED_LOCKED') badgeClass = 'badge-status-locked';

      html += `
        <tr>
          <td><span class="small text-muted font-monospace">${log.timestamp}</span></td>
          <td><strong class="text-light">${log.username}</strong></td>
          <td><code class="text-info">${log.ip_address}</code></td>
          <td><span class="${badgeClass}">${log.status}</span></td>
          <td><span class="small text-muted">${log.failure_reason || '—'}</span></td>
          <td><span class="small text-dim text-truncate d-inline-block" style="max-width: 220px;" title="${log.user_agent}">${log.user_agent}</span></td>
        </tr>
      `;
    });
    tableBody.innerHTML = html;
  } catch (err) {
    console.error('Failed to filter logs:', err);
  }
}

document.addEventListener('DOMContentLoaded', () => {
  loadDashboardCharts();

  const searchInput = document.getElementById('logSearchInput');
  if (searchInput) {
    searchInput.addEventListener('input', debounce(filterAuditLogs, 250));
  }

  const statusSelect = document.getElementById('logStatusFilter');
  if (statusSelect) {
    statusSelect.addEventListener('change', filterAuditLogs);
  }
});
