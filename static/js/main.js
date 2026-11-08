/**
 * Global UI Helper scripts
 */

document.addEventListener('DOMContentLoaded', () => {
  // Auto dismiss flash alerts after 6 seconds
  setTimeout(() => {
    const alerts = document.querySelectorAll('.alert-dismissible');
    alerts.forEach(alert => {
      const bsAlert = bootstrap.Alert.getOrCreateInstance(alert);
      if (bsAlert) bsAlert.close();
    });
  }, 6000);
});
