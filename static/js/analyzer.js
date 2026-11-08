/**
 * Password Strength Analyzer & Security Evaluation Engine
 * Handles real-time API calls, entropy visualization, pattern detection UI,
 * crack-time estimation updates, and password generation.
 */

let debounceTimer = null;

function debounce(func, wait = 150) {
  return function (...args) {
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(() => func.apply(this, args), wait);
  };
}

// ----------------- Real-time Strength Evaluation -----------------

async function evaluatePassword(password) {
  try {
    const response = await fetch('/api/analyze-password', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ password: password })
    });

    if (!response.ok) {
      console.error('API response error', response.status);
      return;
    }

    const data = await response.json();
    renderAnalysisResults(data, password);
  } catch (err) {
    console.error('Failed to analyze password:', err);
  }
}

function renderAnalysisResults(data, rawPassword) {
  // 1. Score and Meter
  const score = data.score || 0;
  const category = data.category || 'Very Weak';
  const color = data.color || 'danger';
  
  const scoreBar = document.getElementById('strengthMeterBar');
  const scoreBadge = document.getElementById('strengthScoreBadge');
  const scoreText = document.getElementById('strengthScoreText');
  
  if (scoreBar) {
    scoreBar.style.width = `${Math.max(5, score)}%`;
    scoreBar.className = `strength-meter-fill meter-${color}`;
  }

  if (scoreBadge) {
    scoreBadge.textContent = `${score}/100`;
    scoreBadge.className = `badge bg-${color === 'orange' ? 'warning text-dark' : color} fs-6`;
  }

  if (scoreText) {
    scoreText.textContent = category;
  }

  // 2. Entropy Statistics
  const theorElem = document.getElementById('theorEntropy');
  const shannonElem = document.getElementById('shannonEntropy');
  const effEntropyElem = document.getElementById('effectiveEntropy');
  const poolSizeElem = document.getElementById('poolSize');

  if (theorElem) theorElem.textContent = `${data.theoretical_entropy} bits`;
  if (shannonElem) shannonElem.textContent = `${data.shannon_entropy} bits/char`;
  if (effEntropyElem) effEntropyElem.textContent = `${data.effective_entropy} bits`;
  if (poolSizeElem) poolSizeElem.textContent = `${data.pool_size} chars`;

  // 3. Checklist Items
  const checklist = data.checklist || {};
  updateChecklistElement('checkLength8', checklist.length_8);
  updateChecklistElement('checkLength12', checklist.length_12);
  updateChecklistElement('checkLower', checklist.has_lower);
  updateChecklistElement('checkUpper', checklist.has_upper);
  updateChecklistElement('checkDigits', checklist.has_digits);
  updateChecklistElement('checkSymbols', checklist.has_symbols);
  updateChecklistElement('checkNoDict', checklist.no_dictionary_words);
  updateChecklistElement('checkNoPatterns', checklist.no_patterns);

  // 4. Crack Times
  if (data.crack_times) {
    updateCrackTime('crackFastGpu', data.crack_times.offline_fast_gpu);
    updateCrackTime('crackBcrypt', data.crack_times.offline_bcrypt);
    updateCrackTime('crackUnthrottled', data.crack_times.online_unthrottled);
    updateCrackTime('crackThrottled', data.crack_times.online_throttled);
  }

  // 5. Detected Patterns
  const patternsContainer = document.getElementById('detectedPatternsList');
  if (patternsContainer) {
    if (!data.patterns || data.patterns.length === 0) {
      patternsContainer.innerHTML = '<span class="text-success small"><i class="bi bi-shield-check me-1"></i>No predictable sequences or keyboard walks detected.</span>';
    } else {
      let html = '';
      data.patterns.forEach(pat => {
        const badgeColor = pat.severity === 'HIGH' ? 'danger' : 'warning';
        html += `
          <div class="mb-2 p-2 rounded" style="background: rgba(239, 68, 68, 0.08); border-left: 3px solid #ef4444;">
            <div class="d-flex justify-content-between align-items-center">
              <strong class="text-light small">${pat.name}</strong>
              <span class="badge bg-${badgeColor} text-uppercase" style="font-size: 0.65rem;">-${pat.penalty} pts</span>
            </div>
            <div class="text-muted small mt-1">${pat.description}</div>
          </div>
        `;
      });
      patternsContainer.innerHTML = html;
    }
  }

  // 6. Dictionary Match Notification
  const dictAlertElem = document.getElementById('dictionaryAlert');
  if (dictAlertElem) {
    const dict = data.dictionary_analysis || {};
    if (dict.is_exact_match) {
      dictAlertElem.className = 'alert alert-danger py-2 px-3 small mb-3';
      dictAlertElem.innerHTML = `<i class="bi bi-exclamation-triangle-fill me-1"></i><strong>Blacklisted:</strong> Matches known weak/leaked password: "<code>${dict.matched_word}</code>".`;
      dictAlertElem.style.display = 'block';
    } else if (dict.is_substring_match) {
      dictAlertElem.className = 'alert alert-warning py-2 px-3 small mb-3';
      dictAlertElem.innerHTML = `<i class="bi bi-exclamation-circle-fill me-1"></i><strong>Dictionary hit:</strong> Contains common word stem: "<code>${dict.substring_matches.join(', ')}</code>".`;
      dictAlertElem.style.display = 'block';
    } else {
      dictAlertElem.style.display = 'none';
    }
  }

  // 7. Feedback & Recommendations
  const feedbackList = document.getElementById('feedbackList');
  if (feedbackList) {
    if (!data.feedback || data.feedback.length === 0) {
      feedbackList.innerHTML = '<li class="text-success small"><i class="bi bi-check-circle-fill me-2"></i>Meets high security standards.</li>';
    } else {
      let items = '';
      data.feedback.forEach(item => {
        items += `<li class="small text-muted mb-1"><i class="bi bi-arrow-right-circle text-info me-2"></i>${item}</li>`;
      });
      feedbackList.innerHTML = items;
    }
  }
}

function updateChecklistElement(elemId, isValid) {
  const elem = document.getElementById(elemId);
  if (!elem) return;

  const icon = elem.querySelector('i');
  if (isValid) {
    elem.classList.remove('invalid');
    elem.classList.add('valid');
    if (icon) {
      icon.className = 'bi bi-check-circle-fill text-success';
    }
  } else {
    elem.classList.remove('valid');
    elem.classList.add('invalid');
    if (icon) {
      icon.className = 'bi bi-circle text-muted';
    }
  }
}

function updateCrackTime(elemId, crackData) {
  const container = document.getElementById(elemId);
  if (!container || !crackData) return;

  const timeVal = container.querySelector('.time-value');
  if (timeVal) {
    timeVal.textContent = crackData.display;
  }

  // Set card color theme based on threat level
  container.classList.remove('danger', 'warning', 'success');
  if (crackData.threat_level === 'HIGH') {
    container.classList.add('danger');
  } else {
    container.classList.add('success');
  }
}

// ----------------- Password Generator -----------------

async function requestGeneratedPassword() {
  const lenInput = document.getElementById('genLength');
  const length = lenInput ? lenInput.value : 16;
  const useUpper = document.getElementById('genUpper') ? document.getElementById('genUpper').checked : true;
  const useDigits = document.getElementById('genDigits') ? document.getElementById('genDigits').checked : true;
  const useSymbols = document.getElementById('genSymbols') ? document.getElementById('genSymbols').checked : true;

  try {
    const url = `/api/generate-password?length=${length}&upper=${useUpper}&digits=${useDigits}&symbols=${useSymbols}`;
    const response = await fetch(url);
    if (!response.ok) return;

    const data = await response.json();
    const resultInput = document.getElementById('generatedPasswordOutput');
    if (resultInput) {
      resultInput.value = data.password;
    }

    // Optionally auto-populate the main password analyzer input if present
    const mainInput = document.getElementById('passwordInput');
    if (mainInput && document.getElementById('autoFillGenerator')?.checked) {
      mainInput.value = data.password;
      evaluatePassword(data.password);
    }
  } catch (err) {
    console.error('Password generation failed:', err);
  }
}

function copyGeneratedPassword() {
  const output = document.getElementById('generatedPasswordOutput');
  if (!output || !output.value) return;

  navigator.clipboard.writeText(output.value).then(() => {
    const copyBtn = document.getElementById('copyGenBtn');
    if (copyBtn) {
      const orig = copyBtn.innerHTML;
      copyBtn.innerHTML = '<i class="bi bi-check-lg text-success"></i> Copied!';
      setTimeout(() => { copyBtn.innerHTML = orig; }, 2000);
    }
  });
}

function applyGeneratedToInput() {
  const output = document.getElementById('generatedPasswordOutput');
  const mainInput = document.getElementById('passwordInput');
  if (output && mainInput && output.value) {
    mainInput.value = output.value;
    mainInput.dispatchEvent(new Event('input'));
  }
}

// ----------------- Initializations -----------------

document.addEventListener('DOMContentLoaded', () => {
  const mainInput = document.getElementById('passwordInput');
  if (mainInput) {
    const debouncedEval = debounce((val) => evaluatePassword(val), 150);
    mainInput.addEventListener('input', (e) => {
      debouncedEval(e.target.value);
    });

    // If there's prefilled value
    if (mainInput.value) {
      evaluatePassword(mainInput.value);
    }
  }

  // Password generator triggers
  const genBtn = document.getElementById('generatePasswordBtn');
  if (genBtn) {
    genBtn.addEventListener('click', requestGeneratedPassword);
  }

  const copyBtn = document.getElementById('copyGenBtn');
  if (copyBtn) {
    copyBtn.addEventListener('click', copyGeneratedPassword);
  }

  const applyBtn = document.getElementById('applyGenBtn');
  if (applyBtn) {
    applyBtn.addEventListener('click', applyGeneratedToInput);
  }

  const lengthRange = document.getElementById('genLength');
  const lengthVal = document.getElementById('genLengthVal');
  if (lengthRange && lengthVal) {
    lengthRange.addEventListener('input', (e) => {
      lengthVal.textContent = e.target.value;
    });
  }

  // Toggle Password Visibility Eye Icons
  document.querySelectorAll('.toggle-password').forEach(btn => {
    btn.addEventListener('click', function () {
      const targetId = this.getAttribute('data-target');
      const input = document.getElementById(targetId);
      if (!input) return;

      const icon = this.querySelector('i');
      if (input.type === 'password') {
        input.type = 'text';
        if (icon) {
          icon.className = 'bi bi-eye-slash-fill';
        }
      } else {
        input.type = 'password';
        if (icon) {
          icon.className = 'bi bi-eye-fill';
        }
      }
    });
  });
});
