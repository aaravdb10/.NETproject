// RBAC System - Main JavaScript File
// Role-Based Access Control Demo Application

// Global Variables
let currentUser = null;
let currentRole = null;
let isDarkMode = false;
let loginAttempts = 0;
let cooldownEndTime = null;
const API_BASE_URL = 'http://localhost:5000/api';
let securityConfig = {
    recaptchaEnabled: false,
    recaptchaSiteKey: '',
    otpExpirySeconds: 300
};
let loginRecaptchaWidgetId = null;
let registerRecaptchaWidgetId = null;
let pendingLoginToken = null;
let pendingRegisterToken = null;

// === Utility helpers ===
function capitalize(str) { return str ? str.charAt(0).toUpperCase() + str.slice(1) : ''; }

function initials(name) {
    const parts = (name || '').split(' ').filter(Boolean);
    if (parts.length === 0) return '?';
    return (parts[0][0] + (parts.length > 1 ? parts[parts.length - 1][0] : '')).toUpperCase();
}

function statCard(icon, label, value, color) {
    const colorMap = {
        blue: { bg: '#dbeafe', fg: '#2563eb' },
        green: { bg: '#dcfce7', fg: '#16a34a' },
        orange: { bg: '#ffedd5', fg: '#ea580c' },
        teal: { bg: '#ccfbf1', fg: '#0d9488' },
        purple: { bg: '#f3e8ff', fg: '#7c3aed' },
        red: { bg: '#fee2e2', fg: '#dc2626' }
    };
    const c = colorMap[color] || colorMap.blue;
    return `<div class="stat-card">
        <div class="stat-icon" style="background:${c.bg};color:${c.fg}"><i class="fas ${icon}"></i></div>
        <div class="stat-info"><div class="stat-value">${value}</div><div class="stat-label">${label}</div></div>
    </div>`;
}

function logActionColor(action) {
    if (!action) return 'gray';
    const a = action.toLowerCase();
    if (a.includes('login')) return 'green';
    if (a.includes('register')) return 'blue';
    if (a.includes('leave')) return 'orange';
    if (a.includes('delete') || a.includes('reject') || a.includes('fail')) return 'red';
    return 'gray';
}

function formatTimestamp(ts) {
    if (!ts) return '';
    try {
        const d = new Date(ts);
        const now = new Date();
        const diff = Math.floor((now - d) / 1000);
        if (diff < 60) return 'Just now';
        if (diff < 3600) return Math.floor(diff / 60) + 'm ago';
        if (diff < 86400) return Math.floor(diff / 3600) + 'h ago';
        if (diff < 604800) return Math.floor(diff / 86400) + 'd ago';
        return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
    } catch { return ts; }
}

function renderLoading(msg) {
    return `<div style="display:flex;flex-direction:column;align-items:center;justify-content:center;padding:60px 20px;color:var(--text-secondary,#64748b);">
        <i class="fas fa-circle-notch fa-spin" style="font-size:2rem;margin-bottom:12px;opacity:0.4;"></i>
        <span style="font-size:0.9rem;">${msg || 'Loading…'}</span>
    </div>`;
}

function renderError(msg) {
    return `<div style="text-align:center;padding:48px 20px;color:var(--text-secondary,#64748b);">
        <i class="fas fa-exclamation-triangle" style="font-size:2.5rem;opacity:0.3;margin-bottom:12px;display:block;"></i>
        <p style="font-size:0.9rem;">${msg || 'Something went wrong.'}</p>
    </div>`;
}

// Mock Data for demonstration
const mockData = {
    users: [
        { id: 1, name: 'Rahul Sharma', email: 'admin@company.com', role: 'admin', status: 'active' },
        { id: 2, name: 'Priya Patel', email: 'manager@company.com', role: 'manager', status: 'active' },
        { id: 3, name: 'Vikram Singh', email: 'employee@company.com', role: 'employee', status: 'active' },
        { id: 4, name: 'Aarav Gandhi', email: 'aarav.gandhi@company.com', role: 'employee', status: 'active' },
        { id: 5, name: 'Neha Gupta', email: 'neha.gupta@company.com', role: 'manager', status: 'inactive' }
    ],
    leaveRequests: [
        { id: 1, userId: 3, employeeName: 'Vikram Singh', type: 'vacation', startDate: '2025-01-15', endDate: '2025-01-20', days: 5, reason: 'Family trip', status: 'pending' },
        { id: 2, userId: 4, employeeName: 'Aarav Gandhi', type: 'sick', startDate: '2025-01-10', endDate: '2025-01-12', days: 3, reason: 'Flu recovery', status: 'approved' },
        { id: 3, userId: 3, employeeName: 'Vikram Singh', type: 'personal', startDate: '2025-01-25', endDate: '2025-01-25', days: 1, reason: 'Personal matters', status: 'rejected' }
    ],
    systemLogs: [
        { id: 1, action: 'User Login', user: 'admin@company.com', timestamp: '2025-01-08 10:30:00', status: 'success' },
        { id: 2, action: 'Role Assignment', user: 'admin@company.com', timestamp: '2025-01-08 10:15:00', status: 'success' },
        { id: 3, action: 'Leave Request', user: 'employee@company.com', timestamp: '2025-01-08 09:45:00', status: 'success' },
        { id: 4, action: 'User Update', user: 'manager@company.com', timestamp: '2025-01-08 09:30:00', status: 'success' }
    ]
};

// Demo users for login
const demoUsers = {
    'admin@company.com': {
        email: 'admin@company.com',
        password: 'admin123',
        role: 'admin',
        name: 'Rahul Sharma',
        department: 'IT'
    },
    'manager@company.com': {
        email: 'manager@company.com',
        password: 'manager123',
        role: 'manager',
        name: 'Priya Patel',
        department: 'HR'
    },
    'employee@company.com': {
        email: 'employee@company.com',
        password: 'employee123',
        role: 'employee',
        name: 'Vikram Singh',
        department: 'Finance'
    }
};

// Initialize the application
document.addEventListener('DOMContentLoaded', function () {
    console.log('DOM loaded, initializing app...');
    initializeDarkMode();
    initializeSmoothScrolling();
    setupEventListeners();
    initializeCooldown();
    initializeSecurityFeatures();

    // Listen for back/forward navigation
    window.addEventListener('hashchange', async () => {
        const handled = await handleOAuthHashCallback();
        if (!handled) checkExistingSession();
    });

    handleOAuthHashCallback().then((handled) => {
        if (!handled) checkExistingSession();
    });
});

function continueWithGoogle(mode = 'login') {
    const finalMode = mode === 'signup' ? 'signup' : 'login';
    window.location.href = `${API_BASE_URL}/auth/google/start?mode=${encodeURIComponent(finalMode)}`;
}

function continueWithGitHub(mode = 'login') {
    const finalMode = mode === 'signup' ? 'signup' : 'login';
    window.location.href = `${API_BASE_URL}/auth/github/start?mode=${encodeURIComponent(finalMode)}`;
}

async function handleOAuthHashCallback() {
    const rawHash = (window.location.hash || '').replace(/^#/, '');
    if (!rawHash) return false;

    const params = new URLSearchParams(rawHash);
    const oauthToken = params.get('oauth_token');
    const oauthError = params.get('oauth_error');

    if (!oauthToken && !oauthError) return false;

    const cleanUrl = `${window.location.pathname}${window.location.search}`;

    if (oauthError) {
        history.replaceState(null, '', cleanUrl);
        showLoginPage();
        showToast(decodeURIComponent(oauthError), 'error');
        return true;
    }

    try {
        const response = await apiCall('/auth/oauth/finalize', 'POST', { token: oauthToken });
        if (!response || !response.success || !response.user) {
            throw new Error('OAuth authentication failed');
        }

        const user = response.user;
        currentUser = {
            id: user.id,
            email: user.email,
            role: user.role,
            department: user.department,
            name: `${user.firstName || ''} ${user.lastName || ''}`.trim() || user.email
        };
        currentRole = user.role;

        localStorage.setItem('currentUser', JSON.stringify(currentUser));
        localStorage.setItem('currentRole', currentRole);

        history.replaceState(null, '', cleanUrl);
        showToast('Signed in successfully', 'success');
        showDashboardPage();
    } catch (error) {
        history.replaceState(null, '', cleanUrl);
        showLoginPage();
        showToast(error.message || 'Social sign-in failed', 'error');
    }

    return true;
}

// Initialize dark mode from localStorage
function initializeDarkMode() {
    const savedTheme = localStorage.getItem('theme');
    if (savedTheme === 'dark') {
        isDarkMode = true;
        document.documentElement.setAttribute('data-theme', 'dark');
        updateDarkModeIcon();
    }
}

// Toggle dark mode
function toggleDarkMode() {
    isDarkMode = !isDarkMode;
    if (isDarkMode) {
        document.documentElement.setAttribute('data-theme', 'dark');
        localStorage.setItem('theme', 'dark');
    } else {
        document.documentElement.removeAttribute('data-theme');
        localStorage.setItem('theme', 'light');
    }
    updateDarkModeIcon();
}

// Update dark mode icon
function updateDarkModeIcon() {
    const darkModeToggles = document.querySelectorAll('.dark-mode-toggle');
    darkModeToggles.forEach(toggle => {
        const icon = toggle.querySelector('i');
        if (icon) {
            icon.className = isDarkMode ? 'fas fa-sun' : 'fas fa-moon';
        }
    });
}

// Show different pages
function showHomePage() {
    console.log('Showing home page');
    hideAllPages();
    document.getElementById('homePage').style.display = 'block';

    // Only scroll if we are not processing a hash load
    if (window.location.hash !== '#home' && window.location.hash !== '') {
        window.history.replaceState(null, null, ' '); // remove hash cleanly
        window.scrollTo({ top: 0, behavior: 'instant' });
    }
}

function showRegisterPage() {
    console.log('Showing register page');
    hideAllPages();
    document.getElementById('registerPage').style.display = 'flex';
    clearOtpStep('register');
    renderRecaptchaWidgets();
    if (window.location.hash !== '#register') {
        window.history.pushState(null, null, '#register');
        window.scrollTo({ top: 0, behavior: 'instant' });
    }
}

function showLoginPage() {
    console.log('Showing login page');
    hideAllPages();
    document.getElementById('loginPage').style.display = 'flex';
    checkCooldownStatus();
    clearOtpStep('login');
    renderRecaptchaWidgets();
    if (window.location.hash !== '#login') {
        window.history.pushState(null, null, '#login');
        window.scrollTo({ top: 0, behavior: 'instant' });
    }
}

function showDashboardPage() {
    console.log('Showing dashboard page');
    hideAllPages();
    document.getElementById('dashboardPage').style.display = 'block';
    setupDashboard();
    if (window.location.hash !== '#dashboard') {
        window.history.pushState(null, null, '#dashboard');
        window.scrollTo({ top: 0, behavior: 'instant' });
    }
}

function hideAllPages() {
    const pages = ['homePage', 'registerPage', 'loginPage', 'dashboardPage'];
    pages.forEach(pageId => {
        const element = document.getElementById(pageId);
        if (element) {
            element.style.display = 'none';
        }
    });
}

// Check for existing session
function checkExistingSession() {
    const savedUser = localStorage.getItem('currentUser');
    const savedRole = localStorage.getItem('currentRole');
    const hash = window.location.hash;

    if (savedUser && savedRole) {
        currentUser = JSON.parse(savedUser);
        currentRole = savedRole;
        // If logged in, always go to dashboard regardless of hash (or default)
        showDashboardPage();
    } else {
        // Not logged in: Route based on hash
        if (hash === '#login') {
            showLoginPage();
        } else if (hash === '#register') {
            showRegisterPage();
        } else {
            // Default to home, clear any invalid hashes like #dashboard
            if (hash === '#dashboard') {
                window.history.replaceState(null, null, ' ');
            }
            showHomePage();
        }
    }
}

function initializeSmoothScrolling() {
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (event) {
            const href = this.getAttribute('href');
            if (!href || href === '#' || href === '#login' || href === '#register' || href === '#dashboard' || href === '#home') {
                return; // Let normal route handles take over for these
            }

            const target = document.querySelector(href);
            if (!target) {
                return;
            }

            event.preventDefault();
            target.scrollIntoView({ behavior: 'smooth', block: 'start' });
        });
    });

    initializeNavbarScrollEffect();
}

function initializeNavbarScrollEffect() {
    const navbar = document.querySelector('#homePage .homepage-navbar');
    if (!navbar) return;

    const onScroll = () => {
        if (window.scrollY > 20) {
            navbar.classList.add('is-scrolled');
        } else {
            navbar.classList.remove('is-scrolled');
        }
    };

    window.addEventListener('scroll', onScroll, { passive: true });
    onScroll();
}

async function initializeSecurityFeatures() {
    try {
        const response = await apiCall('/security/config', 'GET');
        if (response && response.success) {
            securityConfig = {
                recaptchaEnabled: !!response.recaptchaEnabled,
                recaptchaSiteKey: response.recaptchaSiteKey || '',
                otpExpirySeconds: response.otpExpirySeconds || 300
            };
        }
    } catch (error) {
        console.warn('Unable to load security config, continuing with defaults.', error);
    }

    renderRecaptchaWidgets();
}

function renderRecaptchaWidgets(retries = 30) {
    const loginHint = document.getElementById('loginRecaptchaHint');
    const registerHint = document.getElementById('registerRecaptchaHint');

    if (!securityConfig.recaptchaEnabled || !securityConfig.recaptchaSiteKey) {
        const hint = 'reCAPTCHA is running in development bypass mode. Set RECAPTCHA_SITE_KEY and RECAPTCHA_SECRET_KEY for production.';
        if (loginHint) loginHint.textContent = hint;
        if (registerHint) registerHint.textContent = hint;
        return;
    } else {
        if (loginHint) loginHint.textContent = '';
        if (registerHint) registerHint.textContent = '';
    }

    if (typeof grecaptcha === 'undefined') {
        if (retries > 0) {
            setTimeout(() => renderRecaptchaWidgets(retries - 1), 250);
        }
        return;
    }

    if (loginRecaptchaWidgetId === null && document.getElementById('loginRecaptcha')) {
        loginRecaptchaWidgetId = grecaptcha.render('loginRecaptcha', {
            sitekey: securityConfig.recaptchaSiteKey,
            theme: isDarkMode ? 'dark' : 'light'
        });
    }

    if (registerRecaptchaWidgetId === null && document.getElementById('registerRecaptcha')) {
        registerRecaptchaWidgetId = grecaptcha.render('registerRecaptcha', {
            sitekey: securityConfig.recaptchaSiteKey,
            theme: isDarkMode ? 'dark' : 'light'
        });
    }
}

function getRecaptchaToken(flow) {
    if (!securityConfig.recaptchaEnabled || !securityConfig.recaptchaSiteKey) {
        return 'dev-bypass';
    }

    if (typeof grecaptcha === 'undefined') {
        return '';
    }

    const widgetId = flow === 'login' ? loginRecaptchaWidgetId : registerRecaptchaWidgetId;
    if (widgetId === null) {
        return '';
    }

    return grecaptcha.getResponse(widgetId);
}

function resetRecaptcha(flow) {
    if (!securityConfig.recaptchaEnabled || typeof grecaptcha === 'undefined') {
        return;
    }

    const widgetId = flow === 'login' ? loginRecaptchaWidgetId : registerRecaptchaWidgetId;
    if (widgetId !== null) {
        grecaptcha.reset(widgetId);
    }
}

function isValidEmail(email) {
    const pattern = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
    return pattern.test(email);
}

function isValidName(value) {
    const pattern = /^[A-Za-z][A-Za-z\s'-]{1,49}$/;
    return pattern.test(value);
}

function validatePasswordStrength(password) {
    if (password.length < 8) {
        return 'Password must be at least 8 characters long';
    }
    if (!/[A-Z]/.test(password)) {
        return 'Password must include at least one uppercase letter';
    }
    if (!/[a-z]/.test(password)) {
        return 'Password must include at least one lowercase letter';
    }
    if (!/[0-9]/.test(password)) {
        return 'Password must include at least one number';
    }
    if (!/[^A-Za-z0-9]/.test(password)) {
        return 'Password must include at least one special character';
    }
    return '';
}

function revealOtpStep(flow) {
    if (flow === 'login') {
        const otpGroup = document.getElementById('loginOtpGroup');
        const step1 = document.getElementById('loginStep1Fields');
        const otpInput = document.getElementById('loginOtp');
        const submitBtn = document.getElementById('loginSubmitBtn');
        const step1Ind = document.getElementById('loginStep1Ind');
        const step2Ind = document.getElementById('loginStep2Ind');
        if (step1) step1.style.display = 'none';
        if (otpGroup) otpGroup.style.display = 'block';
        if (submitBtn) submitBtn.innerHTML = '<i class="fas fa-shield-alt"></i> Verify &amp; Sign In';
        if (step1Ind) { step1Ind.classList.remove('is-active'); step1Ind.classList.add('is-done'); }
        if (step2Ind) step2Ind.classList.add('is-active');
        if (otpInput) otpInput.focus();
    } else {
        const otpGroup = document.getElementById('registerOtpGroup');
        const step1 = document.getElementById('registerStep1Fields');
        const otpInput = document.getElementById('registerOtp');
        const submitBtn = document.getElementById('registerSubmitBtn');
        const step1Ind = document.getElementById('registerStep1Ind');
        const step2Ind = document.getElementById('registerStep2Ind');
        if (step1) step1.style.display = 'none';
        if (otpGroup) otpGroup.style.display = 'block';
        if (submitBtn) submitBtn.innerHTML = '<i class="fas fa-shield-alt"></i> Verify &amp; Create Account';
        if (step1Ind) { step1Ind.classList.remove('is-active'); step1Ind.classList.add('is-done'); }
        if (step2Ind) step2Ind.classList.add('is-active');
        if (otpInput) otpInput.focus();
    }
}

function clearOtpStep(flow) {
    if (flow === 'login') {
        pendingLoginToken = null;
        const otpGroup = document.getElementById('loginOtpGroup');
        const step1 = document.getElementById('loginStep1Fields');
        const otpInput = document.getElementById('loginOtp');
        const submitBtn = document.getElementById('loginSubmitBtn');
        const step1Ind = document.getElementById('loginStep1Ind');
        const step2Ind = document.getElementById('loginStep2Ind');
        if (otpGroup) otpGroup.style.display = 'none';
        if (step1) step1.style.display = 'block';
        if (otpInput) otpInput.value = '';
        if (submitBtn) submitBtn.innerHTML = '<i class="fas fa-sign-in-alt"></i> Continue';
        if (step1Ind) { step1Ind.classList.remove('is-done'); step1Ind.classList.add('is-active'); }
        if (step2Ind) step2Ind.classList.remove('is-active');
    } else {
        pendingRegisterToken = null;
        const otpGroup = document.getElementById('registerOtpGroup');
        const step1 = document.getElementById('registerStep1Fields');
        const otpInput = document.getElementById('registerOtp');
        const submitBtn = document.getElementById('registerSubmitBtn');
        const step1Ind = document.getElementById('registerStep1Ind');
        const step2Ind = document.getElementById('registerStep2Ind');
        if (otpGroup) otpGroup.style.display = 'none';
        if (step1) step1.style.display = 'block';
        if (otpInput) otpInput.value = '';
        if (submitBtn) submitBtn.innerHTML = '<i class="fas fa-paper-plane"></i> Send verification code';
        if (step1Ind) { step1Ind.classList.remove('is-done'); step1Ind.classList.add('is-active'); }
        if (step2Ind) step2Ind.classList.remove('is-active');
    }
}

// Setup event listeners
function setupEventListeners() {
    // Dark mode toggles
    document.querySelectorAll('.dark-mode-toggle').forEach(toggle => {
        toggle.addEventListener('click', toggleDarkMode);
    });

    // Login form
    const loginForm = document.getElementById('loginForm');
    if (loginForm) {
        loginForm.addEventListener('submit', handleLogin);
    }

    // Register form
    const registerForm = document.getElementById('registerForm');
    if (registerForm) {
        registerForm.addEventListener('submit', handleRegister);
    }

    // Demo buttons
    document.querySelectorAll('.demo-btn').forEach(btn => {
        btn.addEventListener('click', function () {
            const role = this.getAttribute('data-role');
            demoLogin(role);
        });
    });

    // Password toggle â€” login page
    const togglePassword = document.getElementById('togglePassword');
    if (togglePassword) {
        togglePassword.addEventListener('click', function () {
            const passwordField = document.getElementById('password');
            const type = passwordField.getAttribute('type') === 'password' ? 'text' : 'password';
            passwordField.setAttribute('type', type);
            this.classList.toggle('fa-eye');
            this.classList.toggle('fa-eye-slash');
        });
    }

    // Password toggle â€” register page
    const toggleRegPassword = document.getElementById('toggleRegPassword');
    if (toggleRegPassword) {
        toggleRegPassword.addEventListener('click', function () {
            const pwField = document.getElementById('registerPassword');
            const type = pwField.getAttribute('type') === 'password' ? 'text' : 'password';
            pwField.setAttribute('type', type);
            this.classList.toggle('fa-eye');
            this.classList.toggle('fa-eye-slash');
        });
    }

    // Password strength meter â€” register page
    const regPasswordInput = document.getElementById('registerPassword');
    if (regPasswordInput) {
        regPasswordInput.addEventListener('input', function () {
            updatePasswordStrengthUI(this.value);
        });
    }

    // Logout button
    document.addEventListener('click', function (e) {
        const navLink = e.target.closest('.nav-link');
        if (navLink) {
            e.preventDefault();
        }

        if (e.target.matches('.logout-btn') || e.target.closest('.logout-btn')) {
            logout();
        }
    });

    // Access denied modal close
    const closeAccessModal = document.getElementById('closeAccessModal');
    if (closeAccessModal) {
        closeAccessModal.addEventListener('click', closeAccessDeniedModal);
    }
}

// Password strength meter UI
function updatePasswordStrengthUI(password) {
    const bar = document.getElementById('pwBar');
    const label = document.getElementById('pwLabel');
    const wrap = document.getElementById('pwStrength');
    const rules = document.getElementById('pwRules');
    if (!bar || !label || !wrap) return;

    const checks = {
        len: password.length >= 8,
        upper: /[A-Z]/.test(password),
        lower: /[a-z]/.test(password),
        num: /[0-9]/.test(password),
        special: /[^A-Za-z0-9]/.test(password),
    };

    // Update rule list
    if (rules) {
        Object.entries(checks).forEach(([key, ok]) => {
            const li = document.getElementById(`rule-${key}`);
            if (li) {
                li.classList.toggle('rule-ok', ok);
            }
        });
    }

    const score = Object.values(checks).filter(Boolean).length;
    const labels = ['', 'Weak', 'Fair', 'Good', 'Strong', 'Strong'];
    const classes = ['', 'strength-1', 'strength-2', 'strength-3', 'strength-4', 'strength-4'];

    if (password.length === 0) {
        wrap.style.display = 'none';
        return;
    }

    wrap.style.display = 'flex';
    bar.className = `pw-bar ${classes[score]}`;
    label.textContent = labels[score];
}

// Role showcase tab selector (homepage)
function selectRole(role) {
    // Update pills
    document.querySelectorAll('.role-pill').forEach(pill => {
        pill.classList.toggle('active', pill.getAttribute('data-role') === role);
    });
    // Update panels
    document.querySelectorAll('.role-panel').forEach(panel => {
        panel.classList.remove('active');
    });
    const target = document.getElementById('rolePanel-' + role);
    if (target) target.classList.add('active');
}

// Demo login function
function demoLogin(role) {
    console.log('Demo login for role:', role);

    let demoEmail;
    switch (role) {
        case 'admin':
            demoEmail = 'admin@company.com';
            break;
        case 'manager':
            demoEmail = 'manager@company.com';
            break;
        case 'employee':
            demoEmail = 'employee@company.com';
            break;
        default:
            showToast('Invalid demo role', 'error');
            return;
    }

    const user = demoUsers[demoEmail];
    if (user) {
        currentUser = user;
        currentRole = user.role;

        // Save to localStorage
        localStorage.setItem('currentUser', JSON.stringify(user));
        localStorage.setItem('currentRole', user.role);

        showToast(`Logged in as ${user.name} (${user.role})`, 'success');
        showDashboardPage();
    } else {
        showToast('Demo user not found', 'error');
    }
}

// Handle login form submission
async function handleLogin(event) {
    event.preventDefault();

    if (cooldownEndTime && Date.now() < cooldownEndTime) {
        const remainingTime = Math.ceil((cooldownEndTime - Date.now()) / 1000 / 60);
        showToast(`Please wait ${remainingTime} minute(s) before trying again`, 'error');
        return;
    }

    const formData = new FormData(event.target);
    const email = (formData.get('email') || '').trim().toLowerCase();
    const password = (formData.get('password') || '').toString();
    const otp = (formData.get('loginOtp') || '').toString().trim();

    if (!isValidEmail(email)) {
        showToast('Please enter a valid email address', 'error');
        return;
    }

    if (!pendingLoginToken && password.length < 8) {
        showToast('Please enter a valid password', 'error');
        return;
    }

    if (pendingLoginToken) {
        if (!/^\d{6}$/.test(otp)) {
            showToast('Enter the 6-digit OTP sent to your email', 'error');
            return;
        }

        try {
            const response = await apiCall('/auth/login-verify', 'POST', {
                verificationToken: pendingLoginToken,
                otp: otp
            });

            if (response && response.success && response.user) {
                const user = response.user;
                currentUser = {
                    id: user.id,
                    email: user.email,
                    role: user.role,
                    department: user.department,
                    name: `${user.firstName || ''} ${user.lastName || ''}`.trim() || user.email
                };
                currentRole = user.role;

                loginAttempts = 0;
                cooldownEndTime = null;
                localStorage.removeItem('cooldownEndTime');
                hideCooldownMessage();

                localStorage.setItem('currentUser', JSON.stringify(currentUser));
                localStorage.setItem('currentRole', currentRole);

                clearOtpStep('login');
                resetRecaptcha('login');
                showToast('2FA verification successful. Welcome back!', 'success');
                showDashboardPage();
                return;
            }

            showToast('OTP verification failed', 'error');
            return;
        } catch (error) {
            clearOtpStep('login');
            resetRecaptcha('login');
            showToast(error.message || 'Login verification failed', 'error');
            return;
        }
    }

    const recaptchaToken = getRecaptchaToken('login');
    if (!recaptchaToken) {
        showToast('Please complete reCAPTCHA first', 'error');
        return;
    }

    try {
        const response = await apiCall('/auth/login-init', 'POST', {
            email,
            password,
            recaptchaToken
        });

        if (response && response.success && response.verificationToken) {
            pendingLoginToken = response.verificationToken;
            revealOtpStep('login');
            showToast('OTP sent to your registered email', 'success');
            return;
        }
    } catch (error) {
        loginAttempts++;

        if (loginAttempts >= 3) {
            startCooldown();
            showToast('Too many failed attempts. Account locked for 5 minutes.', 'error');
        } else {
            showToast(error.message || `Invalid email or password. Attempt ${loginAttempts}/3`, 'error');
        }

        resetRecaptcha('login');
        return;
    }
}

// Handle register form submission
function handleRegister(event) {
    event.preventDefault();

    const formData = new FormData(event.target);
    const userData = {
        firstName: (formData.get('firstName') || '').trim(),
        lastName: (formData.get('lastName') || '').trim(),
        email: (formData.get('email') || '').trim().toLowerCase(),
        password: (formData.get('password') || '').toString(),
        confirmPassword: (formData.get('confirmPassword') || '').toString(),
        department: (formData.get('department') || '').trim(),
        otp: (formData.get('registerOtp') || '').toString().trim()
    };

    if (!isValidName(userData.firstName) || !isValidName(userData.lastName)) {
        showToast('Please enter valid first and last names', 'error');
        return;
    }

    if (!isValidEmail(userData.email)) {
        showToast('Please enter a valid email address', 'error');
        return;
    }

    if (!pendingRegisterToken) {
        const passwordIssue = validatePasswordStrength(userData.password);
        if (passwordIssue) {
            showToast(passwordIssue, 'error');
            return;
        }
    }

    if (userData.password !== userData.confirmPassword) {
        showToast('Passwords do not match', 'error');
        return;
    }

    if (pendingRegisterToken) {
        if (!/^\d{6}$/.test(userData.otp)) {
            showToast('Enter the 6-digit OTP sent to your email', 'error');
            return;
        }

        apiCall('/auth/register-verify', 'POST', {
            verificationToken: pendingRegisterToken,
            otp: userData.otp
        }).then((response) => {
            if (response && response.success) {
                clearOtpStep('register');
                resetRecaptcha('register');
                document.getElementById('registerForm').reset();
                showToast('Account created successfully with OTP verification!', 'success');
                showLoginPage();
            } else {
                showToast('OTP verification failed', 'error');
            }
        }).catch((error) => {
            clearOtpStep('register');
            resetRecaptcha('register');
            showToast(error.message || 'Registration failed', 'error');
        });

        return;
    }

    const recaptchaToken = getRecaptchaToken('register');
    if (!recaptchaToken) {
        showToast('Please complete reCAPTCHA first', 'error');
        return;
    }

    apiCall('/auth/register-init', 'POST', {
        firstName: userData.firstName,
        lastName: userData.lastName,
        email: userData.email,
        password: userData.password,
        department: userData.department,
        recaptchaToken
    }).then((response) => {
        if (response && response.success && response.verificationToken) {
            pendingRegisterToken = response.verificationToken;
            revealOtpStep('register');
            showToast('OTP sent to your email. Verify to complete signup.', 'success');
        } else {
            showToast('Unable to start registration verification', 'error');
        }
    }).catch((error) => {
        resetRecaptcha('register');
        showToast(error.message || 'Registration failed', 'error');
    });
}

// Setup dashboard based on user role
function setupDashboard() {
    if (!currentUser || !currentRole) {
        showHomePage();
        return;
    }

    // Update navigation
    setupNavigation();

    // Update user info
    const userName = document.getElementById('userName');
    const userRole = document.getElementById('userRole');

    if (userName) userName.textContent = currentUser.name;
    if (userRole) userRole.textContent = currentRole.charAt(0).toUpperCase() + currentRole.slice(1);

    // Setup dashboard content
    const dashboardTitle = document.getElementById('dashboardTitle');
    const dashboardSubtitle = document.getElementById('dashboardSubtitle');

    if (currentRole === 'admin') {
        if (dashboardTitle) dashboardTitle.textContent = 'Admin Dashboard';
        if (dashboardSubtitle) dashboardSubtitle.textContent = 'Complete system control and user management';
        showAdminDashboard();
    } else if (currentRole === 'manager') {
        if (dashboardTitle) dashboardTitle.textContent = 'Manager Dashboard';
        if (dashboardSubtitle) dashboardSubtitle.textContent = 'Team management and oversight';
        showManagerDashboard();
    } else {
        if (dashboardTitle) dashboardTitle.textContent = 'Employee Dashboard';
        if (dashboardSubtitle) dashboardSubtitle.textContent = 'Your personal workspace';
        showEmployeeDashboard();
    }
}

// Setup navigation based on role
function setupNavigation() {
    const navLinks = document.getElementById('navLinks');
    if (!navLinks) return;

    let navHtml = '<a href="javascript:void(0)" class="nav-link active" data-view="dashboard" onclick="showDashboard()">Dashboard</a>';

    if (currentRole === 'admin') {
        navHtml += '<a href="javascript:void(0)" class="nav-link" data-view="users" onclick="showUsers()">Users</a>';
        navHtml += '<a href="javascript:void(0)" class="nav-link" data-view="system-logs" onclick="showSystemLogs()">System Logs</a>';
        navHtml += '<a href="javascript:void(0)" class="nav-link" data-view="leave-requests" onclick="showLeaveRequests()">Leave Requests</a>';
        navHtml += '<a href="javascript:void(0)" class="nav-link" data-view="reports" onclick="showReports()">Reports</a>';
    } else if (currentRole === 'manager') {
        navHtml += '<a href="javascript:void(0)" class="nav-link" data-view="team" onclick="showTeam()">Team</a>';
        navHtml += '<a href="javascript:void(0)" class="nav-link" data-view="leave-requests" onclick="showLeaveRequests()">Leave Requests</a>';
        navHtml += '<a href="javascript:void(0)" class="nav-link" data-view="reports" onclick="showReports()">Reports</a>';
    } else {
        navHtml += '<a href="javascript:void(0)" class="nav-link" data-view="profile" onclick="showProfile()">Profile</a>';
        navHtml += '<a href="javascript:void(0)" class="nav-link" data-view="my-leaves" onclick="showMyLeaveRequests()">My Leaves</a>';
    }

    navLinks.innerHTML = navHtml;
}

function setDashboardContext(title, subtitle = '') {
    const dashboardTitle = document.getElementById('dashboardTitle');
    const dashboardSubtitle = document.getElementById('dashboardSubtitle');
    if (dashboardTitle) dashboardTitle.textContent = title;
    if (dashboardSubtitle) dashboardSubtitle.textContent = subtitle;
}

function setActiveNavByView(view) {
    const navLinks = document.querySelectorAll('.nav-link');
    let matched = false;

    navLinks.forEach((link) => {
        const isActive = link.getAttribute('data-view') === view;
        link.classList.toggle('active', isActive);
        if (isActive) matched = true;
    });

    if (!matched) {
        navLinks.forEach((link) => {
            link.classList.toggle('active', link.getAttribute('data-view') === 'dashboard');
        });
    }
}

// Dashboard content functions
function showDashboard() {
    setActiveNavByView('dashboard');
    setDashboardContext(
        `${capitalize(currentRole || 'employee')} Dashboard`,
        currentRole === 'admin'
            ? 'Complete system control and user management'
            : currentRole === 'manager'
                ? 'Team management and oversight'
                : 'Your personal workspace'
    );
    setupDashboard();
}

// â”€â”€â”€ Dashboard helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
function renderLoading(msg = 'Loadingâ€¦') {
    return `<div class="loading-state"><i class="fas fa-circle-notch spinner-icon"></i><span>${msg}</span></div>`;
}
function renderError(msg = 'Failed to load data.') {
    return `<div class="error-state"><i class="fas fa-exclamation-circle error-icon"></i><span>${msg}</span></div>`;
}
function statCard(icon, label, value, color) {
    return `<div class="stat-card stat-${color}"><div class="stat-icon"><i class="fas ${icon}"></i></div><div class="stat-info"><div class="stat-value">${value}</div><div class="stat-label">${label}</div></div></div>`;
}
function logActionColor(action) {
    if (!action) return 'gray';
    const a = action.toLowerCase();
    if (a.includes('login') && a.includes('fail')) return 'red';
    if (a.includes('login') || a.includes('register')) return 'green';
    if (a.includes('delete')) return 'red';
    if (a.includes('creat') || a.includes('add')) return 'blue';
    if (a.includes('updat') || a.includes('edit')) return 'orange';
    if (a.includes('leave')) return 'orange';
    return 'gray';
}
function formatTimestamp(ts) {
    if (!ts) return 'â€”';
    const d = new Date(ts);
    if (isNaN(d)) return ts;
    return d.toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}
function capitalize(s) { return s ? s.charAt(0).toUpperCase() + s.slice(1) : ''; }
function initials(name) {
    if (!name) return '?';
    const p = name.trim().split(' ');
    return (p[0][0] + (p[1] ? p[1][0] : '')).toUpperCase();
}

function truncateText(value, maxLen = 48) {
    const text = (value || '').toString();
    if (text.length <= maxLen) return text;
    return `${text.slice(0, maxLen - 1)}…`;
}
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

async function showAdminDashboard() {
    const dashboardContent = document.getElementById('dashboardContent');
    if (!dashboardContent) return;
    dashboardContent.innerHTML = renderLoading('Loading dashboardâ€¦');

    try {
        const [statsRes, usersRes, logsRes] = await Promise.all([
            apiCall('/stats', 'GET'),
            apiCall('/users', 'GET'),
            apiCall('/logs?limit=5', 'GET')
        ]);

        const s = statsRes.stats || {};
        const users = usersRes.users || [];
        const logs = logsRes.logs || [];
        const recentUsers = users.slice(0, 4);
        const total = s.totalUsers || 1;
        const inactiveUsers = Math.max(0, (s.totalUsers || 0) - (s.activeUsers || 0));

        const roleBarHTML = (label, count, color) => {
            const pct = Math.round((count / total) * 100);
            return `<div class="mini-bar-row">
                <span class="mini-bar-label">${label}</span>
                <div class="mini-bar-track"><div class="mini-bar-fill" style="width:${pct}%;background:${color};"></div></div>
                <span class="mini-bar-count">${count}</span>
            </div>`;
        };

        const roleSlices = [
            { label: 'Admins', count: s.adminCount || 0, color: '#ef4444' },
            { label: 'Managers', count: s.managerCount || 0, color: '#f97316' },
            { label: 'Employees', count: s.employeeCount || 0, color: '#3b82f6' }
        ];
        const roleGradient = (() => {
            let cursor = 0;
            return roleSlices.map((slice) => {
                const pct = total ? (slice.count / total) * 100 : 0;
                const start = cursor;
                cursor += pct;
                return `${slice.color} ${start.toFixed(2)}% ${cursor.toFixed(2)}%`;
            }).join(', ');
        })();

        const actionBuckets = {
            login: 0,
            register: 0,
            user: 0,
            leave: 0,
            other: 0
        };
        logs.forEach((log) => {
            const action = (log.action || '').toLowerCase();
            if (action.includes('login')) actionBuckets.login += 1;
            else if (action.includes('register')) actionBuckets.register += 1;
            else if (action.includes('user_') || action.includes('password')) actionBuckets.user += 1;
            else if (action.includes('leave')) actionBuckets.leave += 1;
            else actionBuckets.other += 1;
        });

        const actionRows = [
            { label: 'Login', key: 'login', color: '#22c55e' },
            { label: 'Register', key: 'register', color: '#06b6d4' },
            { label: 'User Changes', key: 'user', color: '#a855f7' },
            { label: 'Leave', key: 'leave', color: '#f59e0b' },
            { label: 'Other', key: 'other', color: '#64748b' }
        ];
        const totalActions = Math.max(1, logs.length);

        dashboardContent.innerHTML = `
        <div class="stat-grid">
            ${statCard('fa-users', 'Total Users', s.totalUsers || 0, 'blue')}
            ${statCard('fa-user-check', 'Active Users', s.activeUsers || 0, 'green')}
            ${statCard('fa-calendar-alt', 'Pending Leaves', s.pendingLeaves || 0, 'orange')}
            ${statCard('fa-list-alt', 'System Events', s.totalLogs || 0, 'purple')}
        </div>

        <div class="dashboard-grid">
            <div class="dashboard-card">
                <div class="card-header"><i class="fas fa-users"></i><h3>Recent Users</h3></div>
                <div class="card-content">
                    ${recentUsers.map(u => {
            const name = `${u.firstName} ${u.lastName}`;
            return `<div class="mini-list-item">
                            <div class="avatar-circle role-${u.role}">${initials(name)}</div>
                            <div class="mini-item-info">
                                <div class="mini-item-title fw-600">${name}</div>
                                <div class="mini-item-sub">${u.email}</div>
                            </div>
                            <span class="role-badge role-${u.role}">${capitalize(u.role)}</span>
                        </div>`;
        }).join('')}
                </div>
                <div class="card-footer">
                    <button class="btn btn-primary btn-sm" onclick="showUsers()">View All Users</button>
                </div>
            </div>

            <div class="dashboard-card">
                <div class="card-header"><i class="fas fa-history"></i><h3>Recent Activity</h3></div>
                <div class="card-content">
                    ${logs.length === 0 ? '<p class="text-muted small">No activity yet.</p>' :
                logs.map(l => `<div class="mini-list-item">
                        <span class="action-tag action-${logActionColor(l.action)}">${l.action}</span>
                        <div class="mini-item-info">
                            <div class="mini-item-title fw-600">${l.user_name}</div>
                            <div class="mini-item-sub">${l.details || ''}</div>
                        </div>
                        <span class="text-muted small nowrap">${formatTimestamp(l.timestamp)}</span>
                      </div>`).join('')}
                </div>
                <div class="card-footer">
                    <button class="btn btn-primary btn-sm" onclick="showSystemLogs()">View All Logs</button>
                </div>
            </div>

            <div class="dashboard-card">
                <div class="card-header"><i class="fas fa-chart-pie"></i><h3>Role Breakdown</h3></div>
                <div class="card-content">
                    <div style="display:flex;align-items:center;justify-content:center;margin-bottom:14px;">
                        <div style="width:130px;height:130px;border-radius:50%;background:conic-gradient(${roleGradient});position:relative;">
                            <div style="position:absolute;inset:18px;border-radius:50%;background:var(--card-bg,#fff);display:flex;align-items:center;justify-content:center;flex-direction:column;">
                                <span style="font-size:1.4rem;font-weight:700;line-height:1;">${s.totalUsers || 0}</span>
                                <span class="text-muted small">Users</span>
                            </div>
                        </div>
                    </div>
                    ${roleBarHTML('Admins', s.adminCount || 0, '#ef4444')}
                    ${roleBarHTML('Managers', s.managerCount || 0, '#f97316')}
                    ${roleBarHTML('Employees', s.employeeCount || 0, '#3b82f6')}
                    ${roleBarHTML('Inactive', inactiveUsers, '#64748b')}
                </div>
            </div>

            <div class="dashboard-card">
                <div class="card-header"><i class="fas fa-wave-square"></i><h3>Recent Activity Mix</h3></div>
                <div class="card-content">
                    ${actionRows.map(row => {
                        const count = actionBuckets[row.key];
                        const pct = Math.round((count / totalActions) * 100);
                        return `<div class="mini-bar-row">
                            <span class="mini-bar-label">${row.label}</span>
                            <div class="mini-bar-track"><div class="mini-bar-fill" style="width:${pct}%;background:${row.color};"></div></div>
                            <span class="mini-bar-count">${count}</span>
                        </div>`;
                    }).join('')}
                </div>
            </div>

            <div class="dashboard-card">
                <div class="card-header"><i class="fas fa-bolt"></i><h3>Quick Actions</h3></div>
                <div class="card-content">
                    <div class="quick-actions-grid">
                        <div class="quick-action-tile" onclick="openUserModal()"><i class="fas fa-user-plus"></i>Add User</div>
                        <div class="quick-action-tile" onclick="showLeaveRequests()"><i class="fas fa-calendar-check"></i>Leave Requests ${s.pendingLeaves ? `<span class="count-badge">${s.pendingLeaves}</span>` : ''}</div>
                        <div class="quick-action-tile" onclick="showSystemLogs()"><i class="fas fa-shield-alt"></i>Audit Logs</div>
                        <div class="quick-action-tile" onclick="showReports()"><i class="fas fa-chart-bar"></i>Reports</div>
                    </div>
                </div>
            </div>
        </div>`;
    } catch (err) {
        dashboardContent.innerHTML = renderError('Could not load dashboard data.');
    }
}

async function showManagerDashboard() {
    const dashboardContent = document.getElementById('dashboardContent');
    if (!dashboardContent) return;
    dashboardContent.innerHTML = renderLoading();

    try {
        const [usersRes, leavesRes] = await Promise.all([
            apiCall('/users', 'GET'),
            apiCall('/leaves', 'GET')
        ]);
        const users = usersRes.users || [];
        const leaves = leavesRes.leaves || [];
        const employees = users.filter(u => u.role === 'employee');
        const pending = leaves.filter(l => l.status === 'pending');
        const approved = leaves.filter(l => l.status === 'approved');

        dashboardContent.innerHTML = `
        <div class="stat-grid">
            ${statCard('fa-users', 'Team Members', employees.length, 'blue')}
            ${statCard('fa-clock', 'Pending Leaves', pending.length, 'orange')}
            ${statCard('fa-check-circle', 'Approved Leaves', approved.length, 'green')}
            ${statCard('fa-calendar', 'Total Requests', leaves.length, 'purple')}
        </div>

        <div class="dashboard-grid">
            <div class="dashboard-card">
                <div class="card-header"><i class="fas fa-users"></i><h3>Team Members</h3></div>
                <div class="card-content">
                    ${employees.slice(0, 5).map(u => {
            const name = `${u.firstName} ${u.lastName}`;
            return `<div class="mini-list-item">
                            <div class="avatar-circle role-employee">${initials(name)}</div>
                            <div class="mini-item-info">
                                <div class="mini-item-title fw-600">${name}</div>
                                <div class="mini-item-sub">${u.department || 'N/A'}</div>
                            </div>
                            <span class="status-badge status-${u.status}">${u.status}</span>
                        </div>`;
        }).join('')}
                </div>
                <div class="card-footer"><button class="btn btn-primary btn-sm" onclick="showTeam()">Manage Team</button></div>
            </div>

            <div class="dashboard-card">
                <div class="card-header"><i class="fas fa-calendar-check"></i><h3>Pending Leave Requests</h3></div>
                <div class="card-content">
                    ${pending.length === 0 ? '<p class="text-muted small">No pending requests.</p>' :
                pending.slice(0, 4).map(l => `<div class="mini-list-item">
                        <div class="mini-item-info">
                            <div class="mini-item-title fw-600">${l.employee_name}</div>
                            <div class="mini-item-sub">${capitalize(l.type)} Â· ${l.start_date} â†’ ${l.end_date} (${l.days}d)</div>
                        </div>
                        <div class="action-btns">
                            <button class="icon-btn green-btn" onclick="updateLeaveStatus(${l.id},'approved')"><i class="fas fa-check"></i></button>
                            <button class="icon-btn del-btn"   onclick="updateLeaveStatus(${l.id},'rejected')"><i class="fas fa-times"></i></button>
                        </div>
                      </div>`).join('')}
                </div>
                <div class="card-footer"><button class="btn btn-primary btn-sm" onclick="showLeaveRequests()">View All</button></div>
            </div>
        </div>`;
    } catch (err) {
        dashboardContent.innerHTML = renderError();
    }
}

async function showEmployeeDashboard() {
    const dashboardContent = document.getElementById('dashboardContent');
    if (!dashboardContent) return;
    dashboardContent.innerHTML = renderLoading();

    try {
        const leavesRes = await apiCall('/leaves', 'GET');
        const allLeaves = leavesRes.leaves || [];
        // Filter to current user's leaves
        const myLeaves = allLeaves.filter(l => l.user_id === (currentUser.id || 0));
        const approved = myLeaves.filter(l => l.status === 'approved');
        const pending = myLeaves.filter(l => l.status === 'pending');
        const approvedDays = approved.reduce((s, l) => s + (l.days || 0), 0);

        dashboardContent.innerHTML = `
        <div class="stat-grid">
            ${statCard('fa-paper-plane', 'Total Requests', myLeaves.length, 'blue')}
            ${statCard('fa-check-circle', 'Approved', approved.length, 'green')}
            ${statCard('fa-clock', 'Pending', pending.length, 'orange')}
            ${statCard('fa-sun', 'Days Approved', approvedDays, 'teal')}
        </div>

        <div class="dashboard-grid">
            <div class="dashboard-card">
                <div class="card-header"><i class="fas fa-calendar-alt"></i><h3>My Leave Requests</h3></div>
                <div class="card-content">
                    ${myLeaves.length === 0 ? '<p class="text-muted small">No leave requests yet.</p>' :
                myLeaves.slice(0, 5).map(l => `<div class="mini-list-item">
                        <span class="leave-type-badge leave-${l.type}">${capitalize(l.type)}</span>
                        <div class="mini-item-info">
                            <div class="mini-item-title fw-600">${l.start_date} â†’ ${l.end_date}</div>
                            <div class="mini-item-sub">${l.days} day(s) Â· ${l.reason || ''}</div>
                        </div>
                        <span class="status-badge status-${l.status}">${l.status}</span>
                      </div>`).join('')}
                </div>
                <div class="card-footer">
                    <button class="btn btn-primary btn-sm" onclick="openLeaveModal()">
                        <i class="fas fa-plus"></i> New Request
                    </button>
                </div>
            </div>

            <div class="dashboard-card">
                <div class="card-header"><i class="fas fa-user-circle"></i><h3>My Profile</h3></div>
                <div class="card-content">
                    <div class="mini-list-item"><span class="mini-bar-label">Name</span><span class="fw-600">${currentUser.name}</span></div>
                    <div class="mini-list-item"><span class="mini-bar-label">Email</span><span>${currentUser.email}</span></div>
                    <div class="mini-list-item"><span class="mini-bar-label">Department</span><span>${currentUser.department || 'N/A'}</span></div>
                    <div class="mini-list-item"><span class="mini-bar-label">Role</span><span class="role-badge role-${currentUser.role}">${capitalize(currentUser.role)}</span></div>
                </div>
                <div class="card-footer"><button class="btn btn-primary btn-sm" onclick="showProfile()">Edit Profile</button></div>
            </div>
        </div>`;
    } catch (err) {
        dashboardContent.innerHTML = renderError();
    }
}

// Navigation functions
let _usersCache = [];

async function showUsers() {
    if (!hasPermission('admin')) { showAccessDenied(); return; }
    setActiveNavByView('users');
    setDashboardContext('Users', 'Manage all platform users');
    const dashboardContent = document.getElementById('dashboardContent');
    dashboardContent.innerHTML = renderLoading('Loading usersâ€¦');

    try {
        const res = await apiCall('/users', 'GET');
        _usersCache = res.users || [];
        const activeCount = _usersCache.filter(u => (u.status || '').toLowerCase() === 'active').length;
        const inactiveCount = _usersCache.length - activeCount;
        dashboardContent.innerHTML = `
            <div class="section-toolbar">
                <span class="section-title">All Users</span>
                <div class="toolbar-right">
                    <select class="filter-select" id="userStatusFilter" onchange="filterUsersTable(document.getElementById('userSearch')?.value || '')">
                        <option value="all">All (${_usersCache.length})</option>
                        <option value="active">Active (${activeCount})</option>
                        <option value="inactive">Inactive (${inactiveCount})</option>
                    </select>
                    <div class="search-box">
                        <i class="fas fa-search search-icon"></i>
                        <input type="text" id="userSearch" placeholder="Search usersâ€¦"
                               oninput="filterUsersTable(this.value)">
                    </div>
                    <button class="btn btn-primary" onclick="openUserModal()">
                        <i class="fas fa-plus"></i> Add User
                    </button>
                </div>
            </div>
            <div class="table-container">
                <table class="table" id="usersTable">
                    <thead><tr>
                        <th>User</th><th>Email</th><th>Role</th>
                        <th>Department</th><th>Status</th><th>Actions</th>
                    </tr></thead>
                    <tbody id="usersTableBody">${renderUsersRows(_usersCache)}</tbody>
                </table>
            </div>`;
    } catch (err) {
        dashboardContent.innerHTML = renderError('Failed to load users.');
    }
}

function renderUsersRows(users) {
    if (!users.length) return `<tr><td colspan="6"><div class="loading-state"><span>No users found.</span></div></td></tr>`;
    return users.map(u => {
        const name = `${u.firstName} ${u.lastName}`;
        return `<tr>
            <td>
                <div style="display:flex;align-items:center;gap:10px;">
                    <div class="avatar-circle role-${u.role}">${initials(name)}</div>
                    <span class="fw-600">${name}</span>
                </div>
            </td>
            <td class="text-muted">${u.email}</td>
            <td><span class="role-badge role-${u.role}">${capitalize(u.role)}</span></td>
            <td>${u.department || 'â€”'}</td>
            <td><span class="status-badge status-${u.status}">${u.status}</span></td>
            <td>
                <div class="action-btns">
                    <button class="icon-btn edit-btn" onclick="openUserModal(${u.id})"><i class="fas fa-edit"></i> Edit</button>
                    <button class="icon-btn del-btn"  onclick="confirmDeleteUser(${u.id},'${name.replace(/'/g, "\\'")}')"><i class="fas fa-trash"></i> Delete</button>
                </div>
            </td>
        </tr>`;
    }).join('');
}

function filterUsersTable(val) {
    const v = val.toLowerCase();
    const statusFilter = document.getElementById('userStatusFilter')?.value || 'all';
    const filtered = _usersCache.filter(u => {
        const statusOk = statusFilter === 'all' || (u.status || '').toLowerCase() === statusFilter;
        const queryOk =
        `${u.firstName} ${u.lastName}`.toLowerCase().includes(v) ||
        u.email.toLowerCase().includes(v) ||
        (u.role || '').toLowerCase().includes(v) ||
        (u.department || '').toLowerCase().includes(v);
        return statusOk && queryOk;
    });
    const tbody = document.getElementById('usersTableBody');
    if (tbody) tbody.innerHTML = renderUsersRows(filtered);
}

let _logsCache = [];

async function showSystemLogs() {
    if (!hasPermission('admin')) { showAccessDenied(); return; }
    setActiveNavByView('system-logs');
    setDashboardContext('System Logs', 'Track audit activity and security events');
    const dashboardContent = document.getElementById('dashboardContent');
    dashboardContent.innerHTML = renderLoading('Loading logsâ€¦');

    try {
        const res = await apiCall('/logs?limit=200', 'GET');
        _logsCache = res.logs || [];
        renderLogsView(_logsCache);
    } catch (err) {
        dashboardContent.innerHTML = renderError('Failed to load logs.');
    }
}

function renderLogsView(logs) {
    const dashboardContent = document.getElementById('dashboardContent');
    const uniqueIps = new Set(logs.map(l => l.ip_address).filter(Boolean)).size;
    dashboardContent.innerHTML = `
        <div class="section-toolbar">
            <div class="toolbar-left">
                <span class="section-title">System Audit Logs</span>
                <span class="pending-alert"><i class="fas fa-network-wired"></i>${uniqueIps} unique IPs</span>
            </div>
            <div class="toolbar-right">
                <div class="search-box">
                    <i class="fas fa-search search-icon"></i>
                    <input type="text" id="logSearch" placeholder="Search logsâ€¦"
                           oninput="filterLogsTable(this.value)">
                </div>
                <button class="btn btn-secondary" onclick="exportLogsCSV()">
                    <i class="fas fa-download"></i> Export CSV
                </button>
            </div>
        </div>
        <div class="table-container">
            <table class="table">
                <thead><tr><th>Timestamp</th><th>Action</th><th>User</th><th>IP</th><th>Method</th><th>Endpoint</th><th>User Agent</th><th>Details</th></tr></thead>
                <tbody id="logsTableBody">${renderLogsRows(logs)}</tbody>
            </table>
        </div>`;
}

function renderLogsRows(logs) {
    if (!logs.length) return `<tr><td colspan="8"><div class="loading-state"><span>No logs found.</span></div></td></tr>`;
    return logs.map(l => `<tr>
        <td class="nowrap text-muted small">${formatTimestamp(l.timestamp)}</td>
        <td><span class="action-tag action-${logActionColor(l.action)}">${l.action}</span></td>
        <td class="fw-600">${l.user_name || 'System'}</td>
        <td class="small">${l.ip_address || 'â€”'}</td>
        <td><span class="status-badge status-active">${l.http_method || 'â€”'}</span></td>
        <td class="small" title="${l.request_path || ''}">${truncateText(l.request_path || 'â€”', 28)}</td>
        <td class="small" title="${l.user_agent || ''}">${truncateText(l.user_agent || 'â€”', 42)}</td>
        <td class="text-muted small">${l.details || 'â€”'}</td>
    </tr>`).join('');
}

function filterLogsTable(val) {
    const v = val.toLowerCase();
    const filtered = _logsCache.filter(l =>
        (l.action || '').toLowerCase().includes(v) ||
        (l.user_name || '').toLowerCase().includes(v) ||
        (l.details || '').toLowerCase().includes(v) ||
        (l.ip_address || '').toLowerCase().includes(v) ||
        (l.request_path || '').toLowerCase().includes(v) ||
        (l.user_agent || '').toLowerCase().includes(v) ||
        (l.http_method || '').toLowerCase().includes(v)
    );
    const tbody = document.getElementById('logsTableBody');
    if (tbody) tbody.innerHTML = renderLogsRows(filtered);
}

function exportLogsCSV() {
    const headers = ['Timestamp', 'Action', 'User', 'IP Address', 'Method', 'Endpoint', 'User Agent', 'Details'];
    const rows = _logsCache.map(l => [
        `"${l.timestamp || ''}"`,
        `"${(l.action || '').replace(/"/g, '""')}"`,
        `"${(l.user_name || '').replace(/"/g, '""')}"`,
        `"${(l.ip_address || '').replace(/"/g, '""')}"`,
        `"${(l.http_method || '').replace(/"/g, '""')}"`,
        `"${(l.request_path || '').replace(/"/g, '""')}"`,
        `"${(l.user_agent || '').replace(/"/g, '""')}"`,
        `"${(l.details || '').replace(/"/g, '""')}"`
    ]);
    downloadCSV([headers, ...rows], 'audit_logs.csv');
    showToast('Audit logs exported!', 'success');
}

let _leavesCache = [];
let _leavesFilter = 'all';

async function showLeaveRequests() {
    if (!hasPermission('admin') && !hasPermission('manager')) { showAccessDenied(); return; }
    setActiveNavByView('leave-requests');
    setDashboardContext('Leave Requests', 'Review and manage leave approvals');
    const dashboardContent = document.getElementById('dashboardContent');
    dashboardContent.innerHTML = renderLoading('Loading leave requestsâ€¦');

    try {
        const res = await apiCall('/leaves', 'GET');
        _leavesCache = res.leaves || [];
        _leavesFilter = 'all';
        renderLeavesView();
    } catch (err) {
        dashboardContent.innerHTML = renderError('Failed to load leave requests.');
    }
}

function renderLeavesView() {
    const dashboardContent = document.getElementById('dashboardContent');
    const pending = _leavesCache.filter(l => l.status === 'pending').length;
    const filtered = _leavesFilter === 'all' ? _leavesCache : _leavesCache.filter(l => l.status === _leavesFilter);

    dashboardContent.innerHTML = `
        <div class="section-toolbar">
            <div class="toolbar-left">
                <span class="section-title">Leave Requests</span>
                ${pending ? `<span class="pending-alert"><i class="fas fa-exclamation-circle"></i>${pending} pending</span>` : ''}
            </div>
            <div class="toolbar-right">
                <select class="filter-select" onchange="_leavesFilter=this.value;renderLeavesView()">
                    <option value="all"     ${_leavesFilter === 'all' ? 'selected' : ''}>All</option>
                    <option value="pending" ${_leavesFilter === 'pending' ? 'selected' : ''}>Pending</option>
                    <option value="approved"${_leavesFilter === 'approved' ? 'selected' : ''}>Approved</option>
                    <option value="rejected"${_leavesFilter === 'rejected' ? 'selected' : ''}>Rejected</option>
                </select>
                <button class="btn btn-secondary" onclick="exportLeavesCSV()">
                    <i class="fas fa-download"></i> Export
                </button>
            </div>
        </div>
        <div class="table-container">
            <table class="table">
                <thead><tr>
                    <th>Employee</th><th>Type</th><th>Start</th><th>End</th>
                    <th>Days</th><th>Reason</th><th>Status</th><th>Actions</th>
                </tr></thead>
                <tbody>${renderLeavesRows(filtered)}</tbody>
            </table>
        </div>`;
}

function renderLeavesRows(leaves) {
    if (!leaves.length) return `<tr><td colspan="8"><div class="loading-state"><span>No records.</span></div></td></tr>`;
    return leaves.map(l => `<tr>
        <td>
            <div class="fw-600">${l.employee_name}</div>
            <div class="text-muted small">${l.department || ''}</div>
        </td>
        <td><span class="leave-type-badge leave-${l.type}">${capitalize(l.type)}</span></td>
        <td class="nowrap">${l.start_date}</td>
        <td class="nowrap">${l.end_date}</td>
        <td>${l.days}</td>
        <td class="text-muted small">${l.reason || 'â€”'}</td>
        <td><span class="status-badge status-${l.status}">${l.status}</span></td>
        <td>
            ${l.status === 'pending' ? `
                <div class="action-btns">
                    <button class="icon-btn green-btn" onclick="updateLeaveStatus(${l.id},'approved')"><i class="fas fa-check"></i> Approve</button>
                    <button class="icon-btn del-btn"   onclick="updateLeaveStatus(${l.id},'rejected')"><i class="fas fa-times"></i> Reject</button>
                </div>` : `<span class="text-muted small">â€”</span>`}
        </td>
    </tr>`).join('');
}

async function updateLeaveStatus(id, status) {
    try {
        await apiCall(`/leaves/${id}`, 'PUT', { status });
        // Update cache in-place
        const item = _leavesCache.find(l => l.id === id);
        if (item) item.status = status;
        renderLeavesView();
        showToast(`Leave request ${status}.`, status === 'approved' ? 'success' : 'warning');
    } catch (err) {
        showToast('Failed to update leave status.', 'error');
    }
}

function exportLeavesCSV() {
    const headers = ['Employee', 'Department', 'Type', 'Start', 'End', 'Days', 'Reason', 'Status'];
    const rows = _leavesCache.map(l => [
        `"${l.employee_name}"`, `"${l.department || ''}"`, `"${l.type}"`,
        l.start_date, l.end_date, l.days, `"${(l.reason || '').replace(/"/g, '""')}"`, l.status
    ]);
    downloadCSV([headers, ...rows], 'leave_requests.csv');
    showToast('Leave requests exported!', 'success');
}

async function showTeam() {
    if (!hasPermission('manager')) { showAccessDenied(); return; }
    setActiveNavByView('team');
    setDashboardContext('Team', 'View and monitor your team members');
    const dashboardContent = document.getElementById('dashboardContent');
    dashboardContent.innerHTML = renderLoading();

    try {
        const res = await apiCall('/users', 'GET');
        const employees = (res.users || []).filter(u => u.role === 'employee');
        window._teamCache = employees;
        dashboardContent.innerHTML = `
            <div class="section-toolbar">
                <span class="section-title">Team Members</span>
                <div class="toolbar-right">
                    <span class="count-badge">${employees.length} employees</span>
                    <div class="search-box">
                        <i class="fas fa-search search-icon"></i>
                        <input type="text" id="teamSearch" placeholder="Search teamâ€¦" oninput="filterTeamTable(this.value)">
                    </div>
                </div>
            </div>
            <div class="table-container">
                <table class="table">
                    <thead><tr><th>Name</th><th>Email</th><th>Department</th><th>Status</th></tr></thead>
                    <tbody id="teamTableBody">${employees.map(u => {
            const name = `${u.firstName} ${u.lastName}`;
            return `<tr>
                            <td><div style="display:flex;align-items:center;gap:10px;">
                                <div class="avatar-circle role-employee">${initials(name)}</div>
                                <span class="fw-600">${name}</span>
                            </div></td>
                            <td class="text-muted">${u.email}</td>
                            <td>${u.department || 'â€”'}</td>
                            <td><span class="status-badge status-${u.status}">${u.status}</span></td>
                        </tr>`;
        }).join('')}</tbody>
                </table>
            </div>`;
    } catch (err) {
        dashboardContent.innerHTML = renderError();
    }
}

function filterTeamTable(query) {
    const q = (query || '').toLowerCase();
    const list = window._teamCache || [];
    const filtered = list.filter(u =>
        `${u.firstName} ${u.lastName}`.toLowerCase().includes(q) ||
        (u.email || '').toLowerCase().includes(q) ||
        (u.department || '').toLowerCase().includes(q) ||
        (u.status || '').toLowerCase().includes(q)
    );

    const tbody = document.getElementById('teamTableBody');
    if (!tbody) return;
    tbody.innerHTML = filtered.map(u => {
        const name = `${u.firstName} ${u.lastName}`;
        return `<tr>
                    <td><div style="display:flex;align-items:center;gap:10px;">
                        <div class="avatar-circle role-employee">${initials(name)}</div>
                        <span class="fw-600">${name}</span>
                    </div></td>
                    <td class="text-muted">${u.email}</td>
                    <td>${u.department || 'â€”'}</td>
                    <td><span class="status-badge status-${u.status}">${u.status}</span></td>
                </tr>`;
    }).join('') || `<tr><td colspan="4"><div class="loading-state"><span>No team members found.</span></div></td></tr>`;
}

async function showReports() {
    if (!hasPermission(currentRole === 'admin' ? 'admin' : 'manager')) { showAccessDenied(); return; }
    setActiveNavByView('reports');
    setDashboardContext('Reports', 'Analyze leave activity across teams');
    const dashboardContent = document.getElementById('dashboardContent');
    dashboardContent.innerHTML = renderLoading('Generating reportâ€¦');

    try {
        const res = await apiCall('/reports', 'GET');
        const byEmployee = res.byEmployee || [];
        const byType = res.byType || [];
        const totalReqs = byEmployee.reduce((s, r) => s + r.total, 0);
        const totalApproved = byEmployee.reduce((s, r) => s + r.approved, 0);
        const totalDays = byEmployee.reduce((s, r) => s + r.approved_days, 0);

        const typeColors = { vacation: '#3b82f6', sick: '#ef4444', personal: '#22c55e' };

        dashboardContent.innerHTML = `
        <div class="section-toolbar">
            <span class="section-title">Leave Reports</span>
            <button class="btn btn-secondary" onclick="exportReportCSV()">
                <i class="fas fa-download"></i> Export CSV
            </button>
        </div>

        <div class="stat-grid" style="margin-bottom:24px;">
            ${statCard('fa-paper-plane', 'Total Requests', totalReqs, 'blue')}
            ${statCard('fa-check-circle', 'Approved', totalApproved, 'green')}
            ${statCard('fa-sun', 'Approved Days', totalDays, 'teal')}
        </div>

        <div class="dashboard-grid">
            <div class="dashboard-card">
                <div class="card-header"><i class="fas fa-user-chart"></i><h3>By Employee</h3></div>
                <div class="card-content">
                    <table class="table" style="margin:0">
                        <thead><tr><th>Employee</th><th>Dept</th><th>Total</th><th>Approved</th><th>Pending</th><th>Rejected</th><th>Days</th></tr></thead>
                        <tbody>
                            ${byEmployee.length === 0 ? `<tr><td colspan="7" class="text-muted small" style="padding:16px">No data yet.</td></tr>` :
                byEmployee.map(r => `<tr>
                                <td class="fw-600">${r.name}</td>
                                <td class="text-muted small">${r.department || ''}</td>
                                <td>${r.total}</td>
                                <td class="text-green fw-600">${r.approved}</td>
                                <td class="text-orange">${r.pending}</td>
                                <td class="text-red">${r.rejected}</td>
                                <td class="fw-600">${r.approved_days}</td>
                              </tr>`).join('')}
                        </tbody>
                    </table>
                </div>
            </div>

            <div class="dashboard-card">
                <div class="card-header"><i class="fas fa-chart-pie"></i><h3>By Leave Type</h3></div>
                <div class="card-content">
                    ${byType.map(t => {
                    const pct = totalReqs ? Math.round((t.total / totalReqs) * 100) : 0;
                    const color = typeColors[t.type] || '#6b7280';
                    return `<div class="mini-bar-row">
                            <span class="mini-bar-label">${capitalize(t.type)}</span>
                            <div class="mini-bar-track"><div class="mini-bar-fill" style="width:${pct}%;background:${color};"></div></div>
                            <span class="mini-bar-count">${t.total}</span>
                        </div>`;
                }).join('')}
                </div>
            </div>
        </div>`;

        // Store for CSV export
        window._reportCache = { byEmployee, byType };
    } catch (err) {
        dashboardContent.innerHTML = renderError('Failed to load reports.');
    }
}

function exportReportCSV() {
    const data = window._reportCache;
    if (!data) { showToast('No report data to export', 'warning'); return; }
    const headers = ['Employee', 'Department', 'Total', 'Approved', 'Pending', 'Rejected', 'Approved Days'];
    const rows = data.byEmployee.map(r => [
        `"${r.name}"`, `"${r.department || ''}"`,
        r.total, r.approved, r.pending, r.rejected, r.approved_days
    ]);
    downloadCSV([headers, ...rows], 'leave_report.csv');
    showToast('Report exported!', 'success');
}

async function showProfile() {
    setActiveNavByView(currentRole === 'employee' ? 'profile' : 'dashboard');
    setDashboardContext('Profile', 'View and manage your account details');
    const dc = document.getElementById('dashboardContent');
    if (!dc) return;
    dc.innerHTML = renderLoading('Loading profile…');

    // Fetch profile, leaves, and activity in parallel
    let profileData = currentUser;
    let myLeaves = [];
    let activityLogs = [];

    try {
        const [leavesRes, logsRes] = await Promise.all([
            apiCall('/leaves', 'GET'),
            currentUser.id ? apiCall(`/logs?userId=${currentUser.id}&limit=10`, 'GET') : Promise.resolve({ logs: [] })
        ]);

        // Also try to get extended profile
        if (currentUser.id) {
            try {
                const profileRes = await apiCall(`/profile/${currentUser.id}`, 'GET');
                if (profileRes.user) {
                    profileData = { ...currentUser, ...profileRes.user };
                    profileData.name = `${profileData.firstName || ''} ${profileData.lastName || ''}`.trim();
                }
            } catch (e) { /* use currentUser fallback */ }
        }

        const allLeaves = leavesRes.leaves || [];
        myLeaves = allLeaves.filter(l => l.user_id === (currentUser.id || 0));
        activityLogs = logsRes.logs || [];
    } catch (err) {
        // continue with what we have
    }

    const approved = myLeaves.filter(l => l.status === 'approved');
    const pending = myLeaves.filter(l => l.status === 'pending');
    const rejected = myLeaves.filter(l => l.status === 'rejected');
    const approvedDays = approved.reduce((s, l) => s + (l.days || 0), 0);

    const firstName = profileData.firstName || currentUser.name?.split(' ')[0] || '';
    const lastName = profileData.lastName || currentUser.name?.split(' ').slice(1).join(' ') || '';
    const joinDate = profileData.joinDate ? new Date(profileData.joinDate).toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' }) : 'N/A';

    dc.innerHTML = `
    <div class="profile-page">
        <!-- Profile Header -->
        <div class="profile-header">
            <div class="profile-avatar-large">${initials(currentUser.name || '')}</div>
            <div class="profile-header-info">
                <h2>${currentUser.name || 'User'}</h2>
                <span class="role-badge">${capitalize(currentUser.role || 'employee')}</span>
                <div class="profile-meta">
                    <span><i class="fas fa-envelope"></i> ${currentUser.email || ''}</span>
                    <span><i class="fas fa-building"></i> ${currentUser.department || 'N/A'}</span>
                    <span><i class="fas fa-calendar-alt"></i> Joined ${joinDate}</span>
                </div>
            </div>
        </div>

        <!-- Leave Summary Stats -->
        <div class="stat-grid">
            ${statCard('fa-paper-plane', 'Total Requests', myLeaves.length, 'blue')}
            ${statCard('fa-check-circle', 'Approved', approved.length, 'green')}
            ${statCard('fa-clock', 'Pending', pending.length, 'orange')}
            ${statCard('fa-sun', 'Days Used', approvedDays, 'teal')}
        </div>

        <!-- Profile Info Cards -->
        <div class="profile-grid">
            <!-- Personal Info -->
            <div class="dashboard-card">
                <div class="card-header"><i class="fas fa-user"></i><h3>Personal Information</h3></div>
                <div class="card-content" id="personalInfoCard">
                    <div class="profile-field">
                        <span class="profile-field-label"><i class="fas fa-id-card"></i> First Name</span>
                        <span class="profile-field-value" id="profileFirstName">${firstName}</span>
                    </div>
                    <div class="profile-field">
                        <span class="profile-field-label"><i class="fas fa-id-card"></i> Last Name</span>
                        <span class="profile-field-value" id="profileLastName">${lastName}</span>
                    </div>
                    <div class="profile-field">
                        <span class="profile-field-label"><i class="fas fa-envelope"></i> Email</span>
                        <span class="profile-field-value">${currentUser.email || 'N/A'}</span>
                    </div>
                    <div class="profile-field">
                        <span class="profile-field-label"><i class="fas fa-phone"></i> Phone</span>
                        <span class="profile-field-value" id="profilePhone">${profileData.phone || 'Not set'}</span>
                    </div>
                    <div class="profile-field">
                        <span class="profile-field-label"><i class="fas fa-pen-fancy"></i> Bio</span>
                        <span class="profile-field-value" id="profileBio">${profileData.bio || 'No bio yet'}</span>
                    </div>
                </div>
                <div class="card-footer">
                    <button class="btn btn-primary btn-sm" onclick="openProfileEdit()">
                        <i class="fas fa-edit"></i> Edit Profile
                    </button>
                </div>
            </div>

            <!-- Work Info -->
            <div class="dashboard-card">
                <div class="card-header"><i class="fas fa-briefcase"></i><h3>Work Information</h3></div>
                <div class="card-content">
                    <div class="profile-field">
                        <span class="profile-field-label"><i class="fas fa-user-tag"></i> Role</span>
                        <span class="profile-field-value"><span class="role-badge role-${currentUser.role}">${capitalize(currentUser.role)}</span></span>
                    </div>
                    <div class="profile-field">
                        <span class="profile-field-label"><i class="fas fa-building"></i> Department</span>
                        <span class="profile-field-value" id="profileDept">${currentUser.department || 'N/A'}</span>
                    </div>
                    <div class="profile-field">
                        <span class="profile-field-label"><i class="fas fa-toggle-on"></i> Status</span>
                        <span class="profile-field-value"><span class="status-badge status-active">Active</span></span>
                    </div>
                    <div class="profile-field">
                        <span class="profile-field-label"><i class="fas fa-calendar-plus"></i> Join Date</span>
                        <span class="profile-field-value">${joinDate}</span>
                    </div>
                    <div class="profile-field">
                        <span class="profile-field-label"><i class="fas fa-umbrella-beach"></i> Leave Balance</span>
                        <span class="profile-field-value">${Math.max(0, 20 - approvedDays)} days remaining</span>
                    </div>
                </div>
            </div>

            <!-- Security / Change Password -->
            <div class="dashboard-card">
                <div class="card-header"><i class="fas fa-shield-alt"></i><h3>Security</h3></div>
                <div class="card-content">
                    <div class="password-change-form" id="passwordChangeForm">
                        <div class="form-group">
                            <label>Current Password</label>
                            <div class="input-wrapper">
                                <i class="fas fa-lock"></i>
                                <input type="password" id="currentPw" placeholder="Enter current password">
                            </div>
                        </div>
                        <div class="form-group">
                            <label>New Password</label>
                            <div class="input-wrapper">
                                <i class="fas fa-key"></i>
                                <input type="password" id="newPw" placeholder="Enter new password" minlength="8">
                            </div>
                        </div>
                        <div class="form-group">
                            <label>Confirm New Password</label>
                            <div class="input-wrapper">
                                <i class="fas fa-key"></i>
                                <input type="password" id="confirmNewPw" placeholder="Confirm new password" minlength="8">
                            </div>
                        </div>
                        <div class="form-actions">
                            <button class="btn btn-primary btn-sm" onclick="handlePasswordChange()">
                                <i class="fas fa-save"></i> Update Password
                            </button>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Activity Timeline -->
            <div class="dashboard-card">
                <div class="card-header"><i class="fas fa-history"></i><h3>Recent Activity</h3></div>
                <div class="card-content">
                    ${activityLogs.length === 0 ? '<p class="text-muted small">No recent activity.</p>' :
            `<div class="activity-timeline">
                        ${activityLogs.slice(0, 8).map(l => {
                const color = logActionColor(l.action);
                const iconMap = { green: 'fa-sign-in-alt', blue: 'fa-plus-circle', orange: 'fa-calendar-check', red: 'fa-exclamation-circle', gray: 'fa-circle' };
                return `<div class="timeline-item">
                                <div class="timeline-dot ${color}"><i class="fas ${iconMap[color] || 'fa-circle'}"></i></div>
                                <div class="timeline-info">
                                    <div class="timeline-action">${l.action}</div>
                                    <div class="timeline-detail">${l.details || '—'}</div>
                                </div>
                                <span class="timeline-time">${formatTimestamp(l.timestamp)}</span>
                            </div>`;
            }).join('')}
                    </div>`}
                </div>
            </div>
        </div>
    </div>`;
}

// Open profile edit modal inline
function openProfileEdit() {
    const dc = document.getElementById('dashboardContent');
    if (!dc) return;

    const firstName = currentUser.name?.split(' ')[0] || '';
    const lastName = currentUser.name?.split(' ').slice(1).join(' ') || '';

    dc.innerHTML = `
    <div class="profile-page">
        <div class="dashboard-card" style="max-width:600px;margin:0 auto;">
            <div class="card-header"><i class="fas fa-user-edit"></i><h3>Edit Profile</h3></div>
            <div class="card-content">
                <form id="profileEditForm" style="display:flex;flex-direction:column;gap:14px;">
                    <div class="form-row" style="display:grid;grid-template-columns:1fr 1fr;gap:14px;">
                        <div class="form-group" style="margin:0;">
                            <label>First Name</label>
                            <input type="text" id="editFirstName" value="${firstName}" class="profile-edit-input" style="width:100%;" required>
                        </div>
                        <div class="form-group" style="margin:0;">
                            <label>Last Name</label>
                            <input type="text" id="editLastName" value="${lastName}" class="profile-edit-input" style="width:100%;" required>
                        </div>
                    </div>
                    <div class="form-group" style="margin:0;">
                        <label>Department</label>
                        <select id="editDepartment" class="profile-edit-input" style="width:100%;">
                            <option value="IT" ${currentUser.department === 'IT' ? 'selected' : ''}>Information Technology</option>
                            <option value="HR" ${currentUser.department === 'HR' ? 'selected' : ''}>Human Resources</option>
                            <option value="Finance" ${currentUser.department === 'Finance' ? 'selected' : ''}>Finance</option>
                            <option value="Marketing" ${currentUser.department === 'Marketing' ? 'selected' : ''}>Marketing</option>
                            <option value="Operations" ${currentUser.department === 'Operations' ? 'selected' : ''}>Operations</option>
                        </select>
                    </div>
                    <div class="form-group" style="margin:0;">
                        <label>Phone</label>
                        <input type="tel" id="editPhone" value="${currentUser.phone || ''}" class="profile-edit-input" style="width:100%;" placeholder="e.g. +91 9876543210">
                    </div>
                    <div class="form-group" style="margin:0;">
                        <label>Bio</label>
                        <textarea id="editBio" class="profile-edit-input" style="width:100%;min-height:60px;resize:vertical;" placeholder="Tell us about yourself...">${currentUser.bio || ''}</textarea>
                    </div>
                    <div class="form-actions" style="display:flex;gap:10px;margin-top:4px;">
                        <button type="submit" class="btn btn-primary"><i class="fas fa-save"></i> Save Changes</button>
                        <button type="button" class="btn btn-secondary" onclick="showProfile()"><i class="fas fa-times"></i> Cancel</button>
                    </div>
                </form>
            </div>
        </div>
    </div>`;

    document.getElementById('profileEditForm').addEventListener('submit', handleProfileUpdate);
}

async function handleProfileUpdate(event) {
    event.preventDefault();

    const firstName = document.getElementById('editFirstName').value.trim();
    const lastName = document.getElementById('editLastName').value.trim();
    const department = document.getElementById('editDepartment').value;
    const phone = document.getElementById('editPhone').value.trim();
    const bio = document.getElementById('editBio').value.trim();

    if (!firstName || !lastName) {
        showToast('First and last names are required', 'error');
        return;
    }

    try {
        if (currentUser.id) {
            await apiCall(`/users/${currentUser.id}`, 'PUT', {
                firstName,
                lastName,
                email: currentUser.email,
                role: currentUser.role,
                status: 'active',
                department,
                phone,
                bio
            });
        }

        // Update local state
        currentUser.name = `${firstName} ${lastName}`;
        currentUser.department = department;
        currentUser.phone = phone;
        currentUser.bio = bio;
        currentUser.firstName = firstName;
        currentUser.lastName = lastName;
        localStorage.setItem('currentUser', JSON.stringify(currentUser));

        // Update navbar name
        const userNameEl = document.getElementById('userName');
        if (userNameEl) userNameEl.textContent = currentUser.name;

        showToast('Profile updated successfully!', 'success');
        showProfile();
    } catch (err) {
        showToast(err.message || 'Failed to update profile', 'error');
    }
}

async function handlePasswordChange() {
    const currentPw = document.getElementById('currentPw').value;
    const newPw = document.getElementById('newPw').value;
    const confirmPw = document.getElementById('confirmNewPw').value;

    if (!currentPw || !newPw || !confirmPw) {
        showToast('Please fill in all password fields', 'error');
        return;
    }

    if (newPw.length < 8) {
        showToast('New password must be at least 8 characters', 'error');
        return;
    }

    if (newPw !== confirmPw) {
        showToast('New passwords do not match', 'error');
        return;
    }

    try {
        await apiCall(`/profile/${currentUser.id}/password`, 'PUT', {
            currentPassword: currentPw,
            newPassword: newPw
        });
        showToast('Password changed successfully!', 'success');
        document.getElementById('currentPw').value = '';
        document.getElementById('newPw').value = '';
        document.getElementById('confirmNewPw').value = '';
    } catch (err) {
        showToast(err.message || 'Failed to change password', 'error');
    }
}

let _myLeavesFilter = 'all';
let _myLeavesSort = 'newest';

async function showMyLeaveRequests() {
    setActiveNavByView('my-leaves');
    setDashboardContext('My Leaves', 'Track your requests and statuses');
    const dc = document.getElementById('dashboardContent');
    if (!dc) return;
    dc.innerHTML = renderLoading('Loading your leaves…');

    try {
        const leavesRes = await apiCall('/leaves', 'GET');
        const allLeaves = leavesRes.leaves || [];
        const myLeaves = allLeaves.filter(l => l.user_id === (currentUser.id || 0));

        const approved = myLeaves.filter(l => l.status === 'approved');
        const pending = myLeaves.filter(l => l.status === 'pending');
        const rejected = myLeaves.filter(l => l.status === 'rejected');

        window._myLeavesAll = myLeaves;

        dc.innerHTML = `
        <div class="leaves-page">
            <div class="section-toolbar">
                <span class="section-title">My Leave Requests</span>
                <div class="toolbar-right">
                    <select class="filter-select" onchange="_myLeavesSort=this.value;filterMyLeaves(_myLeavesFilter)">
                        <option value="newest" ${_myLeavesSort === 'newest' ? 'selected' : ''}>Newest First</option>
                        <option value="oldest" ${_myLeavesSort === 'oldest' ? 'selected' : ''}>Oldest First</option>
                        <option value="longest" ${_myLeavesSort === 'longest' ? 'selected' : ''}>Longest Duration</option>
                    </select>
                    <button class="btn btn-primary" onclick="openLeaveModal()">
                        <i class="fas fa-plus"></i> New Request
                    </button>
                </div>
            </div>

            <div class="stat-grid">
                ${statCard('fa-paper-plane', 'Total', myLeaves.length, 'blue')}
                ${statCard('fa-check-circle', 'Approved', approved.length, 'green')}
                ${statCard('fa-clock', 'Pending', pending.length, 'orange')}
                ${statCard('fa-times-circle', 'Rejected', rejected.length, 'purple')}
            </div>

            <div class="filter-tabs" id="leavesFilterTabs">
                <button class="filter-tab ${_myLeavesFilter === 'all' ? 'active' : ''}" onclick="filterMyLeaves('all')">
                    All <span class="tab-count">${myLeaves.length}</span>
                </button>
                <button class="filter-tab ${_myLeavesFilter === 'pending' ? 'active' : ''}" onclick="filterMyLeaves('pending')">
                    Pending <span class="tab-count">${pending.length}</span>
                </button>
                <button class="filter-tab ${_myLeavesFilter === 'approved' ? 'active' : ''}" onclick="filterMyLeaves('approved')">
                    Approved <span class="tab-count">${approved.length}</span>
                </button>
                <button class="filter-tab ${_myLeavesFilter === 'rejected' ? 'active' : ''}" onclick="filterMyLeaves('rejected')">
                    Rejected <span class="tab-count">${rejected.length}</span>
                </button>
            </div>

            <div id="leavesListContainer">
                ${renderMyLeaveCards(myLeaves)}
            </div>
        </div>`;
    } catch (err) {
        dc.innerHTML = renderError('Failed to load your leave requests.');
    }
}

function renderMyLeaveCards(leaves) {
    if (leaves.length === 0) {
        return `<div class="empty-state">
            <i class="fas fa-umbrella-beach"></i>
            <p>No leave requests found</p>
        </div>`;
    }

    const typeIcons = { vacation: 'fa-umbrella-beach', sick: 'fa-thermometer-half', personal: 'fa-user-clock' };

    return leaves.map(l => `
        <div class="leave-card">
            <div class="leave-card-icon ${l.type}">
                <i class="fas ${typeIcons[l.type] || 'fa-calendar'}"></i>
            </div>
            <div class="leave-card-info">
                <div class="leave-card-title">${capitalize(l.type)} Leave</div>
                <div class="leave-card-sub">
                    ${l.start_date} → ${l.end_date} · ${l.reason || 'No reason'}
                </div>
            </div>
            <div class="leave-card-right">
                <span class="status-badge status-${l.status}">${l.status}</span>
                <span class="leave-days-badge">${l.days} day${l.days !== 1 ? 's' : ''}</span>
            </div>
        </div>
    `).join('');
}

function filterMyLeaves(status) {
    _myLeavesFilter = status;
    const all = window._myLeavesAll || [];
    const filtered = (status === 'all' ? all : all.filter(l => l.status === status)).slice();

    filtered.sort((a, b) => {
        if (_myLeavesSort === 'oldest') return (a.start_date || '').localeCompare(b.start_date || '');
        if (_myLeavesSort === 'longest') return (b.days || 0) - (a.days || 0);
        return (b.start_date || '').localeCompare(a.start_date || '');
    });

    // Update active tab
    document.querySelectorAll('.filter-tab').forEach(tab => {
        const text = tab.textContent.trim().toLowerCase();
        const tabStatus = text.startsWith('all') ? 'all'
            : text.startsWith('pending') ? 'pending'
            : text.startsWith('approved') ? 'approved'
            : text.startsWith('rejected') ? 'rejected'
            : '';
        tab.classList.toggle('active', tabStatus === status);
    });

    const container = document.getElementById('leavesListContainer');
    if (container) container.innerHTML = renderMyLeaveCards(filtered);
}

// handleLeaveRequest is now replaced by submitLeaveModal below


// Cooldown and brute force protection
function checkCooldownStatus() {
    if (cooldownEndTime && Date.now() < cooldownEndTime) {
        const remainingTime = Math.ceil((cooldownEndTime - Date.now()) / 1000 / 60);
        showCooldownMessage(remainingTime);
        disableLoginForm(true);
    } else {
        cooldownEndTime = null;
        loginAttempts = 0;
        hideCooldownMessage();
        disableLoginForm(false);
    }
}

function showCooldownMessage(minutes) {
    const loginForm = document.getElementById('loginForm');
    let cooldownDiv = document.querySelector('.cooldown-message');

    if (!cooldownDiv) {
        cooldownDiv = document.createElement('div');
        cooldownDiv.className = 'cooldown-message';
        loginForm.insertBefore(cooldownDiv, loginForm.firstChild);
    }

    cooldownDiv.innerHTML = `
        <i class="fas fa-clock"></i>
        Too many failed login attempts. Please try again in ${minutes} minute(s).
    `;
}

function hideCooldownMessage() {
    const cooldownDiv = document.querySelector('.cooldown-message');
    if (cooldownDiv) {
        cooldownDiv.remove();
    }
}

function disableLoginForm(disabled) {
    const loginBtn = document.querySelector('#loginSubmitBtn');
    const inputs = document.querySelectorAll('#loginForm input');

    if (loginBtn) {
        if (disabled) {
            loginBtn.disabled = true;
            loginBtn.style.opacity = '0.5';
            loginBtn.style.cursor = 'not-allowed';
        } else {
            loginBtn.disabled = false;
            loginBtn.style.opacity = '1';
            loginBtn.style.cursor = 'pointer';
        }
    }

    if (disabled) {
        inputs.forEach(input => input.disabled = true);
    } else {
        inputs.forEach(input => input.disabled = false);
    }
}

function startCooldown() {
    cooldownEndTime = Date.now() + (5 * 60 * 1000); // 5 minutes
    localStorage.setItem('cooldownEndTime', cooldownEndTime.toString());
    checkCooldownStatus();
}

// Initialize cooldown from localStorage
function initializeCooldown() {
    const savedCooldown = localStorage.getItem('cooldownEndTime');
    if (savedCooldown) {
        cooldownEndTime = parseInt(savedCooldown);
        if (Date.now() < cooldownEndTime) {
            // Still in cooldown
        } else {
            // Cooldown expired, clear it
            localStorage.removeItem('cooldownEndTime');
            cooldownEndTime = null;
        }
    }
}

// Permission checking
function hasPermission(requiredRole) {
    if (requiredRole === 'admin') {
        return currentRole === 'admin';
    } else if (requiredRole === 'manager') {
        return currentRole === 'admin' || currentRole === 'manager';
    }
    return true;
}

// Set active navigation link
function setActiveNavLink(index) {
    const navLinks = document.querySelectorAll('.nav-link');
    const target = navLinks[index];
    if (target) {
        const view = target.getAttribute('data-view');
        if (view) {
            setActiveNavByView(view);
            return;
        }
    }

    navLinks.forEach((link, i) => link.classList.toggle('active', i === index));
}

// Access denied modal
function showAccessDenied() {
    const modal = document.getElementById('accessDeniedModal');
    if (modal) {
        modal.style.display = 'flex';
    }
}

function closeAccessDeniedModal() {
    const modal = document.getElementById('accessDeniedModal');
    if (modal) {
        modal.style.display = 'none';
    }
}

// Toast notification system
function showToast(message, type = 'info') {
    const container = document.getElementById('toast-container');
    if (!container) return;

    const toast = document.createElement('div');
    toast.className = `toast ${type}`;

    const icon = type === 'success' ? 'fa-check-circle' :
        type === 'error' ? 'fa-exclamation-circle' :
            type === 'warning' ? 'fa-exclamation-triangle' : 'fa-info-circle';

    toast.innerHTML = `
        <i class="fas ${icon}"></i>
        <span>${message}</span>
    `;

    container.appendChild(toast);

    // Auto remove after 3 seconds
    setTimeout(() => {
        if (toast.parentNode) {
            toast.parentNode.removeChild(toast);
        }
    }, 3000);
}

// Logout function
function logout() {
    currentUser = null;
    currentRole = null;
    localStorage.removeItem('currentUser');
    localStorage.removeItem('currentRole');

    showToast('Logged out successfully!', 'success');

    setTimeout(() => {
        showHomePage();
    }, 1000);
}

// â”€â”€â”€ User Modal â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
async function openUserModal(userId = null) {
    if (!hasPermission('admin')) { showAccessDenied(); return; }
    const modal = document.getElementById('userModal');
    const title = document.getElementById('userModalTitle');
    const errEl = document.getElementById('userModalError');
    if (!modal) return;

    // Reset form
    document.getElementById('userModalId').value = '';
    document.getElementById('userModalFirstName').value = '';
    document.getElementById('userModalLastName').value = '';
    document.getElementById('userModalEmail').value = '';
    document.getElementById('userModalRole').value = 'employee';
    document.getElementById('userModalDept').value = 'IT';
    document.getElementById('userModalStatus').value = 'active';
    if (errEl) { errEl.style.display = 'none'; errEl.textContent = ''; }

    if (userId) {
        title.textContent = 'Edit User';
        // Populate from cache or API
        let user = (_usersCache || []).find(u => u.id === userId);
        if (!user) {
            try {
                const res = await apiCall(`/users`, 'GET');
                user = (res.users || []).find(u => u.id === userId);
            } catch (e) { /* ignore */ }
        }
        if (user) {
            document.getElementById('userModalId').value = user.id;
            document.getElementById('userModalFirstName').value = user.firstName || '';
            document.getElementById('userModalLastName').value = user.lastName || '';
            document.getElementById('userModalEmail').value = user.email || '';
            document.getElementById('userModalRole').value = user.role || 'employee';
            document.getElementById('userModalDept').value = user.department || 'IT';
            document.getElementById('userModalStatus').value = user.status || 'active';
        }
    } else {
        title.textContent = 'Add New User';
    }

    modal.style.display = 'flex';
}

function closeUserModal() {
    const modal = document.getElementById('userModal');
    if (modal) modal.style.display = 'none';
}

async function submitUserModal() {
    const userId = document.getElementById('userModalId').value;
    const firstName = document.getElementById('userModalFirstName').value.trim();
    const lastName = document.getElementById('userModalLastName').value.trim();
    const email = document.getElementById('userModalEmail').value.trim();
    const role = document.getElementById('userModalRole').value;
    const dept = document.getElementById('userModalDept').value;
    const status = document.getElementById('userModalStatus').value;
    const errEl = document.getElementById('userModalError');
    const saveBtn = document.getElementById('userModalSaveBtn');

    if (!firstName || !lastName || !email) {
        if (errEl) { errEl.textContent = 'Please fill in all required fields.'; errEl.style.display = 'block'; }
        return;
    }
    if (errEl) { errEl.style.display = 'none'; }
    if (saveBtn) saveBtn.disabled = true;

    try {
        if (userId) {
            // Update user
            await apiCall(`/users/${userId}`, 'PUT', { firstName, lastName, email, role, department: dept, status });
            showToast('User updated successfully!', 'success');
        } else {
            // Create user
            const res = await apiCall('/users', 'POST', { firstName, lastName, email, role, department: dept });
            showToast(`User created! Default password: ${res.default_password || 'password123'}`, 'success');
        }
        closeUserModal();
        showUsers();
    } catch (err) {
        if (errEl) { errEl.textContent = err.message || 'Operation failed.'; errEl.style.display = 'block'; }
    } finally {
        if (saveBtn) saveBtn.disabled = false;
    }
}

// â”€â”€â”€ Delete User Confirm â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
function confirmDeleteUser(userId, name) {
    if (!hasPermission('admin')) { showAccessDenied(); return; }
    showConfirm(
        'Delete User',
        `Are you sure you want to delete <strong>${name}</strong>? This action cannot be undone.`,
        'danger',
        async () => {
            try {
                await apiCall(`/users/${userId}`, 'DELETE');
                showToast('User deleted successfully.', 'success');
                showUsers();
            } catch (err) {
                showToast('Failed to delete user.', 'error');
            }
        }
    );
}

// â”€â”€â”€ Leave Modal (employee) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
function openLeaveModal() {
    const modal = document.getElementById('leaveModal');
    const errEl = document.getElementById('leaveModalError');
    if (!modal) return;
    document.getElementById('leaveModalType').value = 'vacation';
    document.getElementById('leaveModalStart').value = '';
    document.getElementById('leaveModalEnd').value = '';
    document.getElementById('leaveModalReason').value = '';
    if (errEl) { errEl.style.display = 'none'; }
    modal.style.display = 'flex';
}

function closeLeaveModal() {
    const modal = document.getElementById('leaveModal');
    if (modal) modal.style.display = 'none';
}

async function submitLeaveModal() {
    const type = document.getElementById('leaveModalType').value;
    const startDate = document.getElementById('leaveModalStart').value;
    const endDate = document.getElementById('leaveModalEnd').value;
    const reason = document.getElementById('leaveModalReason').value.trim();
    const errEl = document.getElementById('leaveModalError');

    if (!startDate || !endDate) {
        if (errEl) { errEl.textContent = 'Please select start and end dates.'; errEl.style.display = 'block'; }
        return;
    }
    if (endDate < startDate) {
        if (errEl) { errEl.textContent = 'End date cannot be before start date.'; errEl.style.display = 'block'; }
        return;
    }
    if (errEl) errEl.style.display = 'none';

    try {
        await apiCall('/leaves', 'POST', {
            userId: currentUser.id, type, startDate, endDate, reason
        });
        closeLeaveModal();
        showToast('Leave request submitted!', 'success');
        // Refresh dashboard
        if (currentRole === 'employee') showEmployeeDashboard();
        else showLeaveRequests();
    } catch (err) {
        if (errEl) { errEl.textContent = err.message || 'Submission failed.'; errEl.style.display = 'block'; }
    }
}

// â”€â”€â”€ Confirm Modal â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
let _confirmCallback = null;
function showConfirm(title, message, type, onConfirm) {
    const modal = document.getElementById('confirmModal');
    const titleEl = document.getElementById('confirmTitle');
    const msgEl = document.getElementById('confirmMessage');
    const okBtn = document.getElementById('confirmOkBtn');
    if (!modal) { if (confirm(message.replace(/<[^>]+>/g, ''))) onConfirm(); return; }
    titleEl.textContent = title;
    msgEl.innerHTML = message;
    okBtn.className = `btn btn-${type === 'danger' ? 'danger' : 'primary'}`;
    _confirmCallback = onConfirm;
    modal.style.display = 'flex';
}
function closeConfirmModal() {
    const modal = document.getElementById('confirmModal');
    if (modal) modal.style.display = 'none';
    _confirmCallback = null;
}
function executeConfirm() {
    closeConfirmModal();
    if (_confirmCallback) _confirmCallback();
}

// â”€â”€â”€ CSV helper â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
function downloadCSV(rows, filename) {
    const csv = rows.map(r => r.join(',')).join('\n');
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

// API Helper Function (for future backend integration)
// API Helper Function (for future backend integration)
async function apiCall(endpoint, method = 'GET', data = null) {
    try {
        const config = {
            method: method,
            headers: {
                'Content-Type': 'application/json',
            },
            credentials: 'include'
        };

        if (data) {
            config.body = JSON.stringify(data);
        }

        const response = await fetch(`${API_BASE_URL}${endpoint}`, config);
        const contentType = response.headers.get('content-type') || '';
        const isJson = contentType.includes('application/json');
        const result = isJson ? await response.json() : null;

        if (!response.ok) {
            const backendMessage = result?.message || result?.error;
            const fallbackMessage = isJson ? 'Request failed' : (await response.text()) || 'API request failed';
            throw new Error(backendMessage || fallbackMessage);
        }

        return result || { success: true };
    } catch (error) {
        console.error('API Error:', error);
        throw error;
    }
}
