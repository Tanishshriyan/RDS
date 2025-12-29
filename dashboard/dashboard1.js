/* ===================================
   RANSOMGUARD DASHBOARD JAVASCRIPT
   Real-time WebSocket monitoring
   =================================== */

/* ===================================
   CINEMATIC INTRO SEQUENCE
   =================================== */

// Intro animation controller
class IntroSequence {

    constructor() {
        this.overlay = document.getElementById('intro-overlay');
        this.progress = document.getElementById('loading-progress');
        this.status = document.getElementById('system-status');
        this.particles = document.getElementById('particles');
        
        this.statusMessages = [
            'Initializing systems...',
            'Loading detection engine...',
            'Connecting to backend...',
            'Starting real-time monitoring...',
            'System ready!'
        ];
        
        this.currentStep = 0;
    }

    async start() {
        // Generate particles
        this.createParticles();
        
        // Run loading sequence
        await this.runSequence();
        
        // Hide intro
        setTimeout(() => {
            this.overlay.classList.add('hidden');
        }, 500);
    }

    createParticles() {
        for (let i = 0; i < 30; i++) {
            const particle = document.createElement('div');
            particle.className = 'particle';
            particle.style.left = `${Math.random() * 100}%`;
            particle.style.animationDelay = `${Math.random() * 8}s`;
            particle.style.animationDuration = `${5 + Math.random() * 5}s`;
            this.particles.appendChild(particle);
        }
    }

    async runSequence() {
        for (let i = 0; i < this.statusMessages.length; i++) {
            this.status.textContent = this.statusMessages[i];
            const targetProgress = ((i + 1) / this.statusMessages.length) * 100;
            this.progress.style.width = `${targetProgress}%`;
            await this.sleep(600);
        }
    }

    sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }
}

// Initialize intro on page load
document.addEventListener('DOMContentLoaded', () => {
    const intro = new IntroSequence();
    intro.start();
});

/* ===================================
   CUSTOM CURSOR CONTROLLER
   =================================== */

class CustomCursor {
    constructor() {
        this.cursor = document.getElementById('cursor');
        this.follower = document.getElementById('cursor-follower');
        this.cursorX = 0;
        this.cursorY = 0;
        this.followerX = 0;
        this.followerY = 0;
        
        this.init();
    }

    init() {
        // Track mouse movement
        document.addEventListener('mousemove', (e) => {
            this.cursorX = e.clientX;
            this.cursorY = e.clientY;
        });

        // Hide cursor when leaving window
        document.addEventListener('mouseleave', () => {
            this.cursor.classList.add('hidden');
            this.follower.classList.add('hidden');
        });

        // Show cursor when entering window
        document.addEventListener('mouseenter', () => {
            this.cursor.classList.remove('hidden');
            this.follower.classList.remove('hidden');
        });

        // Mouse down effect
        document.addEventListener('mousedown', () => {
            document.body.classList.add('cursor-active');
        });

        // Mouse up effect
        document.addEventListener('mouseup', () => {
            document.body.classList.remove('cursor-active');
        });

        // Add hover effects for interactive elements
        this.addHoverEffects();

        // Start animation loop
        this.animate();
    }

    addHoverEffects() {
        // Select all interactive elements
        const hoverElements = document.querySelectorAll('a, button, .nav-link, .stat-card, .feature-card, input, textarea');
        
        hoverElements.forEach(element => {
            element.addEventListener('mouseenter', () => {
                document.body.classList.add('cursor-hover');
                
                // Special effect for buttons
                if (element.tagName === 'BUTTON' || element.classList.contains('btn')) {
                    document.body.classList.add('cursor-button');
                }
            });

            element.addEventListener('mouseleave', () => {
                document.body.classList.remove('cursor-hover');
                document.body.classList.remove('cursor-button');
            });
        });

        // Text selection effect
        const textElements = document.querySelectorAll('p, h1, h2, h3, h4, h5, h6, span');
        textElements.forEach(element => {
            element.addEventListener('mouseenter', () => {
                document.body.classList.add('cursor-text');
            });
            element.addEventListener('mouseleave', () => {
                document.body.classList.remove('cursor-text');
            });
        });
    }

    animate() {
        // Smooth cursor movement with easing
        const speed = 0.2; // Lower = smoother/slower

        // Update cursor position (instant)
        this.cursor.style.left = this.cursorX + 'px';
        this.cursor.style.top = this.cursorY + 'px';

        // Update follower with delay (creates trailing effect)
        this.followerX += (this.cursorX - this.followerX) * speed;
        this.followerY += (this.cursorY - this.followerY) * speed;

        this.follower.style.left = (this.followerX - 20) + 'px'; // Center the follower
        this.follower.style.top = (this.followerY - 20) + 'px';

        // Continue animation loop
        requestAnimationFrame(() => this.animate());
    }
}

// Initialize custom cursor after intro
document.addEventListener('DOMContentLoaded', () => {
    // Wait for intro to finish before enabling cursor
    setTimeout(() => {
        const customCursor = new CustomCursor();
    }, 3000); // Match intro duration
});


/* ===================================
   SCROLL ANIMATIONS CONTROLLER
   =================================== */

class ScrollAnimations {
    constructor() {
        this.observerOptions = {
            root: null,
            rootMargin: '0px',
            threshold: 0.15
        };
        
        this.init();
    }

    init() {
        // Add scroll-reveal class to elements
        this.setupScrollReveal();
        
        // Create Intersection Observer
        this.observer = new IntersectionObserver(
            this.handleIntersection.bind(this),
            this.observerOptions
        );

        // Observe all elements with scroll-reveal class
        const elements = document.querySelectorAll('.scroll-reveal');
        elements.forEach(element => this.observer.observe(element));

        // Add parallax effect to hero
        this.setupParallax();

        // Add dynamic stat counter
        this.setupStatCounters();
    }

    setupScrollReveal() {
        // Auto-add scroll-reveal class to key elements
        const selectors = [
            '.stat-card',
            '.feature-card',
            '.engine-card',
            '.pipeline-stage',
            '.section-title',
            '.section-subtitle'
        ];

        selectors.forEach(selector => {
            document.querySelectorAll(selector).forEach(element => {
                if (!element.classList.contains('scroll-reveal')) {
                    element.classList.add('scroll-reveal');
                }
            });
        });
    }

    handleIntersection(entries) {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.classList.add('revealed');
                
                // Unobserve after revealing (performance optimization)
                this.observer.unobserve(entry.target);
            }
        });
    }

    setupParallax() {
        const hero = document.querySelector('.hero');
        if (!hero) return;

        window.addEventListener('scroll', () => {
            const scrolled = window.pageYOffset;
            const parallaxSpeed = 0.5;
            
            if (hero && scrolled < hero.offsetHeight) {
                hero.style.transform = `translateY(${scrolled * parallaxSpeed}px)`;
                hero.style.opacity = 1 - (scrolled / hero.offsetHeight) * 0.5;
            }
        });
    }

    setupStatCounters() {
        // Animate numbers when they come into view
        const statValues = document.querySelectorAll('.stat-value');
        
        statValues.forEach(element => {
            const observer = new IntersectionObserver((entries) => {
                entries.forEach(entry => {
                    if (entry.isIntersecting) {
                        this.animateValue(element);
                        observer.unobserve(entry.target);
                    }
                });
            });
            
            observer.observe(element);
        });
    }

    animateValue(element) {
        const text = element.textContent;
        const hasPercent = text.includes('%');
        const number = parseInt(text.replace(/[^0-9]/g, ''));
        
        if (isNaN(number)) return;

        const duration = 1000;
        const steps = 30;
        const stepValue = number / steps;
        const stepDuration = duration / steps;
        let current = 0;

        const timer = setInterval(() => {
            current += stepValue;
            if (current >= number) {
                current = number;
                clearInterval(timer);
            }
            element.textContent = hasPercent ? `${Math.floor(current)}%` : Math.floor(current);
        }, stepDuration);
    }
}

// Initialize scroll animations after intro
document.addEventListener('DOMContentLoaded', () => {
    setTimeout(() => {
        const scrollAnimations = new ScrollAnimations();
    }, 3000); // Match intro duration
});



/* ===================================
   DASHBOARD CODE 
   =================================== */


class RansomGuardDashboard {
        setupScrollHeader() {
        const header = document.querySelector('header');
        if (!header) return;

        window.addEventListener('scroll', () => {
            if (window.scrollY > 10) {
                header.classList.add('scrolled');
            } else {
                header.classList.remove('scrolled');
            }
        });
    }
    constructor() {
        this.ws = null;
        this.reconnectInterval = 5000;
        this.maxReconnectAttempts = 10;
        this.reconnectAttempts = 0;
        this.activityBuffer = [];
        this.maxActivityItems = 40;
        
        this.init();
    }

    init() {
        console.log('🚀 Initializing RansomGuard Dashboard...');
        this.setupScrollHeader(); 
        this.connectWebSocket();
        this.fetchInitialStats();
    }

/* ===================================
   WEBSOCKET CONNECTION & MESSAGE HANDLING
   =================================== */

connectWebSocket() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws`;
    
    console.log('🔌 Connecting to WebSocket:', wsUrl);
    
    this.ws = new WebSocket(wsUrl);
    
    this.ws.onopen = () => {
        console.log('✅ WebSocket connected successfully');
        this.updateConnectionStatus(true);
    };
    
    this.ws.onmessage = (event) => {
        try {
            const message = JSON.parse(event.data);
            console.log('📨 Received:', message);
            this.handleWebSocketMessage(message);
        } catch (error) {
            console.error('❌ Failed to parse message:', error, event.data);
        }
    };
    
    this.ws.onerror = (error) => {
        console.error('❌ WebSocket error:', error);
        this.updateConnectionStatus(false);
    };
    
    this.ws.onclose = () => {
        console.log('🔌 WebSocket disconnected. Reconnecting in 3s...');
        this.updateConnectionStatus(false);
        setTimeout(() => this.connectWebSocket(), 3000);
    };
}

handleWebSocketMessage(message) {
    const type = message.type;
    console.log('🔧 Processing message type:', type);
    
    switch(type) {
        case 'bulk':
            // Handle bulk events - THIS IS THE KEY ONE
            console.log('📦 Processing bulk events:', message.data);
            if (message.data && Array.isArray(message.data)) {
                message.data.forEach(event => {
                    this.processEvent(event);
                });
            }
            break;

        case 'stats':
            // Handle stats messages (same as system)
            console.log('📊 Updating stats:', message.data);
            this.updateStats(message.data);
            break;

        // case 'system':
        //     // Handle system stats
        //     console.log('📊 Updating system stats:', message.data);
        //     this.updateStats(message.data);
        //     break; 
        
            
        case 'activity':
        case 'event':
            // Single event
            console.log('📝 Processing single event:', message.data);
            this.processEvent(message.data);
            break;
            
        case 'ping':
            // Heartbeat - just log it
            console.log('💓 Ping received');
            break;
            
        default:
            console.warn('⚠️ Unknown message type:', type, message);
            break;
    }
}

processEvent(event) {
    if (!event) return;
    
    console.log('⚙️ Processing event:', event);
    
    // Extract data with fallbacks
    const processName = event.process_name || event.process || event.name || 'Unknown Process';
    const eventType = event.event_type || event.type || 'unknown';
    const score = parseInt(event.score || event.threat_score || 0);
    const timestamp = event.timestamp || new Date().toISOString();
    const pid = event.pid || event.process_id || 'N/A';
    
    // Add to activity feed
    this.addToActivityFeed(processName, eventType, score, timestamp, pid);
    
    // Update threat count if high score
    if (score >= 70) {
        this.updateThreatCount(1);
    }
}

addToActivityFeed(processName, eventType, score, timestamp, pid) {
    const feed = document.getElementById('activity-feed') || 
                 document.querySelector('.activity-feed') ||
                 document.querySelector('.activity-log');
    
    if (!feed) {
        console.warn('⚠️ Activity feed element not found!');
        return;
    }
    
    // Determine severity
    let severity = 'low';
    let icon = '📊';
    let color = '#10b981';
    
    if (score >= 75) {
        severity = 'critical';
        icon = '🚨';
        color = '#ef4444';
    } else if (score >= 50) {
        severity = 'high';
        icon = '⚠️';
        color = '#f59e0b';
    } else if (score >= 30) {
        severity = 'medium';
        icon = '📌';
        color = '#3b82f6';
    }
    
    const item = document.createElement('div');
    item.className = `activity-item activity-${severity}`;
    item.style.animation = 'slideInRight 0.4s ease-out';
    
    item.innerHTML = `
        <div class="activity-icon" style="color: ${color}; font-size: 1.5rem;">
            ${icon}
        </div>
        <div class="activity-content" style="flex: 1;">
            <div class="activity-header" style="display: flex; justify-content: space-between; align-items: center;">
                <strong style="color: #e5e7eb;">${processName}</strong>
                <span class="activity-score" style="
                    background: ${color}22;
                    color: ${color};
                    padding: 2px 8px;
                    border-radius: 4px;
                    font-size: 0.75rem;
                    font-weight: 600;
                ">Score: ${score}</span>
            </div>
            <div class="activity-meta" style="
                font-size: 0.875rem;
                color: #9ca3af;
                margin-top: 4px;
                display: flex;
                gap: 12px;
            ">
                <span>Type: ${eventType}</span>
                <span>PID: ${pid}</span>
                <span>${this.formatTimestamp(timestamp)}</span>
            </div>
        </div>
    `;
    
    // Add to top of feed
    feed.insertBefore(item, feed.firstChild);
    
    // Limit to 100 items
    while (feed.children.length > 100) {
        feed.removeChild(feed.lastChild);
    }
    
    console.log('✅ Added to activity feed:', processName);
}

updateStats(data) {
    console.log('📊 Received stats:', data);
    
    // STRICT VALIDATION
    const required = ['active_threats', 'blocked_today', 'files_monitored', 'protection_rate'];
    const missing = required.filter(f => !(f in data));
    
    if (missing.length > 0) {
        throw new Error(`❌ Backend missing fields: ${missing.join(', ')}`);
    }
    
    // Map to HTML IDs
    const updates = {
        'stat-threats': data.active_threats,
        'stat-blocked': data.blocked_today,
        'stat-files': data.files_monitored,
        'stat-protection': `${data.protection_rate}%`
    };
    
    // Update DOM
    for (const [id, value] of Object.entries(updates)) {
        const el = document.getElementById(id);
        if (!el) {
            throw new Error(`❌ Element #${id} not found in HTML`);
        }
        el.textContent = value;
        console.log(`✅ #${id} = ${value}`);
    }
}


updateThreatCount(increment) {
    this.threatCount += increment;
    const element = document.getElementById('active-threats');
    if (element) {
        element.textContent = this.threatCount;
    }
}

formatTimestamp(timestamp) {
    try {
        const date = new Date(timestamp);
        const now = new Date();
        const diff = Math.floor((now - date) / 1000); // seconds ago
        
        if (diff < 60) return 'Just now';
        if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
        if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
        
        return date.toLocaleTimeString('en-US', { 
            hour: '2-digit', 
            minute: '2-digit'
        });
    } catch (e) {
        return 'Just now';
    }
}

updateConnectionStatus(connected) {
    const statusDot = document.querySelector('.status-dot');
    const statusText = document.querySelector('.status-text');
    
    if (statusDot) {
        statusDot.className = connected ? 'status-dot connected' : 'status-dot disconnected';
        statusDot.style.background = connected ? '#10b981' : '#ef4444';
    }
    
    if (statusText) {
        statusText.textContent = connected ? 'Connected' : 'Disconnected';
    }
}


    // === Event Handlers ===
    handleThreatAlert(data) {
        console.warn('🚨 THREAT ALERT:', data);
        
        // Update threat count
        const threatElement = document.getElementById('stat-threats');
        if (threatElement) {
            const currentCount = parseInt(threatElement.textContent) || 0;
            threatElement.textContent = currentCount + 1;
        }

        // Add to activity feed with high priority
        this.addActivityItem({
            timestamp: new Date().toISOString(),
            process: data.process || 'Unknown Process',
            operation: data.operation || 'suspicious activity',
            path: data.path || 'N/A',
            score: data.score || 100,
            risk: 'high'
        });

        // Show browser notification if permitted
        this.showNotification('Threat Detected!', {
            body: `${data.process || 'Unknown'} triggered security alert`,
            icon: '🚨'
        });
    }

    handleActivityUpdate(data) {
        this.addActivityItem({
            timestamp: data.timestamp || new Date().toISOString(),
            process: data.process || 'Unknown',
            operation: data.operation || 'file operation',
            path: data.path || 'N/A',
            score: data.suspicion_score || data.score || 0,
            risk: this.calculateRiskLevel(data.suspicion_score || data.score || 0)
        });
    }

    handleStatsUpdate(data) {
        // Update all stat cards
        if (data.active_threats !== undefined) {
            this.updateStat('stat-threats', data.active_threats);
        }
        if (data.blocked_today !== undefined) {
            this.updateStat('stat-blocked', data.blocked_today);
        }
        if (data.files_monitored !== undefined) {
            this.updateStat('stat-files', data.files_monitored);
        }
        if (data.protection_rate !== undefined) {
            this.updateStat('stat-protection', `${data.protection_rate}%`);
        }
    }

    handleStatusUpdate(data) {
        // Handle general status updates from backend
        if (data.stats) {
            this.handleStatsUpdate(data.stats);
        }
    }

    // === Activity Feed Management ===
    addActivityItem(item) {
        this.activityBuffer.unshift(item);
        
        // Keep only last N items
        if (this.activityBuffer.length > this.maxActivityItems) {
            this.activityBuffer = this.activityBuffer.slice(0, this.maxActivityItems);
        }

        this.renderActivityFeed();
    }

    renderActivityFeed() {
        const feedElement = document.getElementById('activity-feed');
        if (!feedElement) return;

        if (this.activityBuffer.length === 0) {
            feedElement.innerHTML = `
                <div class="activity-placeholder">
                    <div class="placeholder-icon">📡</div>
                    <p class="placeholder-text">Waiting for events...</p>
                    <p class="placeholder-subtext">Last ${this.maxActivityItems} events from the defense engine</p>
                </div>
            `;
            return;
        }

        feedElement.innerHTML = this.activityBuffer.map(item => `
            <div class="activity-item ${item.risk}-risk">
                <div class="activity-timestamp">${this.formatTimestamp(item.timestamp)}</div>
                <div class="activity-details">
                    <div class="activity-process">${this.escapeHtml(item.process)}</div>
                    <div class="activity-path">
                        <strong>${this.escapeHtml(item.operation)}</strong> → ${this.escapeHtml(item.path)}
                    </div>
                </div>
                <div class="activity-score ${this.getScoreClass(item.score)}">
                    ${item.score}
                </div>
            </div>
        `).join('');
    }

    // === API Calls ===
    async fetchInitialStats() {
        try {
            const response = await fetch('/api/status');
            if (!response.ok) throw new Error('Failed to fetch status');
            
            const data = await response.json();
            console.log('📊 Initial stats:', data);

            if (data.stats) {
                this.handleStatsUpdate(data.stats);
            }
        } catch (error) {
            console.error('❌ Failed to fetch initial stats:', error);
        }
    }

    // === Utility Functions ===
    calculateRiskLevel(score) {
        if (score >= 70) return 'high';
        if (score >= 45) return 'medium';
        return 'low';
    }

    getScoreClass(score) {
        if (score >= 70) return 'high';
        if (score >= 45) return 'medium';
        return 'low';
    }

    formatTimestamp(timestamp) {
        const date = new Date(timestamp * 1000);
        const now = new Date();
        const diffMs = now - date;
        const diffSecs = Math.floor(diffMs / 1000);
        const diffMins = Math.floor(diffSecs / 60);
        const diffHours = Math.floor(diffMins / 60);

        if (diffSecs < 60) return `${diffSecs}s ago`;
        if (diffMins < 60) return `${diffMins}m ago`;
        if (diffHours < 24) return `${diffHours}h ago`;
        
        return date.toLocaleString('en-US', {
            month: 'short',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit'
        });
    }

    updateStat(elementId, value) {
        const element = document.getElementById(elementId);
        if (element) {
            element.textContent = value;
        }
    }

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    showNotification(title, options) {
        if ('Notification' in window && Notification.permission === 'granted') {
            new Notification(title, options);
        }
    }

    // === Event Listeners ===
    setupEventListeners() {
    // Request notification permission
    if ('Notification' in window && Notification.permission === 'default') {
        Notification.requestPermission();
    }

    // Enhanced smooth scroll for navigation links
    document.querySelectorAll('.nav-link').forEach(link => {
        link.addEventListener('click', (e) => {
            const href = link.getAttribute('href');
            if (href.startsWith('#')) {
                e.preventDefault();
                const target = document.querySelector(href);
                if (target) {
                    const offsetTop = target.offsetTop - 80; // Account for header
                    window.scrollTo({
                        top: offsetTop,
                        behavior: 'smooth'
                    });
                    
                    // Add active class animation
                    document.querySelectorAll('.nav-link').forEach(l => l.classList.remove('active'));
                    link.classList.add('active');
                }
            }
        });
    });


        // Highlight active section on scroll
        window.addEventListener('scroll', () => {
            const sections = document.querySelectorAll('section[id]');
            const scrollPosition = window.scrollY + 100;

            sections.forEach(section => {
                const sectionTop = section.offsetTop;
                const sectionHeight = section.offsetHeight;
                const sectionId = section.getAttribute('id');

                if (scrollPosition >= sectionTop && scrollPosition < sectionTop + sectionHeight) {
                    document.querySelectorAll('.nav-link').forEach(link => {
                        link.classList.remove('active');
                        if (link.getAttribute('href') === `#${sectionId}`) {
                            link.classList.add('active');
                        }
                    });
                }
            });
        });
    }
}

/* ===================================
   INITIALIZATION
   =================================== */

let dashboardInstance = null;

// Initialize everything when DOM loads
document.addEventListener('DOMContentLoaded', () => {
    console.log('========================================');
    console.log('🚀 RansomGuard Dashboard Loading...');
    console.log('========================================');
    
    // 1. Start intro animation
    const intro = new IntroSequence();
    intro.start().then(() => {
        console.log('✅ Intro complete');
    });
    
    // 2. Initialize dashboard after intro (3 seconds)
    setTimeout(() => {
        console.log('🎛️ Initializing main dashboard...');
        
        try {
            // Create dashboard instance (adjust class name if needed)
            dashboardInstance = new RansomGuardDashboard();
            window.dashboard = dashboardInstance; // Make globally accessible
            
            console.log('✅ Dashboard initialized successfully');
            console.log('Dashboard instance:', window.dashboard);
        } catch (error) {
            console.error('❌ Dashboard initialization failed:', error);
        }
    }, 3000);
    
    // 3. Initialize custom cursor
    setTimeout(() => {
        console.log('🖱️ Initializing custom cursor...');
        try {
            const cursor = new CustomCursor();
            console.log('✅ Custom cursor initialized');
        } catch (error) {
            console.error('❌ Cursor initialization failed:', error);
        }
    }, 3000);
    
    // 4. Initialize scroll animations
    setTimeout(() => {
        console.log('📜 Initializing scroll animations...');
        try {
            const scrollAnims = new ScrollAnimations();
            console.log('✅ Scroll animations initialized');
        } catch (error) {
            console.error('❌ Scroll animations failed:', error);
        }
    }, 3000);
});

console.log('📄 dashboard.js loaded');
