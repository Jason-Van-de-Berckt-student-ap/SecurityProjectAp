// static/js/common.js

// Dark mode functionality
const themeToggle = document.getElementById("theme-toggle");
const html = document.documentElement;
const savedTheme = localStorage.getItem("theme");

// Apply saved theme or system preference on load
if (savedTheme) {
  html.classList.toggle("dark", savedTheme === "dark");
} else if (window.matchMedia("(prefers-color-scheme: dark)").matches) {
  html.classList.add("dark");
}

// Toggle theme on button click
themeToggle.addEventListener("click", () => {
  html.classList.toggle("dark");
  localStorage.setItem(
    "theme",
    html.classList.contains("dark") ? "dark" : "light"
  );
  // Add a subtle animation effect to the button
  themeToggle.style.transform = "scale(0.95)";
  setTimeout(() => {
    themeToggle.style.transform = "scale(1)";
  }, 150);
});

// Smooth scrolling for anchor links (if any are used)
document.querySelectorAll('a[href^="#"]').forEach((anchor) => {
  anchor.addEventListener("click", function (e) {
    e.preventDefault();
    const targetId = this.getAttribute("href");
    const targetElement = document.querySelector(targetId);
    if (targetElement) {
      targetElement.scrollIntoView({
        behavior: "smooth",
        block: "start",
      });
    }
  });
});

// Particle effect (Highly recommended to remove or optimize significantly for production)
// This effect can be a performance drain, especially on lower-end devices.
// Consider removing it entirely or reimplementing with a canvas for better performance.
function createParticle() {
  const particle = document.createElement("div");
  particle.className =
    "fixed w-1 h-1 md:w-2 md:h-2 bg-blue-400/20 dark:bg-blue-600/20 rounded-full pointer-events-none -z-10";
  particle.style.left = Math.random() * window.innerWidth + "px";
  particle.style.top = window.innerHeight + Math.random() * 100 + "px";
  // Using fixed rotation values for better performance than Math.random() in CSS
  const rotation = Math.random() > 0.5 ? 360 : -360;
  particle.style.animation = `floatParticle ${
    Math.random() * 5 + 5
  }s linear ${Math.random() * 2}s forwards`;
  document.body.appendChild(particle);
  setTimeout(() => {
    particle.remove();
  }, 10000);
}

// Add the floatParticle keyframes to the head only once
// This is still dynamic CSS generation, but better than per-particle.
// Ideally, this keyframe would be in your compiled Tailwind CSS.
if (!document.getElementById("particle-animation-style")) {
  const style = document.createElement("style");
  style.id = "particle-animation-style";
  style.textContent = `@keyframes floatParticle { to { transform: translateY(-110vh) rotate(360deg); opacity: 0; } }`; // Fixed rotation for better performance
  document.head.appendChild(style);
}

// Only start particle generation if not on a loading screen (to avoid conflicts/overload)
// This check assumes 'scan-loading' and 'loading-overlay' IDs are used for active loading states.
document.addEventListener("DOMContentLoaded", () => {
  if (
    !document.getElementById("scan-loading") &&
    !document.getElementById("loading-overlay")
  ) {
    setInterval(createParticle, 1500);
  }
});

// Reusable tab functionality for pages with multiple tabs (e.g., history, darkweb, results)
// This function expects:
// - containerSelector: CSS selector for the parent element containing the tab buttons (e.g., "#history-tabs-container nav")
// - activeClass: String of Tailwind classes for the active tab button
// - inactiveClass: String of Tailwind classes for inactive tab buttons
// - tabContentParentSelector (optional): CSS selector for the common parent of tab content divs.
//   If not provided, it assumes tab contents are siblings of the tab button container or within its immediate parent.
function initializeTabs(
  containerSelector,
  activeClass,
  inactiveClass,
  tabContentParentSelector = null
) {
  const tabContainer = document.querySelector(containerSelector);
  if (!tabContainer) return;

  const tabButtons = tabContainer.querySelectorAll(".tab-button");
  const tabContentsParent = tabContentParentSelector
    ? document.querySelector(tabContentParentSelector)
    : tabContainer.closest(".tab-parent-container") || tabContainer.parentElement;
  const tabContents = tabContentsParent.querySelectorAll(".tab-content");

  tabButtons.forEach((button) => {
    button.addEventListener("click", () => {
      const targetTabId = button.dataset.tab;

      // Deactivate all buttons
      tabButtons.forEach((btn) => {
        btn.className = inactiveClass;
      });
      // Activate the clicked button
      button.className = activeClass;

      // Hide all content and show the target content with fade-in
      tabContents.forEach((content) => {
        if (content.id === targetTabId) {
          content.classList.remove("hidden");
          content.style.opacity = "0"; // Start hidden for fade-in
          setTimeout(() => {
            content.style.opacity = "1";
            content.classList.add("animate-fade-in");
          }, 50); // Small delay for transition
        } else {
          content.classList.add("hidden");
          content.style.opacity = "0";
          content.classList.remove("animate-fade-in"); // Remove animation class if hidden
        }
      });
    });
  });

  // Activate the first tab by default on DOMContentLoaded
  // Use a small timeout to ensure Alpine.js (if present) has initialized
  // and x-show directives have processed before trying to show content.
  if (tabButtons.length > 0) {
    setTimeout(() => {
      tabButtons[0].click();
      // Ensure first tab content is visible without animation on initial load
      const firstTabContentId = tabButtons[0].dataset.tab;
      const firstTabContent = document.getElementById(firstTabContentId);
      if (firstTabContent) {
        firstTabContent.classList.remove("hidden", "animate-fade-in");
        firstTabContent.style.opacity = "1";
      }
    }, 0);
  }
}

// Modal management utilities
const ModalManager = {
  show: function (modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
      modal.classList.remove("hidden");
      // Focus management for accessibility
      const firstFocusable = modal.querySelector(
        "button, input, select, textarea, [tabindex]:not([tabindex='-1'])"
      );
      if (firstFocusable) firstFocusable.focus();
    }
  },

  hide: function (modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
      modal.classList.add("hidden");
    }
  },

  toggle: function (modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
      modal.classList.toggle("hidden");
    }
  },
};

// Enhanced notification system
const NotificationManager = {
  show: function (message, type = "info", duration = 3000) {
    const notification = document.createElement("div");
    notification.className = `fixed top-4 right-4 p-4 rounded-lg shadow-lg z-50 max-w-sm transition-all duration-300 transform translate-x-full opacity-0 ${
      type === "success"
        ? "bg-green-500 text-white"
        : type === "error"
        ? "bg-red-500 text-white"
        : type === "warning"
        ? "bg-yellow-500 text-white"
        : "bg-blue-500 text-white"
    }`;

    const icon =
      type === "success"
        ? "✓"
        : type === "error"
        ? "✗"
        : type === "warning"
        ? "⚠"
        : "ℹ";

    notification.innerHTML = `
      <div class="flex items-center">
        <span class="mr-2 text-lg">${icon}</span>
        <span class="flex-1">${message}</span>
        <button
          onclick="this.parentElement.parentElement.remove()"
          class="ml-2 text-white opacity-70 hover:opacity-100"
        >
          ×
        </button>
      </div>
    `;

    document.body.appendChild(notification);

    // Animate in
    requestAnimationFrame(() => {
      notification.classList.remove("translate-x-full", "opacity-0");
    });

    // Auto remove
    if (duration > 0) {
      setTimeout(() => {
        if (notification.parentNode) {
          notification.classList.add("translate-x-full", "opacity-0");
          setTimeout(() => notification.remove(), 300);
        }
      }, duration);
    }

    return notification;
  },

  success: function (message, duration = 3000) {
    return this.show(message, "success", duration);
  },

  error: function (message, duration = 5000) {
    return this.show(message, "error", duration);
  },

  warning: function (message, duration = 4000) {
    return this.show(message, "warning", duration);
  },

  info: function (message, duration = 3000) {
    return this.show(message, "info", duration);
  },
};

// Form validation utilities
const FormValidator = {
  validateEmail: function (email) {
    const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return re.test(email);
  },

  validatePassword: function (password) {
    return {
      length: password.length >= 8,
      uppercase: /[A-Z]/.test(password),
      lowercase: /[a-z]/.test(password),
      number: /[0-9]/.test(password),
      special: /[^A-Za-z0-9]/.test(password),
      isValid: function () {
        return (
          this.length && this.uppercase && this.lowercase && this.number
        );
      },
      strength: function () {
        const score = [
          this.length,
          this.uppercase,
          this.lowercase,
          this.number,
          this.special,
        ].filter(Boolean).length;
        return score < 3 ? "weak" : score < 5 ? "medium" : "strong";
      },
    };
  },

  validateDomain: function (domain) {
    const re = /^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9](?:\.[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9])*$/;
    return re.test(domain);
  },
};

// Loading state management
const LoadingManager = {
  show: function (elementId, text = "Loading...") {
    const element = document.getElementById(elementId);
    if (element) {
      element.classList.remove("hidden");
      const textElement = element.querySelector(".loading-text");
      if (textElement) textElement.textContent = text;
    }
  },

  hide: function (elementId) {
    const element = document.getElementById(elementId);
    if (element) {
      element.classList.add("hidden");
    }
  },

  toggle: function (elementId, text = "Loading...") {
    const element = document.getElementById(elementId);
    if (element) {
      if (element.classList.contains("hidden")) {
        this.show(elementId, text);
      } else {
        this.hide(elementId);
      }
    }
  },
};

// Timer utilities
const TimerManager = {
  timers: new Map(),

  start: function (timerId, callback, interval = 1000) {
    this.stop(timerId); // Clear existing timer
    const timer = setInterval(callback, interval);
    this.timers.set(timerId, timer);
    return timer;
  },

  stop: function (timerId) {
    const timer = this.timers.get(timerId);
    if (timer) {
      clearInterval(timer);
      this.timers.delete(timerId);
    }
  },

  stopAll: function () {
    this.timers.forEach((timer) => clearInterval(timer));
    this.timers.clear();
  },

  formatDuration: function (milliseconds) {
    if (milliseconds < 1000) return "< 1s";
    if (milliseconds < 60000) return `${Math.floor(milliseconds / 1000)}s`;
    if (milliseconds < 3600000) {
      const minutes = Math.floor(milliseconds / 60000);
      const seconds = Math.floor((milliseconds % 60000) / 1000);
      return `${minutes}m ${seconds}s`;
    }

    const hours = Math.floor(milliseconds / 3600000);
    const minutes = Math.floor((milliseconds % 3600000) / 60000);
    return `${hours}h ${minutes}m`;
  },

  formatTime: function (timestamp) {
    if (!timestamp) return "N/A";
    return new Date(timestamp).toLocaleString();
  },
};

// API utilities
const ApiHelper = {
  async request(url, options = {}) {
    const defaultOptions = {
      headers: {
        "Content-Type": "application/json",
      },
    };

    const config = { ...defaultOptions, ...options };

    try {
      const response = await fetch(url, config);
      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.message || `HTTP error! status: ${response.status}`);
      }

      return data;
    } catch (error) {
      console.error("API request failed:", error);
      throw error;
    }
  },

  async get(url) {
    return this.request(url, { method: "GET" });
  },

  async post(url, data) {
    return this.request(url, {
      method: "POST",
      body: JSON.stringify(data),
    });
  },

  async put(url, data) {
    return this.request(url, {
      method: "PUT",
      body: JSON.stringify(data),
    });
  },

  async delete(url) {
    return this.request(url, { method: "DELETE" });
  },
};

// Data formatting utilities
const DataFormatter = {
  formatBytes: function (bytes) {
    if (bytes === 0) return "0 Bytes";
    const k = 1024;
    const sizes = ["Bytes", "KB", "MB", "GB", "TB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
  },

  formatNumber: function (num) {
    return new Intl.NumberFormat().format(num);
  },

  formatDateTime: function (timestamp, options = {}) {
    if (!timestamp) return "N/A";
    const date = new Date(timestamp);
    const defaultOptions = {
      year: "numeric",
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    };
    return date.toLocaleDateString("en-US", { ...defaultOptions, ...options });
  },

  truncateText: function (text, maxLength = 50) {
    if (!text || text.length <= maxLength) return text;
    return text.substring(0, maxLength) + "...";
  },
};

// DOM utilities
const DomHelper = {
  removeClass: function (selector, className) {
    document.querySelectorAll(selector).forEach((el) => el.classList.remove(className));
  },

  addClass: function (selector, className) {
    document.querySelectorAll(selector).forEach((el) => el.classList.add(className));
  },

  toggleClass: function (selector, className) {
    document.querySelectorAll(selector).forEach((el) => el.classList.toggle(className));
  },

  setContent: function (selector, content) {
    document.querySelectorAll(selector).forEach((el) => (el.textContent = content));
  },

  setHtml: function (selector, html) {
    document.querySelectorAll(selector).forEach((el) => (el.innerHTML = html));
  },

  show: function (selector) {
    this.removeClass(selector, "hidden");
  },

  hide: function (selector) {
    this.addClass(selector, "hidden");
  },
};

// Event delegation helper
function delegateEvent(parent, eventType, selector, handler) {
  parent.addEventListener(eventType, function (e) {
    if (e.target.matches(selector) || e.target.closest(selector)) {
      handler.call(e.target, e);
    }
  });
}

// Debounce utility
function debounce(func, wait, immediate) {
  let timeout;
  return function executedFunction(...args) {
    const later = () => {
      timeout = null;
      if (!immediate) func(...args);
    };
    const callNow = immediate && !timeout;
    clearTimeout(timeout);
    timeout = setTimeout(later, wait);
    if (callNow) func(...args);
  };
}

// Throttle utility
function throttle(func, limit) {
  let inThrottle;
  return function (...args) {
    if (!inThrottle) {
      func.apply(this, args);
      inThrottle = true;
      setTimeout(() => (inThrottle = false), limit);
    }
  };
}

// Copy to clipboard utility
async function copyToClipboard(text) {
  try {
    await navigator.clipboard.writeText(text);
    NotificationManager.success("Copied to clipboard!");
    return true;
  } catch (err) {
    console.error("Failed to copy text: ", err);
    NotificationManager.error("Failed to copy to clipboard");
    return false;
  }
}

// Download utility
function downloadFile(data, filename, type = "text/plain") {
  const blob = new Blob([data], { type });
  const url = window.URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  window.URL.revokeObjectURL(url);
}

// Global error handler
window.addEventListener("error", function (e) {
  console.error("Global error:", e.error);
  NotificationManager.error("An unexpected error occurred. Please try again.");
});

// Global promise rejection handler
window.addEventListener("unhandledrejection", function (e) {
  console.error("Unhandled promise rejection:", e.reason);
  NotificationManager.error("A network or server error occurred. Please try again.");
});

// Auto-hide alerts after 5 seconds
document.addEventListener("DOMContentLoaded", function () {
  const alerts = document.querySelectorAll(".alert");
  alerts.forEach((alert) => {
    setTimeout(() => {
      alert.style.opacity = "0";
      setTimeout(() => alert.remove(), 300);
    }, 5000);
  });
});

// Enhanced form submission with loading states
document.addEventListener("DOMContentLoaded", function () {
  // Add loading states to form submissions
  document.querySelectorAll("form").forEach((form) => {
    form.addEventListener("submit", function (e) {
      const submitBtn = form.querySelector('button[type="submit"]');
      if (submitBtn && !submitBtn.dataset.noLoading) {
        const originalText = submitBtn.innerHTML;
        submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin mr-2"></i>Processing...';
        submitBtn.disabled = true;

        // Restore button after 30 seconds as fallback
        setTimeout(() => {
          submitBtn.innerHTML = originalText;
          submitBtn.disabled = false;
        }, 30000);
      }
    });
  });
});

// Make utilities globally available
window.Modal = ModalManager;
window.Notification = NotificationManager;
window.FormValidator = FormValidator;
window.Loading = LoadingManager;
window.Timer = TimerManager;
window.Api = ApiHelper;
window.DataFormatter = DataFormatter;
window.Dom = DomHelper;
window.copyToClipboard = copyToClipboard;
window.downloadFile = downloadFile;
window.debounce = debounce;
window.throttle = throttle;
window.delegateEvent = delegateEvent;