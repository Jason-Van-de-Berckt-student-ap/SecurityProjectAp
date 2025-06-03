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