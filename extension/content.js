// Hover timers: key = link element, value = timerId
const hoverTimers = new Map();
// Checked URLs: key = full URL, value = { decision, score, reason }
const cachedResults = new Map();

// hover bubble threshold
const HOVER_WARNING_THRESHOLD = 0.9; 

// Give understandable prompts for different cases to help users see why a link looks suspicious.
function promptReasonFromURL(href) {
  try {
    const url = new URL(href);
    const full = href;
    const hostname = url.hostname;
    const reasons = [];

    if (full.length > 80) {
      reasons.push(
        "This link’s web address is unusually long. Fake sites often use long addresses to hide small changes."
      );
    }

    const subdomainCount = hostname.split(".").length - 1;
    if (subdomainCount >= 3) {
      reasons.push(
        "This address has many extra parts in front of the main site name. Legitimate sites usually keep it simple."
      );
    }

    const digitCount = (hostname.match(/\d/g) || []).length;
    if (digitCount >= 3) {
      reasons.push(
        "This address contains a lot of numbers that don’t look like part of a normal brand name."
      );
    }

    if (/[!@%$]/.test(full)) {
      reasons.push(
        "This address includes unusual symbols. Real sites rarely put these symbols in their main address."
      );
    }

    if (url.search && url.search.length > 60) {
      reasons.push(
        "This link has a very long string after the question mark. Suspicious sites often use this to track or trick users."
      );
    }

    if (reasons.length === 0) {
      return "This web address looks unusual compared with typical safe websites.";
    }
    // Only use the first reason to keep the message short.
    return reasons[0];
  } catch (e) {
    // Fallback message when parsing fails
    return "This web address looks unusual compared with typical safe websites.";
  }
}

// Create or update the inline warning bubble near a link.
function showPhishingBubble(link, score, reason) {
  let bubble = link._phishingBubble;
  if (!bubble) {
    bubble = document.createElement("div");
    bubble.style.position = "absolute";
    bubble.style.zIndex = "2147483647";
    bubble.style.background = "#ff4d4f";
    bubble.style.color = "#fff";
    bubble.style.padding = "4px 10px";
    bubble.style.borderRadius = "4px";
    bubble.style.fontSize = "12px";
    bubble.style.boxShadow = "0 0 4px rgba(0,0,0,0.3)";
    bubble.style.pointerEvents = "none";
    bubble.style.whiteSpace = "nowrap";

    document.body.appendChild(bubble);
    link._phishingBubble = bubble;
  }

  // e.g. 0.998 -> 100%
  let percentText = "";
  if (typeof score === "number") {
    const pct = Math.round(score * 100);
    percentText = ` (risk: ${pct}%)`;
  }

  const safeReason =
    typeof reason === "string" && reason.trim().length > 0
      ? reason
      : "This web address looks unusual compared with typical safe websites.";

  bubble.innerHTML = `
    ⚠ Possible phishing site${percentText}<br>
    <span style="font-size:11px;">Reason: ${safeReason}</span>
  `;
  bubble.style.display = "block";

  // Position the bubble just below the link.
  const rect = link.getBoundingClientRect();
  const scrollX = window.scrollX;
  const scrollY = window.scrollY;

  const top = scrollY + rect.bottom + 6;
  let left = scrollX + rect.left;

  // Set once so we can read offsetWidth.
  bubble.style.top = `${top}px`;
  bubble.style.left = `${left}px`;

  // Keep some margin from the right edge of the window.
  const maxLeft = scrollX + window.innerWidth - bubble.offsetWidth - 8;
  if (left > maxLeft) {
    left = Math.max(scrollX + 8, maxLeft);
  }

  bubble.style.left = `${left}px`;
  bubble.style.top = `${top}px`;
}

function hidePhishingBubble(link) {
  const bubble = link._phishingBubble;
  if (bubble) {
    bubble.style.display = "none";
  }
}

// Send a detection request for a single link to the backend model.
function requestCheck(link, rawUrl, source) {
    try {
      const href = rawUrl || link.href;
      if (!href) return;
  
      // Use cached result if available.
      const cached = cachedResults.get(href);
      if (cached) {
        const { decision, score, reason } = cached;
  
        if (source === "hover") {
          // Even if the cache of hover shows "PHISHING", still check if the score exceeds the threshold
          if (
            decision === "PHISHING" &&
            typeof score === "number" &&
            score >= HOVER_WARNING_THRESHOLD
          ) {
            showPhishingBubble(link, score, reason);
          }
        }
        // cache for both hover/click
        return;
      }
  
      chrome.runtime.sendMessage(
        {
          action: "checkLink",
          url: href,
          pageUrl: window.location.href,
          source,
        },
        (response) => {
          if (!response) return;
  
          if (response.decision === "DISABLED") {
            return;
          }
  
          const decision = response.decision || "ERROR";
          const score = response.score;
          const reason = promptReasonFromURL(href);
  
          cachedResults.set(href, { decision, score, reason });
  
          if (source === "hover") {
            // hover filter based on the threshold, and only display bubbles for "high-risk" cases
            if (
              decision === "PHISHING" &&
              typeof score === "number" &&
              score >= HOVER_WARNING_THRESHOLD
            ) {
              showPhishingBubble(link, score, reason);
            }
          }
        }
      );
    } catch (e) {
      console.error("requestCheck error:", e);
    }
  }  

// full-page overlay for navigation detection
let pageOverlay = null;

function showPageOverlay(text = "Checking if this page is safe...") {
  if (pageOverlay) {
    pageOverlay.querySelector(".np-overlay-text").textContent = text;
    pageOverlay.style.display = "flex";
    return;
  }

  const overlay = document.createElement("div");
  overlay.id = "np-page-overlay";
  overlay.style.position = "fixed";
  overlay.style.top = "0";
  overlay.style.left = "0";
  overlay.style.width = "100%";
  overlay.style.height = "100%";
  overlay.style.background = "rgba(0,0,0,0.45)";
  overlay.style.zIndex = "999998";
  overlay.style.display = "flex";
  overlay.style.alignItems = "center";
  overlay.style.justifyContent = "center";
  overlay.style.color = "#fff";
  overlay.style.fontSize = "18px";
  overlay.style.backdropFilter = "blur(2px)";

  overlay.innerHTML = `
    <div style="text-align:center;">
      <div class="np-spinner"
           style="
             width:32px;height:32px;
             border-radius:50%;
             border:3px solid #fff;
             border-top-color:transparent;
             margin:0 auto 12px auto;
             animation: np-spin 0.8s linear infinite;">
      </div>
      <div class="np-overlay-text">${text}</div>
    </div>
  `;

  const style = document.createElement("style");
  style.textContent = `
    @keyframes np-spin {
      from { transform: rotate(0deg); }
      to   { transform: rotate(360deg); }
    }
  `;
  document.head.appendChild(style);

  document.body.appendChild(overlay);
  pageOverlay = overlay;
}

function hidePageOverlay() {
  if (pageOverlay) {
    pageOverlay.style.display = "none";
  }
}

// hover / mouseout / click listeners
// When the mouse hovers over a link for 300 ms, trigger detection.
document.addEventListener("mouseover", (event) => {
  const link = event.target.closest("a[href]");
  if (!link) return;

  const href = link.href;
  if (!href || href.startsWith("javascript:")) return;

  if (hoverTimers.has(link)) return;

  const timerId = setTimeout(() => {
    hoverTimers.delete(link);
    requestCheck(link, href, "hover");
  }, 300);

  hoverTimers.set(link, timerId);
});

// Cancel the timer and hide the bubble when the mouse leaves.
document.addEventListener("mouseout", (event) => {
  const link = event.target.closest("a[href]");
  if (!link) return;

  const timerId = hoverTimers.get(link);
  if (timerId) {
    clearTimeout(timerId);
    hoverTimers.delete(link);
  }
  hidePhishingBubble(link);
});

// On click, send another detection request (for logging/comparison)
// without blocking navigation (for now).
document.addEventListener("click", (event) => {
  const link = event.target.closest("a[href]");
  if (!link) return;

  const href = link.href;
  if (!href || href.startsWith("javascript:")) return;

  const cached = cachedResults.get(href);
  if (cached && cached.decision === "PHISHING") {
    // For now we let navigation + full warning handle it.
    // event.preventDefault();
  }

  requestCheck(link, href, "click");
});

// Receive page-level detection messages from background.js.
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.action === "pageCheckStart") {
    // Only affect the top-level page, not iframes.
    if (window.top === window) {
      showPageOverlay();
    }
  }

  if (msg.action === "pageCheckResult") {
    if (window.top === window) {
      if (msg.decision === "PHISHING") {
        showPageOverlay("This page looks dangerous, redirecting to warning...");
      } else {
        // Hide the overlay when the URL is SAFE or ERROR.
        hidePageOverlay();
      }
    }
  }
});

// as soon as user enter the page, it asks whether the overplay should cover everything
function initPageProtection() {
    // Only protect the top-level page
    if (window.top !== window) return;
  
    try {
      chrome.runtime.sendMessage(
        {
          action: "navOverlayInit",
          url: window.location.href,
        },
        (response) => {
          if (!response || !response.shouldShow) {
            return;
          }

          const show = () => showPageOverlay();
  
          if (!document.body || document.readyState === "loading") {
            // Draw after DOMContentLoaded is completed
            document.addEventListener("DOMContentLoaded", show, { once: true });
          } else {
            // dom is ready, just draw it
            show();
          }
        }
      );
    } catch (e) {
      console.error("navOverlayInit error:", e);
    }
  }
  
  // do it once
  initPageProtection();
