// Hover timers: key = link element, value = timerId
const hoverTimers = new Map();
// Checked URLs: key = full URL, value = { decision, score }
const cachedResults = new Map();

// create or update the inline warning bubble near a link
function showPhishingBubble(link, score) {
  const existing = link._phishingBubble;
  const textScore = typeof score === "number" ? ` (score: ${score.toFixed(2)})` : "";

  let bubble = existing;
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

  bubble.textContent = "! Possible phishing site" + textScore;
  bubble.style.display = "block";

  // position the bubble just below the link
  const rect = link.getBoundingClientRect();
  const scrollX = window.scrollX;
  const scrollY = window.scrollY;

  const top = scrollY + rect.bottom + 6;
  let left = scrollX + rect.left;

  // set once so we can read offsetWidth
  bubble.style.top = `${top}px`;
  bubble.style.left = `${left}px`;

  // keep some margin from the right edge of the window
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

// Send a detection request for a single link to the backend model
function requestCheck(link, rawUrl, source) {
  try {
    const href = rawUrl || link.href;
    if (!href) return;

    // Use cached result if available
    const cached = cachedResults.get(href);
    if (cached) {
      if (cached.decision === "PHISHING" && source === "hover") {
        showPhishingBubble(link, cached.score);
      }
      // whether PHISHING or SAFE, reuse the cached result and avoid a second request
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
        const decision = response.decision || "ERROR";
        const score = response.score;

        cachedResults.set(href, { decision, score });

        if (decision === "PHISHING" && source === "hover") {
          showPhishingBubble(link, score);
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

// Cancel the timer and hide the bubble when the mouse leaves
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

  // Here we could block navigation if it is already known as PHISHING.
  const cached = cachedResults.get(href);
  if (cached && cached.decision === "PHISHING") {
    // For now we let navigation + full warning handle it.
    // event.preventDefault();
    // Later can do A/B testing that one condition blocks, one does not.
  }

  requestCheck(link, href, "click");
});

// receive page-level detection messages from background.js
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
        // hide the overlay when the URL is SAFE or ERROR
        hidePageOverlay();
      }
    }
  }
});
