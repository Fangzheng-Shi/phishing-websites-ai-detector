// Hover timers: key = link element, value = timerId
const hoverTimers = new Map();
// Checked URLs: key = full URL, value = { decision, score, reason }
const cachedResults = new Map();

// hover bubble threshold
const HOVER_WARNING_THRESHOLD = 0.9; 

// href -> true
const inFlightChecks = new Map();

// const BACKEND_ENDPOINT = "http://127.0.0.1:5030/check_url";

// align with background.js
const safeDomains = ["github.com", "google.com"];

function delay(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

function getIsEnabled() {
  return new Promise((resolve) => {
    chrome.storage.sync.get({ isEnabled: false }, (d) => resolve(!!d.isEnabled));
  });
}

function getUserWhitelistHosts() {
  return new Promise((resolve) => {
    chrome.storage.sync.get({ userWhitelistHosts: [] }, (d) => {
      resolve(new Set(d.userWhitelistHosts || []));
    });
  });
}

function isSafeDomain(hostname, userWhitelistHosts) {
  return (
    safeDomains.some((d) => hostname === d || hostname.endsWith("." + d)) ||
    userWhitelistHosts.has(hostname)
  );
}

function checkPageWithBackground(url) {
    return new Promise((resolve, reject) => {
      chrome.runtime.sendMessage({ action: "checkPage", url }, (resp) => {
        if (!resp) return reject(new Error("no response from background"));
        resolve(resp);
      });
    });
  }
  

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
      bubble.style.padding = "10px 12px";
      bubble.style.borderRadius = "10px";
      bubble.style.fontSize = "14px";
      bubble.style.lineHeight = "1.25";
      bubble.style.boxShadow = "0 6px 18px rgba(0,0,0,0.25)";
      bubble.style.pointerEvents = "auto";
      bubble.style.whiteSpace = "normal";
      bubble.style.maxWidth = "320px";
  
      bubble._ownerLink = link;
  
      bubble.addEventListener("mouseleave", (e) => {
        const to = e.relatedTarget;
        const owner = bubble._ownerLink;
        if (owner && to && (to === owner || owner.contains(to))) return;
        hidePhishingBubble(owner);
      });

      bubble.addEventListener("mousedown", (e) => e.stopPropagation());
      bubble.addEventListener("click", (e) => e.stopPropagation());
      bubble.addEventListener("pointerdown", (e) => e.stopPropagation());

  
      document.body.appendChild(bubble);
      link._phishingBubble = bubble;
    }
  
    let pctText = "";
    if (typeof score === "number") pctText = `${Math.round(score * 100)}%`;
  
    const safeReason =
      typeof reason === "string" && reason.trim().length > 0
        ? reason
        : "This web address looks unusual.";
  
    bubble.innerHTML = `
      <div style="font-weight:800;">⚠ High-risk link ${pctText ? `(${pctText})` : ""}</div>
      <div style="margin-top:4px;opacity:0.95;">Be careful before clicking.</div>
      <details style="margin-top:8px;">
        <summary style="cursor:pointer;">Why?</summary>
        <div style="margin-top:6px;font-size:13px;opacity:0.95;">${safeReason}</div>
      </details>
    `;
    bubble.style.display = "block";
  
    const rect = link.getBoundingClientRect();
    const top = window.scrollY + rect.bottom + 8;
    let left = window.scrollX + rect.left;
  
    bubble.style.top = `${top}px`;
    bubble.style.left = `${left}px`;
  
    const maxLeft = window.scrollX + window.innerWidth - bubble.offsetWidth - 8;
    if (left > maxLeft) left = Math.max(window.scrollX + 8, maxLeft);
    bubble.style.left = `${left}px`;
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

      // avoid duplicate requests for same href while backend is still processing
      if (inFlightChecks.has(href)) return;
      inFlightChecks.set(href, true);
  
      chrome.runtime.sendMessage(
        {
          action: "checkLink",
          url: href,
          pageUrl: window.location.href,
          source,
        },
        (response) => {
          inFlightChecks.delete(href);
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
let overlayTimer = null;
let overlayStartAt = 0;
let overlaySkippedUntil = 0;

function showPageOverlay(text = "Checking if this page is safe...") {
  if (Date.now() < overlaySkippedUntil) return;
  overlayStartAt = Date.now();

  if (pageOverlay) {
    pageOverlay.querySelector(".np-overlay-text").textContent = text;
    pageOverlay.style.display = "flex";
    startOverlayProgress();
    return;
  }

  const overlay = document.createElement("div");
  overlay.id = "np-page-overlay";
  overlay.style.position = "fixed";
  overlay.style.top = "0";
  overlay.style.left = "0";
  overlay.style.width = "100%";
  overlay.style.height = "100%";
  overlay.style.background = "rgba(0,0,0,0.55)";
  overlay.style.zIndex = "999998";
  overlay.style.display = "flex";
  overlay.style.alignItems = "center";
  overlay.style.justifyContent = "center";
  overlay.style.color = "#fff";
  overlay.style.fontSize = "18px";
  overlay.style.backdropFilter = "blur(2px)";

   // when the first detection is done, show the overlay
   overlay.style.pointerEvents = "auto";

  overlay.innerHTML = `
    <div style="text-align:center; width:min(520px, calc(100% - 32px));">
      <div class="np-overlay-text" style="opacity:0.95;margin-bottom:12px;">${text}</div>

      <div style="height:10px;background:rgba(255,255,255,0.25);border-radius:999px;overflow:hidden;">
        <div class="np-bar" style="height:100%;width:0%;background:#ffffff;border-radius:999px;"></div>
      </div>

      <div class="np-eta" style="margin-top:10px;font-size:13px;opacity:0.9;">
        Usually takes ~ 10 - 20s
      </div>

      <button class="np-skip-btn"
        style="
          margin-top:14px;
          background:rgba(255,255,255,0.18);
          color:#fff;border:1px solid rgba(255,255,255,0.25);
          border-radius:10px;padding:10px 14px;cursor:pointer;">
        Skip check for now
      </button>
    </div>
  `;

   const panel = overlay.querySelector("div");
   if (panel) panel.style.pointerEvents = "auto";

  overlay.querySelector(".np-skip-btn").addEventListener("click", () => {
    overlaySkippedUntil = Date.now() + 8000;
    pageSkipUntil = Date.now() + 15000;
    hidePageOverlay();
    // do not perform the overlay after clicking the skip
    chrome.runtime.sendMessage({ action: "navUserSkip" }, () => {});
  });

  // The body element might not exist at the `document_start` stage, use a fallback mechanism.\
  (document.body || document.documentElement).appendChild(overlay);
  pageOverlay = overlay;

  startOverlayProgress();
}

// function startOverlayProgress() {
//   bar.style.width = "0%";
//   const bar = pageOverlay?.querySelector(".np-bar");
//   if (!bar) return;

//   clearInterval(overlayTimer);
//   const etaMs = 12000;
//   const start = Date.now();

//   overlayTimer = setInterval(() => {
//     const t = Date.now() - start;
//     const p = Math.min(90, Math.round((t / etaMs) * 90)); // only to 90%
//     bar.style.width = `${p}%`;
//   }, 80);
// }
function startOverlayProgress() {
    const bar = pageOverlay?.querySelector(".np-bar");
    if (!bar) return;
  
    bar.style.width = "0%";
  
    clearInterval(overlayTimer);
    const etaMs = 12000;
    const start = Date.now();
  
    overlayTimer = setInterval(() => {
      const t = Date.now() - start;
      const p = Math.min(90, Math.round((t / etaMs) * 90));
      bar.style.width = `${p}%`;
    }, 80);
  }
  

function hidePageOverlay() {
  clearInterval(overlayTimer);
  overlayTimer = null;
  if (pageOverlay) pageOverlay.style.display = "none";
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

document.addEventListener("mouseout", (event) => {
    const link = event.target.closest("a[href]");
    if (!link) return;
  
    const timerId = hoverTimers.get(link);
    if (timerId) {
      clearTimeout(timerId);
      hoverTimers.delete(link);
    }
  
    const bubble = link._phishingBubble;
    const to = event.relatedTarget;
  
    // don't hide it if it's moving from the link to the bubble
    if (bubble && to && (to === bubble || bubble.contains(to))) return;
  
    hidePhishingBubble(link);
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
// chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
//   if (msg.action === "pageCheckStart") {
//     // Only affect the top-level page, not iframes.
//     if (window.top === window) {
//       showPageOverlay();
//     }
//   }

//   if (msg.action === "pageCheckResult") {
//     if (window.top === window) {
//       if (msg.decision === "PHISHING") {
//         const bar = pageOverlay?.querySelector(".np-bar");
//         if (bar) bar.style.width = "100%";
//         showPageOverlay("This page looks dangerous, redirecting to warning...");
//       } else {
//         // Hide the overlay when the URL is SAFE or ERROR.
//         hidePageOverlay();
//       }
//     }
//   }
// });

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
        async (response) => {
          console.log("[np] start full page check", window.location.href);
          if (!response || !response.shouldShow) {
            return;
          }

          const enabled = await getIsEnabled();
          if (!enabled) return;

          let u;
          try { u = new URL(window.location.href); } catch { return; }
          const wl = await getUserWhitelistHosts();
          if (isSafeDomain(u.hostname, wl)) return;


          //   const show = () => showPageOverlay();
          const show = () => runFullPageCheck(window.location.href);

  
          if (!document.body || document.readyState === "loading") {
            // Draw after DOMContentLoaded is completed
            document.addEventListener("DOMContentLoaded", show, { once: true });
          } else {
            // dom is ready, just draw it
            show();
          }
          console.log("[np] start full page check", window.location.href);
          runFullPageCheck(window.location.href);
        }
      );
    } catch (e) {
      console.error("navOverlayInit error:", e);
    }
}
  
// do it once
initPageProtection();

let pageCheckInFlight = false;
let pageSkipUntil = 0; // The "Don't Force Jump" window period that appears after the user clicks "skip", aligned with the 15-second period in background

async function runFullPageCheck(currentUrl) {
  
  if (pageCheckInFlight) return;
  pageCheckInFlight = true;
  console.log("[np] start full page check", window.location.href);

  showPageOverlay("Checking if this page is safe...");

  // Keep retrying until the backend actually returns (do not directly return null)
  let attempt = 0;
  while (true) {
    try {
    //   const { decision, score } = await fetchDecisionScore(currentUrl);
    //   const { decision, score } = await checkPageWithBackground(currentUrl);
      const { decision, score } = await checkPageViaBackground(currentUrl);

      // If the user has already left this page, then do not process the old results.
      if (window.location.href !== currentUrl) {
        pageCheckInFlight = false;
        return;
      }

      // can cache the results
      cachedResults.set(currentUrl, {
        decision,
        score,
        reason: promptReasonFromURL(currentUrl),
      });

      const bar = pageOverlay?.querySelector(".np-bar");
      if (bar) bar.style.width = "100%";

      if (decision === "PHISHING") {
        // users click skip, show late banner, no jump to anywhere else
        if (Date.now() < pageSkipUntil) {
          hidePageOverlay();
          showLatePhishingBanner(score);
        } else {
          showPageOverlay("This page looks dangerous, redirecting to warning...");
          chrome.runtime.sendMessage(
            { action: "redirectToWarning", url: currentUrl },
            () => {}
          );
        }
      } else {
        hidePageOverlay();
      }

      pageCheckInFlight = false;
      return;
    } catch (e) {
      attempt += 1;

      // no ERROR or null, keep waiting
      if (attempt === 1) {
        showPageOverlay("Still checking... (backend not ready)");
      } else if (attempt % 5 === 0) {
        showPageOverlay("Still checking... (taking longer than usual)");
      }

      const waitMs = Math.min(5000, 1000 + attempt * 500);
      await delay(waitMs);
    }
  }
}


// when users click the 'skip' but the detection shows PHISHING
// give a tip to them
let lateBanner = null;

function showLatePhishingBanner(score) {
  if (lateBanner) return;

  lateBanner = document.createElement("div");
  lateBanner.style.position = "fixed";
  lateBanner.style.top = "12px";
  lateBanner.style.left = "50%";
  lateBanner.style.transform = "translateX(-50%)";
  lateBanner.style.zIndex = "2147483647";
  lateBanner.style.background = "#ff4d4f";
  lateBanner.style.color = "#fff";
  lateBanner.style.padding = "10px 14px";
  lateBanner.style.borderRadius = "12px";
  lateBanner.style.boxShadow = "0 10px 24px rgba(0,0,0,0.25)";
  lateBanner.style.fontSize = "14px";

  const pct = typeof score === "number" ? ` (${Math.round(score * 100)}%)` : "";
  lateBanner.textContent = `⚠ This page was flagged as phishing${pct}. Please be careful.`;

  (document.body || document.documentElement).appendChild(lateBanner);

  setTimeout(() => {
    if (lateBanner) lateBanner.remove();
    lateBanner = null;
  }, 6000);
}

chrome.runtime.onMessage.addListener((msg) => {
  if (msg.action === "latePhishingWarning") {
    showLatePhishingBanner(msg.score);
  }
});

function checkPageViaBackground(url) {
    return new Promise((resolve, reject) => {
      chrome.runtime.sendMessage({ action: "checkPage", url }, (resp) => {
        if (chrome.runtime.lastError) {
          reject(new Error(chrome.runtime.lastError.message));
          return;
        }
        if (!resp) {
          reject(new Error("No response from background"));
          return;
        }
        const decision = resp.decision ?? "ERROR";
        const score = (typeof resp.score === "number")
          ? resp.score
          : (decision === "PHISHING" ? 1 : 0);
        resolve({ decision, score });
      });
    });
  }
  