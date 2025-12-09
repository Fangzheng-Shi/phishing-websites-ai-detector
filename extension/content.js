// Hover timers: key = link element, value = timerId
const hoverTimers = new Map();
// Checked URLs: key = full URL, value = { decision, score, reason }
const cachedResults = new Map();

// Give understandable prompts for different cases to help users see why a link looks suspicious.
function promptReasonFromURL(href) {
  try {
    const url = new URL(href);
    const full = href;
    const hostname = url.hostname;
    const reasons = [];

    if (full.length > 80) {
      reasons.push(
        "This link’s web address is unusually long. Fake sites often use very long addresses to hide small changes."
      );
    }

    const subdomainCount = hostname.split(".").length - 1;
    if (subdomainCount >= 3) {
      reasons.push(
        "This web address has many extra parts in front of the main site name. Legitimate sites usually keep their address simple."
      );
    }

    const digitCount = (hostname.match(/\d/g) || []).length;
    if (digitCount >= 3) {
      reasons.push(
        "This web address contains a lot of numbers that don’t look like part of a normal brand name."
      );
    }

    if (/[!@%$]/.test(full)) {
      reasons.push(
        "This web address includes unusual symbols. Real sites rarely put these symbols in their main address."
      );
    }

    if (url.search && url.search.length > 60) {
      reasons.push(
        "This link has a very long string after the question mark. Suspicious sites often use this to track or trick users."
      );
    }

    if (reasons.length === 0) {
      return "This web address looks different from what we usually see on well-known, legitimate sites.";
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
  const existing = link._phishingBubble;

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

  // change the score like 0.98 into percentage
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
      if (cached.decision === "PHISHING" && source === "hover") {
        showPhishingBubble(link, cached.score, cached.reason);
      }
      // Whether PHISHING or SAFE, reuse the cached result and avoid a second request.
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
        const reason = promptReasonFromURL(href);

        cachedResults.set(href, { decision, score, reason });

        if (decision === "PHISHING" && source === "hover") {
          showPhishingBubble(link, score, reason);
        }
      }
    );
  } catch (e) {
    console.error("requestCheck error:", e);
  }
}
