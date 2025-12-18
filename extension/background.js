// Record the urls that users actively choose to continue visiting, 
// so do not repeatedly intercept the same page
let proceedURLs = new Set();

// simple cache: url -> { decision, score, timestamp }
const urlCache = new Map();
const CACHE_TTL_MS = 10 * 60 * 1000; // 10 mins

// the trusted domains within the current session when users click "Proceed to Page"
const proceedHosts = new Set();

// Record the website address we just checked within the last few seconds
const recentlyChecked = new Set();
const RECENT_TTL_MS = 5000; // Within 5 seconds, consider it as "just checked"

// tabId -> { url, attempt }
const navInFlight = new Map();
// tabId -> untilTimestamp (user clicked "Skip check")
const navSkipUntil = new Map();

    
function markRecentlyChecked(url) {
  recentlyChecked.add(url);
  setTimeout(() => {
    recentlyChecked.delete(url);
  }, RECENT_TTL_MS);
}

function isRecentlyChecked(url) {
  return recentlyChecked.has(url);
}

// whitelist of domains I skip detecting for
const safeDomains = [
  "github.com",
  "google.com",
  // wait to add more
];

let userWhitelistHosts = new Set();

function loadUserWhitelist() {
  chrome.storage.sync.get({ userWhitelistHosts: [] }, (data) => {
    userWhitelistHosts = new Set(data.userWhitelistHosts || []);
  });
}
loadUserWhitelist();

function addHostToWhitelist(host) {
  if (!host) return;
  userWhitelistHosts.add(host);
  chrome.storage.sync.set({ userWhitelistHosts: Array.from(userWhitelistHosts) });
}

// check if the detecting hostname is in whitelist (including subdomains)
// function isSafeDomain(hostname) {
//   return safeDomains.some(d => hostname === d || hostname.endsWith("." + d));
// }
function isSafeDomain(hostname) {
  return (
    safeDomains.some((d) => hostname === d || hostname.endsWith("." + d)) ||
    userWhitelistHosts.has(hostname)
  );
}

chrome.storage.onChanged.addListener((changes, area) => {
  if (area === "sync" && changes.userWhitelistHosts) {
    userWhitelistHosts = new Set(changes.userWhitelistHosts.newValue || []);
  }
});

// avoid messages like “No tab with id” / “Receiving end does not exist”
function safeSendToTab(tabId, msg) {
  try {
    chrome.tabs.sendMessage(tabId, msg, () => {
      // lastError will be triggered if the content script hasn't been called yet or the tab has been closed
      if (chrome.runtime.lastError) {
        // console.debug("sendMessage ignored:", chrome.runtime.lastError.message);
      }
    });
  } catch (e) {
    // ignore
  }
}

chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.sync.set({ isEnabled: false });
});

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "updateState") {
    chrome.storage.sync.set({ isEnabled: request.state });
  }

  if (request.action === "proceedToURL") {
    try {
      const u = new URL(request.url);
      // Record that the entire domain name has been permitted by the user within this session
      proceedHosts.add(u.hostname);
    } catch (e) {
      console.error("Invalid URL in proceedToURL:", request.url, e);
    }
    // keep the original URL
    proceedURLs.add(request.url);
    if (sender && sender.tab) {
      chrome.tabs.update(sender.tab.id, { url: request.url });
    }
  }

  // content script request for a lightweight scan of a specific link（hover/click）
  if (request.action === "checkLink") {
    // to see if the switch is off/on
    chrome.storage.sync.get("isEnabled", (data) => {
      if (!data.isEnabled) {
        // tell content.js if the plugin is closed
        sendResponse({ decision: "DISABLED", score: null });
        return;
      }

      try {
        const base = request.pageUrl || "https://example.com";
        const urlObj = new URL(request.url, base);

        if (isSafeDomain(urlObj.hostname)) {
          console.log("Skip detection for whitelisted domain:", urlObj.hostname);
          sendResponse({ decision: "SAFE", score: 0 });
          return;
        }

        checkUrlWithBackend(urlObj.href)
          .then((data) => {
            console.log(
              "[hover/click] Checked URL:",
              urlObj.href,
              "decision:",
              data.decision,
              "score:",
              data.score
            );
            sendResponse({ decision: data.decision, score: data.score });
          })
          .catch((err) => {
            console.error("Error in checkLink:", err);
            sendResponse({ decision: "ERROR", score: null });
          });
      } catch (e) {
        console.error("Invalid URL in checkLink:", request.url, e);
        sendResponse({ decision: "ERROR", score: null });
      }
    });

    // Asynchronous call to sendResponse
    return true;
  }

  if (request.action === "checkPage") {
    chrome.storage.sync.get("isEnabled", (data) => {
      if (!data.isEnabled) {
        console.log("[page] DISABLED", request.url);
        sendResponse({ decision: "DISABLED", score: 0 });
        return;
      }
  
      let urlObj;
      try {
        urlObj = new URL(request.url);
      } catch (e) {
        console.log("[page] bad url", request.url, e);
        sendResponse({ decision: "ERROR", score: 0 });
        return;
      }
  
      if (isSafeDomain(urlObj.hostname)) {
        console.log("[page] Skip detection for whitelisted domain:", urlObj.hostname);
        sendResponse({ decision: "SAFE", score: 0 });
        return;
      }
  
      checkUrlWithBackend(urlObj.href)
        .then((r) => {
          const decision = r?.decision ?? "ERROR";
          const score =
            typeof r?.score === "number" ? r.score : (decision === "PHISHING" ? 1 : 0);
  
          console.log(
            "[page] Checked URL:",
            urlObj.href,
            "decision:",
            decision,
            "score:",
            score
          );
  
          sendResponse({ decision, score });
        })
        .catch((e) => {
          console.error("[page] checkPage error:", e);
          sendResponse({ decision: "ERROR", score: 0 });
        });
    });
  
    return true;
  }

  // asks whether a navigation overlay should be displayed when the content.js is put in page
  if (request.action === "navOverlayInit") {
    chrome.storage.sync.get("isEnabled", (data) => {
      if (!data.isEnabled) {
        console.log("[navOverlayInit] disabled");
        sendResponse({ shouldShow: false });
        return;
      }
  
      let urlObj;
      try { urlObj = new URL(request.url); }
      catch {
        console.log("[navOverlayInit] bad url", request.url);
        sendResponse({ shouldShow: false });
        return;
      }
  
      if (request.url.startsWith(chrome.runtime.getURL("extension/warning.html"))) {
        console.log("[navOverlayInit] on warning page");
        sendResponse({ shouldShow: false });
        return;
      }
  
      if (proceedURLs.has(request.url)) {
        console.log("[navOverlayInit] proceedURLs hit", request.url);
        sendResponse({ shouldShow: false });
        return;
      }
  
      if (proceedHosts.has(urlObj.hostname)) {
        console.log("[navOverlayInit] proceedHosts hit", urlObj.hostname);
        sendResponse({ shouldShow: false });
        return;
      }
  
      if (isSafeDomain(urlObj.hostname)) {
        console.log("[navOverlayInit] whitelist hit", urlObj.hostname);
        sendResponse({ shouldShow: false });
        return;
      }
  
      console.log("[navOverlayInit] shouldShow true", request.url);
      sendResponse({ shouldShow: true });
    });
    return true;
  }
  

  if (request.action === "addCurrentToWhitelist") {
    try {
      const u = new URL(request.url);
      addHostToWhitelist(u.hostname);
      sendResponse({ ok: true, host: u.hostname });
    } catch (e) {
      console.error("Invalid URL in addCurrentToWhitelist:", request.url, e);
      sendResponse({ ok: false });
    }
    return true;
  }

  if (request.action === "navUserSkip") {
    // do not do a forced redirection due to "late PHISHING" within 15 sec
    navSkipUntil.set(sender?.tab?.id, Date.now() + 15000);
    sendResponse({ ok: true });
    return true;
  }

  if (request.action === "redirectToWarning") {
    const warningPageUrl =
      chrome.runtime.getURL("extension/warning.html") +
      "?url=" +
      encodeURIComponent(request.url);
  
    if (sender && sender.tab) {
      chrome.tabs.update(sender.tab.id, { url: warningPageUrl });
    }
    sendResponse({ ok: true });
    return true;
  }
  
});

const BACKEND_TIMEOUT_MS = 0;


//  keep waiting until backend returns
function checkUrlWithBackend(url, timeoutMs = BACKEND_TIMEOUT_MS) {
  const now = Date.now();

  // Cache: if we already checked this URL recently, reuse it.
  const cached = urlCache.get(url);
  if (cached && now - cached.ts < CACHE_TTL_MS) {
    return Promise.resolve(cached);
  }

  const requestOptions = {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url }),
  };

  // If timeoutMs <= 0, never abort: wait as long as needed.
  let controller = null;
  let timer = null;
  if (typeof timeoutMs === "number" && timeoutMs > 0) {
    controller = new AbortController();
    requestOptions.signal = controller.signal;
    timer = setTimeout(() => controller.abort(), timeoutMs);
  }

  return fetch("http://127.0.0.1:5030/check_url", requestOptions)
    .then(async (response) => {
      if (!response.ok) {
        throw new Error(`Backend error: ${response.status} ${response.statusText}`);
      }
      return response.json();
    })
    .then((data) => {
      if (timer) clearTimeout(timer);

      // Ensure we always have a numeric score.
      // If backend doesn't provide it, fall back to 1 for PHISHING, 0 otherwise.
      const decision = data?.decision ?? "ERROR";
      const rawScore = data?.score;
      const score =
        typeof rawScore === "number"
          ? rawScore
          : decision === "PHISHING"
          ? 1
          : 0;

      const wrapped = {
        decision,
        score,
        ts: Date.now(),
      };

      urlCache.set(url, wrapped);
      markRecentlyChecked(url);
      return wrapped;
    })
    .catch((e) => {
      if (timer) clearTimeout(timer);

      // don't resolve as TIMEOUT (which makes score null and hides overlay).
      // If a timeout was configured and it fired, fall back to "wait without timeout"
      if (e && e.name === "AbortError" && timeoutMs > 0) {
        return checkUrlWithBackend(url, 0);
      }
      throw e;
    });
}


// do full-page navigation detection when the tab is updated
// chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
//   if (!tab.url || tab.url === "about:blank" || tab.url.startsWith("chrome://")) return;
//   if (changeInfo.status !== "loading" && changeInfo.status !== "complete") return;

//   chrome.storage.sync.get("isEnabled", (data) => {
//     if (!data.isEnabled) return;
//     if (tab.url.startsWith(chrome.runtime.getURL("extension/warning.html"))) return;

//     let urlObj;
//     try {
//       urlObj = new URL(tab.url);
//     } catch (e) {
//       console.error("Invalid tab URL:", tab.url, e);
//       return;
//     }

//     if (proceedURLs.has(tab.url) || proceedHosts.has(urlObj.hostname)) {
//       proceedURLs.delete(tab.url);
//       return;
//     }

//     if (isSafeDomain(urlObj.hostname)) return;

//     if (changeInfo.status === "loading") {
//       safeSendToTab(tabId, { action: "pageCheckStart", url: tab.url });
//       return;
//     }

//     // complete: detect and return the results
//     checkUrlWithBackend(tab.url)
//       .then((data) => {
//         console.log("[navigation] Checked URL:", tab.url, "decision:", data.decision, "score:", data.score);

//         safeSendToTab(tabId, {
//           action: "pageCheckResult",
//           url: tab.url,
//           decision: data.decision,
//           score: data.score,
//         });

//         if (data.decision === "PHISHING") {
//           const warningPageUrl =
//             chrome.runtime.getURL("extension/warning.html") +
//             "?url=" +
//             encodeURIComponent(tab.url);
//           chrome.tabs.update(tabId, { url: warningPageUrl });
//         }
//       })
//       .catch((error) => {
//         console.error("Error:", error);
//         // send ERROR only is failed
//         safeSendToTab(tabId, {
//           action: "pageCheckResult",
//           url: tab.url,
//           decision: "ERROR",
//           score: null,
//         });
//       });
//   });
// });
