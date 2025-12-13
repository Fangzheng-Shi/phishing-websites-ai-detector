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
  "chatgpt.com",
  // wait to add more
];

// check if the detecting hostname is in whitelist (including subdomains)
function isSafeDomain(hostname) {
  return safeDomains.some(d => hostname === d || hostname.endsWith("." + d));
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

  // asks whether a navigation overlay should be displayed when the content.js is put in page
  if (request.action === "navOverlayInit") {
    chrome.storage.sync.get("isEnabled", (data) => {
      if (!data.isEnabled) {
        sendResponse({ shouldShow: false });
        return;
      }
  
      let urlObj;
      try {
        urlObj = new URL(request.url);
      } catch (e) {
        console.error("Invalid URL in navOverlayInit:", request.url, e);
        sendResponse({ shouldShow: false });
        return;
      }

      if (request.url.startsWith(chrome.runtime.getURL("extension/warning.html"))) {
        sendResponse({ shouldShow: false });
        return;
      }
  
      if (proceedURLs.has(request.url) || proceedHosts.has(urlObj.hostname)) {
        sendResponse({ shouldShow: false });
        return;
      }

      if (isSafeDomain(urlObj.hostname)) {
        sendResponse({ shouldShow: false });
        return;
      }
  
      sendResponse({ shouldShow: true });
    });
  
    return true;
  }  
});

// communicate with Flask backend and simple caching
function checkUrlWithBackend(url) {
  const now = Date.now();

  // if there are results in the cache, use them directly without sending to the backend at all
  if (isRecentlyChecked(url)) {
    const cached = urlCache.get(url);
    if (cached && now - cached.ts < CACHE_TTL_MS) {
      return Promise.resolve(cached);
    }
    // no cache, go ahead
  }

  const cached = urlCache.get(url);
  if (cached && now - cached.ts < CACHE_TTL_MS) {
    return Promise.resolve(cached);
  }

  return fetch("http://127.0.0.1:5030/check_url", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url }),
  })
    .then((response) => response.json())
    .then((data) => {
      const wrapped = {
        decision: data.decision,
        score: data.score ?? null,
        ts: Date.now(),
      };
      urlCache.set(url, wrapped);
      // marked as "Just checked"
      markRecentlyChecked(url);
      return wrapped;
    });
}

// do full-page navigation detection when the tab is updated
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (!tab.url || tab.url === "about:blank" || tab.url.startsWith("chrome://")) {
    return;
  }

  if (changeInfo.status !== "complete") {
    return;
  }

  chrome.storage.sync.get("isEnabled", (data) => {
    if (!data.isEnabled) {
      return;
    }

    if (tab.url.startsWith(chrome.runtime.getURL("extension/warning.html"))) {
      return;
    }

    let urlObj;
    try {
      urlObj = new URL(tab.url);
    } catch (e) {
      console.error("Invalid tab URL:", tab.url, e);
      return;
    }

    if (proceedURLs.has(tab.url) || proceedHosts.has(urlObj.hostname)) {
      proceedURLs.delete(tab.url);
      console.log("Skip detection for user-approved site:", tab.url);
      return;
    }

    if (isSafeDomain(urlObj.hostname)) {
      console.log("Skip detection for whitelisted domain:", urlObj.hostname);
      return;
    }

    checkUrlWithBackend(tab.url)
      .then((data) => {
        console.log(
          "[navigation] Checked URL:",
          tab.url,
          "decision:",
          data.decision,
          "score:",
          data.score
        );

        // Send the test results to the content.js of the current page
        chrome.tabs.sendMessage(
          tabId,
          {
            action: "pageCheckResult",
            url: tab.url,
            decision: data.decision,
            score: data.score,
          },
          () => {
            // If the content is not present, ignore lastError
          }
        );

        if (data.decision === "PHISHING") {
          const warningPageUrl =
            chrome.runtime.getURL("extension/warning.html") +
            "?url=" +
            encodeURIComponent(tab.url);
          chrome.tabs.update(tabId, { url: warningPageUrl });
        }
      })
      .catch((error) => console.error("Error:", error));
  });
});
