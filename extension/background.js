// Record the urls that users actively choose to continue visiting, 
// so do not repeatedly intercept the same page
let proceedURLs = new Set();

// simple cache: url -> { decision, score, timestamp }
const urlCache = new Map();
const CACHE_TTL_MS = 10 * 60 * 1000; // 10 mins

// whitelist of domains I skip detecting for
const safeDomains = [
  "github.com",
  "google.com",
  // wait to add more
];

// check if the detecting hostname is in whitelist
function isSafeDomain(hostname) {
  return safeDomains.includes(hostname);
}

chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.sync.set({ isEnabled: false });
});

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "updateState") {
    chrome.storage.sync.set({ isEnabled: request.state });
  }

  if (request.action === "proceedToURL") {
    // users click "proceed to URL" in the warning page
    proceedURLs.add(request.url);
    if (sender && sender.tab) {
      chrome.tabs.update(sender.tab.id, { url: request.url });
    }
  }

  // content script request for a lightweight scan of a specific link（hover/click）
  if (request.action === "checkLink") {
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
      // Tell Chrome this response will be sent asynchronously
      return true;
    } catch (e) {
      console.error("Invalid URL in checkLink:", request.url, e);
      sendResponse({ decision: "ERROR", score: null });
    }
  }
});

// communicate with Flask backend and simple caching
function checkUrlWithBackend(url) {
  const now = Date.now();
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
      return wrapped;
    });
}

// do full-page navigation detection when the tab is updated
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  // ignore about:blank
  if (tab.url === "about:blank") return;

  if (changeInfo.status === "complete" && tab.url && !tab.url.startsWith("chrome://")) {
    chrome.storage.sync.get("isEnabled", (data) => {
      if (!data.isEnabled) return;

      // do not intercept warnings itself
      if (tab.url.startsWith(chrome.runtime.getURL("extension/warning.html"))) {
        return;
      }

      // user just chose to continue browsing after receiving a warning
      if (proceedURLs.has(tab.url)) {
        proceedURLs.delete(tab.url);
        return;
      }

      let urlObj;
      try {
        urlObj = new URL(tab.url);
      } catch (e) {
        console.error("Invalid tab URL:", tab.url, e);
        return;
      }

      if (isSafeDomain(urlObj.hostname)) {
        console.log("Skip detection for whitelisted domain:", urlObj.hostname);
        return;
      }

      // multi-stage: notify the content script to show "checking..." overlay
      chrome.tabs.sendMessage(tabId, {
        action: "pageCheckStart",
        url: tab.url,
      });

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

          // Send result so content.js can remove/update the overlay
          chrome.tabs.sendMessage(tabId, {
            action: "pageCheckResult",
            url: tab.url,
            decision: data.decision,
            score: data.score,
          });

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
  }
});
