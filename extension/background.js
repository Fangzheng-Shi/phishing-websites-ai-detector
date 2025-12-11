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

  // if (request.action === "proceedToURL") {
  //   // users click "proceed to URL" in the warning page
  //   proceedURLs.add(request.url);
  //   if (sender && sender.tab) {
  //     chrome.tabs.update(sender.tab.id, { url: request.url });
  //   }
  // }
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
// chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
//   if (tab.url === "about:blank") return;

//   if (changeInfo.status === "complete" && tab.url && !tab.url.startsWith("chrome://")) {
//     // chrome.storage.sync.get("isEnabled", (data) => {
//     //   if (!data.isEnabled) return;
//     // });

//     if (tab.url.startsWith(chrome.runtime.getURL("extension/warning.html"))) {
//       return;
//     }

//     // if (proceedURLs.has(tab.url)) {
//     //   proceedURLs.delete(tab.url);
//     //   return;
//     // }

//     let urlObj;
//     try {
//       urlObj = new URL(tab.url);
//     } catch (e) {
//       console.error("Invalid tab URL:", tab.url, e);
//       return;
//     }

//     // If the user has chosen to continue accessing on the warning page, 
//     // then this URL and all other pages on the same domain will be skipped
//     if (proceedURLs.has(tab.url) || proceedHosts.has(urlObj.hostname)) {
//       proceedURLs.delete(tab.url);
//       console.log("Skip detection for user-approved site:", tab.url);
//       return;
//     }

//     if (isSafeDomain(urlObj.hostname)) {
//       console.log("Skip detection for whitelisted domain:", urlObj.hostname);
//       return;
//     }

//     // multi-stage: notify the content script to show "checking..." overlay
//     chrome.tabs.sendMessage(tabId, {
//       action: "pageCheckStart",
//       url: tab.url,
//     });

//     checkUrlWithBackend(tab.url)
//       .then((data) => {
//         console.log(
//           "[navigation] Checked URL:",
//           tab.url,
//           "decision:",
//           data.decision,
//           "score:",
//           data.score
//         );

//         chrome.tabs.sendMessage(tabId, {
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
//       .catch((error) => console.error("Error:", error));
//   }
// });
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (tab.url === "about:blank") return;
  if (changeInfo.status !== "complete" || !tab.url || tab.url.startsWith("chrome://")) {
    return;
  }

  // read the main switch once here
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

    // the user clicked on "proceed" on the warning page, thus bypassing it directly
    if (proceedURLs.has(tab.url) || proceedHosts.has(urlObj.hostname)) {
      proceedURLs.delete(tab.url);
      console.log("Skip detection for user-approved site:", tab.url);
      return;
    }

    if (isSafeDomain(urlObj.hostname)) {
      console.log("Skip detection for whitelisted domain:", urlObj.hostname);
      return;
    }

    // do the page detection
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
});
