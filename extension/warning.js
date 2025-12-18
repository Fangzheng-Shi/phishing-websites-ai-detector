document.addEventListener("DOMContentLoaded", () => {
  const params = new URLSearchParams(window.location.search);
  const targetUrl = params.get("url");

  const proceedBtn = document.getElementById("proceedBtn");
  const goBackBtn = document.getElementById("goBackBtn");
  const whitelistBtn = document.getElementById("whitelistBtn");

  let host = "";
  try {
    if (targetUrl) host = new URL(targetUrl).hostname;
  } catch (e) {}

  if (whitelistBtn && host) {
    whitelistBtn.textContent = `Always trust ${host}`;
  }

  if (proceedBtn && targetUrl) {
    proceedBtn.addEventListener("click", () => {
      chrome.runtime.sendMessage({ action: "proceedToURL", url: targetUrl }, () => {});
    });
  }

  if (whitelistBtn && targetUrl) {
    whitelistBtn.addEventListener("click", () => {
      whitelistBtn.disabled = true;
      const oldText = whitelistBtn.textContent;
      whitelistBtn.textContent = "Adding to whitelist...";

      chrome.runtime.sendMessage(
        { action: "addCurrentToWhitelist", url: targetUrl },
        (resp) => {
          if (!resp || !resp.ok) {
            whitelistBtn.disabled = false;
            whitelistBtn.textContent = oldText || "Trust this site (Add to whitelist)";
            return;
          }

          // go back to original page
          chrome.runtime.sendMessage({ action: "proceedToURL", url: targetUrl }, () => {});
        }
      );
    });
  }

  if (goBackBtn) {
    goBackBtn.addEventListener("click", () => {
      window.location.href = "https://www.google.com";
    });
  }
});
