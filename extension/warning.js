document.addEventListener("DOMContentLoaded", () => {
  const params = new URLSearchParams(window.location.search);
  const targetUrl = params.get("url");

  const proceedBtn = document.getElementById("proceedBtn");
  const goBackBtn = document.getElementById("goBackBtn");

  if (proceedBtn && targetUrl) {
    proceedBtn.addEventListener("click", () => {
      chrome.runtime.sendMessage(
        { action: "proceedToURL", url: targetUrl },
        () => {
          // Fallback in case the background script fails to redirect:
          // window.location.href = targetUrl;
        }
      );
    });
  }

  if (goBackBtn) {
    goBackBtn.addEventListener("click", () => {
      if (window.history.length > 1) {
        window.history.back();
      } else {
        // if no history go to a default google search page
        window.location.href = "https://www.google.com";
      }
    });
  }
});