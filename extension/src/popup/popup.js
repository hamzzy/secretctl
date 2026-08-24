document.addEventListener("DOMContentLoaded", () => {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (tabs.length > 0) {
      chrome.tabs.sendMessage(tabs[0].id, { type: "GET_STATUS" }, (response) => {
        if (response && response.epoch) {
          document.getElementById("epochVal").textContent = response.epoch;
        }
      });
    }
  });
});
