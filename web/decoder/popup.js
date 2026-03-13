$(document).ready(function () {
  var layoutMode = window.location.search.indexOf("mode=tab") !== -1 ? "tab" : "popup";
  document.documentElement.setAttribute("data-layout", layoutMode);
  document.body.setAttribute("data-layout", layoutMode);
  var fullViewUrl =
    typeof chrome !== "undefined" && chrome.runtime && chrome.runtime.getURL
      ? chrome.runtime.getURL("popup.html") + "?mode=tab"
      : "popup.html?mode=tab";

  function refreshOutputs() {
    hasher.update();
    autoScroll(document);
  }

  $("#input-value, #input-password, #input-url").on("input", refreshOutputs);

  $("#button-popout").on("click", function () {
    if (typeof chrome !== "undefined" && chrome.tabs && chrome.tabs.create) {
      chrome.tabs.create({
        url: fullViewUrl
      });
    } else {
      window.open(fullViewUrl, "_blank");
    }
  });

  $("#tabs li").on("click", function () {
    var nextTab = tabs[this.id];
    if (nextTab == null) {
      return;
    }

    hasher.tab = nextTab;
    hasher.updateUI();
    $("#input-value").trigger("focus");
    autoScroll(document);
  });

  function onHashChange() {
    var hash = window.location.hash.slice(1);
    $(".screens").hide();

    if (hash === "info") {
      $("#screen-2").show();
    } else {
      $("#screen-1").show();
    }

    window.scrollTo(0, 0);
    autoScroll(document);
  }

  $(window).on("hashchange", onHashChange);

  onHashChange();
  hasher.updateUI();
  autoScroll(document);
});
