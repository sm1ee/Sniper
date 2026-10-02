(function () {
  function resizeTextarea(textarea) {
    if (!textarea) {
      return;
    }

    textarea.style.height = "auto";
    // A textarea with a max-height (the Tools input) stops growing there and
    // scrolls; without one it grows to fit, as the read-only outputs do.
    var maxHeight = parseFloat(window.getComputedStyle(textarea).maxHeight);
    var capped = isFinite(maxHeight) && textarea.scrollHeight > maxHeight;
    textarea.style.overflowY = capped ? "auto" : "hidden";
    textarea.style.height = (capped ? maxHeight : textarea.scrollHeight) + "px";
  }

  function prepareTextarea(textarea) {
    if (!textarea || textarea.dataset.autosizeReady === "true") {
      return;
    }

    textarea.dataset.autosizeReady = "true";
    textarea.addEventListener("input", function () {
      resizeTextarea(textarea);
    });
  }

  function collectTextareas(root) {
    var scope = root && root.querySelectorAll ? root : document.querySelector(".decoder-shell");
    if (!scope) {
      return;
    }

    var textareas = scope.querySelectorAll("textarea[data-autosize='decoder']");

    for (var i = 0; i < textareas.length; i++) {
      prepareTextarea(textareas[i]);
      resizeTextarea(textareas[i]);
    }
  }

  function autoScroll(root) {
    var target = root;

    if (typeof root === "string") {
      target = document.querySelector(root);
    }

    collectTextareas(target || document);
  }

  window.autoScroll = autoScroll;
  window.resizeTextarea = resizeTextarea;

  window.addEventListener("load", function () {
    autoScroll(document.querySelector(".decoder-shell"));
  });

  window.addEventListener("resize", function () {
    autoScroll(document.querySelector(".decoder-shell"));
  });
})();
