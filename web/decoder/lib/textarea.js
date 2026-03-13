(function () {
  function resizeTextarea(textarea) {
    if (!textarea) {
      return;
    }

    textarea.style.height = "auto";
    textarea.style.overflowY = "hidden";
    textarea.style.height = textarea.scrollHeight + "px";
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
