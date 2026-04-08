// CodeMirror 6 bundle entry point for Sniper
// Exports all needed symbols on window.CM

export {
  EditorState,
  StateEffect,
  StateField,
  Compartment,
} from "@codemirror/state";

export {
  EditorView,
  ViewPlugin,
  Decoration,
  WidgetType,
  keymap,
  lineNumbers,
  highlightSpecialChars,
  drawSelection,
  placeholder,
} from "@codemirror/view";

export {
  StreamLanguage,
  syntaxHighlighting,
  HighlightStyle,
} from "@codemirror/language";

export {
  search,
  searchKeymap,
  highlightSelectionMatches,
} from "@codemirror/search";

export {
  defaultKeymap,
  history,
  historyKeymap,
  undo,
  redo,
} from "@codemirror/commands";

export {
  tags,
} from "@lezer/highlight";
