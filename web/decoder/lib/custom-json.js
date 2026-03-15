function normalizeDictLikeString(dictString) {
  return dictString
    .replace(/([{,]\s*)'([^'\\]*(?:\\.[^'\\]*)*)'\s*:/g, '$1"$2":')
    .replace(/:\s*'([^'\\]*(?:\\.[^'\\]*)*)'(\s*[,}])/g, ': "$1"$2');
}

function convertJsonToSingleQuoteStyle(jsonString) {
  return jsonString
    .replace(/^(\s*)"([^"\\]*(?:\\.[^"\\]*)*)":/gm, "$1'$2':")
    .replace(/: "([^"\\]*(?:\\.[^"\\]*)*)"(\s*[,}\n])/g, ": '$1'$2");
}

const customJson = {
  jsonBeautifier: (jsonString) => {
    try {
      return JSON.stringify(JSON.parse(jsonString), null, 2);
    } catch (error) {
      return "";
    }
  },

  dictBeautifier: (dictString) => {
    try {
      const normalized = normalizeDictLikeString(dictString);
      const formatted = JSON.stringify(JSON.parse(normalized), null, 2);
      return convertJsonToSingleQuoteStyle(formatted);
    } catch (error) {
      return "";
    }
  }
};
