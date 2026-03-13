var tabs = {
  hash : 1,
  hmac : 2,
  crc : 3,
  cipher : 4,
  net : 5,
  time : 6,
  encode : 7,
  number : 8,
  morse: 9,
  jwt: 10,
  json: 11,
  password: 12,
  string: 13
};

/*
 *  Copy to clipboard
 */
function copyToClipboard(id) {
  var textarea = $("#"+id);
  var value = textarea.val();

  if (navigator.clipboard && window.isSecureContext) {
    return navigator.clipboard.writeText(value);
  }

  return new Promise(function (resolve, reject) {
    try {
      textarea.select();
      document.execCommand("copy");
      resolve();
    } catch (err) {
      reject(err);
    }
  });
}

function stringifyValue(value) {
  if (value == null) {
    return "";
  }

  return String(value);
}

function safeUriTransform(transform, input) {
  try {
    return transform(input);
  } catch (err) {
    return "Parse error";
  }
}

function utf8StringToBytes(value) {
  return new TextEncoder().encode(value);
}

function bytesToUtf8String(bytes) {
  return new TextDecoder().decode(bytes);
}

var hasher = {
  ipcalc : new ipCalc(),
  tab : tabs.hash,
  elements: {
    h1 : {
      id : tabs.hash+"md5",
      tab : tabs.hash,
      title : "MD5",
      calculate : function (input) {
        return CryptoJS.MD5(input);
      }
    },
    h2 : {
      id: tabs.hash+"sha1",
      tab : tabs.hash,
      title: "SHA-1",
      calculate: function (input) {
        return CryptoJS.SHA1(input);
      }
    },
    h3 : {
      id: tabs.hash+"sha224",
      tab : tabs.hash,
      title: "SHA-224",
      calculate: function (input) {
        return CryptoJS.SHA224(input);
      }
    },
    h4 : {
      id: tabs.hash+"sha256",
      tab : tabs.hash,
      title: "SHA-256",
      calculate: function (input) {
        return CryptoJS.SHA256(input);
      }
    },
    h5 : {
      id: tabs.hash+"sha384",
      tab : tabs.hash,
      title: "SHA-384",
      calculate: function (input) {
        return CryptoJS.SHA384(input);
      }
    },
    h6 : {
      id: tabs.hash+"sha512",
      tab : tabs.hash,
      title: "SHA-512",
      calculate: function (input) {
        return CryptoJS.SHA512(input);
      }
    },
    h8 : {
      id: tabs.hash+"ripemd160",
      tab : tabs.hash,
      title: "RIPEMD-160",
      calculate: function (input) {
        return hex_rmd160(input);
      }
    },
    h7 : {
      id: tabs.hash+"md4",
      tab : tabs.hash,
      title: "MD4",
      calculate: function (input) {
        return hex_md4(input);
      }
    },
    h9 : {
      id: tabs.hash+"whirpool",
      tab : tabs.hash,
      title: "Whirlpool",
      calculate: function (input) {
        return Whirlpool(input);
      }
    },

    // HMAC
    hm1 : {
      id : tabs.hmac+"md5",
      tab : tabs.hmac,
      title : "HMAC-MD5",
      calculate : function (input, password) {
        return CryptoJS.HmacMD5(input, password);
      }
    },
    hm2 : {
      id : tabs.hmac+"sha1",
      tab : tabs.hmac,
      title : "HMAC-SHA1",
      calculate : function (input, password) {
        return CryptoJS.HmacSHA1(input, password);
      }
    },
    hm3: {
      id : tabs.hmac+"sha224",
      tab : tabs.hmac,
      title : "HMAC-SHA224",
      calculate : function (input, password) {
        return CryptoJS.HmacSHA224(input, password);
      }
    },
    hm4: {
      id : tabs.hmac+"sha256",
      tab : tabs.hmac,
      title : "HMAC-SHA256",
      calculate : function (input, password) {
        return CryptoJS.HmacSHA256(input, password);
      }
    },
    hm5: {
      id : tabs.hmac+"sha384",
      tab : tabs.hmac,
      title : "HMAC-SHA384",
      calculate : function (input, password) {
        return CryptoJS.HmacSHA384(input, password);
      }
    },
    hm6: {
      id : tabs.hmac+"sha512",
      tab : tabs.hmac,
      title : "HMAC-SHA512",
      calculate : function (input, password) {
        return CryptoJS.HmacSHA512(input, password);
      }
    },
    hm7: {
      id : tabs.hmac+"ripemd160",
      tab : tabs.hmac,
      title : "HMAC-RIPEMD160",
      calculate : function (input, password) {
        return hex_hmac_rmd160(password, input);
      }
    },
    hm8: {
      id : tabs.hmac+"md4",
      tab : tabs.hmac,
      title : "HMAC-MD4",
      calculate : function (input, password) {
        return hex_hmac_md4(password, input);
      }
    },

    // CRC
    c1 : {
      id: tabs.crc+"crc8",
      tab : tabs.crc,
      title: "CRC-8",
      calculate: function (input) {
        return Hex8(Crc8Str(input));
      }
    },
    c2 : {
      id: tabs.crc+"crc16",
      tab : tabs.crc,
      title: "CRC-16",
      calculate: function (input) {
        return Hex16(Crc16Str(input));
      }
    },
    c3 : {
      id: tabs.crc+"fsc16",
      tab : tabs.crc,
      title: "FCS-16",
      calculate: function (input) {
        return Hex16(Fcs16Str(input));
      }
    },
    c4 : {
      id: tabs.crc+"crc32b",
      tab : tabs.crc,
      title: "FCS/CRC-32",
      calculate: function (input) {
        return Hex32(Crc32Str(input));
      }
    },


    // Cipher
    ci1: {
      id : tabs.cipher+"aes256",
      tab : tabs.cipher,
      title : "AES-256",
      calculate : function (input, password) {
        return CryptoJS.AES.encrypt(input, password);
      }
    },
    ci2: {
      id : tabs.cipher+"des",
      tab : tabs.cipher,
      title : "DES",
      calculate : function (input, password) {
        return CryptoJS.DES.encrypt(input, password);
      }
    },
    ci3: {
      id : tabs.cipher+"tripledes",
      tab : tabs.cipher,
      title : "TripleDES",
      calculate : function (input, password) {
        return CryptoJS.TripleDES.encrypt(input, password);
      }
    },
    ci4: {
      id : tabs.cipher+"rabbit",
      tab : tabs.cipher,
      title : "Rabbit",
      calculate : function (input, password) {
        return CryptoJS.Rabbit.encrypt(input, password);
      }
    },
    ci5: {
      id : tabs.cipher+"rc4",
      tab : tabs.cipher,
      title : "RC4",
      calculate : function (input, password) {
        return CryptoJS.RC4.encrypt(input, password);
      }
    },
    ci6: {
      id : tabs.cipher+"rc4drop",
      tab : tabs.cipher,
      title : "RC4Drop",
      calculate : function (input, password) {
        return CryptoJS.RC4Drop.encrypt(input, password);
      }
    },
    ci7: {
      id : tabs.cipher+"aes256-d",
      tab : tabs.cipher,
      title : "AES-256 decrypt",
      calculate : function (input, password) {
        try {
          var words = CryptoJS.AES.decrypt(input, password);
          return CryptoJS.enc.Utf8.stringify(words);
        } catch (err) {
          return "";
        }
      }
    },
    ci8: {
      id : tabs.cipher+"des-d",
      tab : tabs.cipher,
      title : "DES decrypt",
      calculate : function (input, password) {
        try {
          var words = CryptoJS.DES.decrypt(input, password);
          return CryptoJS.enc.Utf8.stringify(words);
        } catch (err) {
          return "";
        }
      }
    },
    ci9: {
      id : tabs.cipher+"tripledes-d",
      tab : tabs.cipher,
      title : "TripleDES decrypt",
      calculate : function (input, password) {
        try {
          var words = CryptoJS.TripleDES.decrypt(input, password);
          return CryptoJS.enc.Utf8.stringify(words);
        } catch (err) {
          return "";
        }
      }
    },
    ci10: {
      id : tabs.cipher+"rabbit-d",
      tab : tabs.cipher,
      title : "Rabbit decrypt",
      calculate : function (input, password) {
        try {
          var words = CryptoJS.Rabbit.decrypt(input, password);
          return CryptoJS.enc.Utf8.stringify(words);
        } catch (err) {
          return "";
        }
      }
    },
    ci11: {
      id : tabs.cipher+"rc4-d",
      tab : tabs.cipher,
      title : "RC4 decrypt",
      calculate : function (input, password) {
        try {
          var words = CryptoJS.RC4.decrypt(input, password);
          return CryptoJS.enc.Utf8.stringify(words);
        } catch (err) {
          return "";
        }
      }
    },
    ci12: {
      id : tabs.cipher+"rc4drop-d",
      tab : tabs.cipher,
      title : "RC4Drop decrypt",
      calculate : function (input, password) {
        try {
          var words = CryptoJS.RC4Drop.decrypt(input, password);
          return CryptoJS.enc.Utf8.stringify(words);
        } catch (err) {
          return "";
        }
      }
    },

    // Net
    net1 : {
      id: tabs.net+"ip2dec",
      tab : tabs.net,
      title: "IP to Dec",
      calculate: function (input) {
        var ipcalc = hasher.ipcalc;
        ipcalc.parse(input);
        if (ipcalc.getIp() != null) {
          return ipcalc.getIp();
        } else {
          return "";
        }
      }
    },
    // Net
    net2 : {
      id: tabs.net+"dec2ip",
      tab : tabs.net,
      title: "Dec to IP",
      calculate: function (input) {
        var ipcalc = hasher.ipcalc;
        ipcalc.parse(input);
        if (ipcalc.getIp() != null) {
          return ipcalc.intToOctetString(ipcalc.getIp());
        } else if (!ipcalc.isIpValid()) {
          return "Invalid IP";
        } else {
          return "";
        }
      }
    },
    net3 : {
      id: tabs.net+"ip2bin",
      tab : tabs.net,
      title: "IP to Bin",
      ruler: 1,
      calculate: function (input) {
        var ipcalc = hasher.ipcalc;
        ipcalc.parse(input);
        if (ipcalc.getIp() != null) {
          return ipcalc.getPaddedBinString(ipcalc.getIp());
        } else {
          return "";
        }
      }
    },
    net4 : {
      id: tabs.net+"ip2hex",
      tab : tabs.net,
      title: "IP to Hex",
      calculate: function (input) {
        var ipcalc = hasher.ipcalc;
        ipcalc.parse(input);
        if (ipcalc.getIp() != null) {
          return ipcalc.getIp().toString(16);
        } else {
          return "";
        }
      }
    },
    net5 : {
      id: tabs.net+"network",
      tab : tabs.net,
      title: "Network / netmask",
      calculate: function (input) {
        var ipcalc = hasher.ipcalc;
        ipcalc.parse(input);
        if (ipcalc.getNetmask() != null) {
          return ipcalc.intToOctetString(ipcalc.getNetwork()) + "/" + ipcalc.intToOctetString(ipcalc.getNetmask());
        } else if (!ipcalc.isNetmaskValid()) {
          return "Invalid netmask";
        } else {
          return "";
        }
      }
    },
    net6 : {
      id: tabs.net+"hostmin",
      tab : tabs.net,
      title: "Min host",
      calculate: function (input) {
        var ipcalc = hasher.ipcalc;
        ipcalc.parse(input);
        if (ipcalc.getNetmask() != null) {
          return ipcalc.intToOctetString(ipcalc.gethHostMin());
        } else {
          return "";
        }
      }
    },
    net7 : {
      id: tabs.net+"hostmax",
      tab : tabs.net,
      title: "Max host",
      calculate: function (input) {
        var ipcalc = hasher.ipcalc;
        ipcalc.parse(input);
        if (ipcalc.getNetmask() != null) {
          return ipcalc.intToOctetString(ipcalc.gethHostMax());
        } else {
          return "";
        }
      }
    },
    net8 : {
      id: tabs.net+"broadcast",
      tab : tabs.net,
      title: "Broadcast",
      calculate: function (input) {
        var ipcalc = hasher.ipcalc;
        ipcalc.parse(input);
        if (ipcalc.getNetmask() != null) {
          return ipcalc.intToOctetString(ipcalc.getBroadcast());
        } else {
          return "";
        }
      }
    },
    net9 : {
      id: tabs.net+"hostnum",
      tab : tabs.net,
      title: "Hosts",
      calculate: function (input) {
        var ipcalc = hasher.ipcalc;
        ipcalc.parse(input);
        if (ipcalc.getNetmask() != null) {
          return ipcalc.gethHostCount();
        } else {
          return "";
        }
      }
    },


    // Time
    time1 : {
      id: tabs.time+"date2ts",
      tab : tabs.time,
      title: "Unixtime",
      calculate: function (input) {
        var date;
        if (/[^\d]/.test(input)) {
          date = new Date(input);
        } else {
          date = new Date(1000*parseInt(input));
        }
        if (!isNaN(date.getTime())) {
          return date.getTime()/1000;
        }
        return "";
      }
    },
    time2 : {
      id: tabs.time+"ts2date",
      tab : tabs.time,
      title: "Local time",
      calculate: function (input) {
        var date;
        if (/[^\d]/.test(input)) {
          date = new Date(input);
        } else {
          date = new Date(1000*parseInt(input));
        }
        if (!isNaN(date.getTime())) {
          return date.toLocaleString();
        }
        return "";
      }
    },
    time3 : {
      id: tabs.time+"date2sql",
      tab : tabs.time,
      title: "DATETIME (local)",
      calculate: function (input) {
        var ddd;
        if (/[^\d]/.test(input)) {
          ddd = new Date(input);
        } else {
          ddd = new Date(1000*parseInt(input));
        }
        if (!isNaN(ddd.getTime())) {
          var y = ddd.getFullYear();
          var m = ddd.getMonth() + 1;
          var d = ddd.getDate();
          var h = ddd.getHours();
          var i = ddd.getMinutes();
          var s = ddd.getSeconds();
          
          m = (m < 10) ? "0" + m : m;
          d = (d < 10) ? "0" + d : d;
          h = (h < 10) ? "0" + h : h;
          i = (i < 10) ? "0" + i : i;
          s = (s < 10) ? "0" + s : s;
          
          return y + "-" + m + "-" + d + " " + h + ":" + i + ":" + s;
        }
        return "";
      }
    },
    time31 : {
      id: tabs.time+"date2sqlutc",
      tab : tabs.time,
      title: "DATETIME (UTC)",
      calculate: function (input) {
        var ddd;
        if (/[^\d]/.test(input)) {
          ddd = new Date(input);
        } else {
          ddd = new Date(1000*parseInt(input));
        }
        if (!isNaN(ddd.getTime())) {
          var y = ddd.getUTCFullYear();
          var m = ddd.getUTCMonth() + 1;
          var d = ddd.getUTCDate();
          var h = ddd.getUTCHours();
          var i = ddd.getUTCMinutes();
          var s = ddd.getUTCSeconds();
          
          m = (m < 10) ? "0" + m : m;
          d = (d < 10) ? "0" + d : d;
          h = (h < 10) ? "0" + h : h;
          i = (i < 10) ? "0" + i : i;
          s = (s < 10) ? "0" + s : s;
          
          return y + "-" + m + "-" + d + " " + h + ":" + i + ":" + s;
        }
        return "";
      }
    },
    time4 : {
      id: tabs.time+"ts2RFC1123",
      tab : tabs.time,
      title: "RFC-1123",
      calculate: function (input) {
        var date;
        if (/[^\d]/.test(input)) {
          date = new Date(input);
        } else {
          date = new Date(1000*parseInt(input));
        }
        if (!isNaN(date.getTime())) {
          return date.toUTCString();
        }
        return "";
      }
    },
    time5 : {
      id: tabs.time+"date2iso",
      tab : tabs.time,
      title: "ISO 8601",
      calculate: function (input) {
        var date;
        if (/[^\d]/.test(input)) {
          date = new Date(input);
        } else {
          date = new Date(1000*parseInt(input));
        }
        if (!isNaN(date.getTime())) {
          return date.toISOString();
        }
        return "";
      }
    },


    // Numbers
    n5 : {
      id: tabs.number+"i5",
      tab : tabs.number,
      title: "Dec to Hex",
      ruler: 1,
      calculate: function (input) {
        return numbers.decToHex(input);
      }
    },
    n6 : {
      id: tabs.number+"i6",
      tab : tabs.number,
      title: "Hex to Dec",
      calculate: function (input) {
        return numbers.hexToDec(input);
      }
    },
    n7 : {
      id: tabs.number+"i7",
      tab : tabs.number,
      title: "Dec to Bin",
      ruler: 1,
      calculate: function (input) {
        return numbers.decToBin(input);
      }
    },
    n8 : {
      id: tabs.number+"i8",
      tab : tabs.number,
      title: "Bin to Dec",
      calculate: function (input) {
        return numbers.binToDec(input);
      }
    },
    n9 : {
      id: tabs.number+"i3",
      tab : tabs.number,
      title: "Dec to Roman",
      calculate: function (input) {
        var rc = new RomanConverter();
        return rc.decToRoman(input);
      }
    },
    n10 : {
      id: tabs.number+"i4",
      tab : tabs.number,
      title: "Roman to Dec",
      calculate: function (input) {
        var rc = new RomanConverter();
        return rc.romanToDec(input);
      }
    },


    // Strings
    s1 : {
      id: tabs.string+"i1",
      tab : tabs.string,
      title: "ASCII to Hex",
      ruler: 2,
      calculate: function (input) {
        try {
          var words = CryptoJS.enc.Latin1.parse(input);
          return CryptoJS.enc.Hex.stringify(words);
        } catch (err) {
          return "Parse error";
        }
      }
    },
    s2 : {
      id: tabs.string+"i2",
      tab : tabs.string,
      title: "Hex to ASCII",
      calculate: function (input) {
        if (/[^0-9a-f]/i.test(input)) {
          return "NaN";
        }
        try {
          var words = CryptoJS.enc.Hex.parse(input);
          return CryptoJS.enc.Latin1.stringify(words);
        } catch (err) {
          return "Parse error";
        }
        return "";
      }
    },
    s3 : {
      id: tabs.string+"utf8-hex",
      tab : tabs.string,
      title: "UTF-8 to Hex",
      ruler: 2,
      calculate: function (input) {
        try {
          var words = CryptoJS.enc.Utf8.parse(input);
          return CryptoJS.enc.Hex.stringify(words);
        } catch (err) {
          return "Parse error";
        }
      }
    },
    s4 : {
      id: tabs.string+"hex-utf8",
      tab : tabs.string,
      title: "Hex to UTF-8",
      calculate: function (input) {
        if (/[^0-9a-f]/i.test(input)) {
          return "NaN";
        }
        try {
          var words = CryptoJS.enc.Hex.parse(input);
          return CryptoJS.enc.Utf8.stringify(words);
        } catch (err) {
          return "Parse error";
        }
        return "";
      }
    },
    s5 : {
      id: tabs.string+"utf16-hex",
      tab : tabs.string,
      title: "UTF-16 to Hex",
      ruler: 2,
      calculate: function (input) {
        try {
          var words = CryptoJS.enc.Utf16.parse(input);
          return CryptoJS.enc.Hex.stringify(words);
        } catch (err) {
          return "Parse error";
        }
      }
    },
    s6 : {
      id: tabs.string+"hex-utf16",
      tab : tabs.string,
      title: "Hex to UTF-16",
      calculate: function (input) {
        if (/[^0-9a-f]/i.test(input)) {
          return "NaN";
        }
        try {
          var words = CryptoJS.enc.Hex.parse(input);
          return CryptoJS.enc.Utf16.stringify(words);
        } catch (err) {
          return "Parse error";
        }
        return "";
      }
    },


    // Encode
    e1: {
      id : tabs.encode+"base64",
      tab : tabs.encode,
      title : "Base64",
      calculate : function (input) {
        try {
          var words = CryptoJS.enc.Utf8.parse(input);
          return CryptoJS.enc.Base64.stringify(words);
        } catch (err) {
          return "Parse error";
        }
      }
    },
    e2: {
      id : tabs.encode+"base64-d",
      tab : tabs.encode,
      title : "Base64 decode",
      calculate : function (input) {
        try {
          var words = CryptoJS.enc.Base64.parse(input);
          return CryptoJS.enc.Utf8.stringify(words);
        } catch (err) {
          return "";
        }
      }
    },
    e3: {
      id : tabs.encode+"base64-d-h",
      tab : tabs.encode,
      title : "Base64 decode to Hex",
      ruler: 2,
      calculate : function (input) {
        try {
          var words = CryptoJS.enc.Base64.parse(input);
          return CryptoJS.enc.Hex.stringify(words);
        } catch (err) {
          return "Parse error";
        }
      }
    },
    e4: {
      id : tabs.encode+"encodeURI",
      tab : tabs.encode,
      title : "encodeURI()",
      calculate : function (input) {
        return encodeURI(input);
      }
    },
    e5: {
      id : tabs.encode+"encodeURIComponent",
      tab : tabs.encode,
      title : "encodeURIComponent()",
      calculate : function (input) {
        return encodeURIComponent(input);
      }
    },
    e6: {
      id : tabs.encode+"decodeURI",
      tab : tabs.encode,
      title : "decodeURI()",
      calculate : function (input) {
        return safeUriTransform(decodeURI, input);
      }
    },
    e7: {
      id : tabs.encode+"decodeURIComponent",
      tab : tabs.encode,
      title : "decodeURIComponent()",
      calculate : function (input) {
        return safeUriTransform(decodeURIComponent, input);
      }
    },
    e8: {
      id : tabs.encode+"htmlspecialchars",
      tab : tabs.encode,
      title : "HTML special chars",
      calculate : function (input) {
        function escapeHtml(html) {
          return html
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
        }          

        return escapeHtml(input);
      }
    },
    e9: {
      id : tabs.encode+"htmlspecialchars-d",
      tab : tabs.encode,
      title : "HTML special chars decode",
      calculate : function (input) {
        function unescapeHtml(html) {
          return html
            .replace(/&amp;/g, "&")
            .replace(/&lt;/g, "<")
            .replace(/&gt;/g, ">")
            .replace(/&quot;/g, '"')
            .replace(/&#039;/g, "'");
        }          

        return unescapeHtml(input);
      }
    },
    // 유니코드 변환
    e10: {
      id: tabs.encode+"unicode-encode",
      tab: tabs.encode,
      title: "convertToUnicode()",
      calculate: function (input) {
        return convertToUnicode(input);
      }
    },
    e11: {
      id: tabs.encode+"unicode-decode",
      tab: tabs.encode,
      title: "convertFromUnicode()",
      calculate: function (input) {
        return convertFromUnicode(input);
      }
    },
    e12: {
      id : tabs.encode+"rot13",
      tab : tabs.encode,
      title : "ROT13 encode/decode",
      calculate : function (input) {
        var renc = new Rot13();
        return renc.encode(input);
      }
    },
    morse1: {
      id: tabs.morse+"morse-encode",
      tab: tabs.morse,
      title: "Morse encode",
      calculate : function (input) {
        return xmorse.encode(input, { space: ' ' });
      }
    },
    morse2: {
      id: tabs.morse+"morse-decode",
      tab: tabs.morse,
      title: "Morse decode",
      calculate : function (input) {
        return xmorse.decode(input, { space: ' ' });
      }
    },
    jwt1: {
      id: tabs.jwt+"jwt-encode",
      tab: tabs.jwt,
      title: "Encode",
      calculate : function (input) {
        return customjwt.encode(input);
      }
    },
    jwt2: {
      id: tabs.jwt+"jwt-decode",
      tab: tabs.jwt,
      title: "Decode",
      calculate : function (input) {
        return customjwt.decode(input);
      }
    },
    jwt3: {
      id: tabs.jwt+"jwt-none-1",
      tab: tabs.jwt,
      title: "none Payload",
      calculate : function (input) {
        return customjwt.none(input);
      }
    },
    jwt4: {
      id: tabs.jwt+"jwt-none-2",
      tab: tabs.jwt,
      title: "NonE Payload",
      calculate : function (input) {
        return customjwt.NonE(input);
      }
    },
    jwt5: {
      id: tabs.jwt+"jwt-none-3",
      tab: tabs.jwt,
      title: "NONE Payload",
      calculate : function (input) {
        return customjwt.NONE(input);
      }
    },
    jwt6: {
      id: tabs.jwt+"jwt-jke",
      tab: tabs.jwt,
      title: "JKU Payload",
      calculate : function (input) {
        return customjwt.JKU(input, $("#input-url").val());
      }
    },
    jwt7: {
      id: tabs.jwt+"jwt-x5u",
      tab: tabs.jwt,
      title: "X5U Payload",
      calculate : function (input) {
        return customjwt.X5U(input, $("#input-url").val());
      }
    },
    jwt8: {
      id: tabs.jwt+"jwt-kid",
      tab: tabs.jwt,
      title: "KID Payload",
      calculate : function (input) {
        return customjwt.KID(input, $("#input-url").val());
      }
    },
    json1: {
      id: tabs.json+"json-beautifier",
      tab: tabs.json,
      title: "JSON Beautifier",
      calculate : function (input) {
        return customJson.jsonBeautifier(input);
      }
    },
    json2: {
      id: tabs.json+"json-dictBeautifier",
      tab: tabs.json,
      title: "Dict Beautifier",
      calculate : function (input) {
        return customJson.dictBeautifier(input);
      }
    },    
    // Password strength
    p1: {
      id: tabs.password+"password-strength",
      tab: tabs.password,
      title: "Password Strength",
      calculate: function (input) {
        var result = checkPasswordStrength(input);
        return "Strength: " + result.strength + "\nScore: " + result.score + "/6\nEntropy: " +
               result.entropy.bits + " bits (" + result.entropy.strength + ")\n\nSuggestions:\n" +
               result.feedback.map(function(item) { return "- " + item; }).join("\n");
      }
    },
    // Base32 Encode
    e_base32_encode: {
      id : tabs.encode+"base32-encode",
      tab : tabs.encode,
      title : "Base32 Encode",
      calculate : function (input) {
        return base32Encode(input);
      }
    },
    // Base32 Decode
    e_base32_decode: {
      id : tabs.encode+"base32-decode",
      tab : tabs.encode,
      title : "Base32 Decode",
      calculate : function (input) {
        try {
          return base32Decode(input);
        } catch (err) {
          return "Invalid Base32 input";
        }
      }
    },
    // Base45 Encode
    e_base45_encode: {
      id : tabs.encode+"base45-encode",
      tab : tabs.encode,
      title : "Base45 Encode",
      calculate : function (input) {
        return base45Encode(input);
      }
    },
    // Base45 Decode
    e_base45_decode: {
      id : tabs.encode+"base45-decode",
      tab : tabs.encode,
      title : "Base45 Decode",
      calculate : function (input) {
         try {
          return base45Decode(input);
        } catch (err) {
          return "Invalid Base45 input";
        }
      }
    },
    // Base58 Encode
    e_base58_encode: {
      id : tabs.encode+"base58-encode",
      tab : tabs.encode,
      title : "Base58 Encode",
      calculate : function (input) {
        try {
          const inputBytes = stringToUint8Array(input);
          return base58Encode(inputBytes);
        } catch (err) {
          return "Error during Base58 encoding";
        }
      }
    },
    // Base58 Decode
    e_base58_decode: {
      id : tabs.encode+"base58-decode",
      tab : tabs.encode,
      title : "Base58 Decode",
      calculate : function (input) {
        try {
          const decodedBytes = base58Decode(input);
          return bytesToUtf8String(decodedBytes);
        } catch (err) {
          return "Invalid Base58 input";
        }
      }
    }
  },
  getElementById : function (id) {
    for (var i in this.elements) {
      if (this.elements[i].id == id) {
        return this.elements[i];
      }
    }
    return null;
  },
  /*
   */
  init : function () {
    this.render();

    for (var i in this.elements) {
      if (this.elements[i].tab == this.tab) {
        $("#"+this.elements[i].id+"-value").click(function (event) {
          $("#output .note").hide();
          var id = this.id.toString().replace("-value", "");
          var textarea = $("#"+id)[0];

          if (
            textarea &&
            (event.target === textarea || (textarea.contains && textarea.contains(event.target)))
          ) {
            return;
          }

          if ($("#"+id).val().length > 0) {
            copyToClipboard(id).then(function () {
              $("#"+id+"-note").text("copied").show("fast");
            }).catch(function () {
              $("#"+id+"-note").text("copy failed").show("fast");
            });
          }
        });
      }
    }

    autoScroll(document);
  },
  /*
   * Recalculate
   */
  update : function () {
    $("#output .note").hide();
    var input = $("#input-value").val();
    var password = $("#input-password").val();

    for (var i in this.elements) {
      this.elements[i].rows = 0;

      if (this.elements[i].tab == this.tab) {
        var value = "";

        try {
          value = this.elements[i].calculate(input, password);
        } catch (err) {
          value = "Error: " + (err && err.message ? err.message : "Calculation failed");
        }

        value = stringifyValue(value);
        $("#"+this.elements[i].id).val(value);

        var res = value.match(/(\n\r|\r\n|\n|\r)/g);
        var rows = 1;
        if (res != null && res.length != undefined) {
          rows = res.length + 1;
        }
        
        this.elements[i].rows = rows;
        $("#"+this.elements[i].id).attr("rows", rows);

        $("#"+this.elements[i].id+"-expand").text("").hide();

        if (this.elements[i].ruler != undefined) {
          $("#"+this.elements[i].id+"-ruler").html(this.ruler(value, this.elements[i].ruler));
        }
      }
    }

    autoScroll(document);
  },
  /*
   * 
   */

  render : function () {
    $("#output").html("");

    for (var i in this.elements) {
      if (this.elements[i].tab == this.tab) {
        var html = 
          '<div class="element">'+
            '<div>'+
              '<span id="'+this.elements[i].id+'-title" class="title">'+
                this.elements[i].title+
              '</span>'+
              '<span id="'+this.elements[i].id+'-expand" class="expand"></span>'+
              '<span id="'+this.elements[i].id+'-note" class="note"></span>'+
            '</div>'+
            '<div id="'+this.elements[i].id+'-value" class="value">'+
              '<textarea id="'+this.elements[i].id+'" rows="1" readonly spellcheck="false" data-autosize="decoder"></textarea>';

              if (this.elements[i].ruler != undefined) {
                html += '<div id="'+this.elements[i].id+'-ruler" class="ruler"></div>';
              }

        html += 
            '</div>'+
          '</div>';
        $("#output").append(html);
      }
    }

    autoScroll(document);
  },
  
  /*
   * UI 업데이트 메서드
   */
  updateUI : function () {
    // 탭 활성화 상태 업데이트
    $("#tabs li").removeClass("on");
    for (var tabName in tabs) {
      if (tabs[tabName] == this.tab) {
        $("#" + tabName).addClass("on");
        break;
      }
    }
    
    // 선택적 필드 표시/숨김
    if (this.tab == tabs.hmac || this.tab == tabs.cipher) {
      $("#input-password-wrapper").show();
    } else {
      $("#input-password-wrapper").hide();
    }

    if (this.tab == tabs.jwt) {
      $("#input-url-wrapper").show();
    } else {
      $("#input-url-wrapper").hide();
    }
    
    this.init();
    this.update();
  },
  
  /*
   * Symbol's numbers
   */
  ruler : function (value, type) {
    var html = "";
    var length = value.length;

    if (type == -1) {
      for (var i = 0; i < value.length; i++) {
        html += '<span title="'+(length - i - 1)+'">&nbsp;</span>';
      }
    } else if (type == 2) {
      for (var j = 0; j < value.length; j += 2) {
        html += '<span title="'+(j / 2 + 1)+'">&nbsp;&nbsp;</span>';
      }
    } else {
      for (var k = 0; k < value.length; k++) {
        html += '<span title="'+(k + 1)+'">&nbsp;</span>';
      }
    }

    return html;
  }
}

// 유니코드 변환 함수
function convertToUnicode(str) {
  let result = '';
  for (let i = 0; i < str.length; i++) {
    result += '\\u' + str.charCodeAt(i).toString(16).padStart(4, '0');
  }
  return result;
}

function convertFromUnicode(str) {
  return str.replace(/\\u([0-9a-fA-F]{4})/g, (_, hex) => 
    String.fromCharCode(parseInt(hex, 16))
  );
}

// Password entropy calculation
function calculateEntropy(password) {
  let charset = 0;
  
  // Estimate entropy based on the character sets in use.
  if (/[a-z]/.test(password)) charset += 26;
  if (/[A-Z]/.test(password)) charset += 26;
  if (/[0-9]/.test(password)) charset += 10;
  if (/[^A-Za-z0-9]/.test(password)) charset += 32;
  
  // Entropy in bits
  const entropy = Math.log2(Math.pow(charset, password.length));
  
  let strength = "Very weak";
  if (entropy >= 80) strength = "Very strong";
  else if (entropy >= 60) strength = "Strong";
  else if (entropy >= 40) strength = "Moderate";
  else if (entropy >= 20) strength = "Weak";
  
  return {
    bits: entropy.toFixed(2),
    strength: strength
  };
}

// Password strength scoring
function checkPasswordStrength(password) {
  let score = 0;
  let feedback = [];

  // Length
  if (password.length >= 8) score += 1;
  if (password.length >= 12) score += 1;
  
  // Uppercase
  if (/[A-Z]/.test(password)) score += 1;
  else feedback.push("Add at least one uppercase letter.");
  
  // Lowercase
  if (/[a-z]/.test(password)) score += 1;
  else feedback.push("Add at least one lowercase letter.");
  
  // Digits
  if (/[0-9]/.test(password)) score += 1;
  else feedback.push("Add at least one number.");
  
  // Symbols
  if (/[^A-Za-z0-9]/.test(password)) score += 1;
  else feedback.push("Add at least one special character.");

  let strength = "Very weak";
  if (score >= 5) strength = "Very strong";
  else if (score >= 4) strength = "Strong";
  else if (score >= 3) strength = "Moderate";
  else if (score >= 2) strength = "Weak";

  // Entropy
  const entropy = calculateEntropy(password);

  return {
    score: score,
    strength: strength,
    feedback: feedback,
    entropy: entropy
  };
}

// Base32 인코딩 함수
function base32Encode(input) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const bytes = utf8StringToBytes(input);
  let output = "";
  let buffer = 0;
  let bitsLeft = 0;

  for (let i = 0; i < bytes.length; i++) {
    buffer = (buffer << 8) | bytes[i];
    bitsLeft += 8;

    while (bitsLeft >= 5) {
      output += alphabet[(buffer >> (bitsLeft - 5)) & 31];
      bitsLeft -= 5;
    }
  }

  if (bitsLeft > 0) {
    output += alphabet[(buffer << (5 - bitsLeft)) & 31];
  }

  while (output.length % 8 !== 0) {
    output += "=";
  }

  return output;
}

// Base32 디코딩 함수
function base32Decode(input) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const normalized = input.toUpperCase().replace(/\s+/g, "").replace(/=+$/, "");
  let output = [];
  let buffer = 0;
  let bitsLeft = 0;

  for (let i = 0; i < normalized.length; i++) {
    const value = alphabet.indexOf(normalized[i]);
    if (value === -1) {
      throw new Error("Invalid Base32 input");
    }

    buffer = (buffer << 5) | value;
    bitsLeft += 5;

    if (bitsLeft >= 8) {
      output.push((buffer >> (bitsLeft - 8)) & 255);
      bitsLeft -= 8;
    }
  }

  return bytesToUtf8String(new Uint8Array(output));
}

// Base45 인코딩 함수
function base45Encode(input) {
  const BASE45_CHARS = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:';
  let output = '';
  const inputBytes = utf8StringToBytes(input);

  for (let i = 0; i < inputBytes.length; i += 2) {
    if (i + 1 < inputBytes.length) {
      // 2바이트 처리 -> 3개의 Base45 문자
      let value = (inputBytes[i] << 8) + inputBytes[i + 1];
      const e = Math.floor(value / (45 * 45));
      value %= (45 * 45);
      const d = Math.floor(value / 45);
      const c = value % 45;
      output += BASE45_CHARS[c] + BASE45_CHARS[d] + BASE45_CHARS[e];
    } else {
      // 1바이트 처리 -> 2개의 Base45 문자
      const value = inputBytes[i];
      const d = Math.floor(value / 45);
      const c = value % 45;
      output += BASE45_CHARS[c] + BASE45_CHARS[d];
    }
  }
  return output;
}

// Base45 디코딩 함수
function base45Decode(input) {
  const BASE45_CHARS = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:';
  const BASE45_MAP = {};
  for (let i = 0; i < BASE45_CHARS.length; i++) {
    BASE45_MAP[BASE45_CHARS[i]] = i;
  }

  let outputBytes = [];
  for (let i = 0; i < input.length; i += 3) {
    if (i + 2 < input.length) {
       // 3개의 Base45 문자 처리 -> 2바이트
      const c = BASE45_MAP[input[i]];
      const d = BASE45_MAP[input[i+1]];
      const e = BASE45_MAP[input[i+2]];
       if (c === undefined || d === undefined || e === undefined) {
         throw new Error("Invalid Base45 character");
       }
      const value = c + d * 45 + e * 45 * 45;
       if (value > 65535) { // 0xFFFF
            throw new Error("Invalid Base45 sequence (3 chars)");
        }
      outputBytes.push(value >> 8); // 상위 바이트
      outputBytes.push(value & 0xFF); // 하위 바이트
    } else if (i + 1 < input.length) {
      // 2개의 Base45 문자 처리 -> 1바이트
      const c = BASE45_MAP[input[i]];
      const d = BASE45_MAP[input[i+1]];
      if (c === undefined || d === undefined) {
          throw new Error("Invalid Base45 character");
      }
      const value = c + d * 45;
       if (value > 255) {
            throw new Error("Invalid Base45 sequence (2 chars)");
        }
      outputBytes.push(value);
    } else {
        // 입력 길이가 3 또는 2의 배수가 아닌 경우 오류
         if (input.length % 3 === 1) {
             throw new Error("Invalid Base45 input length");
         }
         // 길이가 0이거나 3의 배수, 2의 배수이면 정상 종료
    }
  }
  return bytesToUtf8String(new Uint8Array(outputBytes));
}

// Base58 관련 상수 및 헬퍼 함수
const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const BASE58_MAP = {};
for (let i = 0; i < BASE58_ALPHABET.length; i++) {
    BASE58_MAP[BASE58_ALPHABET[i]] = BigInt(i);
}
const BASE = BigInt(58);

// 문자열을 Uint8Array로 변환 (UTF-8 기준)
function stringToUint8Array(str) {
  return utf8StringToBytes(str);
}

// Base58 인코딩 함수 (입력: Uint8Array)
function base58Encode(buffer) {
    if (!buffer || buffer.length === 0) {
        return '';
    }

    let num = BigInt(0);
    // 바이트 배열을 BigInt로 변환
    for (let i = 0; i < buffer.length; i++) {
        num = (num * BigInt(256)) + BigInt(buffer[i]);
    }

    let encoded = '';
    // BigInt를 58로 나누면서 나머지로 Base58 문자 생성
    while (num > 0) {
        const remainder = num % BASE;
        num = num / BASE;
        encoded = BASE58_ALPHABET[Number(remainder)] + encoded;
    }

    // 원본 데이터의 선행 0 바이트 처리 (Base58에서는 '1'로 표현)
    for (let i = 0; i < buffer.length && buffer[i] === 0; i++) {
        encoded = BASE58_ALPHABET[0] + encoded;
    }

    return encoded;
}

// Base58 디코딩 함수 (입력: Base58 문자열, 출력: Uint8Array)
function base58Decode(encoded) {
    if (!encoded || encoded.length === 0) {
        return new Uint8Array(0);
    }

    let num = BigInt(0);
    let leadingZeros = 0;
    // Base58 문자열을 BigInt로 변환
    for (let i = 0; i < encoded.length; i++) {
        const char = encoded[i];
        const value = BASE58_MAP[char];

        if (value === undefined) {
            throw new Error('Invalid Base58 character: ' + char);
        }

        // 선행 '1' 개수 카운트 (0 바이트 개수)
        if (value === BigInt(0) && num === BigInt(0) && leadingZeros === i) {
            leadingZeros++;
        }

        num = (num * BASE) + value;
    }

    // BigInt를 바이트 배열로 변환
    const bytes = [];
    while (num > 0) {
        bytes.unshift(Number(num % BigInt(256))); // BigInt를 Number로 변환 시 주의 필요하나, 256 미만이므로 안전
        num = num / BigInt(256);
    }

    // 선행 0 바이트 추가
    for (let i = 0; i < leadingZeros; i++) {
        bytes.unshift(0);
    }

    return new Uint8Array(bytes);
}
