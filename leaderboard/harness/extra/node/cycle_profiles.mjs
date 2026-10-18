// CycleTLS has no named browser profiles: the README's documented Chrome and Firefox examples, verbatim.
// Shared by bench.mjs (echo endpoint) and probe.mjs (behaviour probe).
export const CYCLE = {
  chrome: { // README "Chrome JA4R fingerprint" + README HTTP/2 table "Chrome" + README Chrome UserAgent
    ja4r: "t13d1516h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0000,0005,000a,000b,000d,0012,0017,001b,0023,002b,002d,0033,44cd,fe0d,ff01_0403,0804,0401,0503,0805,0501,0806,0601",
    http2Fingerprint: "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p",
    userAgent: "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
  },
  firefox: { // README "Firefox HTTP/2 fingerprint" example
    http2Fingerprint: "1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s",
    ja3: "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-51-57-47-53-10,0-23-65281-10-11-35-16-5-51-43-13-45-28-21,29-23-24-25-256-257,0",
    userAgent: "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:141.0) Gecko/20100101 Firefox/141.0",
  },
};
