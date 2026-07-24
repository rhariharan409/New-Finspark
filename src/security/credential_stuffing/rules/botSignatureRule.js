/**
 * Rule R5: Bot Signature Detection
 * Checks if the User-Agent header matches known automation tool patterns or is missing/whitespace.
 */

const KNOWN_BOT_PATTERNS = [
  'python-requests',
  'python-urllib',
  'curl/',
  'wget/',
  'httpie/',
  'go-http-client',
  'java/',
  'okhttp',
  'headlesschrome',
  'phantomjs',
  'selenium',
  'puppeteer',
  'playwright',
  'scrapy',
  'bot',
  'crawler',
  'spider'
];

export function checkBotSignature(userAgent = null) {
  // 1. Missing / null / empty / whitespace UA
  if (!userAgent || typeof userAgent !== 'string' || userAgent.trim() === '') {
    const reason = 'Bot signature detected: User-Agent header is missing';
    const evidence = {
      rule: 'bot_signature',
      user_agent: null,
      confidence: 'low'
    };

    return {
      score_contribution: 15.0,
      reason,
      evidence
    };
  }

  // 2. Check substrings
  const uaLower = userAgent.toLowerCase();
  const matchedPattern = KNOWN_BOT_PATTERNS.find(pattern => uaLower.includes(pattern));

  if (matchedPattern) {
    const reason = `Bot signature detected: User-Agent '${userAgent}' matches known automation tool pattern`;
    const evidence = {
      rule: 'bot_signature',
      user_agent: userAgent,
      matched_pattern: matchedPattern,
      confidence: 'low'
    };

    return {
      score_contribution: 15.0,
      reason,
      evidence
    };
  }

  return {
    score_contribution: 0.0,
    reason: null,
    evidence: {}
  };
}
