module FeedbacksHelper
  # Intentionally incomplete filter (harder XSS, still solvable for CTF)
  # - Drops <script> and <iframe> blocks
  # - Removes ALL inline handlers except 'onbegin' (left as the intended vector)
  # - Scrubs javascript: URIs and risky attributes (style, srcdoc, formaction, href variants)
  # - Blacklists common dangerous words/tokens to raise difficulty (still bypassable via obfuscation)
  # Competitors must leverage SVG animation with onbegin to execute and webhook exfiltrate the flag.
  def naive_filter(html)
    s = html.to_s.dup

    # Drop script and iframe blocks entirely
    s.gsub!(%r{</?script[^>]*>}i, "")
    s.gsub!(%r{<iframe[^>]*>.*?</iframe>}im, "")

    # Remove any inline event handlers EXCEPT 'onbegin'
    # e.g. onclick=..., onerror=..., onload=... are removed; onbegin=... is preserved
    s.gsub!(%r{\son(?!begin)[a-z0-9_-]*\s*=\s*("[^"]*"|'[^']*'|[^\s>]+)}i, "")

    # Remove risky attributes commonly abused
    s.gsub!(%r{\sstyle\s*=\s*("[^"]*"|'[^']*'|[^\s>]+)}i, "")
    s.gsub!(%r{\ssrcdoc\s*=\s*("[^"]*"|'[^']*'|[^\s>]+)}i, "")
    s.gsub!(%r{\sformaction\s*=\s*("[^"]*"|'[^']*'|[^\s>]+)}i, "")
    s.gsub!(%r{\s(?:href|xlink:href)\s*=\s*("[^"]*"|'[^']*'|[^\s>]+)}i, "")

    # Neutralize javascript: protocol
    s.gsub!(/javascript\s*:/i, "#")

    # Word blacklist to make exploitation harder (bypass via entities/comments/zero-width chars)
    words = %w[
      animate img image object embed base meta link style onerror onload onclick onmouseover onfocus
      onanimationstart srcdoc xlink:href href data: base64 alert prompt confirm eval hook webhook requestbin interactsh collaborator burp oast dnslog
      document window location fetch sendBeacon beacon navigator XMLHttpRequest new fromCharCode constructor Function string String concat http https
    ]
    pattern = Regexp.union(words.map { |w| /(?<![a-z0-9:])#{Regexp.escape(w)}(?![a-z0-9:])/i })
    s.gsub!(pattern, "")

    # Remove string concatenation with '+' to force encoded/property access tricks
    s.gsub!("+", "")

    # Disallow backticks to avoid template literals
    s.gsub!("`", "")

    s
  end
end
