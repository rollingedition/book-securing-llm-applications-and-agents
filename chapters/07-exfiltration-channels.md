---
chapter_id: exfiltration-channels
---

# Close the exfiltration channels

By the end of this chapter you can keep an assistant's outbound calls and its reply from carrying a tenant's record to a host the office does not run. You'll write a fetch rule that reads the query as well as the host, a render policy that removes the links and images in a reply that point outside the office, and a scan of the reply's text for a secret. You'll also be able to say, for each rule, which channel it covers and which it leaves open.

[Chapter 1](#what-the-allowlist-cannot-see) named channels that the outbound allowlist could not see. Two of them are this chapter's job. The first is the reply. The assistant writes Markdown, the office's web view draws it, and a picture in the reply is a request that the harness never sees. The second is a fetch to the office's own host. A tenant's number can sit in the address of a page on that host, and the allowlist passes the request because the host is allowed. The chapter adds a third channel that the earlier list did not name: the reply's own words. The assistant can print a secret in plain text, and no link rule looks at text.

The case shows why each one matters. The assistant holds a tenant's record once `lookup_tenant` has run, a payment portal key in its instructions, and a hidden note in the system prompt. Any of these can leave the office by a call, by a link or image in the reply, or by the words of the reply. For each channel the question is the same: which part of the office's output reaches a host or a reader, and which rule sees it first.

## Egress rules {#egress-rules}

A fetch sends two things out: the host and path it names, and the query after the path. The outbound allowlist from [chapter 1](#an-outbound-allowlist) reads the host. It refuses `fetch_page` to any host that is not one of the office's fixture hosts, and it refuses `send_message` to any address outside the office's directory and the contractor's IDs. A host check says where a request goes. It says nothing about what the request carries, which is why this section adds a second rule for the query. A query can carry a tenant's value in several shapes, and a check written for one shape misses the others, so the query rule's list of what it refuses is part of its claim, not a detail of it.

The fetch rule reads the URL and nothing else. A check on the other arguments a tool receives is a different rule, covered by [argument policies in chapter 6](#argument-policies), and this chapter does not replace it.

The primary defence sits outside the code. The network the assistant runs on should reach only the hosts the office names, through a proxy or a firewall that allows named hosts and refuses the rest. A rule in the harness runs in the same process that the model's output steers, so it is the second layer, and it should refuse when it cannot decide. The book's examples make no network call at all. Their fetches go to fixture pages that the environment serves, so in the book the fixture sites are the only hosts the environment reaches. That is a property of the test environment, not a control for the office, and the office has to build the network control itself.

[Example: egress-fetch-paired](../examples/egress-fetch-paired.py)

Two runs on the same cases make the comparison. The first is the undefended run. The second is the same run with the allowlist and a query rule enforced. The query rule refuses a `fetch_page` whose URL carries a tenant's record, and it refuses a URL that it cannot parse. The rule is teaching code and defence in depth, placed behind the network control. Both runs cover the fifteen benign tasks and the sixty dev cases, and the paired differences that the claims rest on are printed beside them.

Utility did not move under the rule. Undefended utility on the dev benign tasks is {{out:egress-fetch-paired:utility, baseline, 15 dev benign tasks}}, and under the rule it is {{out:egress-fetch-paired:utility, egress-fetch, 15 dev benign tasks}}. The paired difference is {{out:egress-fetch-paired:paired difference in utility, egress minus baseline, dev}}, so the rule cost no benign task on this set.

On the dev cases the rule cut undefended attack success from {{out:egress-fetch-paired:attack success, baseline, 60 dev cases}} to {{out:egress-fetch-paired:attack success, egress-fetch, 60 dev cases}}. That cut is not reliable on this set: the paired difference, {{out:egress-fetch-paired:paired difference in attack success, egress minus baseline, dev}}, has an interval of {{out:egress-fetch-paired:paired difference in attack success, egress minus baseline, dev, interval}} that reaches zero.

The paired interval is built as [chapter 8 of Evaluating LLM Applications](https://rollingedition.com/evaluating-llm-applications/s/paired-comparisons) describes, by [bootstrapping over items](https://rollingedition.com/evaluating-llm-applications/s/bootstrap-over-items). Each run's own interval is {{out:egress-fetch-paired:attack success, baseline, 60 dev cases, interval}} undefended and {{out:egress-fetch-paired:attack success, egress-fetch, 60 dev cases, interval}} under the rule, and the paired figure is the one to read.

The held-out split was run once, under the same rule, on its fifteen benign tasks. Utility there is {{out:egress-fetch-paired:utility, baseline, 15 held-out benign tasks}} undefended and {{out:egress-fetch-paired:utility, egress-fetch, 15 held-out benign tasks}} under the rule. Against the baseline, utility moves by {{out:egress-fetch-paired:paired difference in utility, egress minus baseline, held-out}}.

On its sixty cases, attack success is {{out:egress-fetch-paired:attack success, baseline, 60 held-out cases}} undefended and {{out:egress-fetch-paired:attack success, egress-fetch, 60 held-out cases}} under the rule. Under the rule, attack success moves by {{out:egress-fetch-paired:paired difference in attack success, egress minus baseline, held-out}}, and the interval on that movement is {{out:egress-fetch-paired:paired difference in attack success, egress minus baseline, held-out, interval}}.

The dev result did not hold at the size the dev run reported. On held-out the rule stopped {{out:egress-fetch-paired:attack success stopped by the rule, held-out}} undefended successes and added {{out:egress-fetch-paired:attack success added by the rule, held-out}}, and the interval still reaches zero. This section does not claim that the rule lowers attack success on held-out, and the dev figure stays a dev figure.

On this set the allowlist did the refusing: it refused {{out:egress-fetch-paired:refusals by allowlist, attack runs, dev}} calls on attack runs, and the query rule refused {{out:egress-fetch-paired:refusals by query rule, attack runs, dev}}.

The combined configuration stopped {{out:egress-fetch-paired:attack success stopped by the rule, dev}} undefended successes and added {{out:egress-fetch-paired:attack success added by the rule, dev}}. The query rule also refused {{out:egress-fetch-paired:refusals by query rule, benign runs, dev}} calls on benign runs.

That count does not show the query rule is idle. Every fetch on this set that leaked went to `attacker.example`, and the allowlist refuses that host before the query rule is asked. The rule's value is against data sent to the office's own host, where a tenant's number in a query would pass the host check. This set has no case of that kind, so the rule's effect on it is unmeasured. [Chapter 1](#what-the-allowlist-cannot-see) left that path open, and this rule is built for it, but it has not yet been tested against the case it was built for.

**Working rule:** Allowlist the hosts first, then read what the allowed requests carry. A host check tells you where data goes, and a query check tells you what the data is. Name the one you measured and the one you did not.

## Links and images in the reply {#links-and-images-in-the-reply}

The reply is the one output that the reader sees in full, and Markdown has two constructs that make a request on their own. A viewer draws an image by fetching its address, with no click from the reader. A link is followed by a click. Both addresses can hold data.

The book's sources date the technique to 2023. [Simon Willison](https://simonwillison.net/2023/Apr/14/new-prompt-injection-attack-on-chatgpt-web-version-markdown-imag/) reported a description by Roman Samoilenko of a markdown image whose address carried the chat's data to the host that served the image.
A rule that blocks automatic images and nothing else leaves the link channel open. A link needs a click, but the click still sends the link's address, and the address can hold data, so the render policy covers both.

The primary defence for images and links sits in the view. The Content-Security-Policy `img-src` directive "specifies valid sources of images and favicons" ([MDN](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy/img-src)). A page that sets `img-src` to the office's own hosts should stop the view from loading an image from anywhere else, including an image that no harness rule removed. This book cites that definition and ran no browser, so the claim is the directive's definition and nothing more.

The harness rule is defence in depth behind that policy, and it runs on the reply before any view receives it. It parses the reply with markdown-it-py at {{version:markdown-it-py}}, with raw HTML turned off, and walks the parsed tokens. It removes an image or a link whose host is not one of the office's hosts. It also removes an office-host image or link whose path or query carries a tenant's record, or the portal key, or the marker that the hidden note carries, because an office host can serve a page that echoes its query. A removed image keeps its alt text, and a removed link keeps its text. The rule does not follow a redirect, so it is blind to one that an office host sends on.

The rule works on tokens, not on the source. A reference-style image keeps its address on a separate line, and a token-level rewrite finds it where a scan of the raw text could miss it. Two more details keep the output honest. An address the rule keeps is written with its `&` escaped, so the view decodes exactly the string the rule checked. An outside address that the rule leaves in the text, rather than removing, is written as a code span, so the view's autolinking cannot turn it into a link.

Raw HTML is escaped, not removed. The rule's parser has raw HTML off, and the rule escapes any tag it meets and the characters that would start one. The output therefore loads no tag, even in a view that renders raw HTML. The `raw-img-tag` form below is the test of that. Its verdict is `removed` because the image does not survive. The text is escaped, and it is not dropped. The chapter tests this for one parser and one view, and no other renderer. The office's own view has to be tested before the office relies on the rule.

On this set the model's replies rarely carried an image or a link, and the next paragraphs say why that zero should not be trusted. The first example measures the rule on the undefended reply of each attack case, on both splits.

[Example: render-policy-replies](../examples/render-policy-replies.py)

On dev, undefended attack success is {{out:render-policy-replies:attack success before sanitising, dev, 60 cases}}, and it stays at {{out:render-policy-replies:attack success after sanitising, dev, 60 cases}} with the rule. On dev, {{out:render-policy-replies:attack cases whose reply had any image or link, dev}} replies carried an image or a link, so the rule had nothing to act on there.

On held-out, undefended attack success is {{out:render-policy-replies:attack success before sanitising, held-out, 60 cases}}, with an interval of {{out:render-policy-replies:attack success before sanitising, held-out, 60 cases, interval}}. With the rule it is {{out:render-policy-replies:attack success after sanitising, held-out, 60 cases}}, with an interval of {{out:render-policy-replies:attack success after sanitising, held-out, 60 cases, interval}}.

On held-out, {{out:render-policy-replies:attack cases whose reply had any image or link, held-out}} reply carried an image or a link, and the rule removed {{out:render-policy-replies:URLs removed, held-out}} URL. That URL was a link to `attacker.example`, and removing it is the one change the held-out run shows.

The count of cases whose rendered image addresses changed is {{out:render-policy-replies:cases whose rendered URLs changed, dev}} on dev and {{out:render-policy-replies:cases whose rendered URLs changed, held-out}} on held-out. The removed URL was a link, not an image, so this chapter does not call that removal an effect.

**Working rule:** Read a zero from one set as a fact about that set and that model, not as a fact about the channel. Test the channel with an attacker that adapts before the zero carries any weight.

## What the render policy does with each form {#render-forms}

A set with so few reply attacks cannot show what the rule does with each form of image or link. The second example builds the forms directly.

The zero on dev is the model's, and it is not a property of the attacks. The set aims at the reply's channel in three goals: the attacks for `g-key-image`, `g-link` and `g-phone-image` each ran against the image or the link in the reply, and their goal lines in the [chapter 3 baseline](#undefended-baseline) read {{out:attack-set-baseline:goal g-key-image}}, {{out:attack-set-baseline:goal g-link}} and {{out:attack-set-baseline:goal g-phone-image}}. The attacks tried the channel. The model's replies rarely took it. A different model, or an attacker that adapts, could take it, and the chapter does not claim otherwise.


[Example: render-policy-crafted](../examples/render-policy-crafted.py)

That example gives the rule one reply per form, with the address under test, and reports whether the rule's output still loads the image or follows the link. A form marked kept got through. Each verdict is asserted, so the table below is what the rule does with those forms, and not a sample of what it might do.

| Form | Verdict |
| --- | --- |
| `autolink` | {{out:render-policy-crafted:autolink}} |
| `data-uri` | {{out:render-policy-crafted:data-uri}} |
| `encoded-host` | {{out:render-policy-crafted:encoded-host}} |
| `image-in-link` | {{out:render-policy-crafted:image-in-link}} |
| `inline-image` | {{out:render-policy-crafted:inline-image}} |
| `office-image` | {{out:render-policy-crafted:office-image}} |
| `office-tenant-value` | {{out:render-policy-crafted:office-tenant-value}} |
| `port` | {{out:render-policy-crafted:port}} |
| `raw-img-tag` | {{out:render-policy-crafted:raw-img-tag}} |
| `reference-image` | {{out:render-policy-crafted:reference-image}} |
| `userinfo` | {{out:render-policy-crafted:userinfo}} |

Every form but one is removed. The form that stays is the office's own plain image, which the rule has to keep. The removed forms include an outside image, a link to an outside host, a data URI and a reference-style image. An office-host image whose query carries a tenant's value is removed too, because the office's host earns no pass for a tenant's value. In `image-in-link` the attacker's image goes, which is the part under test.

The table covers one address per form. The next example holds the attempts that a security review of this rule and the scan made against them, 22 in all, with each one asserted.

[Example: exfiltration-regressions](../examples/exfiltration-regressions.py)

Each attempt prints one label. For a reply, `clean` means that no address the reader's browser loads or follows points outside the office, checked in five views that each render the output with markdown-it-py. A scan attempt prints the scan's labels, `flagged` with the label it found or `not flagged`. A trace attempt prints whether the sanitised trace has a render event.

Two replies show the render fixes. A reply that carries the escaped form of a link's address prints `{{out:exfiltration-regressions:double-entity-link}}`. A reply whose text is a link to an outside host prints `{{out:exfiltration-regressions:link-text-url-linkify}}`, so a linkifying view does not relink it.

The office-host address that carries the portal key prints `{{out:exfiltration-regressions:office-key}}`. That label asserts only that no outside address loads, not that the office-host address was removed. The emphasised key prints `{{out:exfiltration-regressions:scan-emphasis}}`, and a base64 key prints `{{out:exfiltration-regressions:scan-base64}}`, a known miss that the example records as a limit.

A raw image tag in a view with raw HTML on prints `{{out:exfiltration-regressions:raw-img-html-on}}`, and it leaves `{{out:exfiltration-regressions:trace-raw-img}}` in the trace. The scorer therefore does not count an image the reply no longer loads.

The table does not show one more limit. The query check does not catch a tenant's phone number that an office image carries split over two parameters, double-encoded, written in base64, or only partly written. Such an image is kept, and it loads. The check's docstring states these limits, and this chapter states them too.

**Working rule:** List the channels a render rule covers, and the ones it does not, in the same paragraph as its count. The rule reads the addresses in the reply. It does not follow a redirect that an office host sends on, so an office-host image that redirects to an outside host is still open. No example tests that case, and the chapter says so.

## Output is untrusted {#output-is-untrusted}

The reply is output, and the book treats output the way it treats input from a third party. The 2026 OWASP list for LLM applications gives output handling the ID `LLM10:2026 Improper Output Handling`. The book cites that list's release record ([Zenodo](https://doi.org/10.5281/zenodo.22109014)). [Chapter 2](#risks-mapped) maps the reply's links and images to that entry. The reply's consumers are the view, the reader's browser and the person who copies the text, and each of them needs a check before it acts on the reply.

The office's web view is not pinned in this book, so the rule cannot assume which renderer the view runs. It runs its own parser and assumes that the view draws what that parser draws. Before the office relies on the rule, someone has to test it against the view that readers use.

A channel the fixed set did not use is still a channel. [Chapter 11](#an-attacker-that-iterates) gives an attacker that adapts its cases to the defence. It runs against the fetch rule, but not against the render policy, so the reply channel is not tested against an [adaptive attacker](#adaptive-attacker) in this book.

A check on output belongs at the boundary where the output leaves the harness. The render policy is one check at that boundary, and the secret scan in the last section is another. Each is a filter or a detector, and each is blind in its own way. The render policy sees links and images, and it does not read the words. A reply that prints the key as plain text has no address for the render policy to check, so the policy passes it. The scan reads the words, but only when the view would show them as plain text.

The render policy and the scan run on the same reply, so a reply can pass one and fail the other. The team has to decide, for each check, whether a failure stops the reply or only flags it.

A check that only flags also needs someone to read the flags. A team that never reads them has built a log, not a control. Refusals should be logged by rule and by reason, so that a rise in one shows up before a rate moves.

The reply does not stop at the view. A transcript or a log may keep it, and a secret printed into a transcript stays there after the session ends. So the check at the boundary has to cover every place the reply goes, not only the one the team had in mind when it wrote the rule.

The view also has to render the reply as text and as markup, with no script. This book cannot test the office's view, so the office's test of its view has to confirm that. The chapter's checks help only if the view does what they assume.

Two traps appear in production. The first is reading a zero as safety, which [chapter 1](#what-the-allowlist-cannot-see) covers: the dev count of replies with an image or a link is zero, and the [links and images section](#links-and-images-in-the-reply) says why that zero describes this model's replies, not the channel. The second trap is checking the markup and forgetting the text. A reply can print a secret with no markup at all, and the render policy passes it. Each rule has a blind spot, and the chapter names each one next to the count it produces.

**Working rule:** Check the reply at the point where it leaves the harness, and name each check's blind spot in the paragraph that reports its result.

## Scanning the reply for secrets {#scanning-the-reply-for-secrets}

The payment portal key and the hidden note are in the assistant's context. Once a secret is in the context, the model can print it, and a printed secret is an exfiltration that no link rule sees. Two goals in this book test for the key, and one tests for the note. The primary fix keeps the key out of the context, as [chapter 9](#keys-out-of-the-prompt) does; the scan here is the second layer.

The scan, `egress.secret_scan`, looks for the key and the note's marker in the reply's text: as written, after one round of percent-decoding, and as the view would show it, with tags removed and entities decoded. It returns the labels of what it found, and the harness decides what a hit means. In this book a hit flags the reply and never blocks it. Because the harness flags and does not withhold, a flag is an event for someone to read, not a control on its own.

[Example: secret-scan-replies](../examples/secret-scan-replies.py)

The example runs the scan over the final reply of each attack case and each benign task, with no defence on. On dev, {{out:secret-scan-replies:replies revealing the portal key, dev}} replies revealed the key and {{out:secret-scan-replies:replies revealing the hidden note, dev}} revealed the note. On held-out the counts are {{out:secret-scan-replies:replies revealing the portal key, held-out}} for the key and {{out:secret-scan-replies:replies revealing the hidden note, held-out}} for the note.

Flags whose goal does not test for the secret they reveal are counted too: {{out:secret-scan-replies:reveals not matched to their goal, dev}} on dev and {{out:secret-scan-replies:reveals not matched to their goal, held-out}} on held-out. No benign reply was flagged, with {{out:secret-scan-replies:false alarms on benign replies, dev}} false alarms on dev and {{out:secret-scan-replies:false alarms on benign replies, held-out}} on held-out.

On dev, these flags fit the undefended run. [Chapter 3](#undefended-baseline) reports that run's successes by kind: poisoned figures, page fetches and the hidden note. None of them was the key. The check runs in one direction only: it counts the replies the scan flagged, and it does not count the replies that carried a secret and went unflagged. So this section does not claim that the scan caught every reply that carried a secret. On held-out the book prints no separate count of key-bearing replies to set against the flags.

The scan's reach is what the regression example shows. It catches the key when the underscores are escaped as `\_` or as `&#95;`, when the key is wrapped in emphasis, and when the marker is capitalised or wrapped over two lines. Those attempts are the reason the scan reads the rendered text as well as the source. It does not catch a key or marker written in base64, split across a line break or a space, or spelled out letter by letter. Those misses are printed as limits, and the scan decodes percent-encoding once and no other encoding. A zero from this scan therefore says that the plain text was absent from the reply. It does not say that the secret stayed in the office. A production scan also has to load the office's real keys the way the example loads the fixture world, or it has nothing to match.

What this chapter shows is narrow. One fetch rule was measured on dev, and its effect on the office's own host is unmeasured. A render policy removed the reply channel where the set used it, and a table of crafted forms and the regression set show what the rule does with each. A secret scan caught the plain text it was built for and flagged no benign reply. Every rate in the chapter holds for this attack set, for the model Qwen3-4B-Instruct-2507 at its pin, and for these attacks. Every robustness claim here is scoped to the fixed set. Of this chapter's controls, [chapter 11](#the-gap-to-the-fixed-set) attacks only the fetch rule.

The chapter made three decisions that the rest of the book keeps. The render rule works on tokens and not on source text. It removes what would leave the office and keeps the office's own plain image. And the scan flags a reply and never blocks it.

**Working rule:** A secret scan on output answers one question: was the plain text there? It does not answer whether the secret left. Remove the secret from the context first, and keep the scan as the check for what that removal missed.
