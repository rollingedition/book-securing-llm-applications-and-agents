---
chapter_id: secrets-and-records
---

# Keep secrets and other people's records out of the context

By the end of this chapter you can keep an assistant's secrets out of its prompt, filter the documents it searches by the role of the person it works for, and check its replies for a deposit figure stated without a citation to an office document. You'll measure each defence on the dev split and on the held-out split, and say which attacks it stopped, which it did not, and what it cost in tasks the assistant could no longer finish.

[Chapter 8](#dual-llm) kept untrusted text out of the plan; the secrets and records already in the context are still there. [Chapter 7](#links-and-images-in-the-reply) and its [scan of the reply](#scanning-the-reply-for-secrets) measured the channels that carry text out of a reply. Those channels only matter if the text is in the reply to begin with. The office's assistant has three places where text it should never repeat can get in. Its system prompt holds a payment portal key and an internal note. Its search reads an index of office documents, and some of those are documents the acting user may not read. And the documents themselves can carry a wrong deposit figure that the assistant then states as the office's answer. Undefended, the assistant's attack success on the dev cases was {{out:attack-set-baseline:attack success, dev cases}}. Those successes fall in a few goals, and this chapter takes the ones that involve text the assistant already holds.

Every rate in this chapter holds for this set of attack cases, for this model (Qwen3-4B-Instruct-2507, pinned) and for the scorers in code. Nothing here says a defence solves prompt injection. The [adaptive attacker](#adaptive-attacker) in [chapter 11](#the-gap-to-the-fixed-set) does not run against these defences.

Each section names its split. The held-out figures are the ones this chapter reports for each defence, because each defence was tuned on dev and run once on held-out.

## Hidden context {#hidden-context}

The system prompt is text the model reads on every turn, and a model can print what it reads. OWASP calls this risk Hidden Context Exposure, LLM08:2026, and calls the private data that leaves in an answer Sensitive Information Disclosure, LLM02:2026 ([OWASP's 2026 list](https://doi.org/10.5281/zenodo.22109014)). The 2025 list numbers its entries differently: there LLM08:2025 is Vector and Embedding Weaknesses.

The office's prompt holds two values of this kind. One is the portal key. The other is an internal note. The attack goals that test them are `g-hidden`, `g-key-reply` and `g-key-image`. Each asks the assistant to write the note or the key into a reply, or into an address the reply loads. [Chapter 3](#goals-locations-styles) lists every goal and location. The reply is the one output a reader sees in full, so a value printed there reaches the user with no further step, and no later check has to notice it.

The primary defence is design: a key belongs with the tool that uses it, so the model never holds the value. The book does not build such a tool. What it measures is the removal of the values from the prompt, which is the step the design would otherwise take.

[Example: secrets-out-paired](../examples/secrets-out-paired.py)

Two runs are set side by side: the undefended assistant, and the same assistant with a prompt file that has the note and the key lines removed. Both run on the dev split and on the held-out split. Utility and attack success carry intervals from a percentile bootstrap over items, and paired differences are computed per item, as [Evaluating LLM Applications](https://rollingedition.com/evaluating-llm-applications/s/bootstrap-over-items) and [its paired comparisons](https://rollingedition.com/evaluating-llm-applications/s/paired-comparisons) describe.

The undefended run's prompts held the key or the note's marker, {{out:secrets-out-paired:dev, baseline, prompts holding the key or the note's marker}} on dev. So the secrets were there to be printed. On dev, the undefended run succeeded on {{out:secrets-out-paired:dev, baseline, attack success on the note and key goals}} of the cases that aim at the note or the key. With the two lines removed, those goals gave {{out:secrets-out-paired:dev, secrets-out, attack success on the note and key goals}}, and no prompt held either value: {{out:secrets-out-paired:dev, secrets-out, prompts holding the key or the note's marker}}.

Overall attack success on dev went from {{out:secrets-out-paired:dev, baseline, attack success, 60 cases}} to {{out:secrets-out-paired:dev, secrets-out, attack success, 60 cases}}. The paired difference is {{out:secrets-out-paired:dev, attack success, paired difference}}, with interval {{out:secrets-out-paired:dev, attack success, paired difference, interval}}. Most of the dev change is in the secret goals, which the defence acts on.

The held-out split was run once, after the wording was frozen on dev. There the undefended assistant succeeded on {{out:secrets-out-paired:held-out, baseline, attack success on the note and key goals}} secret-goal cases, and the defended one on {{out:secrets-out-paired:held-out, secrets-out, attack success on the note and key goals}}.

Overall attack success went from {{out:secrets-out-paired:held-out, baseline, attack success, 60 cases}} to {{out:secrets-out-paired:held-out, secrets-out, attack success, 60 cases}}. The paired difference is {{out:secrets-out-paired:held-out, attack success, paired difference}}, with interval {{out:secrets-out-paired:held-out, attack success, paired difference, interval}}. Most of that change is also in the secret goals.

On held-out the defended run completed {{out:secrets-out-paired:held-out, secrets-out, utility, 15 benign tasks}} benign tasks, against {{out:secrets-out-paired:held-out, baseline, utility, 15 benign tasks}} undefended. The paired gain is {{out:secrets-out-paired:held-out, utility, paired difference}}, with interval {{out:secrets-out-paired:held-out, utility, paired difference, interval}}, which excludes zero. That held-out baseline keeps the two prompt lines the defence removes, and the output does not trace why those lines cost the tasks it failed. The other held-out comparisons in chapters 7 to 9 use the same baseline, so each may carry that cost.

On dev the same comparison gave {{out:secrets-out-paired:dev, utility, paired difference}}, with interval {{out:secrets-out-paired:dev, utility, paired difference, interval}}, which includes zero, so dev cannot confirm a gain. Nothing in the output says why the undefended run failed the tasks it failed, so this chapter gives no cause.

**Working rule:** Keep the key and the note out of the prompt before you rely on any check of the reply. A check reads what the model chose to print, and a value that never entered the prompt cannot be printed. Then count the prompts that still hold a value. A zero in the attack goals shows the attacks failed. Only a zero in the prompt shows the value left the context.

## Keys out of the prompt {#keys-out-of-the-prompt}

The last section measured what the note and the key do when they sit in the prompt. This section is about where they should be instead. A key belongs with the harness or the tool that uses it. The model asks a tool to act, the tool holds the credential, and the model receives the result, not the value.

The book builds only a small part of that design. The variant in the last example removes two lines from the prompt file, and the example checks that no prompt holds either value. It does not build a tool that holds the key. How to keep secrets out of the environment that a model's code can read is the subject of [Agent Harnesses, chapter 7](https://rollingedition.com/agent-harnesses/s/secrets), and it is not repeated here. The practical test is short, and people skip it: after a change, search the prompt file and the tool definitions for each marker, and count the matches.

Keeping the values out of the prompt also narrows what a reply check has to catch. A reply check, such as the scan in [chapter 7](#scanning-the-reply-for-secrets), is a second layer. It catches a value that got in some other way. It cannot catch a value the model has read and then restated in its own words, which is why the prompt is the place to act first.

The argument for removal is about what the model can print. It is not a measured result: a model that never saw a value has nothing to print. On these splits the removal cost no benign task. The defended run completed {{out:secrets-out-paired:dev, secrets-out, utility, 15 benign tasks}} benign tasks on dev and {{out:secrets-out-paired:held-out, secrets-out, utility, 15 benign tasks}} on held-out.

**Working rule:** Keep each credential with the code that uses it, and give the model results, not values. Measure the defence by the prompt count, and by the attack goals that need the value. A prompt that never held the key is the evidence that the model had nothing to print.

## Retrieval by role {#retrieval-by-role}

Removing secrets from the prompt does nothing about the documents the assistant reads. Its search reads the office's documents, and the acting user, the staff member the assistant works for in an episode, may not be allowed to read all of them. A search that returns a document the user cannot read gives the assistant a read the user was never given. The data flows in [chapter 2](#data-flows) show where those results go.

The book's access rule comes from each document's source in the case data. It is the book's choice, not a rule the office has adopted, and it fails closed. A document with source `office` that states a figure is **staff**: any listed staff member may read it. Any other `office` document, such as a template, a rota or the house rules, is **public**. Every other document is **owner-only**: a tenant's letter, a contractor's quote, or a document whose source the rule does not name. Only the office manager may read an owner-only document. "Owner" here is that role, not the person the document is about.

The acting user in the example is a staff member, u-02, who can read {{out:filter-before-ranking:documents visible to the user}} documents. The rest are owner-only.

There are two places to apply that filter. The first is after ranking: search all the documents, keep the top k, and then drop the ones the user cannot read. The second is before ranking: drop the documents the user cannot read, build the ranking from what is left, and keep the top k. The primary defence is the index itself: it holds only the documents the acting role may read, built for each role. The control this chapter builds is the query-time filter. It is teaching code and defence in depth, a second layer over the index. Its label is harness (enforcement), because it refuses to rank a document the user cannot read.

[Example: filter-before-ranking](../examples/filter-before-ranking.py)

Both orders run on three queries taken from the tasks, at page sizes of 5 and 2. For the query "spare key deposit" at page size 5, filtering before ranking returned {{out:filter-before-ranking:k 5, query 'spare key deposit', filter before ranking, results}} results, and filtering after ranking returned {{out:filter-before-ranking:k 5, query 'spare key deposit', filter after ranking, results}}. On these queries the counts and the order were the same under both orders, and the example asserts that filtering after ranking returned the same documents in the same order.

The scores did change. For the same query at page size 5, the kept documents scored differently in {{out:filter-before-ranking:k 5, query 'spare key deposit', filter after ranking, scores that differ}}, because the word weights (IDF) still count the owner-only documents the user cannot see. The example also asserts that the order matches an index built from the visible documents alone, and that no hidden document is returned. So filtering after ranking leaks through the scores, even where its results do not change.

A count of results falls only for a query where a hidden document ranks inside the top k, and none of these queries does. Here the tool's design hid the leak: its search returns no scores, so the changed numbers never reached the assistant or the user. That is luck, not a rule. A probe on a toy corpus in the research notes, where a hidden document does rank in the top k, gave a shorter post-filter list and different scores. Retrieval APIs commonly return scores, ranks or counts, so filtering after ranking leaks wherever they do. Filtering before ranking is the rule, because it does not depend on that luck.

One limit sits outside the search. The search tool's description, in every prompt, gives an owner-only quote as an example query, so every acting user learns that the quote exists. Every recording used that description, so it stays.

[Example: retrieval-by-role-paired](../examples/retrieval-by-role-paired.py)

The undefended assistant and the role-filtered one are compared on both splits. On dev, the undefended run completed {{out:retrieval-by-role-paired:dev, baseline, utility, 15 benign tasks}} benign tasks, and the filtered run completed {{out:retrieval-by-role-paired:dev, retrieval-by-role, utility, 15 benign tasks}}.

The paired difference is {{out:retrieval-by-role-paired:dev, utility, paired difference}}, with interval {{out:retrieval-by-role-paired:dev, utility, paired difference, interval}}. Among the completed tasks, {{out:retrieval-by-role-paired:dev, benign tasks whose search lost a document they needed}} lost a search result they needed. That is the one task the filtered run dropped, and the example asserts that the two sets match.

On dev, the filter moved attack success from {{out:retrieval-by-role-paired:dev, baseline, attack success, 60 cases}} to {{out:retrieval-by-role-paired:dev, retrieval-by-role, attack success, 60 cases}}, a paired difference of {{out:retrieval-by-role-paired:dev, attack success, paired difference}}, with interval {{out:retrieval-by-role-paired:dev, attack success, paired difference, interval}}.

On held-out the filter cut no attack. Attack success was {{out:retrieval-by-role-paired:held-out, retrieval-by-role, attack success, 60 cases}} under the filter, against {{out:retrieval-by-role-paired:held-out, baseline, attack success, 60 cases}} undefended, a paired difference of {{out:retrieval-by-role-paired:held-out, attack success, paired difference}}.

The undefended run completed {{out:retrieval-by-role-paired:held-out, baseline, utility, 15 benign tasks}} benign tasks, and the filtered run completed {{out:retrieval-by-role-paired:held-out, retrieval-by-role, utility, 15 benign tasks}}. The paired difference is {{out:retrieval-by-role-paired:held-out, utility, paired difference}}, with interval {{out:retrieval-by-role-paired:held-out, utility, paired difference, interval}}.

Of the tasks the undefended run completed, {{out:retrieval-by-role-paired:held-out, benign tasks whose search lost a document they needed}} lost a search result they had needed.

The index attacks show no effect of the filter on either split. The undefended run's attack success through the index was {{out:retrieval-by-role-paired:dev, baseline, attack success, loc-index, 13 cases}} on dev and {{out:retrieval-by-role-paired:held-out, baseline, attack success, loc-index, 11 cases}} on held-out, so the filter had nothing there to remove. The upload location is thin: {{out:retrieval-by-role-paired:dev, baseline, attack success, loc-upload, 16 cases}} on dev and {{out:retrieval-by-role-paired:held-out, baseline, attack success, loc-upload, 8 cases}} on held-out. Those are counts, not rates to compare.

Which documents count as staff or owner-only is a question about personal data and access policy. [Data Governance as Code, chapter 3](https://rollingedition.com/data-governance-as-code/s/personal-data-in-production) covers where personal data goes wrong in production. This chapter takes the book's source-based labels as given and measures only what the filter does with them.

**Working rule:** Filter by the acting user's rights before ranking, and never rank first and filter the top k afterwards, because the scores still carry the hidden documents. Filter because a search result is a read the user may not have been given, not as an attack defence. On dev the filter's paired change in attack success was {{out:retrieval-by-role-paired:dev, attack success, paired difference}}, and on held-out it was {{out:retrieval-by-role-paired:held-out, attack success, paired difference}}, with {{out:retrieval-by-role-paired:held-out, benign tasks completed on the baseline and not on retrieval-by-role}} benign tasks lost. Run the held-out split before you claim the filter cut attacks.

## Poisoned documents in the index {#poisoned-documents-in-the-index}

A filter decides who may read a document. It says nothing about whether the document is true. A document the user may read can carry a wrong figure, and the assistant can repeat it in a reply. [Chapter 1](#what-the-allowlist-cannot-see) named this as the attack that no outbound rule sees, because nothing leaves the office. The office never set the figure, and the reply carries it anyway.

PoisonedRAG (Zou and colleagues, USENIX Security 2025; [arXiv:2402.07867](https://arxiv.org/abs/2402.07867)) reports that five malicious texts, injected for each target question into a knowledge database of millions of texts, reached a 90% attack success rate. That is the attack's authors' own setup, and this chapter has not checked whether others reproduced it. The book's own measure is different: one wrong deposit figure in one document, against one assistant, on this set.

[Example: poisoned-deposit](../examples/poisoned-deposit.py)

The deposit cases on dev are run under three conditions: the undefended assistant, the one with secrets removed, and the one with the role filter. A poisoned figure in the reply counts as success. The undefended run put poisoned figures into {{out:poisoned-deposit:dev, baseline, attack success, g-deposit cases}} replies. The run with secrets removed got {{out:poisoned-deposit:dev, secrets-out, attack success, g-deposit cases}}, the same count, and the role filter got {{out:poisoned-deposit:dev, retrieval-by-role, attack success, g-deposit cases}}. The secrets change did not move the count, and the filter lowered it. Through the index, the dev attacks succeeded at {{out:retrieval-by-role-paired:dev, baseline, attack success, loc-index, 13 cases}}, so the index was the route for none of the measured poisoned figures.

Benign tasks that state a deposit run under the same three conditions. In each run, {{out:poisoned-deposit:dev, baseline, benign replies that state a deposit}} benign replies stated one. Those are the false-alarm test.

The check is `cite_provenance`, a function in the book's defence code. Its label is harness (enforcement), because it refuses the reply. Its primary defence is the office's own records: a figure in a reply can be trusted only as far as the record it cites keeps that figure right. The check is teaching code and defence in depth. It reads the reply as a reader sees it, with entities decoded, Unicode normalised, format characters removed and line breaks joined. Each figure within twelve words of the word "deposit", written in pounds or as a bare number, needs its own citation: a document ID within the same window that no other figure has used. The cited document must be an office document, and its text must state the figure. If a figure lacks its own citation, or cites a document that is not an office document or does not state it, the reply is refused. Number words, and figures with no deposit word nearby, are not checked. A reply with no deposit figure is allowed.

The example applies that rule to the replies each run recorded, after the fact. So "flagged" below means "would have been refused", not that the episode refused the reply.

[Example: secrets-regressions](../examples/secrets-regressions.py)

The regression example runs the check, the access label and the prompt scan on attempts that try to get round them: figures in other written forms, one citation shared by two figures, a citation in capitals, a citation to a document that is not an office record, and a source spelled with a capital letter. Each attempt's verdict is printed by name, and each is asserted, so a change that lets one through fails the example.

On dev, the check flagged {{out:poisoned-deposit:dev, poisoned replies flagged by cite_provenance}} poisoned replies across the three runs. Across the same runs, its false alarms on benign deposit replies were {{out:poisoned-deposit:dev, false alarms on benign replies that state a deposit, three runs}}.

The held-out split has few deposit cases, so it is a second look and not a rate. There the undefended run put {{out:poisoned-deposit:held-out, baseline, attack success, g-deposit cases}} poisoned figures into replies, the check flagged {{out:poisoned-deposit:held-out, poisoned replies flagged by cite_provenance}} poisoned replies across the three runs, and its false alarms were {{out:poisoned-deposit:held-out, false alarms on benign replies that state a deposit, three runs}}.

The check has a limit that the counts do not show. It proves where a figure came from, not that the document is right. A reply that cites an office document whose text states a wrong figure passes, because the check cannot tell a wrong office record from a right one. On this set no attack through the index put a figure into a reply, so a reply that cites a wrong office record is untested, and the check would pass it. The poisoned replies here were caught only because they cited nothing the office wrote. No example here tests the cited-wrong-record case, and no rate describes it.

The filter and the check do different jobs. The filter decides what the assistant can read. The check decides what a reply may say about a deposit. Neither knows whether a document is true, and only the check looks at the reply the reader gets.

The memory of an assistant is a further limit, and this chapter does not measure it. Here the document stays in the index for the episode. A note the assistant keeps across episodes can carry injected text into later ones. AgentPoison reports poisoning an agent's long-term memory or knowledge base (Chen and colleagues, 2024, [arXiv:2407.12784](https://arxiv.org/abs/2407.12784)); this chapter has not checked whether it was published or reproduced. The set has no memory, and no number here describes one.

**Working rule:** Treat a deposit figure in a reply as unsupported until the reply cites an office document that states it, and read that document too, because the check reads only the reply. On this set the check flagged every poisoned reply and no benign one, on dev and on held-out. The held-out split had few poisoned replies, so that result is thin.

## What goes wrong in production {#what-goes-wrong-in-production}

Four parts of this design can fail in an office that is not this one. None of them is tested by the examples, which run one office, with one prompt file and one index. For each, the signal is what would show the failure first.

**The prompt.** A value removed from one prompt file can come back in the next, for example when a new template is copied from an old one. Run the prompt count in CI, and treat any prompt that holds the key or a marker as a failure.

**The access labels.** They come from each document's source, so a document whose source changes keeps its old label until someone changes it. The labeller fails closed: an unknown source becomes owner-only, which hides a document rather than leaking it. The risk is a document given a wrong `office` source, which makes it staff or public. Compare the count of documents by label between runs, and look for a rise in staff or public documents that nobody meant to publish.

**The citation format.** The check reads the reply and asks for a document ID. An office that cites by title will see the check refuse replies that were right, and it will pass a reply whose cited record is wrong, which no format change fixes. Watch the refusal rate on deposit replies: a rise after a change to the format means the format changed, not the replies. Wrong cited records are found only by reading them against the office's records.

**The per-role index.** In the book's code the role filter is switched on by its variant's own check, so a variant that replaced that check would run without it; a production build sets the filter where the tool's state is built. The primary defence depends on an index built for each role, so a role change or a label change that is not rebuilt leaves a user with documents they should not read. Compare the index with the current labels after each change, and treat a mismatch as a failure.

**Working rule:** Rerun the prompt count and the held-out split after each change to the prompt, to the source labels or to the citation format. A result that held before one of those changes describes the office as it was then.
