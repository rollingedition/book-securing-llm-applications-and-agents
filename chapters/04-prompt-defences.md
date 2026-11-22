---
chapter_id: prompt-defences
---

# Measure what prompt-level defences buy

By the end of this chapter you can measure what a prompt-level defence does to an assistant's attack success and to its utility, count the tokens it adds to each prompt, and read a held-out result without tuning on it. The defences here change only the prompt. None of them changes a tool, a permission or the data the assistant can reach, so each one's effect is whatever the model does with the text it is given. These variants are teaching code and defence in depth. They are not the controls that limit what the assistant can do. Those are enforced outside the model, in [Chapter 1](#an-outbound-allowlist) and [Chapter 6](#least-privilege). Chapter 8 keeps untrusted text away from the model that acts.

The office assistant reads tenant messages, uploaded documents, the search index and the pages it fetches. Any of them can carry an instruction, and the assistant can follow it. [Chapter 3](#undefended-baseline) measured how often that worked on the undefended assistant: it reached a case's goal in {{out:attack-set-baseline:attack success, dev cases}} of the dev cases. A prompt-level defence is the cheapest response to that. It tells the model that tool text is data, marks where untrusted text begins and ends, changes how that text looks, or repeats the staff member's request after it. Each one works, if it works at all, through the model's reading of the prompt.

That is why this book labels all five defences prompt (advice). Spotlighting changes the input text itself, so one could file it as an input control. The book does not, because its effect depends on the model reading the marked text, and a model can read a marker and still act on what the marker surrounds. The harness label was chapter 1's, and it comes back in chapter 6. The other labels, input (detector) and design (isolation), belong to later chapters, where the controls they describe act outside the model.

The chapter measures five variants: a warning in the system prompt, delimiters, datamarking, encoding and repeating the request. Each one runs on the dev split first, where its wording was tuned, and then once on the held-out split, where it is measured with the wording frozen. Every comparison is paired per case, and every interval is a bootstrap over cases, as [Evaluating LLM Applications, chapter 8](https://rollingedition.com/evaluating-llm-applications/s/bootstrap-over-items) explains. Every rate here holds for this fixed attack set and for one model, Qwen3-4B-Instruct-2507, pinned. [Chapter 11](#the-gap-to-the-fixed-set) tests two of them, datamarking and encoding, against an attacker that adapts to them.

The held-out undefended run, which [chapter 3](#undefended-baseline) reports, is lower than dev's. Every held-out comparison in this chapter is against that run, not against the dev numbers, and the paired intervals make that comparison. The held-out example runs each defence once and produces those numbers:

[Example: prompt-defences-held-out](../examples/prompt-defences-held-out.py)

## A warning in the prompt {#a-warning-in-the-prompt}

The simplest defence is a sentence. The warning is appended to the system prompt. It says that text from tools may contain instructions, that the model should never follow them, and that only the staff member's request counts. Nothing else in the prompt changes. The warning's whole cost is the length of that note on each model call.

Its effect depends on whether the model acts on the note, and the note's wording can't settle that in advance. The first example runs all five variants on the dev split, against the undefended run.

[Example: prompt-defences-paired](../examples/prompt-defences-paired.py)

On dev, the warning changed nothing the scorers can see. Its paired difference in attack success is {{out:prompt-defences-paired:prompt-warning, paired difference in attack success}}, and its utility, {{out:prompt-defences-paired:prompt-warning, utility, 15 dev benign tasks}}, matches the undefended run's {{out:attack-set-baseline:utility, dev benign tasks}}.

A zero on the tuned split is not evidence that the warning works. It says that this wording did nothing on this set. [Hines et al.](https://arxiv.org/abs/2403.14720), researchers at Microsoft, report a 2024 arXiv preprint in which an added instruction about prompt injection gave almost no benefit for GPT-3.5-Turbo, and a modest one for another model. That preprint used GPT-family models and synthetic documents, so it sets an expectation for this book and does not replace its measurement.

On held-out, the warning moves the wrong way. Its utility cost is {{out:prompt-defences-held-out:prompt-warning, paired difference in utility}}, and the interval on that difference, {{out:prompt-defences-held-out:prompt-warning, paired difference in utility, interval}}, reaches zero at its upper end. Dev showed no utility cost for the warning, and held-out does. The attack-success interval runs from below zero to above it, so the warning shows no attack reduction the book can claim.

**Working rule:** Run a warning on the held-out split before you credit it, and count its benign cost next to any gain. Keep it as one layer only when its held-out attack-success interval excludes zero. A zero on the tuned split is a reason to run held-out, not a result.

## Delimiters and spotlighting {#delimiters-and-spotlighting}

Spotlighting is the name [Hines et al.](https://arxiv.org/abs/2403.14720) give to transforms of untrusted text that give the model a signal of where the text came from. The preprint describes three: delimiting, [datamarking](#datamarking) and [encoding](#encoding). The idea is that a model which can tell the staff member's words from a tool's words has a better chance of following only the first.

### Delimiters {#delimiters-alone}

Delimiters wrap each untrusted segment in markers, and the system prompt says what the markers mean. Hines et al. report a beneficial effect from delimiters, smaller than datamarking's. On dev, this book's delimiters left utility where the undefended run had it, at {{out:prompt-defences-paired:prompt-delimiters, utility, 15 dev benign tasks}}.

Attack success's paired difference was {{out:prompt-defences-paired:prompt-delimiters, paired difference in attack success}}, with an interval of {{out:prompt-defences-paired:prompt-delimiters, paired difference in attack success, interval}}. That interval reaches zero at its upper end, so the dev run does not show a reduction.

On held-out, the paired difference in attack success is {{out:prompt-defences-held-out:prompt-delimiters, paired difference in attack success}}, with an interval of {{out:prompt-defences-held-out:prompt-delimiters, paired difference in attack success, interval}} that includes zero. Held-out shows no effect either way, and its point estimate is above zero, where dev's was below. Utility's paired difference is {{out:prompt-defences-held-out:prompt-delimiters, paired difference in utility}}.

The markers have a known weakness. Hines et al. note that an adversary who knows the delimiters can write them into their own text, and the variant's docstring in the book's code says the same. No example in this chapter measures that, so the weakness is stated here and not shown.

**Working rule:** Use delimiters to show the model where untrusted text starts and stops, and don't count them as a control on what the model does. A reduction seen on dev counts only if held-out repeats it.

### Datamarking {#datamarking}

Datamarking replaces every whitespace character in the untrusted text with a marker character, and the system prompt names the marker. The model reads the marked text, so the change is visible to the model and not only to the harness. Hines et al. report a larger effect than delimiting's, and no detrimental effect on task performance for GPT-3.5-Turbo on their benchmarks.

On dev, datamarking lowered attack success, and its paired interval excludes zero: the difference is {{out:prompt-defences-paired:prompt-datamark, paired difference in attack success}}, with an interval of {{out:prompt-defences-paired:prompt-datamark, paired difference in attack success, interval}}.

On held-out, the reduction does not hold. The paired difference in attack success is {{out:prompt-defences-held-out:prompt-datamark, paired difference in attack success}}, with an interval of {{out:prompt-defences-held-out:prompt-datamark, paired difference in attack success, interval}} that includes zero. Utility's paired difference is {{out:prompt-defences-held-out:prompt-datamark, paired difference in utility}}, with an interval of {{out:prompt-defences-held-out:prompt-datamark, paired difference in utility, interval}}, which also includes zero. The preprint's finding of no cost is about GPT-3.5-Turbo on its benchmarks. Here the held-out utility point estimate is lower, and its interval includes zero. This book shows neither a cost nor its absence.

Datamarking also changes what an [input detector](#a-classifier-guard) reads. [Chapter 5](#false-alarms-on-real-text) says where to run the detector because of it.

**Working rule:** Measure datamarking's utility on held-out before you accept it, and read its held-out attack-success interval with the dev one beside it. A reduction that appears only on dev is a dev result.

### Encoding {#encoding}

Encoding replaces each untrusted segment with the base64 encoding of its UTF-8 bytes. The system prompt says that tool output is base64 and is data, and that it must not be followed. Third-party tool definitions are untrusted too, so this variant encodes them as well. Encoding therefore changes two things at once, the tool results and the tool definitions, and the book's runs cannot tell the two apart. The model must decode the text before it can read it.

[Hines et al.](https://arxiv.org/abs/2403.14720) report that encoding gave the lowest attack success of the three transforms, and that only the most capable models decode the text with high fidelity. GPT-3.5-Turbo's task performance suffered on encoded text in their experiments. Those were GPT-family models in 2024, not a 4B open-weight model, and their encoding did not change tool definitions, which this variant does. The book's encoded runs also lose utility, and they don't show why. Model size is one possible cause, and the runs do not separate it from encoding the tool results or from encoding the tool definitions. There is no encoded run on the 0.6B model, and no run that varies model size with encoding on.

On dev, encoding moved attack success further than any other variant did. It blocked {{out:prompt-defences-paired:prompt-encode, newly blocked, dev cases}} cases that the undefended run let through, so no defence on this set can lower attack success by more than the undefended run's rate. The paired difference is {{out:prompt-defences-paired:prompt-encode, paired difference in attack success}}, with an interval of {{out:prompt-defences-paired:prompt-encode, paired difference in attack success, interval}}, which excludes zero.

The cost falls on the benign tasks, where encoding's paired difference in utility is {{out:prompt-defences-paired:prompt-encode, paired difference in utility}}, with an interval of {{out:prompt-defences-paired:prompt-encode, paired difference in utility, interval}}. The runs don't show whether the model decoded the encoded text or ignored it. The traces show only that no attack goal was met.

On held-out, encoding's attack-success result holds. The paired difference is {{out:prompt-defences-held-out:prompt-encode, paired difference in attack success}}, with an interval of {{out:prompt-defences-held-out:prompt-encode, paired difference in attack success, interval}} that lies wholly below zero. It is the only held-out attack-success interval that does. The utility cost grows, and its paired difference on the held-out benign tasks is {{out:prompt-defences-held-out:prompt-encode, paired difference in utility}}. Because the variant encodes the tool definitions, that cost comes from the definitions, the tool results, or both, and this chapter's runs do not say which.

**Working rule:** An encoding can stop every attack in a set and still leave the assistant unable to do its work. Read its utility on the held-out benign tasks before you call it a defence. A cost that large is a reason to look for a design that keeps untrusted text away from the model that acts, which is the subject of [Chapter 8](#dual-llm).

## Repeating the request {#repeating-the-request}

After the last tool result, this variant repeats the staff member's request as a user turn, directly before the model's reply. The idea is that the request is the last thing the model reads before it answers, so the model keeps the staff member's goal in view. AgentDojo tests the same design under the name repeat prompt. Its authors report that it raised benign utility and lowered targeted attack success with GPT-4o, and they say it is "unlikely to withstand adaptive attacks" ([AgentDojo](https://arxiv.org/abs/2406.13352), an arXiv preprint, v3, with no venue on the copy). That is the benchmark's result, on its own tasks and model. This book's runs point the other way on utility.

On dev, the repeated request has the largest utility cost of the five variants. Its paired difference in utility is {{out:prompt-defences-paired:prompt-repeat, paired difference in utility}}, with an interval of {{out:prompt-defences-paired:prompt-repeat, paired difference in utility, interval}}. Its paired difference in attack success is {{out:prompt-defences-paired:prompt-repeat, paired difference in attack success}}, with an interval of {{out:prompt-defences-paired:prompt-repeat, paired difference in attack success, interval}} that includes zero, so the lower point estimate is not a reduction this run can show.

The next example looks for the cause among the dev benign tasks whose check needs an action: a message sent for an outbox check, or a visit booked for a booking check.

[Example: prompt-repeat-why](../examples/prompt-repeat-why.py)

Of the {{out:prompt-repeat-why:tasks that need an action, dev benign}} tasks that need an action, the undefended run ended in a text reply without the needed call on {{out:prompt-repeat-why:baseline, text reply without the needed call}}. With the repeated request, it did so on {{out:prompt-repeat-why:prompt-repeat, text reply without the needed call}}. The two runs are one recording each, on the same tasks, and differ only in the repeated request. The model answers in text instead of making the call, and the task's check fails.

On held-out, the repeat's utility cost is {{out:prompt-defences-held-out:prompt-repeat, paired difference in utility}}, with an interval of {{out:prompt-defences-held-out:prompt-repeat, paired difference in utility, interval}} that excludes zero. Its attack-success paired difference is {{out:prompt-defences-held-out:prompt-repeat, paired difference in attack success}}, with an interval of {{out:prompt-defences-held-out:prompt-repeat, paired difference in attack success, interval}} that includes zero.

**Working rule:** Before you repeat the request, count the tasks that need an action and check that the run still makes those calls. A repeat that stops the action also stops the task, and the utility number is what shows it.

## What each costs {#what-each-costs}

Each defence has two costs: the benign tasks it loses, and the tokens it adds to the prompts. The first is in the paired numbers above. The second is counted in the next example, on the dev benign tasks, with the Qwen3 tokeniser from the pinned files. That tokeniser matched the 4B model's own count on the book's probe texts when control tokens are read as control tokens. Each variant's count is summed over that task's model calls in the variant's own run. A run that makes fewer calls has fewer prompts to add to, so a total can fall because the run did less and not because its text is shorter.

[Example: prompt-cost-tokens](../examples/prompt-cost-tokens.py)

Measured as the median over the dev benign tasks, each defence adds these tokens to a task's prompts, summed over its calls:

- the warning, {{out:prompt-cost-tokens:prompt-warning, added prompt tokens, median}} tokens;
- delimiters, {{out:prompt-cost-tokens:prompt-delimiters, added prompt tokens, median}} tokens;
- datamarking, {{out:prompt-cost-tokens:prompt-datamark, added prompt tokens, median}} tokens, up to {{out:prompt-cost-tokens:prompt-datamark, added prompt tokens, maximum}} on the largest task;
- repeating the request, {{out:prompt-cost-tokens:prompt-repeat, added prompt tokens, median}} tokens;
- encoding, {{out:prompt-cost-tokens:prompt-encode, added prompt tokens, median}} tokens, up to {{out:prompt-cost-tokens:prompt-encode, added prompt tokens, maximum}} on the largest task.

The warning adds the same note on every call, so its total scales with the number of calls. Here every dev task's total was {{out:prompt-cost-tokens:prompt-warning, added prompt tokens, maximum}}, the same as its median.

The repeated request has the lowest total, and part of the reason is its run. Its median run makes {{out:prompt-cost-tokens:prompt-repeat, model calls, median}} model calls, against {{out:prompt-cost-tokens:prompt-warning, model calls, median}} for the warning's run. A task whose run ends in text after one tool result makes fewer calls, so it carries fewer reminders.

Encoding has the largest total, and most of it is the tool definitions. Those are encoded on every call, along with the tool results. The median of encoding's added tokens on the tool definitions is {{out:prompt-cost-tokens:prompt-encode, added prompt tokens in tool definitions, median}}, and the rest, the tool results and the system note, has a median of {{out:prompt-cost-tokens:prompt-encode, added prompt tokens elsewhere, median}}. Datamarking also marks the whitespace in the tool definitions, which accounts for {{out:prompt-cost-tokens:prompt-datamark, added prompt tokens in tool definitions, median}} of its median. So the encoding count is the cost of the variant as built, which encodes the definitions by design, and not only of base64 on the tool results.

The token cost does not rank the defences the way the utility cost does. In this run the repeat is the cheapest in tokens, and it has the largest utility cost on dev. On held-out, encoding costs the most utility, a paired difference of {{out:prompt-defences-held-out:prompt-encode, paired difference in utility}} against the repeat's {{out:prompt-defences-held-out:prompt-repeat, paired difference in utility}}, and it is also the largest cost in tokens, measured on dev. A ranking from the tuned split can change on the held-out split, so a cost comparison needs both.

These counts describe these prompts, this tokeniser and this set of short documents. Real tool results are longer, and a deployed model's tokeniser may split the same text differently. Count the tokens with the tokeniser of the model you deploy, on the prompts it will read, and not with the numbers printed here.

**Working rule:** Count each defence's tokens with the deployed model's tokeniser, on the prompts it will read, and count the calls its run makes. Put each cost beside its benign and attack results. If two defences lower attack success by the same amount, keep the one that costs fewer benign tasks and fewer tokens.

## A smaller model {#a-smaller-model}

The undefended 0.6B model looks safer than the 4B model on the dev split, and that is worth a closer look, because it shows how a safety number can come from what a model does rather than from what it resists. The smaller model is Qwen3-0.6B, pinned like the 4B model and run with thinking off. The example sets the two models beside each other on the same dev tasks and cases.

[Example: prompt-small-model](../examples/prompt-small-model.py)

On dev, the 0.6B model looks safer than the 4B model. Its attack success is {{out:prompt-small-model:0.6B, attack success, 60 dev cases}}, and against the 4B model on the same tasks and cases, its paired difference in attack success is {{out:prompt-small-model:0.6B minus 4B, paired difference in attack success}}. Its paired difference in utility is {{out:prompt-small-model:0.6B minus 4B, paired difference in utility}}.

The utility gap is expected: the smaller model does less of the office's work. The attack gap needs a closer look. In each counted attack case, the carrier is the tool result that holds the injected text, and each carrier kind has one tool that returns its full content. The counts ask whether the model called that tool. The 0.6B model never called it in {{out:prompt-small-model:never read the carrier, 0.6B}} counted cases. The 4B model never called it in {{out:prompt-small-model:never read the carrier, 4B}} counted cases. The tool-description cases are left out of both counts, because their text sits in every prompt's tool schema and cannot go unread, and there are {{out:prompt-small-model:tool-description cases left out}} of them.

A case the model never reads cannot reach its goal through that text, so the 0.6B model's zero is partly a fact about what it does. The model also completed {{out:prompt-small-model:0.6B, utility, 15 dev benign tasks}} of the benign tasks. Its zero therefore cannot be read as resistance: it fails to act on the tasks it was given, whether or not an action was injected. A defence that made the 4B model read less would show the same kind of zero. The count of reads, reported beside the rate, is what separates the two cases.

**Working rule:** Before you credit a model or a defence with a lower attack success, count how often it read the carrier. Report that count beside the rate. A rate that comes from text the model never read is a count of what the model did, and it is not evidence that the model resists.

## The held-out run {#the-held-out-run}

Each defence's wording was fixed on the dev split, and each then ran once on the held-out split. Both splits are reported, each claim names its split, and a dev result that held-out doesn't repeat is said not to hold. The dev results were used to choose the wording, so they can't also show that it works. Held-out is a second sample of cases from the same attack families, and one run per defence is all the book takes from it. The intervals are the honest measure of how much one run can move. The held-out undefended run, which is lower than dev's, is reported in [chapter 3](#undefended-baseline).

The held-out example gives each defence's paired attack-success difference, with its interval:

- The warning: {{out:prompt-defences-held-out:prompt-warning, paired difference in attack success}}, interval {{out:prompt-defences-held-out:prompt-warning, paired difference in attack success, interval}}.
- Delimiters: {{out:prompt-defences-held-out:prompt-delimiters, paired difference in attack success}}, interval {{out:prompt-defences-held-out:prompt-delimiters, paired difference in attack success, interval}}.
- Datamarking: {{out:prompt-defences-held-out:prompt-datamark, paired difference in attack success}}, interval {{out:prompt-defences-held-out:prompt-datamark, paired difference in attack success, interval}}.
- Repeating the request: {{out:prompt-defences-held-out:prompt-repeat, paired difference in attack success}}, interval {{out:prompt-defences-held-out:prompt-repeat, paired difference in attack success, interval}}.
- Encoding: {{out:prompt-defences-held-out:prompt-encode, paired difference in attack success}}, interval {{out:prompt-defences-held-out:prompt-encode, paired difference in attack success, interval}}.

Only encoding's attack-success difference excludes zero on held-out, and it does so at the utility cost described above. The held-out run confirms the two large utility costs, of encoding and of repeating the request, whose intervals exclude zero. It does not confirm the smaller costs of the warning and of datamarking, whose intervals reach zero. The warning's cost appeared only on held-out.

Dev was not kinder to every defence. It overstated the delimiters' attack reduction and the repeat's utility cost, and it understated the utility cost of the warning, of datamarking and of encoding. A claim drawn from dev alone would have been wrong for each of them, and in different directions.

Held-out is also a finite resource. A second held-out run after a wording change is a second look at the split, and the result would no longer be held out. If a held-out run shows a defence failing, the fix goes back to dev, and the held-out split is then spent for that wording. Keep a count of how many times each defence has been run on held-out, and report it with the result.

These results hold for one fixed attack set and one model, and the attacks are static: the same cases, in the same wording, every time. [Nasr et al., 2025, *The Attacker Moves Second*](https://arxiv.org/abs/2510.09023), a preprint that is not peer-reviewed as far as its copy shows, searched for attacks against published defences that had reported low static attack success, with the search run on AgentDojo. Its adaptive attacks broke most of them. The list it reports as broken includes spotlighting and prompt sandwiching, the name for the design this chapter calls repeating the request. The preprint's static results were low and its adaptive results were high. A static zero in this chapter is therefore a result for this set and no more. [Chapter 11](#the-gap-to-the-fixed-set) tests two of them, datamarking and encoding, against an attacker that adapts, on this book's own model.

**Working rule:** Report each defence's held-out paired attack-success difference with its interval, and claim a reduction only where that interval excludes zero. Don't tune again on the held-out split. A static result holds for the static set, and it meets an [adaptive attacker](#adaptive-attacker) in chapter 11.
