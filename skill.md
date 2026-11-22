---
description: Use when threat-modelling an LLM assistant or agent that has tools and reads text other people wrote, or when measuring whether a defence against prompt injection, data exfiltration or tool misuse works. Covers the threat model; an attack set scored in code, split into dev and held-out; paired comparisons with intervals; prompt defences, detectors and their false alarms; least privilege, egress rules and isolation in the harness; secrets and retrieval by role; checking third-party tools and model files; adaptive red-teaming; and regression gates.
---

## Draw the assistant's threat model

**When:** Before you add a defence, when you need to know which tools and data an assistant can reach from text it did not write.

1. Draw the assets and trust boundaries from the code's list of tools, not from the design document. For each tool, record what it reads, what it writes, which results carry text from outside, and whether its definition came from outside ([Assets and trust](#assets-and-trust)).
2. Map the data flows, including the outward ones. Name each location's carrier and the tool that delivers it, and count a location as a channel only when some delivery reaches the model ([Data flows](#data-flows)).
3. Count the legs of the lethal trifecta for every tool: private data, untrusted content, and a way to communicate outward. Then remove each leg's tools in turn and count again. Apply the Rule of Two, and keep no tool that combines all three ([The trifecta and the rule of two](#the-trifecta-and-the-rule-of-two)).
4. Map each risk to an OWASP, ASI or ATLAS entry only when the book has confirmed its ID, and say that the risk is not measured when no chapter measures it ([Risks mapped](#risks-mapped)).

**Check:** Run [the example](examples/threat-trifecta-check.py). Its `tools checked` line should read {{out:threat-trifecta-check:tools checked}}, and every tool with all three legs should be named in your model. Check the tool count in [the tool table](examples/threat-tool-table.py) against your prompt's tool list.

**Pitfalls:**
- An allowlist on one channel says nothing about the others. Read every outward flow the same way.
- A design document can list tools the code does not offer, and miss some it does.

## Build an attack set you can score in code

**When:** You need an attack rate you can explain: each case has a goal, a location for its text and a style, and a check decides whether it succeeded.

1. Choose the goals, the locations where the attacker's text can arrive, and the styles it is written in. Keep the three as separate, crossed labels ([Goals, locations and styles](#goals-locations-styles)).
2. Write each goal's check first, on the trace, and make it read every channel the goal names. Test it on one trace that reaches the goal and one that does not, and make it pass both before any case uses it. Count a run that errors apart from a failed attack ([Scorers on the trace](#scorers-on-the-trace)).
3. Split the cases into dev and held-out, with at least one case of each goal, location and style on each. Do not add cases to a split once its results are in ([Dev and held-out](#dev-and-held-out)).
4. Measure the undefended assistant on dev before you change anything, and report each rate with its count and interval. Where a cell is small, report the count alone ([The undefended assistant on dev](#undefended-baseline)).
5. Keep attack strings in data files. Use a public corpus only to measure a classifier on text in general ([Why not a public corpus](#why-not-a-public-corpus)).

**Check:** Run [the example](examples/attack-set-scorers.py). Its passing count for the phone goal should read {{out:attack-set-scorers:g-phone-fetch verdicts passed}}, which is the check working on both traces.

**Pitfalls:**
- A rate over a handful of cases is a count in disguise. Quote the count in the same sentence.

## Measure a defence on the same cases

**When:** You have added a defence and need to say whether it changed attack success or benign utility, and by how much.

1. Run the same cases twice, once undefended and once with the defence on, and pair the results case by case ([An outbound allowlist](#an-outbound-allowlist)).
2. Report the paired difference with its interval and counts. Call the change real only when the interval excludes zero ([Evaluating LLM Applications, chapter 8](https://rollingedition.com/evaluating-llm-applications/s/paired-comparisons)).
3. Compare two configurations only on the same users and tasks ([The office and its assistant](#the-office-and-its-assistant)).
4. Beside any result on a defence, list the channels the defence does not see, in the same paragraph ([What the allowlist cannot see](#what-the-allowlist-cannot-see)).

**Check:** Run [the example](examples/attack-allowlist-paired.py). Its `paired difference, interval` line should read {{out:attack-allowlist-paired:paired difference, interval}}.

**Pitfalls:**
- A zero on tool calls is not a zero on replies or on records.

## Measure what a prompt-level defence buys

**When:** You are considering a warning, delimiters, datamarking, an encoding or a repeated request in the prompt.

1. Tune the wording on dev only. If a dev result sends you back to change the defence, it is a new defence with its own held-out run ([Dev and held-out](#dev-and-held-out)).
2. Run the defence once on held-out, and count its benign cost beside any gain. Keep a warning as a layer only when its held-out attack-success interval excludes zero. A zero on dev is a reason to run held-out, not a result ([A warning in the prompt](#a-warning-in-the-prompt)).
3. Treat delimiters as a way to show the model where untrusted text starts and stops, not as a control on what the model does ([Delimiters](#delimiters-alone)). Measure datamarking's utility on held-out before you accept it ([Datamarking](#datamarking)).
4. Read an encoding's utility on the held-out benign tasks before you call it a defence. It can stop every attack in a set and still leave the assistant unable to do its work ([Encoding](#encoding)).
5. Before you repeat the request, count the tasks that need an action, and check that the run still makes those calls. A repeat that stops the action also stops the task ([Repeating the request](#repeating-the-request)).
6. Count each defence's tokens with the deployed model's tokeniser, beside its benign and attack results ([What each costs](#what-each-costs)).
7. Before you credit a smaller model with lower attack success, count how often it read the carrier text ([A smaller model](#a-smaller-model)).
8. Report each defence's held-out paired difference with its interval, and do not tune again on held-out ([The held-out run](#the-held-out-run)).

**Check:** Run [the example](examples/prompt-defences-held-out.py). Its baseline attack success on the 60 held-out cases should read {{out:prompt-defences-held-out:baseline, attack success, 60 held-out cases}}, the figure each defence is compared against.

**Pitfalls:**
- A prompt defence is one layer. Do not describe it as a fix for prompt injection.

## Detect injected text, and count the false alarms

**When:** You want a classifier or a model to flag injected text before the assistant reads it, and you need to know how often it is wrong.

1. Read the model card for what the model was built for, and count the detector's errors on your own texts before you trust a flag ([A classifier guard](#a-classifier-guard)).
2. Pick the threshold on dev, with a rule written down before you saw the scores. Print the flagged counts at every grid value, and the number of scores near the pick ([Picking a threshold on dev](#picking-a-threshold-on-dev)).
3. Count false alarms on held-out and on public text separately, naming the kind of text in each count ([False alarms on real text](#false-alarms-on-real-text)).
4. Measure a filter's price on the benign tasks it touches, paired with the same tasks undefended. Read each interval before its point ([The detector as a filter](#the-detector-as-a-filter)).
5. For a model used as a detector, count its errors on dev and state which way they run before its verdicts count ([The open model as a detector](#the-open-model-as-a-detector)).
6. A content-safety guard that flags nothing on benign text answers a different question, so its quiet says nothing about injection ([A content-safety guard is not an injection detector](#a-content-guard-is-not-a-detector)).

**Check:** Run [the example](examples/detector-threshold-dev.py). Its `dev scores within 0.02 of the pick` line should read {{out:detector-threshold-dev:dev scores within 0.02 of the pick}}.

## Enforce least privilege in the harness

**When:** A task should reach only the tools it needs, and a refusal must come from code rather than from the model's judgment.

1. Write each task's tool list in code, from the task's request, before the run starts. Put only those tools in the prompt, and refuse and log any call to a tool outside the list. A task that cannot name its tools before it reads data is outside this control, and its design should say so ([A tool filter per task](#a-tool-filter-per-task)).
2. Write one argument policy per task, from its request and schemas. Run it on every call, and refuse any call it cannot read. Test it against the encodings an attacker would try, and write down each form it allows ([Argument policies](#argument-policies)).
3. Put an approval on every tool with a side effect, counting a fetch that carries data out as one ([Approval for side effects](#approval-for-side-effects)).
4. Tokenise untrusted text with special tokens off, insert your own markers by ID, and check the token IDs of the composed prompt ([Control tokens in untrusted text](#control-tokens-in-untrusted-text)).
5. Replay each control on held-out as well as dev, and count refusals on the benign tasks. Fifteen tasks with no lost task show a cost under about one task in fifteen ([What least privilege costs](#what-least-privilege-costs)).

**Check:** Run [the example](examples/least-privilege-held-out.py). Its `baseline, attack success, 60 held-out cases` line should read {{out:least-privilege-held-out:baseline, attack success, 60 held-out cases}}, and its controls should be read beside it.

**Pitfalls:**
- A rule on the values in a call is not a rule on its content.

## Close the exfiltration channels

**When:** The assistant can fetch pages, send messages, or put links and images in its reply.

1. Allowlist the hosts first, then read what the allowed requests carry. A host check says where data goes, and a query check says what the data is. Name the one you measured and the one you did not ([Egress rules](#egress-rules)).
2. Keep the network limit outside the code as the primary defence. The check in the harness is the second layer, and it should refuse when it cannot decide ([Egress rules](#egress-rules)).
3. Apply the render policy to links and images in the reply, and list in the same paragraph the channels it covers and those it does not, such as a redirect an office host sends on ([Links and images in the reply](#links-and-images-in-the-reply), [What the render policy does with each form](#render-forms)).
4. Treat the output as untrusted, and check the reply at the point where it leaves the harness. Name each check's blind spot in the paragraph that reports its result ([Output is untrusted](#output-is-untrusted)).
5. A secret scan on output answers one question: was the plain text there? It does not show that the secret left. Remove the secret from the context first, and keep the scan for what that removal missed ([Scanning the reply for secrets](#scanning-the-reply-for-secrets)).

**Check:** Run [the example](examples/egress-fetch-paired.py). Its `utility, baseline, 15 dev benign tasks` line should read {{out:egress-fetch-paired:utility, baseline, 15 dev benign tasks}}, and the paired difference in attack success should read with its interval beside it.

**Pitfalls:**
- A zero from one set is a fact about that set and that model, not about the channel.

## Isolate untrusted text from the model that plans

**When:** The model that chooses calls must never read untrusted text directly, or a design must keep it apart.

1. For a dual LLM, hold untrusted text in variables the planner refers to, and let a quarantined model read them. Check that the quarantined model is ever called. A design whose second model never runs is measured only by what it hides ([The dual LLM](#dual-llm)).
2. For plan-then-execute, count the first replies that hold the whole plan. If the model writes one call at a time, let the plan grow across replies, or expect the send to be refused after the reads ([Plan-then-execute](#plan-then-execute)).
3. For taint labels, label a value where a tool result enters the planner's context, and refuse it only where it reaches a side-effecting argument. Measure the refusals on held-out before you fix the rule ([Taint labels](#taint-labels)).
4. Report each design's benign utility on held-out beside its attack success. Keep a design only where its attack-success interval excludes zero ([The utility cost](#the-utility-cost)).

**Check:** Run [the example](examples/isolation-cost.py). Its `benign tasks lost, design-dual-llm` line should read {{out:isolation-cost:benign tasks lost, design-dual-llm}}.

## Keep secrets and other people's records out of the context

**When:** A prompt would hold a key, a note, or records the acting user may not read.

1. Keep the key and the note out of the prompt before you rely on any check of the reply, since a value that never entered the prompt cannot be printed. Then count the prompts that still hold a value ([Hidden context](#hidden-context)).
2. Keep each credential with the code that uses it, and give the model results, not values. Measure the defence by the prompt count and by the attack goals that need the value ([Keys out of the prompt](#keys-out-of-the-prompt)).
3. Filter by the acting user's rights before ranking, never after, since the scores of hidden documents still shape a top k that is filtered later ([Retrieval by role](#retrieval-by-role)).
4. Treat a figure in a reply as unsupported until the reply cites an office document that states it, and read that document too, since the check reads only the reply ([Poisoned documents in the index](#poisoned-documents-in-the-index)).
5. Rerun the prompt count and the held-out split after each change to the prompt, the source labels or the citation format ([What goes wrong in production](#what-goes-wrong-in-production)).

**Check:** Run [the example](examples/secrets-out-paired.py). Its `dev, baseline, attack success, 60 cases` line should read {{out:secrets-out-paired:dev, baseline, attack success, 60 cases}}, beside the prompt count.

## Check third-party parts before the assistant is offered them

**When:** You are adding a tool from another party, a model file, or a dependency.

1. Check each tool's declared effect and arguments against its behaviour, on the definition the server offers and again on each change ([Declared effects are claims](#descriptions-are-claims)).
2. Pin every tool definition from the version a person approved, and compare the pin on each load. A changed definition drops out until a person approves it and regenerates its pin. A pin does not show that the approved claim was true, so run the claim check as well ([Pinning tool definitions](#pinning-tool-definitions)).
3. Load only safetensors weights, from a pinned commit. Check the SHA-256 and size of every file the loader reads, and refuse pickle-format files without unpickling them ([Model files](#model-files)).
4. Pin every requirement with `==`, and record a hash for each line, so that an install fails on any changed byte. Until the hashes are in place, say that the versions are fixed, not that the bytes are ([Dependency pins](#dependency-pins)).

**Check:** Run [the example](examples/dependency-pin-check.py). Its `exact == pins` line should read {{out:dependency-pin-check:exact == pins}}, and its `refused requirement lines` line should be zero.

## Red-team with an adaptive attacker

**When:** You need to know what a defence does when the attacker can read the reply and try again.

1. Before you read an adaptive rate, check that round 0 matches the fixed set for the same cases and defences. If it does not, the two numbers do not share a baseline ([An attacker that iterates](#an-attacker-that-iterates)).
2. Fix the number of attacker turns before the run, and use the same number for every defence and every case. A budget chosen after the results can make any defence look stronger or weaker ([The budget](#the-budget)).
3. Read each gap beside its round 0 count and case count. A zero gap with a zero-width interval means no case changed ([The gap to the fixed set](#the-gap-to-the-fixed-set)).
4. In the same paragraph as any adaptive result, name the defences the loop did not attack ([What the result does not show](#what-the-result-does-not-show)).
5. Before a garak module counts as covering a location, confirm at the pinned version that its detector scores the reply the assistant would send ([Mapping onto a toolkit](#mapping-onto-a-toolkit)).

**Check:** Run [the example](examples/adaptive-round-count.py). Its `round 0 mismatches against the fixed set` line should say none.

## Keep the defences from regressing

**When:** You changed a defence's code, wording, policy or recording, and need a gate that runs on every change.

1. Run the gate on every change, on dev only. Treat a failed check as a regression until someone has found its cause on dev. Do not rerun held-out to see whether a failing change passes, because that spends the split ([The gate](#the-gate)).
2. Choose each threshold once, on dev, from the defended run and the baseline, and store it with the rule that produced it. Read each check against the interval's bound, never against the rate. A changed threshold is a new choice on dev, reviewed like any other change to the gate ([Choose thresholds once, from dev](#thresholds-and-intervals)).
4. Log every outbound call, allowed or refused, every refused call, and every withheld result, with its host where the call has one. Log nothing else until an incident needs it ([Log what the defences decide](#security-events)).
5. When an incident names a case, read every refusal logged for it before any code, then that case's lines under each configuration. Do not name a product as the cause, or reproduce a real incident's payload ([Answer an incident from the log](#answering-an-incident)).
6. Print each risk ID with its list's year or date, and take IDs only from lists the book has checked ([Report in the standards' terms](#reporting-in-the-standards-terms)).

**Check:** Run [the example](examples/gate-catches-a-regression.py). Its `ceiling, stored` line should read {{out:gate-catches-a-regression:ceiling, stored}}, and the regressed run should FAIL the attack check.

**Pitfalls:**
- A gate on dev catches drift on the cases it was measured on. It does not show the defence works on new cases.
