---
chapter_id: third-party-parts
---

# Check what third parties hand the assistant

By the end of this chapter you can check the parts of an assistant that other people wrote: the tools a server offers, the files of the model the assistant loads, and the packages its code installs. You'll test a tool's declared effects and arguments against what the tool does, pin a tool definition so that a later change is caught, check model files by hash and scan them before anything reads them, and see what a version pin fixes and what it leaves open.

Chapters 6 to 9 trusted the tools, model files and packages themselves. The office's assistant does not work from its own code alone. Two of its eight tools, `list_slots` and `book_visit`, come from a contractor's server. The host reads each tool's name, description, parameters and annotations and passes them to the model along with the prompt, and the model decides what to call from those words. Nobody at the office reads them first. On dev, the injections placed in tool descriptions reached the model through the tool block of its prompt, and [chapter 3](#undefended-baseline) counts them. Three kinds of claim need checking: what a tool declares it does, whether its definition is still the one that was approved, and whether the files and packages that run on the office's machines are the ones someone reviewed.

The definitions come from [Model Context Protocol in Practice, chapter 9](https://rollingedition.com/model-context-protocol-in-practice/s/tool-poisoning), which uses the terms this chapter keeps. In that chapter, a *tool definition* is "text from its server that the host passes to the model: its description, input schema and annotations."

Tool poisoning, in the same terms, "puts instructions for the model into a tool's definition." None of the checks in this chapter reads a description for instructions. The behaviour check tests declared effects and argument names against what the tool does, and the pin tests whether a definition is still the one a person approved. A poisoned description is caught when a person reads it at approval, which the same chapter covers under [tool poisoning](https://rollingedition.com/model-context-protocol-in-practice/s/tool-poisoning).

A *rug pull* is the change that follows approval: "a server changes a definition after the user approved it." The agreement the user gave no longer covers what the model is reading. The pin is the check for that change, and it is the subject of the second section.

The risk sits in the threat model. [Chapter 2](#risks-mapped) files a third party's definitions or outputs entering the prompt under ASI04 Agentic Supply Chain Vulnerabilities, from the OWASP Top 10 for Agentic Applications (Dec 9, 2025). MITRE ATLAS lists tool poisoning as AML.T0110, as [MITRE's D3FEND page for that technique](https://d3fend.mitre.org/offensive-technique/attack/AML.T0110/) states, and a rug pull as AML.T0109, as [the D3FEND page for that technique](https://d3fend.mitre.org/offensive-technique/attack/AML.T0109/) states.

## Declared effects are claims {#descriptions-are-claims}

A tool declares its effect in its annotations: `readOnlyHint` says that it only reads, and `destructiveHint` says that it may write. Its parameters name the arguments it takes. Those are claims the server makes, and a server can put a read-only label on a tool that writes. The host does not test the claim, so the check below does.

In production the drift is rarely deliberate. A vendor adds a tool that writes and forgets the label, a tool gains an argument its schema never names, or a write begins to touch a second table. Nobody notices until a reviewer happens to read the declaration and the code together. A check that runs whenever the definition changes turns that reading into a routine step.

The check tests the claims in three steps. It compares each tool's declared arguments with the arguments its code reads, which it collects from subscripts, `get` calls and `in` tests in the code's syntax tree. It takes the declared effect from the annotations. Then it makes one fresh call on a copy of the office's state and records which state fields changed. A read claim must come with no write, and a write claim must come with a write to exactly the tables approved when the tool was reviewed. A tool that declares no effect is not taken as a read: it disagrees if it writes, and it is `undeclared` if it does not.

[Example: description-behaviour-check](../examples/description-behaviour-check.py)

The contractor's listing declares no annotations at all. The check reports `book_visit` as `{{out:description-behaviour-check:verdict, book_visit, contractor}}`, because the call writes `{{out:description-behaviour-check:observed writes, book_visit, contractor}}` and no write is declared. That is a gap in the contractor's listing, and the book pins it as it stands. The verdict for `list_slots` is `{{out:description-behaviour-check:verdict, list_slots, contractor}}`: it declares nothing and its call writes no state field, so the claim is neither held nor broken.

The check holds when the declaration is right. The script builds a copy of `book_visit` that declares a write, and its verdict is `{{out:description-behaviour-check:verdict, book_visit, declared write}}`. The same copy with only `bookings` approved disagrees, `{{out:description-behaviour-check:verdict, book_visit, second table}}`, because the call also writes `slots`. The third copy declares read-only, and its call still writes `{{out:description-behaviour-check:observed writes, book_visit, read-only copy}}`, so the verdict is `{{out:description-behaviour-check:verdict, book_visit, read-only copy}}`.

A pin would not catch that third copy. A pin proves that a definition has not changed since it was approved. It says nothing about whether the approved claim was true, so this check has to run as well.

The check has limits, and the output shows some of them. It makes one call per tool with the arguments the script supplies, on the office's fixture state, and it compares only the state fields the snapshot covers. A write that happens only with other arguments, or in a field outside the snapshot, is not seen. An argument read by iterating over the whole argument dict is not seen either, so a branch that reads its arguments that way escapes the argument comparison. A verdict of `agrees` means the claim held on this call. It is not a proof about every call.

**Working rule:** Before a third-party tool is offered to the assistant, check its declared effect and arguments against its behaviour. A read claim should come with no write, a write claim with a write to the approved tables, and every declared argument should match an argument the code reads. Run the check on the definition the server offers, and run it again whenever that definition changes.

## Pinning tool definitions {#pinning-tool-definitions}

The primary defence is the host's approval of each definition before the tool is offered, with the pin as its record. [Model Context Protocol in Practice, chapter 9](https://rollingedition.com/model-context-protocol-in-practice/s/pin-tool-definitions) teaches the pin and its attack, so this section does not repeat that. It adds what this book measures and the behaviour check the pin does not cover.

The pin here is a SHA-256 hash over every key of a tool's definition: its name, description, parameters, annotations and any other key the server sends, serialised as canonical JSON with each string in NFC form. Key order does not matter, and any value does. A later change to `readOnlyHint`, a single doubled space, or an added `title` changes the pin.

Next comes the rug pull, built in code. The script makes a copy of the contractor's server in which the carrier tool's description gains the sentence of one dev attack. The output prints the case ID and never the sentence. The carrier is `{{out:pin-tool-definitions:carrier case}}`, the changed tool is `{{out:pin-tool-definitions:changed tool}}`, and its verdict is `{{out:pin-tool-definitions:verdict, after the change, book_visit}}`.

[Example: pin-tool-definitions](../examples/pin-tool-definitions.py)

The listing step is the host's gate on which tools reach the prompt. In the example the gate is `pinning.listable`, and it offers only the tools whose verdict is verified. The only tool listed to the model after the change is `{{out:pin-tool-definitions:tools listed to the model after the change}}`. Of the two contractor tools, `{{out:pin-tool-definitions:tools pinned}}` have pins, and both verify before the change. The gate lists frozen copies, made after the check from the canonical form that was hashed, so the listed object cannot change after the check. A host that lists through `pinning.listable` would not send the changed tool to its prompt. The office's harness does not use the gate: it builds its tool block from the contractor's file, so this is a demonstration of the gate, not of the office's route.

A server with no pins gives the gate nothing to compare. A tool with no pin is `unpinned`, and it is not listed. The risk is a host that writes pins automatically on the first load, so the first load's definitions pass without a reading by anyone. The host should refuse to start a server whose pins are missing, and a person should take the pins.

[Example: third-party-bypasses](../examples/third-party-bypasses.py)

The example runs {{out:third-party-bypasses:attempts asserted}} attempts from the security review through the same code, and asserts the verdict each one gives. The attempts cover what the gate and the other checks in this chapter must refuse: a tool name offered twice, an added or renamed key, a key order that changes nothing, a copy changed after the listing, a new tool with no pin, a requirement line with a wildcard, and a model folder with an unpinned file. The rows are regression rows. They say what the code decides for each case, and they do not measure how often an attack gets through.

The gate needs a careful reading. The office's harness does not call `pinning.listable` in any recording in this book, so the output shows what the gate decides for one changed definition. It does not measure how often an attack gets through this route. The chapter reports no attack rate for pinning, and the defence has no measured result on the attack set.

In production a pin is a file in the repository, and a change to it is reviewed like any other change to code. The reviewer reads the diff of the description, which is the sentence a person has to judge. The pins are taken once, by a person, from the definitions that were approved. A pipeline that regenerated pins on each run would approve whatever the server says at that point, and the pin would then record the rug pull instead of catching it.

**Working rule:** Pin every tool definition the assistant is offered, from the definition a person approved, and compare the pin on each load. A tool whose definition has changed drops out of the listing until a person approves the changed definition and regenerates its pin. A pin does not show that the approved claim was true, so run the claim check as well.

## Model files {#model-files}

The assistant's classifier, from [chapter 5](#a-classifier-guard), is loaded from a model repository. A repository holds more than weights. It holds configuration and tokenizer files, and anything else its author put beside them. The loader reads files from that repository, so each file is a point where a third party's bytes can enter the process. The question for each file is whether it can do anything beyond supply numbers.

The risk that matters most is a file that runs code when it is read. Python's pickle format does that by design. The Python documentation says the module "is not secure" and that data should be unpickled only when it is trusted ([Python documentation, pickle](https://docs.python.org/3/library/pickle.html)). The same page warns that a crafted pickle can execute arbitrary code when it is loaded, so a file that is a pickle has to be treated as code until something proves otherwise.

Safetensors is a different kind of format, one meant for "storing tensors safely (as opposed to pickle)" ([safetensors documentation](https://huggingface.co/docs/safetensors/index)). That is a statement about what the format is for. It says nothing about the other files in a repository, and a repository can ship a file of any kind beside its weights. That is why the loader's hash checks cover those files too.

The primary control is the format rule: the loader reads only safetensors weights, and its allow patterns exclude pickle-format files. The hash check is defence in depth behind it. It reads only safetensors weights from a commit whose identity is pinned, and it checks every file's SHA-256 and size against the pin before the file is used. A branch name can move when its owner pushes to it, and a commit cannot.

Some files in the detector repository are pickles and are not pinned. `training_args.bin` is one. A probe at the pinned commit listed its entries without loading it: it is a `torch.save` archive whose object is stored as `data.pkl`, so loading it with `torch.load(..., weights_only=False)`, or with `pickle`, would run whatever that object names. The loader never opens it.

[Example: model-file-checks](../examples/model-file-checks.py)

Run against the seven files the classifier uses, the checks show the rules holding on those files. The classifier has `{{out:model-file-checks:detector files pinned}}` pinned files, and the cached copies match their pins, which the example asserts. Of the pinned files, `{{out:model-file-checks:pinned files with a pickle suffix}}` have a pickle file suffix. Of the loader's allow patterns, `{{out:model-file-checks:loader patterns matching training_args.bin}}` match `training_args.bin`.

The snapshot folder must hold only the pinned files. The check lists any unpinned file by name and opens none, and the count is `{{out:model-file-checks:unpinned files in the snapshot folder}}`. Whether the loading library would read such a file depends on its own file choice, which this book did not test. The check makes the folder's contents visible. It runs before the load, so it does not stop a file being changed after it.

The scanner check is the part to read closely. The script builds, in memory, a pickle whose only action is to call `print`, and it scans that pickle by reading its opcodes. Nothing is unpickled, and `print` never runs. This is the one test pickle in the book, and the book builds nothing that runs a command. The scanner is picklescan at version `{{version:picklescan}}`. It reports the pickle as suspicious, not infected: `{{out:model-file-checks:picklescan infected files}}` infected files, `{{out:model-file-checks:picklescan suspicious globals}}` suspicious global and `{{out:model-file-checks:picklescan dangerous globals}}` dangerous globals. The one global is `__builtin__.print`, marked `{{out:model-file-checks:picklescan global, __builtin__.print}}`. The module is written `__builtin__` because the pickle is written with protocol 2, and protocols 0 to 2 record builtins under that name.

Read that verdict as a finding, not as a label. The scanner checks each global against a table of names. The version pinned here lists builtins such as `eval`, `exec` and `open` in its table of unsafe globals, and `print` is not in that part of the table, so the scanner marks it suspicious rather than dangerous. A scanner's verdict is a finding about the names it checks. It is not a statement that the file is safe, and the book's rule is to refuse the format rather than trust a report.

A matching hash shows that the file is the one that was reviewed. It does not show that the file is safe, and it covers the seven files of the classifier, not every model the office could load.

What goes wrong when the rule is skipped is plain. A team that loads a pickle from a repository nobody reviewed runs that file's code in the assistant's own process, next to the tools and the data the assistant holds. The scanner might catch the file, or it might not, and the team learns which only after the load. Refusing the format removes that bet.

**Working rule:** Load only safetensors weights, from a pinned commit, and check the SHA-256 and size of every file the loader reads. Refuse pickle-format files, and never unpickle one to inspect it. When a scanner reports a file, treat its verdict as a finding about the names it checks, and keep the hash check on the files it did not cover.

## Dependency pins {#dependency-pins}

The primary control is the exact version pin, which says which release gets installed. A hash is the second layer, and this book's file does not yet carry one. A version pin does not say which bytes come with that release. A requirement such as `package==1.2.3` fixes the version, and a hash fixes the file. The hash is what makes a rebuilt environment match the reviewed one.

Production builds go wrong in a familiar way. A rebuild a month later installs a different release of a package that nobody listed, because a dependency of a dependency was left unpinned. The file the team reviewed no longer describes the environment that runs. The requirements file here is compiled, so it lists those indirect packages too, and its comment lines name the package each one comes from. Every requirement in it should therefore be an exact pin.

The check reads a JSON copy of the requirements file, `data/third-party/requirements.json`, not the file itself. The book's runner copies data files and not the example's own folder. The copy records the file it came from, and the two must stay equal.

[Example: dependency-pin-check](../examples/dependency-pin-check.py)

A line is judged on its exact text. A comment or blank line is skipped, and each requirement line must be an exact `name==version`. A leading or trailing space, an environment marker, a URL, a wildcard, an extra or a `#` after the pin makes the line refused. The file has `{{out:dependency-pin-check:exact == pins}}` requirement lines with `==`, and `{{out:dependency-pin-check:refused requirement lines}}` refused. The check skipped `{{out:dependency-pin-check:comment and blank lines skipped}}` comment and blank lines.

The file has `{{out:dependency-pin-check:allowed option lines}}` allowed option line, the extra index for the CPU build of PyTorch. Any other option is refused: an include, an editable install, a constraints file, or a second index. The check refused none of them. The file has `{{out:dependency-pin-check:hash options}}` `--hash` options, so it pins versions without pinning the bytes behind them. That is the gap. A line such as `package==1.2.3` is satisfied by whichever file the index serves for that version, unless something checks the file's hash.

The hash check belongs to the installer, and this book's examples do not run an installer. The pip documentation sets the rule that once one requirement has a hash, hashes become required for all of them, and that requirements must be pinned to a URL, a path or `==` ([pip, secure installs](https://pip.pypa.io/en/stable/topics/secure-installs/)). The uv page for `pip compile` says that to check runtime dependencies with `uv pip install` or `uv pip sync`, one uses `--require-hashes` ([uv, pip compile](https://docs.astral.sh/uv/pip/compile/)). The book does not claim how uv behaves beyond that sentence.

Pinning and hashing do different jobs, and this chapter keeps them apart. The `==` pins fix versions, which the example checks, and the hashes fix bytes, which the file does not yet carry. A CI rule that failed on any line without an exact pin would keep the file in this state; that rule is a recommendation the book does not run.

When a pin changes on purpose, the change should arrive as a reviewed diff of the requirements file, with the reason in the commit message. A build that rewrote the file on its own would move the pins without anyone reading them, which is the same failure as a pipeline that regenerates tool pins.

A pin shows that a definition, a model file or a requirement is unchanged since it was reviewed, and a hash shows that a file is unchanged. Neither shows that the thing is safe. The behaviour check, the format rule and the review narrow that risk, each within the limits this chapter states, and the examples in this chapter show where each one stops.

**Working rule:** Pin every requirement with `==`, and record a hash for each line, so that an install fails on any changed byte. Until the hashes are in place, say that the versions are fixed and not that the bytes are.
