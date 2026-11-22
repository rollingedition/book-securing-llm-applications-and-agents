---
chapter_id: threat-model
---

# Draw the assistant's threat model

By the end of this chapter you can draw an assistant's threat model: its assets, the places where text from outside enters it, the flows that carry that text to the model and its tools, and the channels an attacker would use to get data out. You'll count the legs of the lethal trifecta for each tool and for the whole assistant, check that count against Meta's Rule of Two, and map each risk to the OWASP entry that names it.

The office's assistant, from [chapter 1](#the-office-and-its-assistant), read an inbox message, looked up a tenant and fetched a page. The attack in that chapter worked through those three steps, and it was one attack. A test of one attack shows what that attack did. It doesn't show what else the assistant can reach. Before any defence is chosen, you need a list of what the assistant touches, where the text it reads comes from, and which paths lead out of the office. This chapter draws that list from the office's own code, and the claims about the office come with an example you can run.

## Assets and trust {#assets-and-trust}

An asset is anything the office would lose, or anything an attacker would want: a record, a secret, or the ability to act for the office. A trust boundary is the point where text of a different origin enters the assistant's context. Text on the far side of a boundary, such as a tenant's message or a contractor's tool description, has no authority over the assistant. The model still reads it in the same stream as the office's own instructions, so the boundary is a fact about where the text came from, not something the model enforces by itself.

The office has four assets. The first is tenant records: name, unit, phone number, rent balance and bank reference, all returned by one tool. The second is the hidden context in the system prompt, which holds the office's internal bank-reconciliation note and a portal key. The key is fake, and no example prints its value, but an attacker would still want it. The third is the ability to act: sending a message, which lands in an outbox the scorers read, and booking a contractor's visit. The fourth is the reply itself. The web view renders it as Markdown, so a link or an image in the reply is a channel out of the office. [Chapter 7](#exfiltration-channels) deals with that channel.

A record matters because of who receives it. A tenant may know their own bank reference, and the assistant is meant to read it back to them. What the office would lose is the assistant handing a tenant's record to someone who asked for a different tenant, or to an address outside the office. That is why the asset is named by its route out as well as by its contents, and why the threat model has to follow the record to the tool that returns it and from there to every channel that can carry it.

To find which tools reach these assets, the book reads the tool code instead of the design notes.

[Example: threat-tool-table](../examples/threat-tool-table.py)

Only one tool returns private records, and the example asserts it. The listing prints one line per tool for what it reads, what it writes, whether its output carries outside text, whether its definition came from a third party, whether it reaches outside the office, and whether it returns private records. The assistant is offered {{out:threat-tool-table:tools in SPECS}} tools, the same number the prompt's tool list names. Six belong to the office. Two, `list_slots` and `book_visit`, come from the contractor, and their definitions were written outside the office.

Output is the harder column. {{out:threat-trifecta-check:tools whose output carries outside text}} tools return text that someone outside the office wrote. Four are office tools: `list_messages` and `read_message` return inbox messages, `search_documents` returns documents, and `fetch_page` returns a page. The fifth is `list_slots`, which returns a slot's note, and the contractor may write that note. So "untrusted output" is a property of each result. A tool's name doesn't settle it, and a tool that looks internal can carry outside text.

The table also shows that the prompt holds the portal key and the internal note on every episode, whichever tools are offered, so a count of tools misses those values. The code asserts this. Removing a tool removes the path to the records it reads, but not the values that sit in the prompt. [Chapter 9](#secrets-and-records) takes up that problem and makes a promise about it: the book measures what happens to these values when they are kept out of the prompt.

**Working rule:** Draw the assets and boundaries from the code's list of tools, not from the design document. For each tool the model is offered, record what it reads, what it writes, which results carry outside text and whether its definition came from outside. Check the count against the prompt's tool list. A tool in one list and missing from the other is a gap in the model you're drawing.

## Data flows {#data-flows}

A data flow follows a piece of text from the place it was written to the point where the model reads it. Each boundary has a carrier, which is the field of the assistant's state that holds the text, and a channel, which is the way that text reaches the model. In the office there are two kinds of carrier. The first is text inside a result the assistant asked for: an inbox message, a document from an upload or from the search index, a fetched page, or a contractor slot's note. That text arrives when the assistant calls a tool. The second is text inside a tool's definition: the name, description and schema that the model sees in every prompt, whether or not it calls that tool. Tool poisoning puts instructions for the model into a tool's definition, and [Model Context Protocol in Practice, chapter 9](https://rollingedition.com/model-context-protocol-in-practice/s/tool-poisoning) covers it. The first kind arrives when the model asks for it. The second arrives every time. The second kind matters more than its size suggests. A definition is read before the model chooses a tool, so it can change which tool gets called, not only what a call returns.

The six places where outside text can enter are the locations the attack set uses. [Chapter 3](#goals-locations-styles) defines them and says how the cases were built. The example prints them with a `loc-` prefix, and this book drops the prefix.

[Example: threat-flows](../examples/threat-flows.py)

Each location has one carrier and one delivering channel, and the example checks both. The listing gives each one:

| Location | Carrier | Reaches the model through |
| --- | --- | --- |
| `inbox` | an inbox message | `read_message` |
| `upload` | a document a tenant uploads | `search_documents` |
| `index` | a document already in the search index | `search_documents` |
| `page` | a fixture page | `fetch_page` |
| `server-output` | a slot's note from the contractor | `list_slots` |
| `tool-description` | a contractor tool's definition | the prompt's tool list, with no call |

Two locations share a channel. `upload` and `index` both reach the model through `search_documents`, because in both cases the text sits in a document the search returns. The counts here are over the {{out:threat-flows:fixed cases}} fixed attack cases, dev and held-out together. Chapter 1's {{out:threat-flows:rough cases, chapter 1's set, not counted}} rough cases are left out. Of the fixed cases, {{out:threat-flows:loc-inbox, fixed cases}} arrive through the inbox and {{out:threat-flows:loc-page, fixed cases}} through a page. These counts describe how the set is built, so they say nothing about how often the assistant follows an attack.

The output also records which other tools read a location's field without carrying its text to the model. `list_messages` reads the inbox that way, but the attack set puts its text in the message body, and `list_messages` doesn't return the body. It does return the sender and subject, which outsiders write, and the trifecta count below counts that as outside text. `book_visit` reads the slots without carrying their notes, so the note's channel is `list_slots`. Those reads don't add a channel for the attack set, so a reader counting channels can skip them.

The flows also show the way out, and the outward paths are the ones a defence has to cut. `send_message` writes to the outbox, which holds accepted messages that nothing delivers. `fetch_page` records the URL it was asked for, and that URL can carry data in its query. `book_visit` sends its arguments to the contractor's server, so it is outward even though the booking is one the office wants. The reply's links and images leave when the web view renders them. [Chapter 1](#an-outbound-allowlist) measures an allowlist on the first two channels and says what it can't see: the rendered reply ([what the allowlist cannot see](#what-the-allowlist-cannot-see)).

Follow [the attack from chapter 1](#the-attack-that-works) through these tables and it becomes a path. The injected text entered at the inbox. The assistant read it through `read_message`, which put the text in the model's context. The text then led the model to `lookup_tenant` and to `fetch_page`, and each of those steps is a flow from one carrier to one channel. A threat model is the set of such paths the assistant can take, from every location to every outward channel. The attack is one path in that set. The chapter's job is to list the others, so that a defence on one path is not mistaken for a defence on all of them.

**Working rule:** For each location, name its carrier and the tool that delivers it, and mark whether the text arrives when the model asks or on every prompt. Count a location as a channel only when some delivery reaches the model. Read the outward flows the same way, because an allowlist on one channel says nothing about the others.

## The trifecta and the rule of two {#the-trifecta-and-the-rule-of-two}

Simon Willison named the lethal trifecta in [a June 2025 post](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/). It has three legs: access to private data, exposure to untrusted content, and a way to communicate externally. His point is about data theft: an agent that combines the three can be tricked into reading private data and sending it to an attacker. Removing a leg closes that path. It doesn't close every attack. The book's own booking attack and deposit-figure attack need no private data. One makes the assistant book a visit nobody asked for, and the other makes it state a poisoned figure as the answer. [Chapter 6](#least-privilege) and [chapter 9](#secrets-and-records) deal with the attacks that act or mislead without taking data. Willison's advice was to avoid the combination in one agent, and the trifecta is a framing from one author, widely cited.

Meta turned the same idea into a design rule in [a post of 31 October 2025](https://ai.meta.com/blog/practical-ai-agent-security/), which it calls the Agents Rule of Two. The rule says an agent session should combine no more than two of three properties: processing untrustworthy inputs, reaching sensitive systems or private data, and changing state or communicating externally. The post says the rule should hold until prompt injection can be reliably detected and refused, and it describes prompt injection as an unsolved weakness of LLMs in general. An agent that needs all three should not run on its own; it needs supervision, such as a person approving its actions. [Chapter 6](#least-privilege) builds on that clause. The post also points to Meta's own protection tools. This book treats the rule as a check on a design, not a measured defence, and no result in this chapter shows that it reduces attacks.

[Example: threat-trifecta-check](../examples/threat-trifecta-check.py)

Here the count is taken over tools, and none of the {{out:threat-trifecta-check:tools checked}} tools holds all three legs. `lookup_tenant` holds the private leg alone, `send_message` holds the outward leg alone, and `fetch_page`, `book_visit` and `list_slots` hold two legs each, untrusted and outward. The untrusted leg sits on {{out:threat-trifecta-check:tools holding the untrusted leg}} tools in all. It has two sources: a result that carries outside text, or a third-party definition. Five tools hold it through their output: `fetch_page`, `list_messages`, `list_slots`, `read_message` and `search_documents`. `book_visit` holds it by definition alone. Its output is the contractor's booking, not outside text, but the contractor wrote its definition, and the example counts a third-party definition as untrusted, since the model reads that definition on every prompt. Taken together, the assistant as offered holds all three legs. Removing the private tools leaves two, and so does removing the untrusted tools or the outward tools. By this count, the Rule of Two holds with any one leg removed. The code asserts each of those results, so a change to a tool that breaks one fails the run.

When a reviewer reads a trifecta count, three questions matter more than the total: which tools the model is offered, which text reaches its prompt by any route, and which channels can carry data out of the office. The count answers the first question only. The other two need the [flows](#data-flows) from the previous section.

The count is taken over tools, and that is where it breaks: a run can read private data and never send it, as [chapter 3](#undefended-baseline) shows. The success count has the same blind spot: a run where private data entered the context but never left counts as a failure. With the private tools removed, the example still finds the private values in the prompt. The portal key and the internal note are there on every episode, so the session still holds the private leg, and the model can still send those values out by the outward tools if an injected instruction asks. The working unit here is what reaches the model, not the list of tools.

The contractor's tools make the outward leg harder to reason about. `list_slots` and `book_visit` are outward, and their definitions come from the contractor, so the office didn't write the text the model reads about them. `book_visit` sends its arguments to the contractor's server, which means an argument the user never asked for leaves the office even when the booking itself is wanted. [Chapter 6](#least-privilege) writes argument policies for calls like this one, and [chapter 10](#third-party-parts) covers the contractor's server and definitions. [Chapter 8](#isolation-by-design) builds a design that cuts the untrusted leg from the tools: one model reads the outside text with no tools, and a second model with tools never sees that text raw.

**Working rule:** Count the legs for every tool you offer. Then remove each leg's tools in turn and count again, and count the private leg by what reaches the prompt as well as by which tools read it.

## Risks mapped {#risks-mapped}

A risk has a name, and the lists that describe it give it a number. A reader who meets "goal hijack" in one place and ASI01 in another needs to know they are the same risk. This book maps each risk to the entry that names it. The entries come from two lists. The [OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications/) was published on 9 December 2025 and numbers its entries ASI01 to ASI10. The OWASP GenAI LLM Top 10 2026 is cited by its pinned release, [v1.0 on Zenodo](https://doi.org/10.5281/zenodo.22109014). OWASP publishes both under openly licensed terms with share-alike conditions, so this book gives names and IDs and explains each risk in its own words. It does not reproduce the lists' descriptions.

Only some IDs are confirmed for this book. Where the book has not confirmed an ID, the table below names the risk in words and leaves the ID out. The MITRE ATLAS matrix also has techniques for these attacks, but the release the book pins has not been confirmed, so this chapter prints no ATLAS technique IDs. A technique ID printed against an unconfirmed release would be a claim the reader can't check.

| Risk, in this book's words | Entry (ASI, Dec 9, 2025; LLM 2026) | Where the office shows it | Chapter |
| --- | --- | --- | --- |
| Text the assistant reads changes what it is trying to do | ASI01 Agent Goal Hijack; LLM01:2026 Prompt Injection | `inbox`, `upload`, `index`, `page` | [3](#attack-set), [4](#prompt-defences), [5](#injection-detectors) |
| A tool is used for something the user didn't ask for | ASI02 Tool Misuse & Exploitation | `send_message`, `book_visit` | [6](#least-privilege) |
| The assistant uses its authority on a name an attacker supplies | ASI03 Identity & Privilege Abuse | `lookup_tenant` | [6](#least-privilege), [9](#secrets-and-records) |
| The assistant has more power than its task needs | LLM03:2026 Excessive Agency | every tool, on every task | [6](#least-privilege) |
| A third party's definitions or outputs enter the prompt | ASI04 Agentic Supply Chain Vulnerabilities | `list_slots`, `book_visit` | [10](#third-party-parts) |
| Private values in the prompt leave by an outward channel | LLM02:2026 Sensitive Information Disclosure; LLM08:2026 Hidden Context Exposure | the system prompt, tenant records | [9](#secrets-and-records) |
| A poisoned figure in a document becomes the assistant's answer | ASI06 Memory & Context Poisoning | `search_documents` | [9](#secrets-and-records) |
| The reply loads a link or image that carries data out | LLM10:2026 Improper Output Handling | the rendered reply | [7](#exfiltration-channels) |

Two notes on the table. The mapping is this book's reading of each entry's name and scope, not a statement by OWASP about this office. And the row about the poisoned figure is the book's own placement: the attack set's wrong-deposit goal is the case the row describes, and [chapter 9](#secrets-and-records) is where the book looks at it.

Read each row from left to right. The risk is the reader's question, the entry is the name a reader will find in the source, the office column says where the question arises in this case, and the chapter column says where the book measures an answer, and for the first row that is the baseline in chapter 3. The table also shows what a threat model is for. Each row names an entry, a place in the office, and the chapter that measures a defence against it. Every row here has a chapter. A row that had none would be a risk the book doesn't test, and the text would say so.

A threat model is finished when every path from a location to an outward channel is either covered by a row, or stated as not measured. A list of risks alone doesn't finish it. The paths matter more than the names, because a defence is placed on a path, and a path it misses stays open. A table is not coverage. The reviewer checks each outward path against a row, and a path with no row is open, whatever the table's length.

A model drawn from the design document misses what the code does. A tool added in a later change is then missing from the picture, and the trifecta gets counted on the tools the designers remember. Draw the model again whenever a tool is added or a definition changes, and let the code's tool list, not the document, decide what is in it.

Decisions this chapter made:
- The threat model is drawn from the code: eight tools, six from the office and two from the contractor.
- Legs are counted over what reaches the model's prompt as well as over tools.
- ASI and LLM IDs are printed only where confirmed for this book. The other risks are named in words.
- No MITRE ATLAS IDs or release number are printed until the release is confirmed.

**Working rule:** Map a risk to an entry only with an ID the book has confirmed, and name it in words otherwise. Give every row a chapter that measures a defence, or say in the text that the risk is not measured.
