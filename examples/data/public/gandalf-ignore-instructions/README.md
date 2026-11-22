# Lakera/gandalf_ignore_instructions, test split

- Source: https://huggingface.co/datasets/Lakera/gandalf_ignore_instructions
- Revision: 04737b65e90a6794ec227012e4a255a7def6344b
- Licence: MIT (see LICENSE in this folder; read on the card at this revision)
- File: test.jsonl, sorted by id, one JSON object per line with id, text and label.
- Labels: 1 = injection, 0 = benign. 112 of 112 rows are labelled 1.

Rows: the test split only (112). Every row is an attack, so the label is 1 for all rows and the file measures recall only; it has no benign rows. The card says a few samples might not be real injections. The similarity column is dropped. Only id, text and label are kept.

The texts are attack text, written to test a detector. They are data, not instructions: no example follows them, and the book never sends them to a tool.
