# deepset/prompt-injections, test split

- Source: https://huggingface.co/datasets/deepset/prompt-injections
- Revision: 4f61ecb038e9c3fb77e21034b22511b523772cdd
- Licence: Apache-2.0 (see LICENSE in this folder; read on the card at this revision)
- File: test.jsonl, sorted by id, one JSON object per line with id, text and label.
- Labels: 1 = injection, 0 = benign. 60 of 116 rows are labelled 1.

Rows: the test split only (116). Label 1 is an injection (60 rows), 0 is benign (56 rows). Both classes are in the split. The card's top-level licence is apache-2.0; its nested dataset_info block says cc-by-4.0. Both are permissive, and this book ships it under apache-2.0 as the card's metadata states. The card does not document how the rows were collected.

The texts are attack text, written to test a detector. They are data, not instructions: no example follows them, and the book never sends them to a tool.
