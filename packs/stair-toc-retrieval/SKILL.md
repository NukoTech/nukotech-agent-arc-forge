---
name: stair-toc-retrieval
description: >-
  Use when searching a long document, book, manual, or corpus that has a table
  of contents or heading tree, instead of flat chunk RAG. Works with any
  general-purpose LLM.
---
# STAIR table-of-contents retrieval

Source method: IBM Research, STAIR (STructure Aware Information Retriever), arXiv:2609.03874 (3 Sep 2026). Authors: Vineet Kumar, Meghanadh Pulivarthi, Vishwajeet Kumar, Jaydeep Sen, Riyaz Ahmad Bhat, Sachindra Joshi. Benchmark: SearchTome (18 open textbooks, 6 domains).

This skill is a prompt-level pattern any general-purpose LLM can run without per-book fine-tuning. It is not a claim that the model has IBM’s fine-tuned Mistral weights.

## When

Use this when the user asks a question against a long document, book, manual, filing, or help corpus that already has a table of contents, heading outline, or section tree.

Do not use it on a flat pile of notes with no headings. Do not use it to decide fraud, legal guilt, or any automated action against a person.

## What the paper actually measured

STAIR fine-tunes a model so that, given a query plus the full table of contents, it emits one leaf section title. Recall@1 on SearchTome averages 82.6 percent. Comparables in the same table: fine-tuned DSI 76.9, dense DPR (NV-Embed-v2) 68.7, BM25 59.5, Claude Haiku 45.6, untuned Mistral Instruct v0.2 13.8. Recall@3 / nDCG@3 for STAIR average 90.8 / 87.5.

“Hallucination” in the paper means emitting a title that is not a real leaf in that table of contents, not a wrong answer. STAIR did that on 0.05 percent of predictions. DSI did it on 3.25 percent. The paper does not test whether an answer written from the retrieved section is correct.

Training in the paper: one LoRA (r=16, alpha=32) on Mistral Instruct v0.2 per book, up to 200 epochs, early stop patience 20, input up to 14k tokens, output up to 64 tokens. Constrained generation limits the output vocabulary to valid leaf titles. Queries were synthetic questions written by Mixtral 8x7B from each paragraph. The paper has not tested company-scale collections (millions of URLs). It needs a real table of contents. Future work they name: build a ToC on corpora that lack one, and zero-shot multi-hop over leaf text.

## Steps

1. Extract the document’s own outline. Keep parent titles and leaf titles. A leaf is a section that has no children.
2. If there is no outline, stop and say so. Fall back to ordinary keyword or dense retrieval. Do not invent a table of contents and call it STAIR.
3. Put the full outline in the prompt with the user question. Instruct the model: return exactly one leaf title copied from the outline, no explanation. Reject any title that is not an exact leaf in the outline, and retry once with the rejection noted.
4. Open only that leaf’s text (include the parent path as a label). Answer from that text. If the leaf does not contain the answer, say the section was a miss and try the next-best leaf, at most three leaves.
5. Report the section title you used. Do not report the paper’s 82.6 percent as this run’s accuracy. Section match is not answer correctness.
6. Do not fine-tune a per-book model, scrape restricted systems, or spend money unless the user explicitly asks for that experiment.

## Prompt shape (portable)

Book or corpus name.
Instruction: pick the single best leaf section from the outline that can answer the query. Output only the leaf title, copied exactly. No explanation.
Outline: parent headings unmarked; each leaf prefixed with “leaf”.
Query: the user’s question.

## Do not

- Flatten the document into equal token chunks before trying the outline.
- Treat a retrieved section as proof the answer is right.
- Cite 82.6 percent, 0.05 percent, or “65x” as a result of this skill. Those numbers belong only to IBM’s fine-tuned SearchTome runs.
- Install this as an automated tool that files, scores people, or takes action. It is a retrieval habit only.
