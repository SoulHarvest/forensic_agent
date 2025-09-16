import argparse
import os
import subprocess
import textwrap
from datetime import datetime, timezone
from hashlib import sha1
from typing import List

from dotenv import load_dotenv
from openai import OpenAI

import chromadb
from chromadb.utils import embedding_functions
from rich.console import Console
from rich.panel import Panel
from rich.markdown import Markdown

console = Console()

CHROMA_PATH = "rag_store/chroma"  # on-disk persistence for Chroma

# ======================
# Config
# ======================
MODEL_CHAT = "gpt-5"
MODEL_EMBED = "text-embedding-3-small"

CHUNK_MAX_LINES = 200              # chunk plugin output into <= this many lines
CHUNK_MAX_CHARS = 6000             # and never exceed this many characters
RETRIEVE_TOP_K = 6                 # default number of chunks to retrieve
VOL_TIMEOUT_SECONDS = 300          # per plugin
MAX_CONTEXT_CHARS = 16000          # max total chars from retrieved chunks
VOL_RENDERER = "json"  # force Volatility output into JSON (safer encoding)

# Default plugins
DEFAULT_PLUGINS = [
    ["windows.info"],
    ["windows.pslist", "--physical"],
    ["windows.cmdline"],
    ["windows.netscan"],
    ["windows.driverscan"],
]

# ======================
# Utilities
# ======================

def get_chroma_collection():
    os.makedirs(CHROMA_PATH, exist_ok=True)
    client = chromadb.PersistentClient(path=CHROMA_PATH)
    openai_ef = get_openai_embedding_fn()  # attach here
    coll = client.get_or_create_collection(
        name="volatility_chunks",
        metadata={"hnsw:space": "cosine"},
        embedding_function=openai_ef
    )
    return coll

def get_openai_embedding_fn():
    # Uses the same MODEL_EMBED you already set (e.g., "text-embedding-3-small")
    return embedding_functions.OpenAIEmbeddingFunction(
        api_key=os.environ["OPENAI_API_KEY"],
        model_name=MODEL_EMBED
    )

def now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")

def ensure_dirs(path: str) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)

def vol_exe_path() -> str:
    # Prefer venv vol.exe, else system 'vol'
    venv_vol = os.path.join(".venv", "Scripts", "vol.exe")
    return venv_vol if os.path.exists(venv_vol) else "vol"

def run_cmd(cmd: list[str]) -> tuple[int, str, str]:
    env = os.environ.copy()
    env["PYTHONUTF8"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",      # read as UTF-8
        errors="replace",      # don’t crash on weird glyphs
        env=env,               # 👈 force UTF-8 inside vol.exe process
    )
    try:
        out, err = proc.communicate(timeout=VOL_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        proc.kill()
        out, err = proc.communicate()
        err = (err or "") + "\n[ERROR] Command timed out."
    return proc.returncode, out or "", err or ""

def chunk_text(s: str, max_lines: int = CHUNK_MAX_LINES, max_chars: int = CHUNK_MAX_CHARS) -> List[str]:
    """Chunk by lines, but respect a char ceiling too."""
    lines = s.splitlines()
    chunks, current, char_count = [], [], 0
    for line in lines:
        # If adding this line would overflow, flush current
        if len(current) >= max_lines or (char_count + len(line) + 1) > max_chars:
            if current:
                chunks.append("\n".join(current))
            current, char_count = [], 0
        current.append(line)
        char_count += len(line) + 1
    if current:
        chunks.append("\n".join(current))
    # Empty output still produces one empty chunk to keep alignment
    if not chunks:
        chunks = [""]
    return chunks

# ======================
# Embedding + Chat
# ======================

def embed_texts(client: OpenAI, texts: List[str]) -> List[List[float]]:
    resp = client.embeddings.create(model=MODEL_EMBED, input=texts)
    return [d.embedding for d in resp.data]

def build_chat_prompt(question: str, context_docs: List[dict]) -> List[dict]:
    # Fill with as many chunks as we can within MAX_CONTEXT_CHARS
    used = 0
    blocks = []
    for d in context_docs:
        chunk = f"# Source {d['id']} | {d['plugin']} | chunk {d['chunk_index']}\n{d['content']}\n"
        if used + len(chunk) > MAX_CONTEXT_CHARS and blocks:
            break
        blocks.append(chunk)
        used += len(chunk)

    context_blob = "\n\n".join(blocks) if blocks else "(no relevant context)"
    system = (
        "You are a precise, cautious DFIR analyst. "
        "Answer based ONLY on the provided memory forensics context. "
        "If context is insufficient, say so and suggest the next Volatility step. "
        "Cite sources inline as [Source <id>], and include a short 'Next steps' list."
    )
    user = textwrap.dedent(f"""
    Question: {question}

    Context (Volatility outputs, chunked):
    {context_blob}
    """).strip()

    return [
        {"role": "system", "content": system},
        {"role": "user", "content": user},
    ]

# ======================
# Volatility + Indexing
# ======================

def resolve_plugins(user_list: list[str] | None) -> list[list[str]]:
    if not user_list:
        return DEFAULT_PLUGINS
    raw: list[list[str]] = []
    for item in user_list:
        for part in item.split(","):
            argv = part.strip().split()       # split into argv (e.g. ["windows.malfind", "--pid", "948"])
            if argv:
                raw.append(argv)
    return raw

def run_volatility_and_index(image_path: str, plugins: List[List[str]]):
    coll = get_chroma_collection()
    vol = vol_exe_path()

    for argv in plugins:
        name = " ".join(argv)
        cmd = [vol, "-f", image_path, "-r", VOL_RENDERER] + argv
        print(f"[vol] Running: {' '.join(cmd)}")
        rc, out, err = run_cmd(cmd)
        if rc != 0:
            print(f"[vol] WARN plugin failed (exit={rc}): {name}")
            if err:
                print(f"[vol] stderr:\n{err}")

        text = ""
        if err.strip():
            text += "STDERR:\n" + err.strip() + "\n\n"
        text += "STDOUT:\n" + (out or "").strip()

        chunks = chunk_text(text, CHUNK_MAX_LINES, CHUNK_MAX_CHARS)
        print(f"[vol] -> {len(chunks)} chunks")

        # add each chunk to Chroma
        for idx, content in enumerate(chunks):
            doc_id = sha1((name + " " + " ".join(cmd) + f"#{idx}" + content).encode("utf-8", "ignore")).hexdigest()

            # skip if already present
            existing = coll.get(ids=[doc_id])
            if existing and existing.get("ids") and existing["ids"]:
                continue

            coll.add(
                ids=[doc_id],
                documents=[content],
                metadatas=[{
                    "plugin": name,
                    "command": " ".join(cmd),
                    "chunk_index": idx,
                    "image_path": image_path,
                    "created_at_utc": now_utc(),
                }],
            )

def retrieve_with_chroma(question: str, top_k: int, where: dict | None = None) -> List[dict]:
    coll = get_chroma_collection()
    res = coll.query(query_texts=[question], n_results=top_k, where=where)

    docs = []
    if res and res.get("ids") and res["ids"] and res["ids"][0]:
        for i in range(len(res["ids"][0])):
            docs.append({
                "id": res["ids"][0][i],
                "plugin": res["metadatas"][0][i].get("plugin", ""),
                "command": res["metadatas"][0][i].get("command", ""),
                "chunk_index": res["metadatas"][0][i].get("chunk_index", -1),
                "content": res["documents"][0][i],
            })
    return docs

def summarize_source(d: dict, max_len: int = 120) -> str:
    """
    Summarize a source chunk for human-readable traceability.
    Shows plugin + chunk index + a preview line.
    """
    # split into lines, skip empty ones
    lines = [ln.strip() for ln in d["content"].splitlines() if ln.strip()]
    preview = ""
    for ln in lines:
        # skip STDOUT/STDERR headers
        if ln.startswith("STDERR:") or ln.startswith("STDOUT:"):
            continue
        preview = ln
        break
    if not preview and lines:
        preview = lines[0]
    if len(preview) > max_len:
        preview = preview[:max_len - 1] + "…"

    return f"[{d['plugin']} | chunk {d['chunk_index']}] {preview}"
# ======================
# Subcommands
# ======================

def cmd_index(args):
    load_dotenv()
    image = os.path.abspath(args.image)
    if not os.path.exists(image):
        raise SystemExit(f"[!] Image not found: {image}")

    plugins = resolve_plugins(args.plugins)
    print(f"[+] Indexing image: {image}")
    print(f"[+] Using Chroma path: {os.path.abspath(CHROMA_PATH)}")
    run_volatility_and_index(image, plugins)
    print("[+] Indexing complete.")

def cmd_ask(args):
    load_dotenv()
    client = OpenAI()
    context_docs = retrieve_with_chroma(args.query, args.topk)
    if not context_docs:
        print("[!] No indexed data yet. Run 'index' first.")
        return
    messages = build_chat_prompt(args.query, context_docs)
    resp = client.chat.completions.create(model=MODEL_CHAT, messages=messages)
    answer = (resp.choices[0].message.content or "").strip()

    ensure_dirs("answers/answer.md")
    out_path = args.out or f"answers/answer_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.md"
    header = f"# Answer\n- Model: `{MODEL_CHAT}`\n- Time: {now_utc()}\n\n"
    srcs = "\n".join([
    f"- [id: {d['id']}] {summarize_source(d)}"
    for d in context_docs
])
    footer = f"\n\n---\n## Sources used\n{srcs}\n"
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(header + answer + footer)

    console.print(Panel.fit(Markdown(answer), title="Answer", border_style="cyan"))
    console.print(Panel.fit(
       Markdown("\n".join([f"- {summarize_source(d)}" for d in context_docs]) or "_(no sources)_"),
        title="Sources used",
       border_style="magenta"
   ))
    print(f"\n[+] Saved to {out_path}")

def cmd_chat(args):
    load_dotenv()
    client = OpenAI()
    print("RAG chat. Type your question and press Enter. Type 'exit' to quit.")
    while True:
        try:
            q = input("\n> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nBye.")
            return
        if not q:
            continue
        if q.lower() in {"exit", "quit"}:
            print("Bye.")
            return
        context_docs = retrieve_with_chroma(q, args.topk)
        if not context_docs:
            print("[!] No indexed data yet. Run 'index' first.")
            continue
        messages = build_chat_prompt(q, context_docs)
        resp = client.chat.completions.create(model=MODEL_CHAT, messages=messages)
        print("\n" + (resp.choices[0].message.content or "").strip())
        ans = (resp.choices[0].message.content or "").strip()
        console.print(Panel.fit(Markdown(ans), title="Answer", border_style="cyan"))
        console.print(Panel.fit(
            Markdown("\n".join([f"- {summarize_source(d)}" for d in context_docs]) or "_(no sources)_"),
            title="Sources used",
            border_style="magenta"
        ))
# ======================
# Main
# ======================

def main():
    parser = argparse.ArgumentParser(description="Volatility + RAG: index, ask, and chat over a memory dump.")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_index = sub.add_parser("index", help="Run Volatility plugins, chunk + embed outputs into a Chroma vector store.")
    p_index.add_argument("-f", "--image", required=True, help="Path to memory image (e.g., dump.raw)")
    p_index.add_argument("--plugins", nargs="*", default=None,
                     help="Full plugin names (space- or comma-separated). e.g. --plugins windows.pslist windows.cmdline")
    p_index.set_defaults(func=cmd_index)

    p_ask = sub.add_parser("ask", help="Ask a one-off question using RAG retrieval (Chroma).")
    p_ask.add_argument("-q", "--query", required=True, help="Your question.")
    p_ask.add_argument("--topk", type=int, default=RETRIEVE_TOP_K, help=f"How many chunks to retrieve (default {RETRIEVE_TOP_K})")
    p_ask.add_argument("-o", "--out", default=None, help="Write the answer to this file (default answers/answer_<timestamp>.md)")
    p_ask.set_defaults(func=cmd_ask)

    p_chat = sub.add_parser("chat", help="Interactive chat with retrieval on each turn (Chroma).")
    p_chat.add_argument("--topk", type=int, default=RETRIEVE_TOP_K, help=f"How many chunks to retrieve (default {RETRIEVE_TOP_K})")
    p_chat.set_defaults(func=cmd_chat)


    args = parser.parse_args()
    args.func(args)

if __name__ == "__main__":
    main()

