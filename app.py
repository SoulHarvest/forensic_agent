# app.py
import json
import pandas as pd
import os
import sys
import shlex
import subprocess
from subprocess import PIPE, Popen
from datetime import datetime
from pathlib import Path
import streamlit as st
from dotenv import load_dotenv
import os, subprocess
from shutil import which

def vol_path() -> str:
    venv_vol = Path(".venv") / "Scripts" / "vol.exe"
    return str(venv_vol) if venv_vol.exists() else "vol"

@st.cache_data(show_spinner=False)
def run_vol_json(image_path: str, plugin: str, *extra_args: str) -> dict:
    """Run vol with JSON renderer and cache the parsed JSON."""
    cmd = [vol_path(), "-f", image_path, "-r", "json", plugin, *extra_args]
    proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr or f"vol failed: {cmd}")
    try:
        return json.loads(proc.stdout or "{}")
    except json.JSONDecodeError:
        # Some plugins print logs + JSON; try to find the JSON blob
        s = proc.stdout
        start = s.find("{")
        end = s.rfind("}")
        return json.loads(s[start:end+1])

def rows_to_df(vol_json: dict) -> pd.DataFrame:
    """Vol3 JSON typically has header/rows or just rows with dicts."""
    if not vol_json:
        return pd.DataFrame()
    # Case 1: already list of dicts
    if isinstance(vol_json, list):
        return pd.DataFrame(vol_json)
    # Case 2: common Vol3 schema
    rows = vol_json.get("rows") or vol_json.get("data") or []
    if rows and isinstance(rows[0], dict):
        return pd.DataFrame(rows)
    # Case 3: rows as lists + separate columns
    cols = vol_json.get("columns") or []
    if rows and cols:
        return pd.DataFrame(rows, columns=cols)
    return pd.DataFrame(rows)

def try_parse_vol_json(s: str) -> dict:
    """Best-effort parse of Volatility JSON (some plugins print logs + JSON)."""
    s = (s or "").strip()
    if not s:
        return {}
    try:
        return json.loads(s)
    except json.JSONDecodeError:
        # Try to extract the largest JSON-looking slice
        start = s.find("{")
        end = s.rfind("}")
        if start != -1 and end != -1 and end > start:
            try:
                return json.loads(s[start:end + 1])
            except Exception:
                return {}
        # Array form
        if s.startswith("[") and s.endswith("]"):
            try:
                return json.loads(s)
            except Exception:
                return {}
        return {}

def rows_to_df(vol_json: dict) -> pd.DataFrame:
    """Normalize common Vol3 JSON shapes into a DataFrame."""
    if not vol_json:
        return pd.DataFrame()
    # Already a list of dicts
    if isinstance(vol_json, list):
        return pd.DataFrame(vol_json)
    # Common Vol3 schema variations
    rows = vol_json.get("rows") or vol_json.get("data") or []
    cols = vol_json.get("columns") or []
    if rows and isinstance(rows[0], dict):
        return pd.DataFrame(rows)
    if cols and rows:
        return pd.DataFrame(rows, columns=cols)
    return pd.DataFrame(rows)

# --- App config ---
st.set_page_config(page_title="Forensic Agent UI", layout="wide")
load_dotenv()  # so OPENAI_API_KEY is available to subprocess calls

PROJECT_ROOT = Path(__file__).parent
PYTHON = sys.executable                     # ensures we run inside this venv
MAIN = str(PROJECT_ROOT / "main.py")        # your CLI entrypoint

DEFAULT_PRESET = [
    "windows.info",
    "windows.pslist --physical",
    "windows.cmdline",
    "windows.netscan",
    "windows.dlllist",
]

def run_cli(args: list[str]) -> tuple[int, str, str]:
    """Run a subprocess and return rc, stdout, stderr (all as text)."""
    env = os.environ.copy()
    # keep UTF-8 behavior consistent with your CLI
    env["PYTHONUTF8"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"
    proc = subprocess.Popen(
        args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, encoding="utf-8", errors="replace", env=env
    )
    out, err = proc.communicate()
    return proc.returncode, out or "", err or ""

st.title("Forensic Agent (Volatility + RAG)")

# --- Sidebar: image & plugin selection ---
st.sidebar.header("Configuration")

SAMPLES_DIR = PROJECT_ROOT / "samples"
SAMPLES_DIR.mkdir(parents=True, exist_ok=True)

# discover existing images
valid_exts = {".raw", ".mem", ".img", ".dmp", ".bin"}
existing_images = sorted(
    [p for p in SAMPLES_DIR.glob("*") if p.suffix.lower() in valid_exts],
    key=lambda p: p.name.lower()
)

# keep last path
if "img_path" not in st.session_state:
    st.session_state.img_path = str(existing_images[0]) if existing_images else str(SAMPLES_DIR / "MemoryDump_Lab1.raw")

mode = st.sidebar.radio(
    "Choose image source",
    options=["Pick from samples/", "Upload a new image", "Type a local path"],
    index=0 if existing_images else 2
)

# 1) Pick from samples/
if mode == "Pick from samples/":
    if not existing_images:
        st.sidebar.info("No images found in samples/. Switch to upload or type a path.")
    else:
        labels = [f"{p.name}  ({p.stat().st_size/1_048_576:.1f} MB)" for p in existing_images]
        idx = st.sidebar.selectbox("Select an existing image", list(range(len(existing_images))), format_func=lambda i: labels[i])
        chosen = existing_images[idx]
        st.session_state.img_path = str(chosen)

# 2) Upload a new image (saved into samples/)
elif mode == "Upload a new image":
    uploaded = st.sidebar.file_uploader(
        "Upload (.raw, .mem, .img, .dmp, .bin)",
        type=[e.strip(".") for e in valid_exts],
        help="Large files may be slow. Prefer 'Type a local path' for multi-GB images."
    )
    if uploaded is not None:
        save_path = SAMPLES_DIR / uploaded.name
        with open(save_path, "wb") as f:
            f.write(uploaded.getbuffer())
        st.session_state.img_path = str(save_path)
        st.sidebar.success(f"Saved to samples/: {save_path.name}")

# 3) Type a local path (no copy)
else:
    manual = st.sidebar.text_input("Memory image path (local file)", value=st.session_state.img_path)
    st.session_state.img_path = manual

img_path = st.session_state.img_path
st.sidebar.write(f"**Selected path:** `{img_path}`")

# Preset plugins (select as many as you like)
preset_select = st.sidebar.multiselect(
    "Common plugins (preset)",
    options=DEFAULT_PRESET,
    default=["windows.info", "windows.pslist --physical"]
)

# Freeform plugin text (comma or space separated)
freeform = st.sidebar.text_input(
    "Extra plugins (space or comma separated)",
    placeholder="windows.malfind, windows.vadinfo"
)

def parse_plugins(preset_list, free_text):
    # combine preset + freeform, split by comma, then further split into argv tokens
    combined = list(preset_list)
    if free_text.strip():
        # split by comma first (optional groups)
        for chunk in free_text.split(","):
            if chunk.strip():
                combined.append(chunk.strip())
    # Now split each entry into argv (supports flags like --pid 948)
    argv_lists = []
    for entry in combined:
        # shlex.split handles quotes if needed
        tokens = shlex.split(entry)
        if tokens:
            argv_lists.append(" ".join(tokens))  # we pass strings to your CLI which re-splits
    return argv_lists

plugin_entries = parse_plugins(preset_select, freeform)

st.sidebar.write("**Resolved plugins to run:**")
st.sidebar.code("\n".join(plugin_entries) or "(none)")

# --- session state init (put near the top of app.py) ---
if "qa_history" not in st.session_state:
    st.session_state.qa_history = []  # list of dicts: {time, image, q, ans, rc}

MAX_QA = 20  # keep last 20 Q&A
def _push_history(item: dict):
    st.session_state.qa_history.append(item)
    if len(st.session_state.qa_history) > MAX_QA:
        st.session_state.qa_history = st.session_state.qa_history[-MAX_QA:]


st.divider()
st.header("📊 Forensics Dashboard")

if not img_path or not Path(img_path).exists():
    st.info("Select or upload a memory image above to enable the dashboard.")
else:
    tabs = st.tabs(["Processes", "Network", "Services", "Injections"])

    # Processes
    with tabs[0]:
        try:
            js = run_vol_json(img_path, "windows.pslist", "--physical")
            df = rows_to_df(js)
            st.subheader("Processes")
            if not df.empty:
                # Common renames (Vol can vary)
                df = df.rename(columns={
                    "PID": "pid", "PPID": "ppid", "ImageFileName": "image",
                    "CreateTime": "create_time", "ExitTime": "exit_time"
                })
                # Quick filters
                colA, colB = st.columns(2)
                name_filter = colA.text_input("Filter by process name contains", "")
                ppid_filter = colB.number_input("Filter by PPID (optional)", min_value=0, value=0, step=1)
                df_view = df.copy()
                if name_filter:
                    df_view = df_view[df_view.astype(str).apply(lambda r: name_filter.lower() in r.str.lower().to_string(), axis=1)]
                if ppid_filter:
                    df_view = df_view[df_view.get("ppid", 0) == ppid_filter]
                st.dataframe(df_view, use_container_width=True, height=360)
                # Simple chart: top parents by child count
                if "ppid" in df_view.columns:
                    st.caption("Top parent processes by child count")
                    st.bar_chart(df_view["ppid"].value_counts().head(10))
            else:
                st.warning("No pslist rows parsed.")
        except Exception as e:
            st.error(f"pslist error: {e}")

    # Network
    with tabs[1]:
        try:
            js = run_vol_json(img_path, "windows.netscan")
            df = rows_to_df(js)
            st.subheader("Network (netscan)")
            if not df.empty:
                df = df.rename(columns={
                    "LocalAddr": "laddr", "LocalPort": "lport",
                    "ForeignAddr": "raddr", "ForeignPort": "rport",
                    "PID": "pid", "Owner": "owner", "Proto": "proto", "State": "state"
                })
                colA, colB = st.columns(2)
                only_listening = colA.checkbox("Only listening", value=False)
                owner_contains = colB.text_input("Owner contains", "")
                df_view = df.copy()
                if only_listening and "state" in df_view.columns:
                    df_view = df_view[df_view["state"].str.contains("LISTEN", case=False, na=False)]
                if owner_contains and "owner" in df_view.columns:
                    df_view = df_view[df_view["owner"].str.contains(owner_contains, case=False, na=False)]
                st.dataframe(df_view, use_container_width=True, height=360)
            else:
                st.warning("No netscan rows parsed.")
        except Exception as e:
            st.error(f"netscan error: {e}")

    # Services (svcscan)
    with tabs[2]:
        try:
            js = run_vol_json(img_path, "windows.svcscan")
            df = rows_to_df(js)
            st.subheader("Services (svcscan)")
            if not df.empty:
                st.dataframe(df, use_container_width=True, height=360)
                if "ServiceName" in df.columns:
                    st.caption("Top services")
                    st.bar_chart(df["ServiceName"].value_counts().head(20))
            else:
                st.warning("No svcscan rows parsed.")
        except Exception as e:
            st.error(f"svcscan error: {e}")

    # Injections (malfind)
    with tabs[3]:
        try:
            js = run_vol_json(img_path, "windows.malfind")
            df = rows_to_df(js)
            st.subheader("Malfind")
            if not df.empty:
                # Heuristic flags
                rx_cols = [c for c in df.columns if "Protection" in c or "protection" in c]
                if rx_cols:
                    sus = df[df[rx_cols[0]].str.contains("RX|RWX", na=False)]
                    st.write(f"Suspected injected regions: {len(sus)}")
                st.dataframe(df, use_container_width=True, height=360)
            else:
                st.info("No malfind hits parsed.")
        except Exception as e:
            st.error(f"malfind error: {e}")

# --- Main: actions ---
col1, col2 = st.columns(2)

with col1:
    st.subheader("Index")
    st.write("Run Volatility plugins and index outputs into Chroma.")
    if st.button("Run indexing"):
        if not img_path or not Path(img_path).exists():
            st.error("Image path not found. Please set a valid path.")
        elif not plugin_entries:
            st.error("No plugins selected. Choose at least one.")
        else:
            # Build CLI: pass each plugin as a separate argument to --plugins
            args = [PYTHON, MAIN, "index", "-f", img_path, "--plugins"]
            args.extend(plugin_entries)
            with st.spinner("Indexing… this may take a while depending on plugins and image size."):
                rc, out, err = run_cli(args)
            st.success(f"Indexing finished with exit code {rc}")
            if out.strip():
                st.write("**stdout**")
                st.code(out, language="bash")
            if err.strip():
                st.write("**stderr**")
                st.code(err, language="bash")

with col2:
    st.subheader("Ask")
    question = st.text_area(
        "Ask a question about the indexed evidence (natural language)",
        value="Any suspicious processes or unusual service groups? Cite sources."
    )
    topk = st.slider("Top-K retrieved chunks", min_value=4, max_value=40, value=10, step=2)
    if st.button("Ask question"):
        if not question.strip():
            st.error("Please enter a question.")
        else:
            args = [PYTHON, MAIN, "ask", "-q", question, "--topk", str(topk), "-f", img_path]
            with st.spinner("Thinking…"):
                rc, out, err = run_cli(args)
            # Your CLI prints a colored Answer panel + Sources panel; we just render its text.
            st.write(f"**Exit code**: {rc}")
            if out.strip():
                st.markdown("### Output")
                st.code(out)
            if err.strip():
                st.markdown("### stderr")
                st.code(err, language="bash")

# 💡 append to history (store time, image, question, and a compact answer)
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            compact_ans = out.strip()
            if len(compact_ans) > 1200:
                compact_ans = compact_ans[:1200] + "…"
            entry = {
                "time": ts,
                "image": Path(img_path).name if img_path else "(none)",
                "q": question.strip(),
                "ans": compact_ans,
                "rc": rc,
            }
            if "qa_history" in st.session_state:
                st.session_state.qa_history.append(entry)
            else:
                st.session_state.qa_history = [entry]

    st.markdown("### 🧾 Recent questions")
    if st.session_state.qa_history:
        # newest first, last 5
        for item in st.session_state.qa_history[-5:][::-1]:
            st.markdown(
                f"**{item['time']}** — `{item['image']}`  \n"
                f"**Q:** {item['q']}  \n"
                f"**A (excerpt):**\n\n> {item['ans']}"
            )
        # optional: clear button
        if st.button("Clear history"):
            st.session_state.qa_history = []
            st.success("History cleared.")
    else:
        st.caption("_No questions asked yet in this session._")

st.divider()
st.subheader("Volatility Command Output")

COMMON_PLUGINS = [
    "windows.info",
    "windows.pslist",
    "windows.pstree",
    "windows.psscan",
    "windows.cmdline",
    "windows.netscan",
    "windows.dlllist",
    "windows.svcscan",
    "windows.filescan",
    "windows.malfind",
    "windows.netstat",
]

with st.container():
    plugin_cmd = st.selectbox("Select a plugin", options=COMMON_PLUGINS, index=0)
    extra_args = st.text_input("Extra plugin arguments (optional)", placeholder="e.g., --physical or --dump")
    renderer = st.selectbox("Renderer", options=["text", "json"], index=0)  # 👈 choose output style
    also_index = st.toggle("Also index results into Chroma (uses main.py index)", value=True)

    if st.button("Run Volatility"):
        if not img_path or not Path(img_path).exists():
            st.error("Image path not found. Please set or select a valid image in the Index panel.")
        else:
            # Always show a human preview first (text or JSON),
            # then optionally index via your CLI so chunks go into Chroma.
            venv_vol = os.path.join(".venv", "Scripts", "vol.exe")
            vol = venv_vol if os.path.exists(venv_vol) else which("vol") or "vol"

            cmd = [vol, "-f", img_path]
            if renderer == "json":
                cmd += ["-r", "json"]  # JSON for neat DataFrame parsing
            cmd += [plugin_cmd]
            if extra_args.strip():
                cmd.extend(extra_args.split())

            with st.spinner(f"Running `{plugin_cmd}`…"):
                proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
                rc = proc.returncode
                out = proc.stdout or ""
                err = proc.stderr or ""

            st.write(f"**Exit code:** {rc}")

            if out.strip():
                st.markdown("### stdout")
                if renderer == "json":
                    # Show raw JSON for transparency
                    st.code(out, language="json")
                    # And also a tidy table view
                    parsed = try_parse_vol_json(out)
                    df = rows_to_df(parsed)
                    if not df.empty:
                        st.markdown("### Structured Table View")
                        st.dataframe(df, use_container_width=True, height=360)
                    else:
                        st.caption("_No tabular rows parsed from JSON output._")
                else:
                    # text renderer → show as monospace for alignment
                    st.code(out, language="bash")

            if err.strip():
                st.markdown("### stderr")
                st.code(err, language="bash")

            if also_index:
                # Route through your CLI to persist into Chroma
                args = [PYTHON, MAIN, "index", "-f", img_path, "--plugins", plugin_cmd]
                if extra_args.strip():
                    args.extend(extra_args.split())
                with st.spinner(f"Indexing `{plugin_cmd}` into Chroma…"):
                    rc2, out2, err2 = run_cli(args)

                st.markdown("### Index log")
                st.write(f"**Exit code:** {rc2}")
                if out2.strip():
                    st.code(out2, language="bash")
                if err2.strip():
                    st.code(err2, language="bash")

st.divider()
st.caption("Tip: You can run indexing again at any time, then re-ask questions. The app uses the same Chroma store on disk.")
