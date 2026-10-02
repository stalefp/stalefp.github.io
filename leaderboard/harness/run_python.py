"""Run the Python cases of the existing harness (bench.py, next to this file) and save the raw echo JSON per case.

We don't import bench.py directly because importing it runs the whole benchmark and overwrites
tlsbench/results.json. Instead we execute only its imports, helper functions and the URL/CASES
assignments (via the AST), so the leaderboard always uses the same run_* functions and case list.

Usage: run_python.py <outdir> [url]
"""
import ast, json, os, sys, time, traceback

HARNESS = os.path.dirname(os.path.abspath(__file__))
out = sys.argv[1]
url = sys.argv[2] if len(sys.argv) > 2 else None
os.makedirs(out, exist_ok=True)

src = open(os.path.join(HARNESS, "bench.py")).read()
tree = ast.parse(src)
keep = []
for node in tree.body:
    if isinstance(node, (ast.Import, ast.ImportFrom, ast.FunctionDef)):
        if isinstance(node, ast.ImportFrom) and node.module == "fp":
            continue  # bench.py's fp import needs cwd=tlsbench; not needed for raw capture
        keep.append(node)
    elif isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id in ("URL", "CASES") for t in node.targets):
        keep.append(node)
ns = {"__name__": "bench_cases"}
exec(compile(ast.Module(body=keep, type_ignores=[]), "bench.py", "exec"), ns)
if url:
    ns["URL"] = url  # run_* functions read the module-global URL

summary = []
for lib, profile, fn in ns["CASES"]:
    name = f"{lib}_{profile}"
    t0 = time.time()
    try:
        d = fn(profile)
        json.dump(d, open(os.path.join(out, name + ".json"), "w"), indent=1)
        summary.append(dict(lib=lib, profile=profile, ok=True, secs=round(time.time() - t0, 2)))
        print(f"{name:32} ok  ja4={d.get('tls', {}).get('ja4')}", flush=True)
    except Exception as e:
        summary.append(dict(lib=lib, profile=profile, ok=False, err=repr(e)[:300]))
        print(f"{name:32} ERR {repr(e)[:200]}", flush=True)
json.dump(dict(url=ns["URL"], cases=summary), open(os.path.join(out, "_python_summary.json"), "w"), indent=1)
