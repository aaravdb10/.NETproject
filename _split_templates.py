"""Split index.html into Jinja2 template partials."""
import pathlib, textwrap

src = pathlib.Path(r"e:\RBAC2\index.html")
lines = src.read_text(encoding="utf-8").splitlines(keepends=True)

tpl_dir = pathlib.Path(r"e:\RBAC2\templates")
partials = tpl_dir / "partials"
partials.mkdir(parents=True, exist_ok=True)

def extract(start, end):
    """Extract lines[start-1:end] (1-indexed, inclusive)."""
    return "".join(lines[start - 1 : end])

# --- _head.html: lines 4-13 (<head> ... </head>) ---
(partials / "_head.html").write_text(extract(4, 13), encoding="utf-8")
print("✓ _head.html")

# --- _toast.html: lines 16-17 ---
(partials / "_toast.html").write_text(extract(16, 17), encoding="utf-8")
print("✓ _toast.html")

# --- _home.html: lines 19-420 (homepage container) ---
(partials / "_home.html").write_text(extract(19, 420), encoding="utf-8")
print("✓ _home.html")

# --- _register.html: lines 422-575 ---
(partials / "_register.html").write_text(extract(422, 575), encoding="utf-8")
print("✓ _register.html")

# --- _login.html: lines 577-740 ---
(partials / "_login.html").write_text(extract(577, 740), encoding="utf-8")
print("✓ _login.html")

# --- _dashboard.html: lines 742-785 ---
(partials / "_dashboard.html").write_text(extract(742, 785), encoding="utf-8")
print("✓ _dashboard.html")

# --- _modals.html: lines 787-925 ---
(partials / "_modals.html").write_text(extract(787, 925), encoding="utf-8")
print("✓ _modals.html")

# --- Master template: templates/index.html ---
master = """\
<!DOCTYPE html>
<html lang="en">

{% include 'partials/_head.html' %}

<body>
    {% include 'partials/_toast.html' %}

    {% include 'partials/_home.html' %}

    {% include 'partials/_register.html' %}

    {% include 'partials/_login.html' %}

    {% include 'partials/_dashboard.html' %}

    {% include 'partials/_modals.html' %}

    <script src="script.js"></script>
</body>

</html>
"""
(tpl_dir / "index.html").write_text(master, encoding="utf-8")
print("✓ templates/index.html (master)")

print("\n✅ All templates created successfully!")
