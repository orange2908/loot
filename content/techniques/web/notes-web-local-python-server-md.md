---
title: "Local Python server (Web)"
category: "web"
type: "technique"
tags: ["my-notes", "personal", "flask", "local", "python", "server", "web"]
summary: "Personal note: Local Python server (Web)."
source:
  name: "Personal notes"
origin_path: "Web/Local Python server.md"
---

```python
from flask import Flask, send_from_directory

app = Flask(__name__)

@app.route('/static/<path:path>')

def send_static(path):
    return send_from_directory('static', path)

if __name__ == "__main__":
    app.run(port=5000)
```

---

*From your own notes: `Web/Local Python server.md`*
