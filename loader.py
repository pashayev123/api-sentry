
import json
from pathlib import Path


def load_spec(path):
    path = Path(path)
    content = path.read_text(encoding="utf-8")

    if path.suffix.lower() == ".json":
        data = json.loads(content)
    else:
        import yaml
        data = yaml.safe_load(content)

    if not isinstance(data, dict):
        raise ValueError("OpenAPI document must contain an object")

    return data
