# 中文注释:固定英文日志事件与完整 Unicode 变量名边界不是中文数字边界。
import re

EVENT = re.compile(r"\b(client connected|client disconnected)\b")
FILENAME = re.compile(r"^[\w.\-]+\.[a-z0-9]{1,6}$", re.I)

t = ""
ident = r"(?:[^\W\d]|_)\w*"
path_assign = dict(re.findall(r"(" + ident + r")\s*=\s*path\s*\(\s*r?[\"']([^\"'\n]+)[\"']\s*\)", t))
str_assign = dict(re.findall(r"(" + ident + r")\s*=\s*r?[\"']([^\"'\n]+)[\"']", t))
if re.search(r"\b" + re.escape(var) + r"\s*\.\s*write_text", t):
    pass
