import re

NUM = re.compile(r"(?<![\w.])(\d+(?:\.\d+)?%?)")
POPEN = re.compile(r"\bpopen\b")
SAMPLE = "本次处理12.3%"
