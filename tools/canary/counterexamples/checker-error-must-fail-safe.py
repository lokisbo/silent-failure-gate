# Safe counterexample: diagnostic vocabulary alone is not an error accumulator.
problems = 0
with open("sample.log", encoding="utf-8", errors="replace") as stream:
    text = stream.read()
if "FAIL" in text:
    problems += 1
return_code = 1 if problems else 0