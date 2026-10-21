hits = []
errors = []


def scan(paths):
    for p in paths:
        try:
            hits.extend(open(p, encoding='utf-8').read().count('-'))
        except OSError as exc:
            errors.append((p, str(exc)))
    return 1 if hits else 0
