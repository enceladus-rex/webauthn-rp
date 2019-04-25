def snake_to_camel_case(s: str) -> str:
  chunks = s.split('_')
  capped = [x[0].upper() + x[1:] for x in chunks[1:]]
  if chunks:
    return chunks[0] + ''.join(capped)
  return ''


def camel_to_snake_case(s: str) -> str:
  words = []
  s_index = 0
  for i in range(len(s)):
    if s[i].isupper():
      words.append(s[s_index:i].lower())
      s_index = i
  if s_index < len(s): words.append(s[s_index:].lower())
  return '_'.join(words)