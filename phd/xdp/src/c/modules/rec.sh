python3 -u - <<'PY'
  import socket
  s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  s.bind(("0.0.0.0", 9999))
  while True:
      data, addr = s.recvfrom(65535)
      print(addr, len(data), data[:80])
  PY

