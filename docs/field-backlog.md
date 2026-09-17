# Field backlog — moved to the graph

The queue of questions raised during the September 2026 field duty now lives
in the `net-observer` realm (`r210`). This file is a pointer, not a source:
the graph holds the questions, their anchors and their closing criteria.

| Was | Node |
|---|---|
| The coworking ban-carousel episode the questions arose from | #57 «🔥 Бан-карусель коворкинга» |
| V-A · live forensics over the socket | #58 |
| V-B · BSSID / interface MAC in the link sample + a roam signature | #59 |
| V-C · a ban cycle as one episode with a period | #60 |
| V-D · a controlled-experiment (bisection) mode via the CLI | #61 |
| V-E · per-flow kill: dial timeouts beside a green raw probe | #62 |
| V-F · external reachability as an incident axis (owner's decision) | #63 |

The "already closed" list was not transferred: those are facts about the code
and sit in the nodes that describe it (#10 «Инцидент», #15 «Опознание
сигнатуры»).

---

## V-G · Коллектор физического egress + корреляция всплеска с баном

**Наблюдение (2026-09-17).** Триггер пер-клиентского бана на коворкинге
ищется по ФИЗИЧЕСКИМ исходящим коннектам к иностранным IP на en0 (SYN к
VLESS-серверам + синхронный залп urltest-проб раз в 3м — подпись
адрес-сканера для MikroTik). Обсервер этого не видит: pcap-кольцо намеренно
исключает жирный поток (только ARP/ICMP/DHCP), а Clash `/connections`
показывает потоки ВНУТРИ туннеля (app→tun), не физические коннекты к
серверам. Пришлось поднимать `netstat`-логгер SYN_SENT по SSH.

**Answered when.** Есть коллектор физического egress'а (например, netstat
SYN_SENT/ESTABLISHED к не-локальным IP, non-root), пишущий rate/spread
новых коннектов; и сигнатура/запрос, коррелирующая всплеск исходящих
коннектов с наступлением gw-drop/per-client-block — так «что я отправил
прямо перед баном» становится ответом продукта, а не ручного netstat.
