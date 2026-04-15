# End-to-End Logic

Questo file descrive il comportamento corrente dei path UDP e TCP del
progetto, con focus su:

- punto di ingresso del traffico
- stato condiviso mantenuto dai backend deferred
- condizioni che portano a `PASS`, `DROP` o `bufferizzazione`
- teardown e pulizia

I riferimenti di implementazione principali sono:

- `netfilter_hook_udp.c`
- `deferred_analysis_udp.c`
- `tcp_stream_hook.c`
- `deferred_analysis_tcp.c`

## Lockless e RCU

Il codice corrente usa una combinazione di:

- `RCU` per rendere lockless i lookup reader su alcune hashtable
- operazioni atomiche per aggiornare stato monotono o bitmask
- spinlock solo dove serve ancora serializzare struttura dati, create,
  delete o code mutabili

### Cosa significa qui "lockless"

Nel progetto "lockless" non significa assenza totale di lock ovunque.
Significa soprattutto:

- nessun lock nel fast path dei reader
- nessun lock per aggiornare campi che possono essere gestiti in modo
  atomico
- lock mantenuti solo per modifiche strutturali della hashtable o per
  strutture non adatte a `RCU` puro

### `RCU` nel progetto

Quando una tabella e' `RCU`-safe:

- i reader fanno `rcu_read_lock()`
- il lookup usa `hash_for_each_possible_rcu()`
- la rimozione usa `hash_del_rcu()`
- la memoria viene liberata con `kfree_rcu()`

Questo consente di dereferenziare un'entry in modo sicuro durante la
sezione RCU senza prendere il lock della tabella.

### Strutture oggi lockless o parzialmente lockless

#### `state_ht`

`state_ht` e' la struttura piu' evoluta dal punto di vista lockless.

Caratteristiche:

- lookup via `RCU`
- create serializzata solo sul miss
- `req_mask`, `done_mask`, `hit_mask` aggiornati atomicamente
- `verdict` aggiornato con transizioni monotone
- `last_seen_jiffies` aggiornato con `WRITE_ONCE`

Implicazione:

- il fast path del worker e dei reader non prende `state_lock`
- `state_lock` serve ormai solo per create strutturale e teardown

#### `snap_ht`

`snap_ht` usa `RCU` per i lookup reader della snapshot.

Caratteristiche:

- il reader legge la snapshot sotto `rcu_read_lock()`
- il replace della snapshot dello stesso `pkt_id` resta serializzato
- il free e' differito con `kfree_rcu()`

Implicazione:

- il worker puo' leggere il frame senza prendere `snap_lock`
- `snap_lock` resta solo per replace/delete strutturale

#### Worker TCP

Il backend TCP non ha ancora una hashtable `RCU`-safe, ma il worker
deferred non fa piu' lookup nella tabella.

Caratteristiche:

- il work item riceve direttamente un puntatore stabile a
  `dw_tcp_flow_state`
- `drop_armed` viene aggiornato con `WRITE_ONCE`
- `approved_seq` avanza con `cmpxchg()`

Implicazione:

- il worker TCP non prende `dw_tcp_flow_lock`
- il lock resta su create/lookup e sullo stato per-flow non ancora
  convertito

### Strutture ancora lock-based

#### `meta_ht`

Resta lock-based perche' il suo uso principale e' `put` e `get-and-del`.
E' un buon candidato futuro a `RCU`, ma il beneficio atteso e' inferiore
rispetto a `state_ht` e `snap_ht`.

#### `flow_ht`

Resta lock-based perche' non e' solo una hashtable: ogni entry contiene
una FIFO mutabile di pacchetti buffered.

Problemi principali:

- ordine intra-flow da preservare
- rimozione dalla testa della FIFO
- rilascio temporaneo del lock attorno a `nf_reinject()`
- possibile free del flow quando la coda diventa vuota

Per questo `flow_ht` non e' un candidato semplice a `RCU` puro.

## UDP

## Obiettivo

Per UDP il sistema implementa un modello "hold until verdict" a livello
pacchetto. Se un pacchetto e' correlato con il path XDP e richiede
analisi deferred, viene messo in coda e reiniettato solo quando il suo
stato e' terminale.

## Ingresso

Il path di ingresso e' `NF_INET_LOCAL_IN` in `netfilter_hook_udp.c`.

Flusso:

1. Il pacchetto viene parsato come IPv4/UDP.
2. Si costruisce una chiave `dw_pkt_key`.
3. Il hook netfilter prova a consumare la correlazione prodotta da XDP
   tramite `dw_meta_get_and_del()`.
4. Se la correlazione manca, il pacchetto non e' tracciato e viene
   accettato direttamente.
5. Se la correlazione esiste, il pacchetto e' associato a:
   - `pkt_id`
   - `req_mask`

## Stato condiviso UDP

Il backend UDP usa quattro strutture principali.

### `state_ht`

Tabella per-packet, indicizzata da `pkt_id`.

Contiene:

- `req_mask`: analisi richieste
- `done_mask`: analisi completate
- `hit_mask`: analisi con match malevolo
- `verdict`: `UNKNOWN`, `PASS`, `DROP`
- `last_seen_jiffies`

Uso:

- coordinare i worker che analizzano lo stesso pacchetto
- determinare quando il pacchetto e' terminale

Stato attuale:

- lookup reader via `RCU`
- update delle mask via atomiche
- `verdict` monotono
- lock solo per create/teardown strutturale

Dettagli lockless:

- il fast path tenta prima un lookup `RCU`
- se l'entry esiste, aggiorna `req_mask` senza lock
- solo il caso di miss prende `state_lock` per creare la nuova entry

### `meta_ht`

Tabella di correlazione tra chiave XDP e `(pkt_id, req_mask)`.

Uso:

- XDP pubblica la correlazione
- netfilter la consuma una sola volta

### `snap_ht`

Tabella `pkt_id -> snapshot del frame`.

Uso:

- XDP salva una copia del frame
- il worker deferred la legge per ispezionare il payload
- viene rimossa quando il pacchetto esce dal ciclo deferred

Stato attuale:

- lookup reader via `RCU`
- replace/delete serializzati
- free differito con `kfree_rcu()`

Dettagli lockless:

- la lettura della snapshot non la consuma piu' direttamente
- la snapshot viene rimossa solo nel path di completamento del pacchetto
  o durante il replace/teardown

### `flow_ht`

Tabella per-flow, indicizzata da 5-tupla UDP.

Ogni `flow_ent` contiene una FIFO `q` di pacchetti buffered.

Uso:

- preservare l'ordine dei pacchetti dello stesso flow
- consentire il delivery solo dalla testa del flow

Nota:

- e' la struttura piu' "stateful" del path UDP
- non e' lockless
- protegge sia la hashtable sia la FIFO interna del flow

## Produzione dello stato dal lato XDP

Il backend UDP esporta tre kfunc usate da XDP:

- `dw_register_and_schedule(pkt_id, req_mask)`
- `dw_meta_put(key, pkt_id, req_mask)`
- `dw_pkt_snapshot_put(data, len, pkt_id)`

In pratica XDP:

1. decide che il pacchetto UDP va monitorato
2. assegna un `pkt_id`
3. salva:
   - stato per-packet
   - correlazione per netfilter
   - snapshot del frame
4. pianifica uno o piu' work item deferred in base ai bit di `req_mask`

## Worker deferred UDP

Ogni bit di `req_mask` genera un `analysis_work`.

Flusso del worker:

1. il worker riceve:
   - `pkt_id`
   - bit dell'analisi
   - puntatore stabile a `pkt_state`
2. se il bit corrisponde all'analisi payload, legge la snapshot dal
   `snap_ht`
3. aggiorna:
   - `hit_mask` se trova un match
   - `done_mask` quando termina
4. legge `req_mask` corrente
5. aggiorna il `verdict`

Regole del `verdict`:

- se almeno un bit richiesto compare in `hit_mask`, il `verdict` diventa
  `DROP`
- se tutti i bit richiesti compaiono in `done_mask` e non ci sono hit,
  il `verdict` diventa `PASS`
- `DROP` prevale sempre su `PASS`

Dal punto di vista della sincronizzazione:

- `done_mask` e `hit_mask` sono bitmask atomiche
- `req_mask` e' anch'essa atomica
- `PASS` viene impostato solo se il valore precedente e' `UNKNOWN`
- `DROP` puo' sovrascrivere `UNKNOWN` o `PASS`

Quando il pacchetto diventa terminale, il worker chiama
`dw_try_deliver_ready()`.

## Bufferizzazione e consegna UDP

Quando il hook netfilter intercetta un pacchetto correlato:

1. se `nfq_stopping` e' attivo, il pacchetto viene accettato senza
   queueing
2. se `verdict == DROP`, il pacchetto viene droppato subito
3. altrimenti il pacchetto viene passato a NFQUEUE
4. `dw_buffer_nfqueue_entry()` inserisce il pacchetto in `flow_ht`

Da questo momento il pacchetto e' buffered e resta in attesa della
consegna ordinata.

## Drainer UDP

La consegna avviene in `dw_try_deliver_ready()` /
`__dw_try_deliver_ready()`.

Regole:

- si guarda solo la testa della FIFO di ogni flow
- se la testa non e' pronta, il flow resta bloccato
- i pacchetti successivi dello stesso flow non possono superarla

Casi per il pacchetto in testa:

- `nfq_stopping == 1`
  il pacchetto viene accettato e rilasciato
- `verdict == DROP`
  il pacchetto viene droppato
- `done_mask` non copre `req_mask`
  il flow resta fermo
- tutte le analisi richieste sono finite e non ci sono hit
  il pacchetto viene reiniettato in `PASS`

Prima di reiniettare o droppare il pacchetto, il backend chiama
`snap_drop(pkt_id)` e rilascia la snapshot.

## Teardown UDP

L'ordine atteso e':

1. fermare il lato XDP/eBPF
2. fermare il hook netfilter
3. quiescere NFQUEUE
4. distruggere workqueue e tabelle

Passi principali:

- `dw_begin_nfqueue_stop()` alza `nfq_stopping`
- `nf_unregister_net_hook()` impedisce nuovi ingressi netfilter
- `dw_quiesce_nfqueue()` drena i pacchetti buffered ancora in coda
- `destroy_workqueue(dw_wq)` aspetta la fine dei worker
- teardown delle hashtable

Durante `dw_quiesce_nfqueue()` i pacchetti ancora in coda vengono
accettati per evitare di lasciare entry NFQUEUE in flight.

## Proprieta' pratiche UDP

- un pacchetto correlato puo' essere trattenuto completamente prima
  della consegna a user space
- l'ordine intra-flow e' preservato
- `state_ht` e `snap_ht` hanno path reader lockless
- `flow_ht` resta la parte maggiormente serializzata

## TCP

## Obiettivo

Per TCP il sistema non lavora a livello pacchetto singolo, ma a livello
stream post-reordering. Il kernel continua a gestire ACK, riordino e
receive queue; il backend deferred osserva chunk contigui dello stream e
prova a limitare la lettura a user space.

## Ingresso

I punti di ingresso sono in `tcp_stream_hook.c`.

### `tcp_data_queue`

E' hookato con un kretprobe.

Uso:

- dopo che il kernel ha gia' validato e messo in ordine i dati
- il backend chiama `dw_tcp_enqueue_stream(sk)`

### `tcp_recvmsg`

E' hookato con un kprobe pre-handler.

Uso:

- prima che i byte siano copiati in user space
- il backend chiama `dw_tcp_approved_len(sk, req_len)`
- se il backend ha approvato solo parte del flusso, il kprobe riduce
  `req_len`

## Stato condiviso TCP

Il backend TCP usa `dw_tcp_flow_ht`, indicizzata da `sock_cookie`.

Ogni `dw_tcp_flow_state` contiene:

- `sk`
- `next_seq`
- `approved_seq`
- `next_seq_valid`
- `approved_seq_valid`
- `drop_armed`
- `tail_len` e `tail[]`
- `last_seen_jiffies`

Significato:

- `next_seq`: prossimo byte ancora da prendere dal receive queue per un
  nuovo chunk
- `approved_seq`: massimo boundary contiguo gia' approvato
- `drop_armed`: il flusso va abortito
- `tail`: ultimi byte del chunk precedente, per match che attraversano i
  confini tra chunk

## Enqueue del chunk TCP

`dw_tcp_enqueue_stream(sk)` fa questo:

1. trova o crea lo state del flow
2. se `drop_armed` e' gia' attivo, rifiuta
3. inizializza `next_seq` e `approved_seq` da `tp->copied_seq` al primo
   utilizzo
4. legge `tp->rcv_nxt` per capire quanti byte contigui sono disponibili
5. sceglie un chunk massimo di `DW_TCP_CHUNK_MAX`
6. copia i byte dal receive queue con `dw_tcp_copy_stream_chunk()`
7. prepende l'eventuale `tail` del chunk precedente
8. aggiorna il nuovo `tail`
9. accoda un worker deferred sulla workqueue TCP

## Worker deferred TCP

Ogni chunk genera ora uno stato condiviso per-chunk e un insieme di
work item calcolato da una `req_mask` del chunk, simile al fan-out UDP
ma senza una hashtable dedicata.

Lo stato del chunk contiene:

- range `[from_seq, to_seq)`
- range effettivamente scansionato
- buffer del chunk
- puntatore allo state del flow
- `req_mask`
- `done_mask`
- `hit_mask`
- `pending`

Le due analisi dummy correnti sono:

- `DW_TCP_REQ_A1`: dummy sempre benigna
- `DW_TCP_REQ_A2`: ricerca della needle `"malicious"`

La `req_mask` del chunk e' oggi derivata dal workload del chunk stesso:

- `DW_TCP_REQ_A1` viene sempre schedulata
- `DW_TCP_REQ_A2` viene schedulata solo se la finestra effettiva del
  chunk e' abbastanza grande da poter contenere la needle

Quindi, a differenza della versione precedente, il numero di analisi TCP
non e' piu' fisso: dipende dal chunk corrente.

Ogni worker:

- aggiorna `hit_mask` se trova un match
- aggiorna `done_mask` quando finisce
- decrementa `pending`

Solo l'ultimo worker che porta `pending` a zero finalizza il chunk.

Esito di finalizzazione:

- se almeno una analisi ha prodotto hit:
  - alza `drop_armed`
  - prende `sk`
  - purga `sk_receive_queue`
  - chiama `tcp_abort()`
- se nessuna analisi ha prodotto hit:
  - prova ad avanzare `approved_seq` da `from_seq` a `to_seq`
  - l'avanzamento avviene solo se il boundary e' ancora contiguo

Questo fa si' che `approved_seq` cresca solo dopo il completamento di
tutte le analisi del chunk.

## Gating del read path TCP

`dw_tcp_approved_len(sk, requested_len)` calcola quanti byte sono
effettivamente leggibili.

Regole:

- se il flow non esiste, restituisce `0`
- se `approved_seq_valid == false`, restituisce `0`
- se `drop_armed == true`, restituisce `0`
- altrimenti permette fino a `approved_seq - copied_seq`

Il kprobe su `tcp_recvmsg` usa questo valore per ridurre la `len`
richiesta.

## Teardown TCP

Nel modulo TCP:

1. si distrugge la workqueue
2. si svuota `dw_tcp_flow_ht`
3. per ogni flow si rilascia `sock_put(sk)` se presente

Non esiste un equivalente NFQUEUE del path UDP, perche' il gating TCP e'
basato su stream e non su packet reinjection.

## Proprietà pratiche TCP

- il backend lavora solo su dati gia' riordinati dal kernel
- il gating e' best-effort prima della copia a user space
- byte gia' letti da user space non possono essere "revocati"
- in caso di match malevolo il backend interrompe la connessione

## Differenze chiave UDP vs TCP

- UDP blocca o rilascia singoli pacchetti
- TCP approva o nega intervalli di stream
- UDP usa `pkt_id`, snapshot e NFQUEUE
- TCP usa `sock_cookie`, sequence numbers e receive queue
- UDP puo' fare `PASS/DROP` prima della consegna
- TCP puo' solo limitare la lettura futura o abortire la connessione

## Stato attuale della sincronizzazione

### UDP

- `state_ht`: reader lockless via `RCU`, update atomici
- `snap_ht`: reader lockless via `RCU`
- `meta_ht`: ancora lock-based
- `flow_ht`: ancora lock-based

### TCP

- il worker deferred non fa piu' lookup nella hashtable
- `dw_tcp_flow_lock` protegge ancora create/lookup e stato per-flow
  come `next_seq` e `tail`
- `drop_armed` e `approved_seq` hanno gia' update senza lock nel worker
- il chunk TCP usa ora stato condiviso per-chunk con `done_mask`,
  `hit_mask` e `pending` atomici

## Osservazione finale

Il backend UDP implementa una politica di trattenimento forte a livello
pacchetto. Il backend TCP implementa una politica di approvazione a
livello stream, necessariamente piu' debole ma coerente con la semantica
del protocollo e del receive path del kernel.
