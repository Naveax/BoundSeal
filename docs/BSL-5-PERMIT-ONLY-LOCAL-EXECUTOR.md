# BSL-5 — Permit-Only Local Executor Contract

## Amaç

BSL-5, gelecekteki gerçek transport backend'lerinden önce bağlantı yürütme sınırını dondurur. Bu aşama hiçbir socket, DNS resolver, TLS el sıkışması, HTTP istemcisi, proxy veya gerçek hedef bağlantısı içermez.

## Zorunlu akış

```text
Gateway allow kararı
  -> tek kullanımlık ticket
  -> exact ticket consumption
  -> TransportPermit
  -> transport audit tail
  -> PermitExecutor
  -> terminal ExecutionReceipt
  -> gateway in-flight budget release
```

## Executor API sınırı

Executor aşağıdaki girdileri kabul etmez:

- URL
- hostname çözümleme talebi
- serbest biçimli IP
- serbest biçimli port
- cookie veya session
- proxy hedefi
- redirect URL'si

Executor yalnız `TransportPermit` içinden türetilmiş `PermitEndpoint` kullanır. Endpoint şu alanlardan oluşur:

- ticket ve gateway decision kimliği
- DNS context kimliği
- permit tarafından seçilmiş IP
- permit tarafından seçilmiş port
- HTTP/HTTPS scheme
- permit tarafından bağlı TLS SNI
- permit tarafından bağlı HTTP Host authority
- redirect depth
- ticket binding hash

## State machine

```text
Prepared
  -> PermitRejected
  -> Cancelled
  -> EmergencyStopped
  -> Connecting
      -> Connected
          -> Completed
          -> TimedOut
          -> BudgetRejected
          -> BackendFailed
      -> TimedOut
      -> BackendFailed
```

Her çalışma tek bir terminal state üretir.

## Sabit limitler

- connect timeout: `1..=30_000 ms`
- total timeout: connect timeout'tan küçük olamaz, en fazla `120_000 ms`
- read bütçesi: `1..=64 MiB`
- write bütçesi: `1..=64 MiB`

İlk varsayılan profil:

- 5 saniye connect timeout
- 15 saniye total timeout
- 2 MiB read
- 256 KiB write

## Cancellation ve emergency-stop

BSL-5 deterministik kontratta cancellation ve emergency-stop sinyallerini çalıştırma başlamadan uygular. Emergency-stop cancellation'dan önceliklidir. Gelecekte async backend eklendiğinde aynı outcome sözleşmesi periyodik kontrol noktalarına taşınacaktır.

## Audit bağlama

Her execution audit olayı şunları taşır:

- execution ve executor kimliği
- ticket ve decision kimliği
- DNS context
- transport audit tail anchor
- ticket binding hash
- endpoint fingerprint
- IP, port, scheme, SNI ve HTTP Host
- redirect depth
- state history
- outcome
- connect/total süre
- read/write byte sayıları

Executor audit zinciri SHA-256 append-only kayıtlarından oluşur. Transport audit tail değeri execution event içinde hashlenir; böylece sonuç belirli ticket tüketim kaydına bağlanır.

## Gateway bütçe yaşam döngüsü

Başarılı ticket tüketimi bir gateway in-flight slotuna sahiptir. `bsl-local-executor` şu terminal durumların tamamında slotu tam bir kez bırakır:

- completed
- cancelled
- emergency stopped
- connect timeout
- total timeout
- read/write budget exceeded
- backend failure
- executor configuration/audit error

Ticket mismatch, expiry veya clock regression daha önce pinned transport katmanında serbest bırakılır; local pipeline ikinci kez release etmez.

## Sentetik backend

`SyntheticBackend` yalnız önceden tanımlanmış raporlar üretir:

- connect süresi
- total süre
- read/write byte sayıları
- kontrollü failure code

Hiçbir işletim sistemi network API'si çağrılmaz.

## Bu aşamada özellikle bulunmayanlar

- `TcpStream`, UDP veya QUIC
- resolver
- TLS certificate validation
- HTTP request/response
- redirect takipçisi
- browser veya proxy
- session vault
- scanner adapter
- public internet çıkışı
- gerçek hedef execution

Gerçek transport, ancak permit dışı bağlantının derleme ve test seviyesinde imkânsız olduğu doğrulandıktan sonra ayrı bir aşamada değerlendirilecektir.
