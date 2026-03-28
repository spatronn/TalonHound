# Retro Scan Trigger Notes

## Purpose
Bu not, yeni eklenen IOC’lerin retro scan tarafından **manuel müdahale olmadan** ne zaman işleneceğini hızlıca doğrulamak için hazırlanmıştır.

## Current Runtime Behavior (2026-03-28)

- `ioc-retro-engine`
  - `IOC_RETRO_SCAN_INTERVAL_SECONDS=3600` (yaklaşık 1 saat)
  - Backlog yoksa idle moda geçer ve bir sonraki taramaya kadar bekler.
- `ioc-retro-engine` içinde `IOC_LOOKUP_SYNC_ENABLED=0`
  - Retro worker kendi başına `ioc_lookup` sync yapmaz.
  - `ioc_lookup` güncellemesi için correlation tarafındaki sync döngüsü önemlidir.

## Verified Test Flow

### Test-1 (manual assist)
1. IOC eklendi: `122.201.253.204`
2. Correlation worker restart ile `ioc_lookup` sync tetiklendi.
3. Retro worker çalıştı ve logda doğrulandı:
   - `matched_rows=1`
   - `inserted_or_upserted=1`
4. `ioc_match_events` içinde `processing_path=retro`, `retroactive=true` kaydı görüldü.

### Test-2 (no manual trigger)
1. IOC eklendi: `13.70.121.184`
2. Manuel restart/tetik yapılmadı.
3. Sonraki zamanlanmış retro döngüsünde alarmın tetiklendiği gözlemlendi.

## UI Signal

`/system` > ClickHouse altında:
- `Last retro scanned IOC`
- `Last Retro Run`

alanları retro davranışını takip etmek için kullanılabilir.

## Operational Expectation

- Son retro run zamanı `T` ise, backlog yokken bir sonraki run genellikle `T + ~1 saat` olur (küçük sapmalar mümkün).
