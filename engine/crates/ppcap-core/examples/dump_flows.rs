//! Tiny Parquet flow-row dumper for manual verification of the L7/SNI enrichment columns.
//!
//! Usage: `cargo run --example dump_flows -- <flows.parquet>`
//! Prints one line per flow: category | endpoint | dst_port | app_proto | app_proto_src | sni,
//! then a one-line tally of how many rows carry a non-null app_proto_src / sni.

use arrow_array::{Array, BooleanArray, StringArray, UInt16Array};
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;

fn main() {
    let path = std::env::args()
        .nth(1)
        .expect("usage: dump_flows <flows.parquet>");
    let file = std::fs::File::open(&path).expect("open parquet");
    let reader = ParquetRecordBatchReaderBuilder::try_new(file)
        .expect("parquet reader")
        .build()
        .expect("build reader");

    let mut total = 0usize;
    let mut payload_src = 0usize;
    let mut sni_rows = 0usize;
    for batch in reader {
        let batch = batch.expect("batch");
        let src = batch
            .column(2)
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        let dst = batch
            .column(3)
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        let dp = batch
            .column(5)
            .as_any()
            .downcast_ref::<UInt16Array>()
            .unwrap();
        let app = batch
            .column(7)
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        let cat = batch
            .column(16)
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        let aps = batch
            .column(17)
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        let sni = batch
            .column(18)
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        let severity = batch
            .column(19)
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        let score = batch
            .column(20)
            .as_any()
            .downcast_ref::<UInt16Array>()
            .unwrap();
        let ioc = batch
            .column(21)
            .as_any()
            .downcast_ref::<BooleanArray>()
            .unwrap();
        let opt = |a: &StringArray, i: usize| {
            if a.is_null(i) {
                "NULL".to_string()
            } else {
                a.value(i).to_string()
            }
        };
        for i in 0..batch.num_rows() {
            total += 1;
            if !aps.is_null(i) && aps.value(i) == "payload" {
                payload_src += 1;
            }
            if !sni.is_null(i) {
                sni_rows += 1;
            }
            println!(
                "category={:<8} endpoint={}:{} dst_port={:<6} app_proto={:<6} app_proto_src={:<8} sni={:<24} severity={:<8} threat_score={:<3} ioc={}",
                cat.value(i),
                src.value(i),
                dst.value(i),
                dp.value(i),
                opt(app, i),
                opt(aps, i),
                opt(sni, i),
                severity.value(i),
                score.value(i),
                ioc.value(i),
            );
        }
    }
    println!("--- {total} flows; {payload_src} with app_proto_src=payload; {sni_rows} with non-null sni ---");
}
