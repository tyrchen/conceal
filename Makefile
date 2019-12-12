BENCH_10=bench_conceal

$(BENCH_10):
	cargo bench --bench $@ --  --sample-size 10
