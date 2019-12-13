BENCH_10=bench_conceal
GIT_BRANCH=$(strip $(shell git symbolic-ref --short HEAD))

$(BENCH_10):
	cargo bench --bench $@ --  --sample-size 10

pr:
	@git push origin $(GIT_BRANCH)
	@hub pull-request
