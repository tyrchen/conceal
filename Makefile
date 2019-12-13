BENCH_10=bench_conceal
GIT_BRANCH=$(strip $(shell git symbolic-ref --short HEAD))

$(BENCH_10):
	cargo bench --bench $@ --  --sample-size 10

pr:
	@git push origin $(GIT_BRANCH)
	@hub pull-request

link:
	@rm -f $(HOME)/.cargo/bin/conceal
	@ln -s $(HOME)/.target/debug/conceal $(HOME)/.cargo/bin/conceal

link-release:
	@rm -f $(HOME)/.cargo/bin/conceal
	@ln -s $(HOME)/.target/release/conceal $(HOME)/.cargo/bin/conceal
