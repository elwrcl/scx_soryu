# scx_soryu

a port of the BMQ/LFBMQ scheduling policy onto [sched_ext](https://docs.kernel.org/scheduler/sched-ext.html).
the policy is pure BPF C; userspace is a thin Rust loader and more safer than normal scheduler.

## tested on

| machine | cpu | status |
| --- | --- | --- |
| target, tested | Intel i5-3210m (Ivy Bridge, 2c/4t) | **verified** — bare metal, extended game + build sessions |
| target, untested | Ryzen 5 PRO 4650u (Renoir, 6c/12t) | not yet run |
| target, untested | Ryzen 5 7500F (ZEN4, 6c/12t) | not yet run |

## development

```sh
nix develop                 # clang, bpftool, rust, libbpf; kernel drift guard
```

run it by hand:

```sh
sudo ./target/release/scx_soryu
```

or as a NixOS service — see [`docs/service.md`](docs/service.md).

test VM (a smoke test, not a benchmark — measure on bare metal):

```sh
nix build .#nixosConfigurations.testvm.config.system.build.vm
./result/bin/run-nixos-vm
```

## kernel

audited series is **7.1.x**. the devShell refuses to open outside it.
`vmlinux.h` is generated from the running kernel's BTF and is not committed.
