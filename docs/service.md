# the NixOS service

the scheduler is now also a flake package and a NixOS module. running
`sudo ./target/release/scx_soryu` by hand still works — the service is an
addition, not a replacement.

## adding it to copland

`flake.nix` inputs:

```nix
scx-soryu.url = "github:elwrcl/scx_soryu/bmq";
```

in the configuration:

```nix
imports = [ inputs.scx-soryu.nixosModules.default ];

services.scx-soryu = {
  enable = true;
  notify.user = "elars";   # desktop notification on ejection
};
```

that's it. the defaults are measured values: `sliceUs = 1000`
([`slice.md`](slice.md)), `starveMs = 128` ([`stage6-starve.md`](stage6-starve.md)),
`timeoutMs = 5000`, `reportSec = 60`.

to turn it off: `services.scx-soryu.enable = false;` or
`systemctl stop scx-soryu`. either one falls back to EEVDF immediately.

## "something happened and nobody noticed"

an ejection is a silent event: the kernel drops the scheduler, every task
falls back to default kernel scheduler, and nothing on the desktop says so. three layers were added to fix that.

**1. the loader says so, loudly.** ejection used to be a bare
`Error: ...` line printed by anyhow — easy to scroll past in a terminal,
unlabeled and unsearchable in the journal. now it's two ERROR-level lines:

```
scx_soryu was ejected by the kernel: EXIT: runnable task stall (...)
all tasks are back on default kernel scheduler; the scheduler is NOT running
```

**2. systemd retries three times, then gives up.** `Restart=on-failure`,
3 starts in 5 minutes. a transient load spike recovers on its own; a
persistent problem doesn't flap forever — it lands in `failed`.

**3. `failed` triggers a desktop notification.** a second unit bound with
`OnFailure=` finds the user's session bus and calls
`notify-send --urgency=critical`. if there's no session, it exits quietly
(no notification, no error either).

either way, the full story is in the journal:

```
journalctl -u scx-soryu -n 200
```

## telemetry noise

the loader prints four lines a second — fine in a terminal, a disaster in
the journal. `--report-sec` was added; the service uses 60. shutdown is
still checked once a second regardless, so `systemctl stop` isn't slowed
down.

to see live status while the service is running:

```
sudo scx_soryu --monitor 3
```

## verified in a VM

`nixosConfigurations.servicevm` — the same test VM, but running the
scheduler as a service instead of by hand. `tools/servicevm.sh`:

| check | result |
| --- | --- |
| comes up at boot | `active`, `sched_ext=enabled` |
| clean `systemctl stop` | `inactive`, `sched_ext=disabled`, **not** `failed` |
| restarts | `active`, `enabled` |
| repeated SIGKILL | 2 restarts, then `failed` — no flapping |
| journal | `Start request repeated too quickly` + `Failed with result 'start-limit-hit'` |

a clean `systemctl stop` mattered: SIGTERM reaches the loader and drops the
struct_ops link, so unload is clean and the unit isn't marked `failed`.

## packaging note

`packages.default` builds inside the sandbox: the BPF object is compiled
against `scx_utils`'s vendored `vmlinux.h`, then CO-RE-relocated against
the running kernel's BTF at load time. so the build doesn't depend on the
running kernel — `/sys/kernel/btf/vmlinux` is only needed at **run** time.

(the `src/bpf/vmlinux.h` sitting in the repo turned out unused — deleting
it, the build still passes the same way. it was already gitignored.)
