{
  description = "scx_soryu — BMQ/LFBMQ policy port for sched_ext";

  # The test VM's kernel is the same derivation as 
  # the host's booted kernel. See docs/KERNEL.md.

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/18b9261cb3294b6d2a06d03f96872827b8fe2698";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    let
      system = "x86_64-linux";
      pkgs = nixpkgs.legacyPackages.${system};
      kernelPackages = pkgs.linuxPackages_7_1;
      kernelVersion = kernelPackages.kernel.modDirVersion;

      auditedSeries = "7.1";
      vmBase = { pkgs, lib, ... }: {
        boot.kernelPackages = kernelPackages;

        # SysRq-S (sched_ext reset) and SysRq-D (dump) are gated behind
        # SYSRQ_ENABLE_RTNICE (0x100). NixOS's default of 184 omits it, so
        # the emergency escape hatch is dead unless we set this.
        boot.kernel.sysctl."kernel.sysrq" = 440;

        virtualisation = {
          cores = 4;
          memorySize = 4096;
          graphics = false;
          # the host: 2 physical cores x 2 threads, one LLC. Without
          # this QEMU reports 4 sockets and scx_bpf_select_cpu_dfl()'s SMT
          # walk has nothing real to walk.
          qemu.options = [ "-cpu host" "-smp 4,sockets=1,cores=2,threads=2" ];
          sharedDirectories.soryu = {
            source = "/home/elars/Projects/scx_soryu";
            target = "/mnt/soryu";
          };
        };

        services.getty.autologinUser = "root";
        users.users.root.password = "";

        # rt-tests carries both cyclictest and hackbench (M1 harness).
        environment.systemPackages = with pkgs; [ stress-ng rt-tests ];

        system.stateVersion = "25.05";
      };
    in
    {
      devShells.${system}.default = pkgs.mkShell {
        name = "scx_soryu";

        nativeBuildInputs = with pkgs; [
          clang
          llvm
          bpftools
          pkg-config
          rustc
          cargo
          rustfmt
          clippy
          rust-analyzer
        ];

        buildInputs = with pkgs; [
          libbpf
          elfutils
          zlib
          zstd
        ];

        # scx_utils' build script runs bindgen, which dlopens libclang.
        LIBCLANG_PATH = "${pkgs.libclang.lib}/lib";

        # The nix cc-wrapper injects -fzero-call-used-regs, which clang rejects
        # for -target bpf. nixpkgs' own scx derivation disables the same knob.
        hardeningDisable = [ "zerocallusedregs" ];

        RUSTFLAGS = builtins.concatStringsSep " " [
          "-C relocation-model=pic"
          "-C link-args=-lelf"
          "-C link-args=-lz"
          "-C link-args=-lzstd"
        ];

        shellHook = ''
          expected="${kernelVersion}"
          series="${auditedSeries}"
          running="$(uname -r)"
          running_series="$(echo "$running" | cut -d. -f1,2)"

          if [ "$running_series" != "$series" ]; then
            cat >&2 <<MSG

          ╔══════════════════════════════════════════════════════════════╗
          ║  KERNEL SERIES MISMATCH — refusing to enter                  ║
          ╚══════════════════════════════════════════════════════════════╝
            audited series : $series.x
            booted         : $running

MSG
          return 1
          fi

          if [ "$running" != "$expected" ]; then
            cat >&2 <<MSG
          warning: patch-level kernel drift
            flake VM kernel : $expected
            booted          : $running
            Same $series.x series, so the kfunc audit still holds. The test VM
            will run $expected while bare metal runs $running. The BPF object
            is compiled against scx_utils' vendored vmlinux.h and relocated
            against the booted kernel's BTF at load time (CO-RE), so the build
            does not depend on which of the two you are on.
MSG
          fi

          # Needed to *load*, not to build: libbpf resolves CO-RE relocations
          # against this at attach time.
          if [ ! -r /sys/kernel/btf/vmlinux ]; then
            echo "error: /sys/kernel/btf/vmlinux unreadable; CONFIG_DEBUG_INFO_BTF required" >&2
            return 1
          fi

          echo "scx_soryu devShell — kernel $running, BTF ok"
        '';
      };

      packages.${system}.default = pkgs.rustPlatform.buildRustPackage {
        pname = "scx_soryu";
        version = "0.1.0";

        # target/ is a gigabyte and nixos.qcow2 is the VM's disk; neither
        # belongs in the store path, and both would invalidate the hash on
        # every build.
        src = pkgs.lib.cleanSourceWith {
          src = ./.;
          filter = path: _type:
            !(builtins.elem (baseNameOf path) [ "target" "result" "nixos.qcow2" ]);
        };

        cargoLock.lockFile = ./Cargo.lock;

        nativeBuildInputs = with pkgs; [
          clang
          llvm
          bpftools
          pkg-config
          rustPlatform.bindgenHook   # scx_utils runs bindgen; needs libclang
        ];

        buildInputs = with pkgs; [ libbpf elfutils zlib zstd ];

        # Same two workarounds the devShell needs, for the same reasons.
        hardeningDisable = [ "zerocallusedregs" ];
        RUSTFLAGS = builtins.concatStringsSep " " [
          "-C relocation-model=pic"
          "-C link-args=-lelf"
          "-C link-args=-lz"
          "-C link-args=-lzstd"
        ];

        doCheck = false;   # the tests that matter need a kernel, not a sandbox

        meta = {
          description = "BMQ/LFBMQ policy port for sched_ext";
          mainProgram = "scx_soryu";
        };
      };

      nixosModules.default = { config, lib, pkgs, ... }:
        let
          cfg = config.services.scx-soryu;
        in
        {
          options.services.scx-soryu = {
            enable = lib.mkEnableOption "the scx_soryu sched_ext scheduler";

            package = lib.mkOption {
              type = lib.types.package;
              default = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
              description = "scx_soryu build to run.";
            };

            sliceUs = lib.mkOption {
              type = lib.types.ints.positive;
              default = 1000;
              description = ''
                Timeslice in microseconds. 1000 is the measured knee: the
                same compile took 4m49s at 4194 and 4m39s at both 1000 and
                500. 4194 restores BMQ's own value.
              '';
            };

            boostOnWake = lib.mkOption {
              type = lib.types.bool;
              default = false;
              description = ''
                Boost a waking task in proportion to how long it slept.

                BMQ means to do this but ships the line as a comparison rather
                than a subtraction, so in practice it never happens. Measured
                both ways: off halves the interactive tail past 1 ms, in 63 of
                68 paired intervals, at no cost in compile time. See
                docs/boost-on-wake.md. true restores the intended behaviour.
              '';
            };

            starveMs = lib.mkOption {
              type = lib.types.ints.unsigned;
              default = 128;
              description = ''
                Anti-starvation deadline. 0 restores BMQ's semantics.
              '';
            };

            timeoutMs = lib.mkOption {
              type = lib.types.ints.positive;
              default = 5000;
              description = "Kernel watchdog threshold for a stalled task.";
            };

            reportSec = lib.mkOption {
              type = lib.types.ints.positive;
              default = 60;
              description = ''
                Seconds between telemetry lines in the journal. The loader's
                own default is 1, which is right for a terminal and far too
                chatty for a service.
              '';
            };

            extraArgs = lib.mkOption {
              type = lib.types.listOf lib.types.str;
              default = [ ];
              example = [ "--debug" ];
            };

            notify = {
              enable = lib.mkOption {
                type = lib.types.bool;
                default = cfg.notify.user != null;
                defaultText = lib.literalExpression "notify.user != null";
                description = ''
                  Send a desktop notification when the scheduler gives up.

                  Being ejected is silent: the kernel puts every task back on
                  default scheduler and nothing on the desktop says so. 
                  Without this the only trace is the journal.
                '';
              };

              user = lib.mkOption {
                type = lib.types.nullOr lib.types.str;
                default = null;
                example = "elars";
                description = "Desktop user to notify.";
              };
            };
          };

          config = lib.mkIf cfg.enable {
            assertions = [{
              assertion = !cfg.notify.enable || cfg.notify.user != null;
              message = "services.scx-soryu.notify.enable needs notify.user.";
            }];

            systemd.services.scx-soryu = {
              description = "scx_soryu sched_ext scheduler";
              documentation = [ "https://github.com/elwrcl/scx_soryu" ];
              wantedBy = [ "multi-user.target" ];
              after = [ "systemd-udev-settle.service" ];
              startLimitIntervalSec = 300;
              startLimitBurst = 3;

              onFailure = lib.mkIf cfg.notify.enable [ "scx-soryu-notify.service" ];

              serviceConfig = {
                ExecStart = lib.escapeShellArgs ([
                  (lib.getExe cfg.package)
                  "--slice-us" (toString cfg.sliceUs)
                  "--starve-ms" (toString cfg.starveMs)
                  "--boost-on-wake" (lib.boolToString cfg.boostOnWake)
                  "--timeout-ms" (toString cfg.timeoutMs)
                  "--report-sec" (toString cfg.reportSec)
                ] ++ cfg.extraArgs);

                Type = "simple";
                Restart = "on-failure";
                RestartSec = 5;
                KillSignal = "SIGTERM";
                TimeoutStopSec = 15;

                # Losing the scheduler to the OOM killer would be a strange
                # way to lose the scheduler.
                OOMScoreAdjust = -500;
              };
            };

            systemd.services.scx-soryu-notify = lib.mkIf cfg.notify.enable {
              description = "Report that scx_soryu gave up";
              serviceConfig = {
                Type = "oneshot";
                ExecStart = pkgs.writeShellScript "scx-soryu-notify" ''
                  set -u
                  echo "soryu panic!; the system is running default scheduler" >&2
                  echo "journalctl -u scx-soryu -n 200 has the exit reason" >&2

                  uid=$(${pkgs.coreutils}/bin/id -u ${cfg.notify.user}) || exit 0
                  bus=/run/user/$uid/bus
                  [ -S "$bus" ] || exit 0

                  ${pkgs.util-linux}/bin/runuser -u ${cfg.notify.user} --                     ${pkgs.coreutils}/bin/env                       "DBUS_SESSION_BUS_ADDRESS=unix:path=$bus"                       ${pkgs.libnotify}/bin/notify-send                         --urgency=critical                         --icon=dialog-error                         "scx_soryu durdu"                         "Sistem EEVDF'e döndü. journalctl -u scx-soryu" || true
                '';
              };
            };
          };
        };

      nixosConfigurations.testvm = nixpkgs.lib.nixosSystem {
        inherit system;
        modules = [
          "${nixpkgs}/nixos/modules/virtualisation/qemu-vm.nix"
          vmBase
        ];
      };

      nixosConfigurations.servicevm = nixpkgs.lib.nixosSystem {
        inherit system;
        modules = [
          "${nixpkgs}/nixos/modules/virtualisation/qemu-vm.nix"
          vmBase
          self.nixosModules.default
          {
            services.scx-soryu = {
              enable = true;
              reportSec = 5;
              # No desktop session in here, so nothing to notify.
              notify.enable = false;
            };
          }
        ];
      };
    };
}
