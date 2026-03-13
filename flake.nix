{
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";

  outputs = { self, nixpkgs }:
    let
      system = "x86_64-linux";
      pkgs = nixpkgs.legacyPackages.${system};

      vfsModule = self.packages.${system}.default;

      mockTailscaled = pkgs.stdenv.mkDerivation {
        pname = "mock-tailscaled";
        version = "0.1.0";
        src = ./.;
        buildPhase = ''
          gcc -o mock_tailscaled mock_tailscaled.c
        '';
        installPhase = ''
          mkdir -p $out/bin
          cp mock_tailscaled $out/bin/
        '';
      };
    in {
      packages.${system}.default = pkgs.stdenv.mkDerivation {
        pname = "samba-vfs-tailscale";
        version = "0.1.0";
        src = ./.;

        buildInputs = [ pkgs.samba pkgs.talloc pkgs.curl pkgs.jansson ];

        buildPhase = ''
          # Assert Samba VFS interface version matches vendored structs
          SAMBA_VFS_VERSION=$(grep '#define SMB_VFS_INTERFACE_VERSION' \
            ${pkgs.samba.dev}/include/samba-4.0/source3/include/vfs.h \
            | grep -oP '\d+' || echo "unknown")
          EXPECTED_VERSION=50
          if [ "$SAMBA_VFS_VERSION" != "$EXPECTED_VERSION" ]; then
            echo "ERROR: Samba VFS interface version mismatch"
            echo "  Expected: $EXPECTED_VERSION (vendored structs from samba 4.22.6)"
            echo "  Found:    $SAMBA_VFS_VERSION"
            echo "  Update vendored struct declarations in vfs_tailscale.c"
            exit 1
          fi

          gcc -shared -fPIC \
            -DHAVE_IMMEDIATE_STRUCTURES=1 \
            -I${pkgs.samba.dev}/include/samba-4.0 \
            -I${pkgs.talloc}/include \
            -I${pkgs.curl.dev}/include \
            -I${pkgs.jansson}/include \
            -L${pkgs.samba}/lib/samba \
            -L${pkgs.talloc}/lib \
            -L${pkgs.curl}/lib \
            -L${pkgs.jansson}/lib \
            -lsmbd-base-private-samba \
            -lauth-private-samba \
            -lsamba-sockets-private-samba \
            -ltalloc -lcurl -ljansson \
            -o vfs_tailscale.so vfs_tailscale.c whois.c
        '';

        installPhase = ''
          mkdir -p $out/lib/samba/vfs
          cp vfs_tailscale.so $out/lib/samba/vfs/
        '';
      };

      checks.${system} = {
        default = pkgs.stdenv.mkDerivation {
          pname = "samba-vfs-tailscale-test";
          version = "0.1.0";
          src = ./.;

          buildInputs = [ pkgs.talloc pkgs.curl pkgs.jansson ];

          buildPhase = ''
            gcc -o test_whois test_whois.c whois.c \
              -I${pkgs.talloc}/include \
              -I${pkgs.curl.dev}/include \
              -I${pkgs.jansson}/include \
              -L${pkgs.talloc}/lib \
              -L${pkgs.curl}/lib \
              -L${pkgs.jansson}/lib \
              -ltalloc -lcurl -ljansson -lpthread
            ./test_whois
          '';

          installPhase = ''
            mkdir -p $out
            touch $out/passed
          '';
        };

        integration = pkgs.testers.runNixOSTest {
          name = "samba-tailscale-auth-integration";

          nodes.machine = { pkgs, ... }: {
            users.users.testuser = { isNormalUser = true; };

            services.samba = {
              enable = true;
              settings = {
                global = {
                  security = "user";
                  "map to guest" = "bad user";
                  "preload modules" = "${vfsModule}/lib/samba/vfs/vfs_tailscale.so";
                };
                testshare = {
                  path = "/srv/share";
                  "read only" = "no";
                  "guest ok" = "yes";
                  "vfs objects" = "tailscale:/run/mock-tailscaled.sock";
                };
                denyshare = {
                  path = "/srv/denyshare";
                  "read only" = "no";
                  "guest ok" = "yes";
                  "vfs objects" = "tailscale:/run/mock-tailscaled-unknown.sock";
                };
                nontailscale = {
                  path = "/srv/nontailscale";
                  "read only" = "no";
                  "guest ok" = "yes";
                  "vfs objects" = "tailscale:/run/mock-tailscaled-nomatch.sock";
                };
              };
            };

            systemd.services.mock-tailscaled = {
              wantedBy = [ "multi-user.target" ];
              before = [ "samba-smbd.service" ];
              serviceConfig.ExecStart =
                "${mockTailscaled}/bin/mock_tailscaled /run/mock-tailscaled.sock 127.0.0.1:0 testuser";
            };

            systemd.services.mock-tailscaled-unknown = {
              wantedBy = [ "multi-user.target" ];
              before = [ "samba-smbd.service" ];
              serviceConfig.ExecStart =
                "${mockTailscaled}/bin/mock_tailscaled /run/mock-tailscaled-unknown.sock 127.0.0.1:0 nosuchuser";
            };

            # Mock that only recognizes 10.0.0.1 — 127.0.0.1 gets 404
            systemd.services.mock-tailscaled-nomatch = {
              wantedBy = [ "multi-user.target" ];
              before = [ "samba-smbd.service" ];
              serviceConfig.ExecStart =
                "${mockTailscaled}/bin/mock_tailscaled /run/mock-tailscaled-nomatch.sock 10.0.0.1:0 testuser";
            };

            environment.systemPackages = [ pkgs.samba ];
          };

          testScript = ''
            machine.wait_for_unit("mock-tailscaled.service")
            machine.wait_for_file("/run/mock-tailscaled.sock")
            machine.wait_for_unit("mock-tailscaled-unknown.service")
            machine.wait_for_file("/run/mock-tailscaled-unknown.sock")
            machine.wait_for_unit("mock-tailscaled-nomatch.service")
            machine.wait_for_file("/run/mock-tailscaled-nomatch.sock")
            machine.wait_for_unit("samba-smbd.service")

            machine.succeed("mkdir -p /srv/share && chown testuser /srv/share")
            machine.succeed("mkdir -p /srv/denyshare")
            machine.succeed("mkdir -p /srv/nontailscale")

            # Happy path: tailscale user maps to existing local user
            machine.succeed("smbclient //127.0.0.1/testshare -N -c 'ls'")

            # Write through SMB and verify ownership
            machine.succeed("echo hello > /tmp/testfile")
            machine.succeed("smbclient //127.0.0.1/testshare -N -c 'put /tmp/testfile testfile'")
            machine.succeed("stat -c %U /srv/share/testfile | grep testuser")

            # Deny: tailscale user maps to non-existent local user
            machine.fail("smbclient //127.0.0.1/denyshare -N -c 'ls'")

            # Deny: client IP not recognized by tailscaled (not a tailscale peer)
            machine.fail("smbclient //127.0.0.1/nontailscale -N -c 'ls'")
          '';
        };
      };
    };
}
