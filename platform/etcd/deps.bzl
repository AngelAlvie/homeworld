load("//bazel:gorepo_patchfix.bzl", "go_repository_alt")

def etcd_dependencies():
    go_repository_alt(
        name = "com_github_coreos_etcd",
        commit = "d57e8b8d97adfc4a6c224fe116714bf1a1f3beb9",  # 3.3.12
        importpath = "github.com/coreos/etcd",
        build_external = "vendored",
        build_file_proto_mode = "disable_global",
        prepatch_cmds = [
            # to get etcd's vendoring strategy to be compatible with gazelle
            "cp -RT cmd/vendor vendor",
            "rm -r cmd/vendor",
        ],
        postpatches = ["//etcd:etcd-visibility.patch", "//etcd:etcdctl-visibility.patch"],
    )
