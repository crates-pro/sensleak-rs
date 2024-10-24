load("@prelude//rust:cargo_package.bzl", "cargo")

# package definitions
filegroup(
    name = "sensleak-0.2.1.crate",
    srcs = glob(["src/**/*.rs"]),
)

pkg_deps = [
    "//third-party:assert_cmd",
    "//third-party:axum",
    "//third-party:chrono",
    "//third-party:clap",
    "//third-party:csv",
    "//third-party:env_logger",
    "//third-party:git2",
    "//third-party:hyper",
    "//third-party:log",
    "//third-party:mockito",
    "//third-party:postgres",
    "//third-party:rayon",
    "//third-party:regex",
    "//third-party:sea-orm",
    "//third-party:serde",
    "//third-party:serde_json",
    "//third-party:tempfile",
    "//third-party:tokio",
    "//third-party:toml",
    "//third-party:tower-http",
    "//third-party:utoipa",
    "//third-party:utoipa-swagger-ui",
    "//third-party:walkdir",
]

# targets
cargo.rust_library(
    name = "sensleak",
    srcs = [":sensleak-0.2.1.crate"],
    crate_root = "sensleak-0.2.1.crate/src/lib.rs",
    edition = "2021",
    deps = pkg_deps,
    visibility = ["PUBLIC"],
)

cargo.rust_binary(
    name = "api",
    srcs = [":sensleak-0.2.1.crate"],
    crate_root = "sensleak-0.2.1.crate/src/api.rs",
    edition = "2021",
    deps = [":sensleak"] + pkg_deps,
    visibility = ["PUBLIC"],
)

cargo.rust_binary(
    name = "scan",
    srcs = [":sensleak-0.2.1.crate"],
    crate_root = "sensleak-0.2.1.crate/src/main.rs",
    edition = "2021",
    deps = [":sensleak"] + pkg_deps,
    visibility = ["PUBLIC"],
)
