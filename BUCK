load("@prelude//rust:cargo_package.bzl", "cargo")

# package definitions
filegroup(
    name = "sensleak-0.3.0.crate",
    srcs = glob(["src/**/*.rs"]),
)

pkg_deps = [
    "//third-party:actix-cors",
    "//third-party:actix-web",
    "//third-party:assert_cmd",
    "//third-party:chrono",
    "//third-party:clap",
    "//third-party:csv",
    "//third-party:env_logger",
    "//third-party:git2",
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
    "//third-party:utoipa",
    "//third-party:utoipa-swagger-ui",
    "//third-party:walkdir",
]

# targets
cargo.rust_library(
    name = "sensleak",
    srcs = [":sensleak-0.3.0.crate"],
    crate_root = "sensleak-0.3.0.crate/src/lib.rs",
    edition = "2024",
    deps = pkg_deps,
    visibility = ["PUBLIC"],
)

cargo.rust_binary(
    name = "api",
    srcs = [":sensleak-0.3.0.crate"],
    crate_root = "sensleak-0.3.0.crate/src/api.rs",
    edition = "2024",
    deps = [":sensleak"] + pkg_deps,
    visibility = ["PUBLIC"],
)

cargo.rust_binary(
    name = "scan",
    srcs = [":sensleak-0.3.0.crate"],
    crate_root = "sensleak-0.3.0.crate/src/main.rs",
    edition = "2024",
    deps = [":sensleak"] + pkg_deps,
    visibility = ["PUBLIC"],
)
