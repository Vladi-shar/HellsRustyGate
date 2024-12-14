fn main() {
    // Use the `cc` crate to compile the assembly
    cc::Build::new()
        .file("src/hellsgate.asm") // Path to your assembly file
        .compile("hellsgate"); // Name of the static library to produce
}
