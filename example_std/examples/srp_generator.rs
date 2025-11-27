use clap::Parser;

#[derive(Parser, Debug)]
#[command(about = "Generate salt & verifier from pairing code like 111-22-333")]
struct Args {
    /// The pairing code to process (111-22-333)
    pairing_code: String,
}

fn byte_slice_to_string(b: &[u8]) -> String {
    //    0x84, 0x3e, 0x54, 0xd4, 0x61, 0xd8, 0xbd, 0xee, 0x78, 0xcf, 0x96, 0xb3, 0x30, 0x85, 0x4c,
    let mut r = String::new();
    for c in b.chunks(15) {
        r += "        ";
        for x in c {
            r += &format!("0x{:0>2x}, ", x);
        }
        r.pop(); // remove the last space.
        r += "\n";
    }

    r
}

fn main() {
    let args = Args::parse();

    let mut ctx = micro_hap::AccessoryContext::default();
    use micro_hap::PairCode;
    let pair_code =
        PairCode::from_str(&args.pairing_code).expect("expected pair code with hyphen, 111-22-333");
    println!(
        "Pairing Code bytes: {:?}  as digits: {:?}",
        pair_code,
        pair_code.to_digits()
    );
    ctx.info.assign_from(rand::random(), pair_code);

    println!("// srp salt and verifier for {:?}", pair_code.to_digits());
    print!("const SRP_SALT: [u8;16] = [\n",);
    print!("{}", byte_slice_to_string(&ctx.info.salt));
    print!("];\n");

    print!("const SRP_VERIFIER: [u8;384] = [\n");
    print!("{}", byte_slice_to_string(&ctx.info.verifier));
    print!("];\n");
}
