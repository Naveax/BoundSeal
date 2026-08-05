from pathlib import Path

path = Path("crates/nxb-evidence-key-provider/src/lib.rs")
text = path.read_text(encoding="utf-8")
old = '''        let (plan, mut activation, _) = signed_plan(now);
        let replacement = if &activation.signature_hex[..2] == "00" {
            "01"
        } else {
            "00"
        };
        activation.signature_hex.replace_range(0..2, replacement);
        let mut provider = provider(now);'''
new = '''        let (plan, activation, _) = signed_plan(now);
        let mut signature = decode_hex(&activation.signature_hex, "signature").expect("signature");
        signature[0] ^= 0x01;
        let activation = EvidenceKeyActivation::from_signature(plan.plan_sha256.clone(), &signature)
            .expect("tampered activation");
        let mut provider = provider(now);'''
if text.count(old) != 1:
    raise SystemExit("expected exactly one invalid-signature fixture")
text = text.replace(old, new, 1)
path.write_text(text, encoding="utf-8", newline="\n")
