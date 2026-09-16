#![cfg(feature="json")]
use lytics_event::{Seed,sign_body,verify_native};
#[test]
fn tracker_identity_and_signature_retain_the_frozen_domain_profile(){
    let rows:serde_json::Value=serde_json::from_str(include_str!("fixtures/domain-v1.json")).unwrap();
    let row=&rows[0];let key=Seed::from_entropy([7;32]).neuron(row["domain"].as_str().unwrap(),row["hrp"].as_str().unwrap()).unwrap();
    assert_eq!(key.bech32,row["address"]);assert_eq!(hex::encode(key.native),row["native_hex"]);
    let body=row["body"].as_str().unwrap().as_bytes();let(pubkey,signature)=sign_body(key.signing_key(),body,&key.bech32);
    use base64::Engine;
    assert_eq!(hex::encode(base64::engine::general_purpose::STANDARD.decode(&signature).unwrap()),row["signature_hex"]);
    assert_eq!(verify_native(body,&key.bech32,&pubkey,&signature,"lytics").unwrap(),key.native);
    assert!(verify_native(body,&key.bech32,&pubkey,&signature,"cyber").is_err());
}
