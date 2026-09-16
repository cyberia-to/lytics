//! The original signing evidence is retained inside the encrypted payload.
use lytics_event::{Event,EventBody,Pow,encode_body,event_hash,pow_verify,verify_native};
use serde::{Serialize,Deserialize};
#[derive(Debug,Clone,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Origin {
    version:u32,
    pubkey:String,
    signature:String,
    pow:Pow,
    accepted_target:u64,
    hrp:String,
}
impl Origin {
    pub fn capture(event:&Event,hrp:&str,accepted_target:u64)->Self {
        Self{version:1,pubkey:event.pubkey.clone(),signature:event.signature.clone(),
            pow:event.pow,accepted_target,hrp:hrp.into()}
    }
    pub fn verify(&self,body:&EventBody,hrp:&str)->Result<cybergraph::NeuronId,String>{
        if self.version!=1 || self.hrp!=hrp{return Err("event provenance version or HRP mismatch".into());}
        let bytes=encode_body(body);let hash=event_hash(&bytes);
        let subject=verify_native(&bytes,&body.neuron,&self.pubkey,&self.signature,hrp).map_err(|e|e.to_string())?;
        if !pow_verify(&hash,self.pow.nonce,self.accepted_target){return Err("stored event proof of work mismatch".into());}
        Ok(subject)
    }
}
