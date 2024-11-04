extern crate num_bigint;
extern crate rand;

use std::str::FromStr;

use crypto::{
    merkle_tree::MerkleProof,
    poseidon::{PoseidonHasher, PoseidonSignature},
    HashFunction, SignatureFunction,
};
use heimdall::credential::Credential;
use ledger_authority::LedgerAuthority;
use nft::{shielded_fractional_nft::ShieldedFractionalNFT, FractionalNFT, NFT};
use num_bigint::{BigInt, RandBigInt, RandomBits};
use rand::Rng;
use serde::{Deserialize, Serialize};

const TREE_DEPTH: u32 = 10;
const TRUST_DEPTH: u32 = 10;

#[derive(Debug, Serialize, Deserialize)]
pub struct NFTCredential<H: HashFunction, S: SignatureFunction> {
    #[serde(bound(
        serialize = "Credential<H,S>: Serialize",
        deserialize = "Credential<H,S>: Deserialize<'de>"
    ))]
    pub credential: Credential<H, S>,
    pub nft: ShieldedFractionalNFT,
}

impl NFTCredential<PoseidonHasher, PoseidonSignature> {
    pub fn new(
        attributes: &Vec<String>,
        id: u64,
        expiration: u128,
        credential_type: &str,
        delegatable: bool,
        registry: &str,
        sk_issuer: &BigInt,
        owner: &BigInt,
        ledger_authority: &mut dyn LedgerAuthority<PoseidonHasher, 2>,
        trust_list_proof: &MerkleProof<PoseidonHasher, 2>,
    ) -> Result<NFTCredential<PoseidonHasher, PoseidonSignature>, Box<dyn std::error::Error>> {
        let mut rng = rand::thread_rng();
        let mut credential_type = "NFTCredential:".to_owned() + credential_type;
        let (nft_source, pk_nft) = PoseidonSignature::new_key_pair();
        dbg!("Starting Cred");
        let credential: Credential<PoseidonHasher, PoseidonSignature> = Credential::new(
            attributes,
            id,
            &pk_nft,
            expiration,
            &credential_type,
            delegatable,
            registry,
            sk_issuer.clone(),
        );
        dbg!("Cred erstellt");
        let nft = ShieldedFractionalNFT::new(
            &nft_source,
            &BigInt::from_str("1").unwrap(),
            &owner,
            ledger_authority,
            trust_list_proof,
            sk_issuer,
        )?;
        dbg!("Cnft erstellt");

        Ok(NFTCredential { credential, nft })
    }
    pub fn transfer_split(
        &self,
        private_key: &BigInt,
        fraction: [BigInt; 2],
        target_a: &BigInt,
        target_b: &BigInt,
        ledger_authority: &mut dyn LedgerAuthority<PoseidonHasher,2>,
    ) -> Result<(Self, Self), Box<dyn std::error::Error>> {
        let (nft_split_a, nft_split_b) = self.nft.transfer_split(private_key, fraction, target_a, target_b, ledger_authority)?;

        Ok((NFTCredential{credential: self.credential.clone(),nft: nft_split_a}, NFTCredential{credential: self.credential.clone(),nft: nft_split_b}))
    }

    
    pub fn burn(
        &mut self,
        private_key: &BigInt,
        ledger_authority: &mut dyn LedgerAuthority<PoseidonHasher,2>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.nft.burn(private_key, ledger_authority)
    }
}

#[cfg(test)]
mod tests {
    use crypto::poseidon::PoseidonHasher;
    use ledger_authority::{DefaultLedgerAuthority, LedgerAuthority};
    use nft::NFT;
    use std::str::FromStr;

    use super::*;

    #[test]
    fn init_credential() {
        let source = BigInt::from_str("333").unwrap();
        let value = BigInt::from_str("120").unwrap();

        let trusted_priv = BigInt::from_str("1").unwrap();
        let trusted_pub = BigInt::from_str(
            "18586133768512220936620570745912940619677854269274689475585506675881198879027",
        )
        .unwrap();

        let owner_a_priv = BigInt::from_str("2").unwrap();
        let owner_a_pub = BigInt::from_str(
            "8645981980787649023086883978738420856660271013038108762834452721572614684349",
        )
        .unwrap(); //poseidon of 2

        let owner_b_priv = BigInt::from_str("3").unwrap();
        let owner_b_pub = BigInt::from_str(
            "6018413527099068561047958932369318610297162528491556075919075208700178480084",
        )
        .unwrap(); //poseidon of 3

        println!("Ledger authority init start");

        let mut trust_list = vec![
            trusted_pub.to_string(),
            "2".to_owned(),
            "3".to_owned(),
            "4".to_owned(),
            "5".to_owned(),
        ];

        for _ in trust_list.len()..((2 as u32).pow(TRUST_DEPTH) as usize) {
            trust_list.push("0".to_owned());
        }

        let mut ledger_authority: DefaultLedgerAuthority<PoseidonHasher, 2> =
            DefaultLedgerAuthority::new(TREE_DEPTH, trust_list);
        println!("Ledger authority init finished");

        //
        // minting
        //
        println!("Testing minting");

        //default case
        let proof = ledger_authority.get_trust_list().generate_proof(0).unwrap();
        dbg!("Proof created");

        let nft_wrap = NFTCredential::new(
            &vec![
                "John".to_owned(),
                "Jones".to_owned(),
                "male".to_owned(),
                "843995700".to_owned(),
                "blue".to_owned(),
                "180".to_owned(),
                "115703781".to_owned(),
                "499422598".to_owned(),
            ],
            255 as u64,
            365,
            "test",
            false,
            "revocRegistry",
            &trusted_priv,
            &owner_a_pub,
            &mut ledger_authority,
            &proof,
        );
        let nft = nft_wrap.unwrap();
        //
        // transfer_split
        //
        println!("Testing transfer");
        //default case
        let (mut nft_a,mut nft_b) = nft
            .transfer_split(
                &owner_a_priv,
                [BigInt::from(1), BigInt::from(2)],
                &owner_a_pub,
                &owner_b_pub,
                &mut ledger_authority,
            )
            .expect("transfer default case");


    
        //
        // burn
        //
        println!("Testing burn");

        //default case
        nft_b.burn(&owner_b_priv,&mut ledger_authority).expect("burn default case");
    }
}
