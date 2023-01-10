use std::{
    fs::File,
    io::{BufReader, BufWriter, Write},
};
use std::path::Path;

use ff::Field;
use halo2_gadgets::sha256::{BlockWord, Sha256, Table16Chip, Table16Config};
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{
        create_proof, keygen_pk, keygen_vk, verify_proof, Advice, Circuit, Column,
        ConstraintSystem, Error, Fixed, Instance, ProvingKey,
    },
    poly::{
        kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG},
            multiopen::{ProverGWC, VerifierGWC},
            strategy::SingleStrategy,
        },
        Rotation,
    },
    transcript::{
        Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
    },
};
use halo2_proofs::poly::commitment::Params;
use halo2curves::bn256::{Bn256, Fr, G1Affine};
use rand_core::OsRng;

#[derive(Default)]
struct MyCircuit {
    sha_count: u64,
}

impl Circuit<Fr> for MyCircuit {
    type Config = Table16Config;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        Table16Chip::configure(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        Table16Chip::load(config.clone(), &mut layouter)?;
        let table16_chip = Table16Chip::construct(config);

        /*let input = [
            BlockWord(Value::known(0b01100001011000100110001110000000)),
            BlockWord(Value::known(0b00000000000000000000000000000000)),
            BlockWord(Value::known(0b00000000000000000000000000000000)),
            BlockWord(Value::known(0b00000000000000000000000000000000)),
            BlockWord(Value::known(0b00000000000000000000000000000000)),
            BlockWord(Value::known(0b00000000000000000000000000000000)),
            BlockWord(Value::known(0b00000000000000000000000000000000)),
            BlockWord(Value::known(0b00000000000000000000000000000000)),
            BlockWord(Value::known(0b00000000000000000000000000000000)),
            BlockWord(Value::known(0b00000000000000000000000000000000)),
            BlockWord(Value::known(0b00000000000000000000000000000000)),
            BlockWord(Value::known(0b00000000000000000000000000000000)),
            BlockWord(Value::known(0b00000000000000000000000000000000)),
            BlockWord(Value::known(0b00000000000000000000000000000000)),
            BlockWord(Value::known(0b00000000000000000000000000000000)),
            BlockWord(Value::known(0b00000000000000000000000000011000)),
        ];*/

        //aa931f5ee58735270821b3722866d8882d1948909532cf8ac2b3ef144ae8043363d1d3728b49f10c7cd78c38289c8012477473879f3b53169f2a677b7fbed0c7
        /*
10101010100100110001111101011110
11100101100001110011010100100111
00001000001000011011001101110010
00101000011001101101100010001000
00101101000110010100100010010000
10010101001100101100111110001010
11000010101100111110111100010100
01001010111010000000010000110011
01100011110100011101001101110010
10001011010010011111000100001100
01111100110101111000110000111000
00101000100111001000000000010010
01000111011101000111001110000111
10011111001110110101001100010110
10011111001010100110011101111011
01111111101111101101000011000111
10000000000000000000000000000000
00000000000000000000000000000000
00000000000000000000000000000000
00000000000000000000000000000000
00000000000000000000000000000000
00000000000000000000000000000000
00000000000000000000000000000000
00000000000000000000000000000000
00000000000000000000000000000000
00000000000000000000000000000000
00000000000000000000000000000000
00000000000000000000000000000000
00000000000000000000000000000000
00000000000000000000000000000000
00000000000000000000000000000000
00000000000000000000001000000000
         */
        let input = [
            BlockWord(Value::known(0b10101010100100110001111101011110)),
            BlockWord(Value::known(0b11100101100001110011010100100111)),
            BlockWord(Value::known(0b00001000001000011011001101110010)),
            BlockWord(Value::known(0b00101000011001101101100010001000)),
            BlockWord(Value::known(0b00101101000110010100100010010000)),
            BlockWord(Value::known(0b10010101001100101100111110001010)),
            BlockWord(Value::known(0b11000010101100111110111100010100)),
            BlockWord(Value::known(0b01001010111010000000010000110011)),
            BlockWord(Value::known(0b01100011110100011101001101110010)),
            BlockWord(Value::known(0b10001011010010011111000100001100)),
            BlockWord(Value::known(0b01111100110101111000110000111000)),
            BlockWord(Value::known(0b00101000100111001000000000010010)),
            BlockWord(Value::known(0b01000111011101000111001110000111)),
            BlockWord(Value::known(0b10011111001110110101001100010110)),
            BlockWord(Value::known(0b10011111001010100110011101111011)),
            BlockWord(Value::known(0b01111111101111101101000011000111)),
            BlockWord(Value::known(0b10000000000000000000000000000000)),
            BlockWord(Value::known(0b00000000000000000000000000000000)),
            BlockWord(Value::known(0b00000000000000000000000000000000)),
            BlockWord(Value::known(0b00000000000000000000000000000000)),
            BlockWord(Value::known(0b00000000000000000000000000000000)),
            BlockWord(Value::known(0b00000000000000000000000000000000)),
            BlockWord(Value::known(0b00000000000000000000000000000000)),
            BlockWord(Value::known(0b00000000000000000000000000000000)),
            BlockWord(Value::known(0b00000000000000000000000000000000)),
            BlockWord(Value::known(0b00000000000000000000000000000000)),
            BlockWord(Value::known(0b00000000000000000000000000000000)),
            BlockWord(Value::known(0b00000000000000000000000000000000)),
            BlockWord(Value::known(0b00000000000000000000000000000000)),
            BlockWord(Value::known(0b00000000000000000000000000000000)),
            BlockWord(Value::known(0b00000000000000000000000000000000)),
            BlockWord(Value::known(0b00000000000000000000001000000000)),
        ];

        for _i in 0..self.sha_count {
            let out = Sha256::digest(table16_chip.clone(), layouter.namespace(|| "'publick key'"), &input)?;
            //println!("out: {:?}", out)
        }

        Ok(())
    }
}

fn process_one(k: u32, sha_count: u64) -> Result<(), Error> {
    println!("start process, k={}, sha count={}", k, sha_count);
    // Initialize the polynomial commitment parameters
    let params_path_str = format!("./sha256_params_k_{}", k);
    let params_path = Path::new(params_path_str.as_str());
    if File::open(params_path).is_err() {
        println!("start get param {:?}", chrono::offset::Utc::now());
        let params = ParamsKZG::<Bn256>::setup(k, OsRng);
        let mut buf = Vec::new();

        params.write(&mut buf).expect("Failed to write params");
        let mut file = File::create(params_path).expect("Failed to create sha256_params");

        file.write_all(&buf[..])
            .expect("Failed to write params to file");
        println!("end   get param {:?}", chrono::offset::Utc::now());
    }

    let params_fs = File::open(params_path).expect("couldn't load sha256_params");
    let params: ParamsKZG::<Bn256> =
        Params::read::<_>(&mut BufReader::new(params_fs)).expect("Failed to read params");

    let empty_circuit: MyCircuit = MyCircuit {sha_count};

    // Initialize the proving key
    println!("start get pk vk {:?}", chrono::offset::Utc::now());
    let vk = keygen_vk(&params, &empty_circuit).expect("keygen_vk should not fail");
    let pk = keygen_pk(&params, vk, &empty_circuit).expect("keygen_pk should not fail");
    println!("end   get pk vp {:?}", chrono::offset::Utc::now());

    let circuit: MyCircuit = MyCircuit {sha_count};

    let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
    println!("start create proof {:?}", chrono::offset::Utc::now());
    create_proof::<
        KZGCommitmentScheme<Bn256>,
        ProverGWC<'_, Bn256>,
        Challenge255<G1Affine>,
        _,
        Blake2bWrite<Vec<u8>, G1Affine, Challenge255<_>>,
        _,
    >(
        &params,
        &pk,
        &[circuit],
        &[&[]],
        OsRng,
        &mut transcript,
    )
        .expect("prover should not fail");
    println!("end   get proof {:?}", chrono::offset::Utc::now());
    let proof = transcript.finalize();

    let proof_path_str = format!("./sha256_proof_k_{}_count_{}", k, sha_count);
    let proof_path = Path::new(proof_path_str.as_str());
    let mut file = File::create(&proof_path).expect("Failed to create sha256_proof");
    file.write_all(&proof[..]).expect("Failed to write proof");

    Ok(())
}

fn main() {
    process_one(22, 512).unwrap();
}
