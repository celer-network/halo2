use ark_std::{end_timer, start_timer};
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{create_proof, keygen_pk, keygen_vk, verify_proof, Circuit, ConstraintSystem, Error},
    poly::commitment::Params,
    transcript::{Blake2bRead, Blake2bWrite, Challenge255},
};
use halo2curves::pasta::{pallas, EqAffine};
use rand::rngs::OsRng;

use std::{env, fs::File, io::{prelude::*, BufReader}, path::Path};

use halo2_gadgets::sha256::{BlockWord, Sha256, Table16Chip, Table16Config, BLOCK_SIZE};

use halo2_proofs::{
    poly::{
        commitment::ParamsProver,
        ipa::{
            commitment::{IPACommitmentScheme, ParamsIPA},
            multiopen::{ProverIPA, VerifierIPA},
            strategy::AccumulatorStrategy,
        },
    },
    transcript::{TranscriptReadBuffer, TranscriptWriterBuffer},
};

#[derive(Default)]
struct MyCircuit {
    sha_count: u64,
}

impl Circuit<pallas::Base> for MyCircuit {
    type Config = Table16Config;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<pallas::Base>) -> Self::Config {
        Table16Chip::configure(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<pallas::Base>,
    ) -> Result<(), Error> {
        Table16Chip::load(config.clone(), &mut layouter)?;
        let table16_chip = Table16Chip::construct(config);

        let input = [
            BlockWord(Value::known(0b01111000100000000000000000000000)),
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
            BlockWord(Value::known(0b00000000000000000000000000001000)),
        ];

        // sha one block per loop
        for _i in 0..self.sha_count {
            let _ = Sha256::digest(table16_chip.clone(), layouter.namespace(|| "'sha one'"), &input)?;
        }

        Ok(())
    }
}

fn process_one(k: u32, sha_count: u64) -> Result<(), Error> {
    // Initialize the polynomial commitment parameters
    println!("process sha, k:{}, sha count:{}", k, sha_count);
    let params_path_str = format!("./sha256_params_k_{}", k);
    let params_path = Path::new(params_path_str.as_str());
    if File::open(&params_path).is_err() {
        let timer_get_param = start_timer!(|| format!("build params with K = {}", k));
        let params: ParamsIPA<EqAffine> = ParamsIPA::new(k);
        let mut buf = Vec::new();
        end_timer!(timer_get_param);

        params.write(&mut buf).expect("Failed to write params");
        let mut file = File::create(&params_path).expect("Failed to create sha256_params");

        file.write_all(&buf[..])
            .expect("Failed to write params to file");
    }

    let params_fs = File::open(&params_path).expect("couldn't load sha256_params");
    let params: ParamsIPA<EqAffine> =
        ParamsIPA::read::<_>(&mut BufReader::new(params_fs)).expect("Failed to read params");

    let empty_circuit: MyCircuit = MyCircuit {sha_count};

    // Initialize the proving key
    let timer_get_pk_vk = start_timer!(|| "build pk vk");
    let vk = keygen_vk(&params, &empty_circuit).expect("keygen_vk should not fail");
    let pk = keygen_pk(&params, vk, &empty_circuit).expect("keygen_pk should not fail");
    end_timer!(timer_get_pk_vk);

    let circuit: MyCircuit = MyCircuit {sha_count};

    // Create a proof
    let proof_path_str = format!("./sha256_proof_k_{}_count_{}", k, sha_count);
    let proof_path = Path::new(proof_path_str.as_str());
    let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
    let timer_create_proof = start_timer!(|| "create proof");
    create_proof::<IPACommitmentScheme<_>, ProverIPA<_>, _, _, _, _>(
        &params,
        &pk,
        &[circuit],
        &[&[]],
        OsRng,
        &mut transcript,
    )
        .expect("proof generation should not fail");
    end_timer!(timer_create_proof);
    let proof: Vec<u8> = transcript.finalize();
    let mut file = File::create(&proof_path).expect("Failed to create sha256_proof");
    file.write_all(&proof[..]).expect("Failed to write proof");

    use halo2_proofs::poly::VerificationStrategy;
    let strategy = AccumulatorStrategy::new(&params);
    let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
    let timer_verify = start_timer!(|| "verify");
    let strategy = verify_proof::<IPACommitmentScheme<_>, VerifierIPA<_>, _, _, _>(
        &params,
        pk.get_vk(),
        strategy,
        &[&[]],
        &mut transcript,
    ).unwrap();
    end_timer!(timer_verify);
    Ok(())
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let k: u32 = args[1].parse().unwrap();
    let sha_block: u64 = args[2].parse().unwrap();
    process_one(k, sha_block).unwrap();
}
