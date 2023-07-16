/*

 This crate translates the following zkas circuit into halo2.

 // arithmetic.zk

 constant "Arith" {}

 witness "Arith" {
    Base a,
    Base b,
 }

 circuit "Arith" {
     sum = base_add(a, b);
     constrain_instance(sum);
     product = base_mul(a, b);
     constrain_instance(product);
     difference = base_sub(a, b);
     constrain_instance(difference);
 }

*/

pub mod gadget;

use crate::gadget::{
    arithmetic::{ArithChip, ArithConfig, ArithInstruction},
    assign_free_advice,
};
use halo2_proofs::{
    circuit::*,
    pasta::{pallas, vesta},
    plonk,
    plonk::*,
    poly::commitment::Params,
    transcript::Blake2bRead,
};

////////////////////////////////////////////////// Circuit ///////////////////////////////////////////////

// Q: The most important question is: what is the proof size? what is the verification time ie the virtualization penalty?

#[derive(Clone)]
struct MyConfig {
    instance: Column<Instance>,
    advices: [Column<Advice>; 3],
    arith_config: ArithConfig,
}

#[derive(Default, Clone)]
struct MyCircuit {
    a: Value<pallas::Base>,
    b: Value<pallas::Base>,
}

// By using a trait bound with an impl block that uses generic type parameters,
// we can implement methods conditionally for types that implement the specified traits.
// https://doc.rust-lang.org/book/ch10-02-traits.html
impl Circuit<pallas::Base> for MyCircuit {
    type Config = MyConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<pallas::Base>) -> Self::Config {
        let advices = [
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
        ];
        let instance = meta.instance_column();

        meta.enable_equality(instance);
        meta.enable_equality(advices[0]);
        meta.enable_equality(advices[1]);
        meta.enable_equality(advices[2]);

        Self::Config {
            instance,
            advices,
            arith_config: ArithChip::configure(meta, advices[0], advices[1], advices[2]),
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<pallas::Base>,
    ) -> Result<(), Error> {
        let arith_chip = ArithChip::construct(config.arith_config);
        let a = assign_free_advice(layouter.namespace(|| "load a"), config.advices[0], self.a)?;
        let b = assign_free_advice(layouter.namespace(|| "load b"), config.advices[1], self.b)?;

        let sum = arith_chip.add(layouter.namespace(|| "a + b"), &a, &b)?;
        layouter.constrain_instance(sum.cell(), config.instance, 0)?;

        // Q: Why is the selector cell of the mul region in a different column that those of sum and sub gate?
        let product = arith_chip.mul(layouter.namespace(|| "a * b"), &a, &b)?;
        layouter.constrain_instance(product.cell(), config.instance, 1)?;

        let diff = arith_chip.sub(layouter.namespace(|| "a - b"), &a, &b)?;
        layouter.constrain_instance(diff.cell(), config.instance, 2)?;

        Ok(())
    }
}

////////////////////////////////////////////////// Proof ///////////////////////////////////////////////

#[derive(Clone, Default, PartialEq, Eq)]
pub struct Proof(Vec<u8>);

impl AsRef<[u8]> for Proof {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Proof {
    pub fn verify(
        &self,
        vk: &VerifyingKey,
        instances: &[pallas::Base],
    ) -> std::result::Result<(), plonk::Error> {
        let strategy = SingleVerifier::new(&vk.params);
        let mut transcript = Blake2bRead::init(&self.0[..]);

        plonk::verify_proof(
            &vk.params,
            &vk.vk,
            strategy,
            &[&[instances]],
            &mut transcript,
        )
    }

    pub fn new(bytes: Vec<u8>) -> Self {
        Proof(bytes)
    }
}

impl core::fmt::Debug for Proof {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Proof({:?})", self.0)
    }
}

/////////////////////////////////////////// VerifyingKey //////////////////////////////////////////////

#[derive(Clone, Debug)]
pub struct VerifyingKey {
    pub params: Params<vesta::Affine>,
    pub vk: plonk::VerifyingKey<vesta::Affine>,
}

impl VerifyingKey {
    pub fn build(k: u32, c: &impl Circuit<pallas::Base>) -> Self {
        let params = Params::new(k);
        let vk = plonk::keygen_vk(&params, c).unwrap();
        VerifyingKey { params, vk }
    }
}

/////////////////////////////////////////// Wasm entrypoint //////////////////////////////////////////////

// I: Optimization idea: AOT compilation and caching the native code
#[no_mangle]
pub extern "C" fn entrypoint() {
    let k = 4;
    let circuit = MyCircuit {
        a: Value::known(pallas::Base::from(69)),
        b: Value::known(pallas::Base::from(42)),
    };
    let public_inputs = vec![
        pallas::Base::from(69 + 42),
        pallas::Base::from(69 * 42),
        pallas::Base::from(69 - 42),
    ];
    let vk = VerifyingKey::build(k, &circuit);

    let proof_bytes = include_bytes!("../proof.bin");
    let proof_vec = proof_bytes.to_vec();
    let proof = Proof::new(proof_vec);
    assert!(proof.verify(&vk, &public_inputs).is_ok());
}

// Same work, but do not verify
#[no_mangle]
pub extern "C" fn entrypoint_no_verify() {
    let k = 4;
    let circuit = MyCircuit {
        a: Value::known(pallas::Base::from(69)),
        b: Value::known(pallas::Base::from(42)),
    };
    let _public_inputs = vec![
        pallas::Base::from(69 + 42),
        pallas::Base::from(69 * 42),
        pallas::Base::from(60 - 42),
    ];
    let _vk = VerifyingKey::build(k, &circuit);

    // include_bytes has no runtime cost: https://stackoverflow.com/a/61625729
    let proof_bytes = include_bytes!("../proof.bin");
    let proof_vec = proof_bytes.to_vec();
    let _ = Proof::new(proof_vec);
    // let _ = proof.verify(&vk, &public_inputs);
}

#[no_mangle]
pub extern "C" fn entrypoint_no_verify_no_vk() {
    let _k = 4;
    let _circuit = MyCircuit {
        a: Value::known(pallas::Base::from(69)),
        b: Value::known(pallas::Base::from(42)),
    };
    let _public_inputs = vec![
        pallas::Base::from(69 + 42),
        pallas::Base::from(69 * 42),
        pallas::Base::from(60 - 42),
    ];
    // let _vk = VerifyingKey::build(k, &circuit);

    // include_bytes has no runtime cost: https://stackoverflow.com/a/61625729
    let proof_bytes = include_bytes!("../proof.bin");
    let proof_vec = proof_bytes.to_vec();
    let _ = Proof::new(proof_vec);
    // let _ = proof.verify(&vk, &public_inputs);
}

//////////////////////////////////////////// Tests ///////////////////////////////////

#[cfg(all(test, feature = "gen_proof"))]
mod tests {
    use super::*;
    use halo2_proofs::dev::MockProver;
    use halo2_proofs::transcript::Blake2bWrite;
    use rand::rngs::OsRng;
    use rand::RngCore;

    #[derive(Clone, Debug)]
    pub struct ProvingKey {
        pub params: Params<vesta::Affine>,
        pub pk: plonk::ProvingKey<vesta::Affine>,
    }

    impl ProvingKey {
        pub fn build(k: u32, c: &impl Circuit<pallas::Base>) -> Self {
            let params = Params::new(k);
            let vk = plonk::keygen_vk(&params, c).unwrap();
            let pk = plonk::keygen_pk(&params, vk, c).unwrap();
            ProvingKey { params, pk }
        }
    }

    impl Proof {
        pub fn create(
            pk: ProvingKey,
            circuits: &[impl Circuit<pallas::Base>],
            instances: &[pallas::Base],
            mut rng: impl RngCore,
        ) -> std::result::Result<Self, plonk::Error> {
            let mut transcript = Blake2bWrite::<_, vesta::Affine, _>::init(vec![]);
            plonk::create_proof(
                &pk.params,
                &pk.pk,
                circuits,
                &[&[instances]],
                &mut rng,
                &mut transcript,
            )?;

            Ok(Proof(transcript.finalize()))
        }
    }

    #[test]
    fn test_circuit() {
        // Q: Why are there unused rows? (see the circuit layout)
        let circuit = MyCircuit {
            a: Value::known(pallas::Base::from(69)),
            b: Value::known(pallas::Base::from(42)),
        };

        // Make layout diagram for the circuit
        // use halo2_proofs::dev::CircuitLayout;
        // use plotters::prelude::*;
        // let root = BitMapBackend::new("target/layout.png", (3840, 2160)).into_drawing_area();
        // root.fill(&WHITE).unwrap();
        // let root = root.titled("Circuit Layout", ("sans-serif", 60)).unwrap();
        // CircuitLayout::default().render(4, &circuit, &root).unwrap();

        let k = 4;

        let pk = ProvingKey::build(k, &circuit);
        let public_inputs = vec![
            pallas::Base::from(69 + 42),
            pallas::Base::from(69 * 42),
            pallas::Base::from(69 - 42),
        ];

        // Alternative API
        // let prover = MockProver::run(k, &circuit, vec![public_inputs.clone()]).unwrap();
        // prover.assert_satisfied();

        let proof = Proof::create(pk, &[circuit.clone()], &public_inputs, &mut OsRng).unwrap();
        let vk = super::VerifyingKey::build(k, &circuit);
        assert!(proof.verify(&vk, &public_inputs).is_ok());

        println!("Proof size [{} kB]", proof.as_ref().len() as f64 / 1024.0);

        let mut file = std::fs::File::create("proof.bin").unwrap();
        use std::io::{Read, Write};
        file.write_all(proof.as_ref());
    }
}

#[cfg(all(test, feature = "wasm_verify"))]
mod tests {
    use std::time::Instant;
    use wasmer_compiler_singlepass::Singlepass;

    #[test]
    fn test_wasm_verify() {
        use wasmer::FunctionEnv;
        use wasmer::{imports, Instance, Module, Store};

        let now = Instant::now();
        /////////// Basically setting up the wasm runtime /////////

        // IMPORTANT: Singlepass to match darkfi. Singlepass compiles under 500ms at the cost longer runtime
        let compiler_config = Singlepass::new();
        let mut store = Store::new(compiler_config);

        // let mut store = Store::default();
        let _env = FunctionEnv::new(&mut store, ());
        let wasm_bytes = include_bytes!("../wasm_verifier_arithmetic.wasm");
        let module = Module::new(&store, wasm_bytes).unwrap();
        let import_object = imports! {};
        let instance = Instance::new(&mut store, &module, &import_object).unwrap();
        // Why does darkfi runtime compile wasm everytime, instead of compiling once?
        let entrypoint = instance.exports.get_function("entrypoint").unwrap();
        println!("wasm setup [{:?}ms]", now.elapsed().as_millis());

        let now = Instant::now();
        let _answer = entrypoint.call(&mut store, &[]).unwrap().to_vec();
        println!(
            "wasm built vk and verifed in [{:?}ms]",
            now.elapsed().as_millis()
        );

        let entrypoint = instance
            .exports
            .get_function("entrypoint_no_verify")
            .unwrap();

        let now = Instant::now();
        let _answer = entrypoint.call(&mut store, &[]).unwrap().to_vec();
        println!("Wasm built vk in [{:?}ms]", now.elapsed().as_millis());

        let entrypoint = instance
            .exports
            .get_function("entrypoint_no_verify_no_vk")
            .unwrap();

        let now = Instant::now();
        let _answer = entrypoint.call(&mut store, &[]).unwrap().to_vec();
        println!(
            "Wasm runs without building vk in [{:?}ms]",
            now.elapsed().as_millis()
        );
    }
}
