use zapper_backend_lib::infrastructure::circuit::count_constraints;
use zapper_backend_lib::infrastructure::params::CryptoParams;
use ark_std::test_rng;

fn main() {
    let mut rng = test_rng();
    let params = CryptoParams::setup(&mut rng);
    let num_constraints = count_constraints(params);
    println!("{}", num_constraints);
}
