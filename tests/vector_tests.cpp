#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>

#include "vector.h"

const double EPSILON = 0.25;

static std::mt19937 mt;

static std::vector<double>
generate_random_vector(size_t n) {
	std::uniform_real_distribution<double> dist(-128.0, 127.0);

	std::vector<double> nums(n);
	for (double &num : nums) {
		num = dist(mt);
	}
	return nums;
}

TEST_CASE("Vector Functionality", "[vector]") {
	mt.seed(0);

	const size_t poly_modulus_degree = 8192;
	seal::EncryptionParameters params(seal::scheme_type::ckks);
	params.set_poly_modulus_degree(poly_modulus_degree);
	params.set_coeff_modulus(seal::CoeffModulus::Create(poly_modulus_degree, { 60, 30, 60 }));

	auto ctx = std::make_shared<seal::SEALContext>(params);

	/* use a scale of 2^30 to encode */
	double scale = pow(2.0, 30);

	/* key setup */
	seal::KeyGenerator keygen(*ctx);
	const seal::SecretKey sk = keygen.secret_key();
	seal::PublicKey pk;
	keygen.create_public_key(pk);

	/* with these params we have 8192 / 2 = 4096 slots */
	const size_t dim = GENERATE(2048, 4096, 8192, 16384);
	const std::vector<double> items = generate_random_vector(dim);

	plain_vector vector(ctx, items, scale);
	REQUIRE(vector.pt_size() == (dim + 4096 - 1) / 4096);
	REQUIRE(vector.dim() == dim);

	SECTION("decode plain_vector") {
		std::vector<double> decoded = vector.decode();
		REQUIRE_THAT(decoded, Catch::Approx(items).epsilon(EPSILON));
	}

	SECTION("encrypt plain_vector with public key") {
		ckks_vector enc(ctx, pk, vector);

		SECTION("decrypt ckks_vector") {
			plain_vector dec = enc.decrypt(sk);
			
			std::vector<double> decoded = dec.decode();
			REQUIRE_THAT(decoded, Catch::Approx(items).epsilon(EPSILON));
		}
	}
}
