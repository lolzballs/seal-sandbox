#pragma once

#include <seal/seal.h>

class ckks_vector;

class plain_vector {
public:
	plain_vector(const std::shared_ptr<seal::SEALContext>,
			const std::vector<double> &, float scale);
	plain_vector(const std::shared_ptr<seal::SEALContext> ctx,
			std::vector<seal::Plaintext> pts, size_t dim)
		: seal_ctx(std::move(ctx)),
		  dim_(dim),
		  pts(std::move(pts)) {}

	std::vector<double> decode() const;

	size_t dim() const {
		return dim_;
	}

	size_t pt_size() const {
		return pts.size();
	}

	const seal::Plaintext &operator[](size_t index) const {
		return pts[index];
	}
private:
	std::shared_ptr<seal::SEALContext> seal_ctx;

	size_t dim_;
	std::vector<seal::Plaintext> pts;
};

class ckks_vector {
public:
	ckks_vector(const std::shared_ptr<seal::SEALContext>,
			const seal::PublicKey &, const plain_vector &);
	
	plain_vector decrypt(const seal::SecretKey &) const;
private:
	std::shared_ptr<seal::SEALContext> seal_ctx;
	seal::Evaluator evaluator;

	size_t dim;
	std::vector<seal::Ciphertext> cts;
};
