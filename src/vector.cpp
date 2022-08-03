#include <gsl/gsl>

#include "vector.h"

plain_vector::plain_vector(const std::shared_ptr<seal::SEALContext> ctx,
		const std::vector<double> &values, float scale)
	: seal_ctx(std::move(ctx)),
   	  dim_(values.size()) {
	seal::CKKSEncoder encoder(*ctx);
	size_t slot_count = encoder.slot_count();

	size_t pt_count = (values.size() + slot_count - 1) / slot_count;
	pts.reserve(pt_count);
	gsl::span<const double> values_span = gsl::make_span(values);
	for (size_t i = 0; i < values.size(); i += slot_count) {
		size_t length = slot_count;
		if (length > values.size() - i) {
			length = gsl::dynamic_extent;
		}
		gsl::span<const double> span = values_span.subspan(i, length);

		seal::Plaintext pt;
		encoder.encode(span, scale, pt);
		pts.emplace_back(std::move(pt));
	}
}

std::vector<double> plain_vector::decode() const {
	seal::CKKSEncoder encoder(*seal_ctx);

	std::vector<double> values(encoder.slot_count() * pts.size());
	gsl::span<double> values_span = gsl::make_span(values);
	size_t offset = 0;
	for (const seal::Plaintext &pt : pts) {
		encoder.decode(pt, values_span.subspan(offset, encoder.slot_count()));
		offset += encoder.slot_count();
	}
	values.resize(dim_);
	return values;
}

ckks_vector::ckks_vector(const std::shared_ptr<seal::SEALContext> ctx,
		const seal::PublicKey &key, const plain_vector &plain_vector)
	: seal_ctx(std::move(ctx)),
	  evaluator(*seal_ctx),
	  dim(plain_vector.dim()) {
	cts.reserve(plain_vector.pt_size());

	seal::Encryptor encryptor(*ctx, key);
	for (size_t i = 0; i < plain_vector.pt_size(); i++) {
		seal::Ciphertext ct;
		encryptor.encrypt(plain_vector[i], ct);
		cts.emplace_back(std::move(ct));
	}
}

plain_vector ckks_vector::decrypt(const seal::SecretKey &sk) const {
	seal::Decryptor decryptor(*seal_ctx, sk);
	std::vector<seal::Plaintext> pts;
	for (const seal::Ciphertext &ct : cts) {
		seal::Plaintext pt;
		decryptor.decrypt(ct, pt);
		pts.emplace_back(std::move(pt));
	}

	return plain_vector(seal_ctx, std::move(pts), dim);
}
