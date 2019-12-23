#pragma once
#include <memory>
#include <cstddef>
#include <cstdint>

namespace SleepyDiscord {

	class GenericOpusDecoder {
	public:
		virtual ~GenericOpusDecoder() = default;
		virtual int decodeOpus(uint8_t* encodedData, size_t encodedDataSize,
			int16_t* decodedData) = 0;
	};

	typedef GenericOpusDecoder* (*const CustomInitOpusDecoder)();

	class CustomOpusDecoder : public GenericOpusDecoder {
	public:
		static CustomInitOpusDecoder init;
		CustomOpusDecoder() : decoder(init()) {}
		inline int decodeOpus(uint8_t* encodedData, size_t encodedDataSize,
			int16_t* decodedData) override {
			return decoder->decodeOpus(encodedData, encodedDataSize, decodedData);
		}
	private:
		std::unique_ptr<GenericOpusDecoder> decoder;
	};
}
